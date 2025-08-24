#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, time, json, subprocess, shlex
from pathlib import Path
import pandas as pd
from ipaddress import ip_address

DEF_IN_PATH = Path("reports/scores/alerts_merged_stream.csv")
DEF_IPSET   = "ml_blacklist"
DEF_TIMEOUT = 600                # saniye
DEF_SRC     = ["rules","ml"]     # kaynaklar
DEF_MIN_SEV = "med"              # low/med/high
DEF_STATE   = Path("/var/lib/ida-netids/ban_state.json")

# Varsayılan whitelist: senin makinen dahil
DEF_WHITELIST = {
    "127.0.0.1",
    "::1",
    "192.168.1.36"
}

SEV_ORDER = {"low": 0, "med": 1, "high": 2}

def run(cmd: str, check=False, quiet=False):
    if not quiet:
        print(f"[sh] {cmd}")
    res = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    if not quiet and res.stdout.strip():
        print(res.stdout.strip())
    if res.returncode != 0 and check:
        raise RuntimeError(res.stderr.strip() or f"cmd failed: {cmd}")
    return res

def ensure_ipset(set_name: str, ipset_timeout: int, quiet=False):
    # var mı?
    r = run(f"ipset list {set_name}", check=False, quiet=quiet)
    if r.returncode == 0:
        return
    # yoksa oluştur
    run(f"ipset create {set_name} hash:ip timeout {ipset_timeout}", check=True, quiet=quiet)

def ensure_iptables_rule(set_name: str, quiet=False):
    # INPUT zincirinde ipset DROP var mı?
    chk = run(f"iptables -C INPUT -m set --match-set {set_name} src -j DROP", check=False, quiet=True)
    if chk.returncode == 0:
        return
    # ekle
    run(f"iptables -I INPUT -m set --match-set {set_name} src -j DROP", check=True, quiet=quiet)

def load_state(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return {"banned": {}}  # ip -> last_added_ts

def save_state(path: Path, st: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(st, indent=2))

def parse_args():
    ap = argparse.ArgumentParser(description="Automatic actions (ban) from merged alerts.")
    ap.add_argument("--in", dest="in_csv", default=str(DEF_IN_PATH), help="Merged alerts CSV path")
    # İKİ MOD: only-latest veya lookback window
    ap.add_argument("--only-latest", action="store_true", help="Act only on alerts from the last merge (max ts_merged)")
    ap.add_argument("--since-sec", type=int, default=0, help="Lookback seconds (ignored if --only-latest)")
    ap.add_argument("--min-severity", default=DEF_MIN_SEV, choices=list(SEV_ORDER.keys()))
    ap.add_argument("--sources", default=",".join(DEF_SRC), help="Comma list of sources to act on (rules,ml)")
    ap.add_argument("--types", default="", help="Optional comma list of attack types to include (e.g. port_scan,bruteforce)")
    ap.add_argument("--exclude-types", default="", help="Comma list of attack types to exclude")
    ap.add_argument("--ipset", default=DEF_IPSET, help="ipset set name")
    ap.add_argument("--block-sec", type=int, default=DEF_TIMEOUT, help="ipset entry timeout seconds")
    ap.add_argument("--cooldown-sec", type=int, default=60, help="Do not re-add same IP within this period")
    ap.add_argument("--ban-limit", type=int, default=100, help="Max number of IPs to ban per run")
    ap.add_argument("--proof-min", type=int, default=1, help="Min repeated evidence per IP (rows) within selection")
    ap.add_argument("--whitelist", default="", help="Comma list of IPs to whitelist")
    ap.add_argument("--whitelist-file", default="", help="Optional file with newline-separated IPs to whitelist")
    ap.add_argument("--dry-run", action="store_true", help="Do not apply, just print actions")
    ap.add_argument("--ensure-fw", action="store_true", help="Ensure iptables rule exists")
    ap.add_argument("--quiet", action="store_true", help="Less shell output")
    return ap.parse_args()

def compile_whitelist(args) -> set:
    wl = set(DEF_WHITELIST)
    if args.whitelist:
        wl |= {x.strip() for x in args.whitelist.split(",") if x.strip()}
    if args.whitelist_file:
        fp = Path(args.whitelist_file)
        if fp.exists():
            wl |= {ln.strip() for ln in fp.read_text().splitlines() if ln.strip()}
    # normalize: valid ip only
    wl2 = set()
    for ip in wl:
        try:
            ip_address(ip)
            wl2.add(ip)
        except Exception:
            pass
    return wl2

def main():
    args = parse_args()
    in_path = Path(args.in_csv)
    if not in_path.exists():
        print(f"[actions] no alerts file: {in_path}")
        return

    # kaynak/filtre parametrelerini hazırla
    sources = {s.strip().lower() for s in args.sources.split(",") if s.strip()}
    types_inc = {t.strip() for t in args.types.split(",") if t.strip()}
    types_exc = {t.strip() for t in args.exclude_types.split(",") if t.strip()}

    wl = compile_whitelist(args)
    print(f"[actions] whitelist: {sorted(wl)}")

    # --- ALERTS CSV oku (boş/başlıksız toleranslı) ---
    try:
        if in_path.stat().st_size == 0:
            print(f"[actions] skip — {in_path} yok ya da boş")
            return
    except Exception:
        print(f"[actions] skip — {in_path} okunamadı")
        return

    try:
        df = pd.read_csv(in_path, low_memory=False)
    except pd.errors.EmptyDataError:
        print(f"[actions] skip — {in_path} başlıksız/boş gibi görünüyor")
        return
    except Exception as e:
        print(f"[actions] skip — {in_path} okunurken hata: {e}")
        return

    if df.empty:
        print("[actions] empty alerts file")
        return

    # kolonlar ve normalizasyon
    tcol = "ts_merged" if "ts_merged" in df.columns else ("ts_generated" if "ts_generated" in df.columns else "ts")
    if tcol in df.columns:
        df[tcol] = pd.to_numeric(df[tcol], errors="coerce").fillna(0.0)
    else:
        print("[actions] no timestamp column, skipping")
        return

    for c in ("severity","source","type"):
        if c not in df.columns:
            df[c] = ""
        df[c] = df[c].astype(str).str.strip().str.lower()
    for c in ("attacker_ip","target_ip"):
        if c not in df.columns:
            df[c] = ""
        df[c] = df[c].astype(str).str.strip()

    # SEÇİM: only-latest veya window
    if args.only_latest:
        max_ts = df[tcol].max()
        df = df[df[tcol] == max_ts].copy()
        print(f"[actions] only-latest mode: ts={max_ts}")
    else:
        if args.since_sec and args.since_sec > 0:
            now = time.time()
            df = df[df[tcol] >= now - args.since_sec].copy()
            print(f"[actions] window mode: last {args.since_sec}s")

    if df.empty:
        print("[actions] no alerts in selection")
        return

    # filtreler
    min_ord = SEV_ORDER.get(args.min_severity, 0)
    df = df[df["severity"].map(lambda x: SEV_ORDER.get(x, 0)) >= min_ord]
    df = df[df["source"].isin(sources)]
    if types_inc:
        df = df[df["type"].isin(types_inc)]
    if types_exc:
        df = df[~df["type"].isin(types_exc)]
    df = df[df["attacker_ip"].notna() & (df["attacker_ip"] != "")]

    if df.empty:
        print("[actions] nothing to act on after filtering")
        return

    # gruplama (kanıt sayısı)
    grp = df.groupby("attacker_ip").size().reset_index(name="n_rows")
    grp = grp[grp["n_rows"] >= max(1, args.proof_min)]
    grp = grp[~grp["attacker_ip"].isin(wl)]

    if grp.empty:
        print("[actions] no candidates (whitelist/proof filters)")
        return

    candidates = list(grp.sort_values("n_rows", ascending=False)["attacker_ip"])
    if args.ban_limit and len(candidates) > args.ban_limit:
        candidates = candidates[:args.ban_limit]
    print(f"[actions] candidates: {candidates}")

    # state + cooldown
    st = load_state(DEF_STATE)
    banned = st.get("banned", {})
    now = time.time()

    to_add = []
    for ip in candidates:
        last = float(banned.get(ip, 0.0) or 0.0)
        if (now - last) < max(0, args.cooldown_sec):
            print(f"[actions] skip {ip}: cooldown ({int(now-last)}s ago)")
            continue
        try:
            ip_address(ip)
        except Exception:
            print(f"[actions] skip invalid ip: {ip}")
            continue
        to_add.append(ip)

    if not to_add:
        print("[actions] nothing to add after cooldown/validation]")
        return

    print(f"[actions] will {'ADD' if not args.dry_run else 'DRY-ADD'} to ipset={args.ipset}, timeout={args.block_sec}s: {to_add}")

    if not args.dry_run:
        ensure_ipset(args.ipset, args.block_sec, quiet=args.quiet)
        if args.ensure_fw:
            ensure_iptables_rule(args.ipset, quiet=args.quiet)
        for ip in to_add:
            run(f"ipset add {args.ipset} {ip} timeout {args.block_sec}", check=False, quiet=args.quiet)
            banned[ip] = now
        st["banned"] = banned
        save_state(DEF_STATE, st)

    print("[actions] done.")

if __name__ == "__main__":
    main()
