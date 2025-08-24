#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, time
from pathlib import Path
import pandas as pd

# Birleşik akışta bulunmasını istediğimiz alanlar
DEF_KEEP = [
    "ts","uid","orig_h","orig_p","resp_h","resp_p","proto","service","conn_state",
    "p_cal","pred","margin","type","severity","attacker_ip","target_ip","reason","source"
]

def read_stream(path: Path, source_name: str, max_rows: int, window_sec: int) -> pd.DataFrame:
    """Kaynak CSV'yi boş/bozuk dosyalara toleranslı okuyup pencere/trim uygular."""
    if not path.exists():
        return pd.DataFrame()
    try:
        if path.stat().st_size == 0:
            return pd.DataFrame()
    except Exception:
        return pd.DataFrame()

    try:
        df = pd.read_csv(path, low_memory=False)
    except pd.errors.EmptyDataError:
        # başlıksız/boş gibi
        return pd.DataFrame()
    except Exception:
        return pd.DataFrame()

    if df.empty:
        return pd.DataFrame()

    # Zaman kolonu tahmini ve pencere
    tcol = "ts_merged" if "ts_merged" in df.columns else (
        "ts_generated" if "ts_generated" in df.columns else (
            "ts" if "ts" in df.columns else None
        )
    )
    if tcol and window_sec and window_sec > 0:
        df[tcol] = pd.to_numeric(df[tcol], errors="coerce")
        if df[tcol].notna().any():
            cut = df[tcol].max() - window_sec
            df = df[df[tcol] >= cut]

    # Kaynak etiketi yoksa ekle, varsa normalize et
    if "source" not in df.columns:
        df["source"] = source_name
    else:
        df["source"] = df["source"].fillna(source_name).astype(str).str.lower()

    # Çok büyükse son max_rows
    if max_rows and len(df) > max_rows:
        df = df.tail(max_rows)

    return df

def ensure_columns(df: pd.DataFrame, keep: list[str]) -> pd.DataFrame:
    """Eksik kolonları ekler (NA ile)."""
    if df.empty:
        return df
    for c in keep:
        if c not in df.columns:
            df[c] = pd.NA
    return df

def apply_cooldown(out: pd.DataFrame, out_path: Path, cooldown_sec: int) -> pd.DataFrame:
    """Aynı (type,attacker_ip,target_ip) için son N sn içinde yazılmış satırları ele."""
    if cooldown_sec <= 0 or out.empty:
        return out
    now = time.time()
    if out_path.exists():
        try:
            prev = pd.read_csv(out_path, low_memory=False)
            if not prev.empty and "ts_merged" in prev.columns:
                prev["ts_merged"] = pd.to_numeric(prev["ts_merged"], errors="coerce")
                recent = prev[prev["ts_merged"] >= now - cooldown_sec]
                recent_keys = set(zip(
                    recent["type"].fillna(""),
                    recent["attacker_ip"].fillna(""),
                    recent["target_ip"].fillna("")
                ))
                def is_dup(row):
                    return (str(row.get("type") or ""),
                            str(row.get("attacker_ip") or ""),
                            str(row.get("target_ip") or "")) in recent_keys
                out = out[~out.apply(is_dup, axis=1)]
        except Exception:
            pass
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml", default="reports/scores/alerts_stream.csv", help="ML alarm CSV yolu")
    ap.add_argument("--rules", default="reports/scores/alerts_rule_stream.csv", help="Rules alarm CSV yolu")
    ap.add_argument("--out", default="reports/scores/alerts_merged_stream.csv", help="Birleşik çıktı CSV yolu")
    ap.add_argument("--max-rows", type=int, default=250000, help="Her kaynaktan en fazla kaç satır okunacak")
    ap.add_argument("--window-sec", type=int, default=0, help="Son N saniyelik alarmları dikkate al (0=kapalı)")
    ap.add_argument("--cooldown-sec", type=int, default=0, help="Aynı (type,attacker_ip,target_ip) için tekrarlı yazımı N sn engelle (0=kapalı)")
    args = ap.parse_args()

    ml_df = read_stream(Path(args.ml), "ml", args.max_rows, args.window_sec)
    rb_df = read_stream(Path(args.rules), "rules", args.max_rows, args.window_sec)

    if ml_df.empty and rb_df.empty:
        print("[merge] no alerts to merge")
        return

    # ÖNCE concat (kolon kesmeden), SONRA eksik kolonları tamamla ve DEF_KEEP'e indir
    out = pd.concat([ml_df, rb_df], ignore_index=True)
    if out.empty:
        print("[merge] nothing to write after concat")
        return

    out = ensure_columns(out, DEF_KEEP)
    out = out[DEF_KEEP].copy()
    out["ts_merged"] = time.time()

    out_path = Path(args.out)
    out = apply_cooldown(out, out_path, args.cooldown_sec)
    if out.empty:
        print("[merge] nothing to write after cooldown filter")
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    header = not out_path.exists()
    out.to_csv(out_path, mode="a", index=False, header=header)
    print(f"[merge] wrote {len(out)} rows")
    try:
        print(out[["source","type","severity"]].value_counts().head(5).to_string())
    except Exception:
        pass

if __name__ == "__main__":
    main()
