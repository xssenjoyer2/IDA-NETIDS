import argparse, json
from pathlib import Path
import pandas as pd
import numpy as np
import ipaddress
import yaml

def read_csv_safe(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, low_memory=False)

ALIASES = {
    "id.orig_h": "orig_h",
    "id.resp_h": "resp_h",
    "id.orig_p": "orig_p",
    "id.resp_p": "resp_p",
}

NUMERICS = [
    "duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts",
    "missed_bytes","orig_ip_bytes","resp_ip_bytes","orig_p","resp_p"
]

def is_internal(ip: str) -> bool:
    try:
        ipobj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return ipobj.is_private or ipobj.is_link_local

def flow_dir_row(oh, rh):
    i_o = is_internal(str(oh))
    i_r = is_internal(str(rh))
    if i_o and i_r: return "i↔i"
    if i_o and not i_r: return "i→e"
    if not i_o and i_r: return "e→i"
    return "e↔e"

def load_service_map(p: Path):
    if not p or not p.exists():
        return {}, "other"
    y = yaml.safe_load(p.read_text())
    return y.get("map", {}), y.get("default", "other")

def norm_service(val, mp, default_):
    if pd.isna(val):
        return default_
    s = str(val).strip().lower()
    tokens = [t.strip() for t in s.split(",") if t.strip()]
    if not tokens:
        return default_

    # 1) Tünel önceliği
    if "ayiya" in tokens:
        return "tunnel_ayiya"

    # 2) QUIC + SSL birlikte
    if "quic" in tokens and "ssl" in tokens:
        return "quic_tls"

    # 3) SSL + baz servis (http/smtp/imap/pop3 -> *_tls)
    if "ssl" in tokens and any(t for t in tokens if t != "ssl"):
        base = next((t for t in tokens if t != "ssl"), "tls")
        if base in {"http", "smtp", "imap", "pop3"}:
            return f"{base}_tls"
        # Diğerleri için haritadan geçir; yoksa olduğu gibi tut
        return mp.get(base, base)

    # 4) Tek/diğer durumlar: ilk token'ı haritadan geçir; yoksa bırak
    base = tokens[0]
    return mp.get(base, base)

def ensure_cols(df: pd.DataFrame, cols, fill=np.nan):
    for c in cols:
        if c not in df.columns:
            df[c] = fill
    return df

def alias_and_types(df: pd.DataFrame) -> pd.DataFrame:
    rename = {c:ALIASES[c] for c in df.columns if c in ALIASES}
    df = df.rename(columns=rename)
    for c in NUMERICS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    if "ts" in df.columns:
        df["_ts_dt"] = pd.to_datetime(df["ts"], unit="s", errors="coerce", utc=True)
    else:
        df["_ts_dt"] = pd.NaT
    return df

def add_flow_dir(df: pd.DataFrame) -> pd.DataFrame:
    ensure_cols(df, ["orig_h","resp_h"])
    df["flow_dir"] = np.vectorize(flow_dir_row)(df["orig_h"], df["resp_h"])
    return df

def normalize_labels(df: pd.DataFrame, fixed_label: str) -> pd.DataFrame:
    # label -> lowercase (bu df, normal/attack tek tip set; sabitliyoruz)
    df["label"] = fixed_label.lower()

    # attack_type kolonunu normalize et
    if "attack_type" not in df.columns:
        # kolon yoksa label'a göre doldur
        df["attack_type"] = "none" if df["label"].iloc[0] == "normal" else "unknown_attack"
    else:
        # ÖNEMLİ: NaN kontrolünü orijinal seri üzerinden yap (s),
        # string normalizasyon için 'at' kullan
        s = df["attack_type"]
        at = s.astype(str).str.strip().str.lower()

        if df["label"].iloc[0] == "normal":
            # normal -> her koşulda 'none'
            df["attack_type"] = "none"
        else:
            # attack -> boş/NaN/'none' ise 'unknown_attack'
            empty = s.isna() | (at == "") | (at == "none")
            df.loc[empty,  "attack_type"] = "unknown_attack"
            df.loc[~empty, "attack_type"] = at[~empty]

    return df

def normalize_service(df: pd.DataFrame, mp, default_):
    ensure_cols(df, ["service"])
    df["service_norm"] = df["service"].apply(lambda x: norm_service(x, mp, default_))
    return df

def drop_dups(df: pd.DataFrame) -> pd.DataFrame:
    if "uid" in df.columns:
        return df.drop_duplicates(subset=["uid"], keep="first")
    keep_cols = [c for c in ["orig_h","resp_h","orig_p","resp_p","proto","_ts_dt"] if c in df.columns]
    if keep_cols:
        return df.drop_duplicates(subset=keep_cols, keep="first")
    return df.drop_duplicates(keep="first")

def profile(df: pd.DataFrame) -> dict:
    prof = {"rows": int(df.shape[0]), "cols": int(df.shape[1])}
    if "_ts_dt" in df.columns:
        tmin = pd.to_datetime(df["_ts_dt"].min()); tmax = pd.to_datetime(df["_ts_dt"].max())
        prof["time_range"] = {
            "min": None if pd.isna(tmin) else str(tmin),
            "max": None if pd.isna(tmax) else str(tmax),
        }
    nulls = df.isna().mean().sort_values(ascending=False).head(30).to_dict()
    prof["null_rates_top30"] = {k: round(v, 4) for k, v in nulls.items()}
    for col in ["service_norm","conn_state","proto","flow_dir"]:
        if col in df.columns:
            vc = df[col].value_counts().head(15).to_dict()
            prof[f"top_{col}"] = vc
    return prof

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--normal", required=True, type=Path)
    ap.add_argument("--attack", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--map", required=False, type=Path, help="conf/service_map.yml")
    ap.add_argument("--drop-external-external", action="store_true")
    ap.add_argument("--ayiya-policy", choices=["keep","drop","mark-rare"], default="keep")
    ap.add_argument("--profile-out", type=Path, default=Path("reports/combined_raw_profile.json"))
    args = ap.parse_args()

    mp, default_serv = load_service_map(args.map) if args.map else ({}, "other")

    df_norm = alias_and_types(read_csv_safe(args.normal))
    df_att  = alias_and_types(read_csv_safe(args.attack))

    df_norm = normalize_labels(df_norm, "normal")
    df_att  = normalize_labels(df_att,  "attack")

    df_norm = normalize_service(df_norm, mp, default_serv)
    df_att  = normalize_service(df_att,  mp, default_serv)

    df_norm = add_flow_dir(df_norm)
    df_att  = add_flow_dir(df_att)

    common_cols = sorted(set(df_norm.columns) | set(df_att.columns))
    df_norm = ensure_cols(df_norm, common_cols)
    df_att  = ensure_cols(df_att,  common_cols)
    df = pd.concat([df_norm[common_cols], df_att[common_cols]], ignore_index=True)

    if args.drop_external_external:
        if "flow_dir" in df.columns:
            df = df[df["flow_dir"] != "e↔e"].copy()

    if args.ayiya_policy != "keep" and "service_norm" in df.columns:
        mask = df["service_norm"] == "tunnel_ayiya"
        if args.ayiya_policy == "drop":
            df = df[~mask].copy()
        elif args.ayiya_policy == "mark-rare":
            df["rare_service"] = np.where(mask, 1, 0)

    df = drop_dups(df)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(args.out, index=False)

    prof = profile(df)
    args.profile_out.parent.mkdir(parents=True, exist_ok=True)
    args.profile_out.write_text(json.dumps(prof, indent=2))
    print(f"[OK] wrote {args.out}  rows={df.shape[0]}")
    print(f"[OK] wrote {args.profile_out}")

if __name__ == "__main__":
    main()
