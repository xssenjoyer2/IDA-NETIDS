import argparse, re
from pathlib import Path
import pandas as pd
import numpy as np

EPS = 1e-6

# Sayısal giriş kolonları (varsa)
NUM_KEEP = [
    "duration","orig_bytes","resp_bytes","orig_pkts","resp_pkts",
    "missed_bytes","orig_ip_bytes","resp_ip_bytes","orig_p","resp_p"
]

# One-hot yapılacak kategorikler
CAT_COLS = ["proto","service_norm","conn_state","flow_dir"]

def winsorize(s: pd.Series, p=0.995):
    s = pd.to_numeric(s, errors="coerce")
    lo = s.quantile(1-p) if p > 0.5 else s.min()
    hi = s.quantile(p)
    return s.clip(lower=lo, upper=hi)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True, type=Path)
    ap.add_argument("--X", dest="x_out", required=True, type=Path)
    ap.add_argument("--ybin", dest="ybin_out", required=True, type=Path)
    ap.add_argument("--ymulti", dest="ymulti_out", required=True, type=Path)
    ap.add_argument("--topk-service", type=int, default=60, help="service_norm için en sık K kategori")
    args = ap.parse_args()

    df = pd.read_csv(args.inp, low_memory=False)

    # --- KATEGORİK NORMALİZASYON ---
    def _norm(s): 
        return s.astype(str).str.strip()

    # conn_state: UPPER + UNK
    if "conn_state" in df.columns:
        df["conn_state"] = _norm(df["conn_state"]).str.upper()
        df["conn_state"] = df["conn_state"].replace({
            "-": "UNK", "": "UNK", "NAN": "UNK"
        })
        allowed = {
            "OTH","REJ","RSTO","RSTOS0","RSTR","RSTRH",
            "S0","S1","S2","S3","SF","SH","SHR","UNK"
        }
        df["conn_state"] = np.where(df["conn_state"].isin(allowed), df["conn_state"], "UNK")

    # proto: lower + unknown
    if "proto" in df.columns:
        df["proto"] = _norm(df["proto"]).str.lower().replace({
            "-": "unknown", "": "unknown", "nan": "unknown"
        })

    if "service_norm" not in df.columns:
        if "service" in df.columns:
            df["service_norm"] = (
                df["service"].astype(str).str.strip().str.lower()
                .replace({"-": "unknown", "": "unknown", "nan": "unknown"})
            )
        else:
            # service de yoksa hepsini unknown yap
            df["service_norm"] = "unknown"

    # service_norm: lower + unknown
    if "service_norm" in df.columns:
        df["service_norm"] = _norm(df["service_norm"]).str.lower().replace({
            "-": "unknown", "": "unknown", "nan": "unknown"
        })

    # flow_dir: okunabilir sabitlere + unknown
    if "flow_dir" in df.columns:
        df["flow_dir"] = _norm(df["flow_dir"]).replace({
            "i↔i": "i_i",
            "i→e": "i_to_e",
            "e→i": "e_to_i",
            "e↔e": "e_e",
            "-": "unknown", "": "unknown", "nan": "unknown"
        })
        df["flow_dir"] = np.where(
            df["flow_dir"].isin(["i_i","i_to_e","e_to_i","e_e","unknown"]),
            df["flow_dir"], 
            "unknown"
        )

    # 1) Sayısalları güvene al (NaN->0)
    for c in NUM_KEEP:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)

    # 2) Türetilmiş sayısallar
       # 2) Türetilmiş sayısallar — alan yoksa 0-serisi kullan
    def num_or_zero(col, dtype="float64"):
        if col in df.columns:
            return pd.to_numeric(df[col], errors="coerce").fillna(0).astype(dtype)
        else:
            return pd.Series(0, index=df.index, dtype=dtype)

    orig_bytes = num_or_zero("orig_bytes")
    resp_bytes = num_or_zero("resp_bytes")
    orig_pkts  = num_or_zero("orig_pkts")
    resp_pkts  = num_or_zero("resp_pkts")
    duration   = num_or_zero("duration")

    df["bytes_total"] = orig_bytes + resp_bytes
    df["pkts_total"]  = orig_pkts + resp_pkts
    # payda 0 ise 1'e zorla (seriler üzerinde güvenli)
    df["bytes_ratio"] = orig_bytes / resp_bytes.replace(0, 1)
    df["bps"] = 8.0 * df["bytes_total"] / (duration + EPS)
    df["pps"] = df["pkts_total"] / (duration + EPS)

    # 3) Winsorize (uçları kırp)
    for c in ["bytes_total","pkts_total","bytes_ratio","bps","pps"]:
        df[c] = winsorize(df[c])

    # 4) Bayraklar
    df["is_zero_bytes"] = (df["bytes_total"] == 0).astype(np.uint8)
    df["is_priv_port"] = (df.get("resp_p", 0) < 1024).astype(np.uint8)
    df["is_ephemeral"] = (df.get("resp_p", 0) >= 49152).astype(np.uint8)

    # 5) service_norm'u top-K ile sınırlayıp nadirleri sepete at
    if "service_norm" in df.columns:
        topk = df["service_norm"].astype(str).value_counts().nlargest(args.topk_service).index
        df["service_norm"] = np.where(
            df["service_norm"].astype(str).isin(topk),
            df["service_norm"],
            "service_other_rare"
        )

    # 6) One-hot (drop_first=False → üretimde daha güvenli)
    cats = [c for c in CAT_COLS if c in df.columns]
    feature_cols = cats + [
        "bytes_total","pkts_total","bytes_ratio","bps","pps",
        "is_zero_bytes","is_priv_port","is_ephemeral"
    ]
    X = pd.get_dummies(df[feature_cols], columns=cats, drop_first=False)

    # --- EK 1: NaN güvence ---
    X = X.fillna(0)

    # --- EK 1.5: Kolon adlarını sanitize et (LightGBM özel karakter hatasını önle) ---
    safe_cols = [re.sub(r"[^0-9A-Za-z_]", "_", c) for c in X.columns]
    X.columns = safe_cols
    # Olası çakışmaları birleştir (dummy için max mantıklı)
    if len(set(safe_cols)) != len(safe_cols):
        X = X.T.groupby(level=0).max().T

    # --- EK 2: Hafıza optimizasyonu ---
    for c in ["bytes_total","pkts_total","bytes_ratio","bps","pps"]:
        if c in X.columns:
            X[c] = X[c].astype("float32")
    oh_prefixes = [f"{k}_" for k in cats]
    for col in X.columns:
        if any(col.startswith(p) for p in oh_prefixes) or col in ["is_zero_bytes","is_priv_port","is_ephemeral"]:
            X[col] = X[col].astype("uint8")

    # 7) Etiketler
    if "label" not in df.columns:
    # canlı/etiketsiz akışlar için varsayılan
        df["label"] = "normal"
    y_bin = (df["label"].astype(str).str.lower() == "attack").astype(int)
    if "attack_type" in df.columns:
        y_multi = df["attack_type"].astype(str).fillna("none")
    else:
        y_multi = pd.Series(["none"] * len(df))

    # 8) Kaydet
    args.x_out.parent.mkdir(parents=True, exist_ok=True)
    X.to_parquet(args.x_out, index=False)
    y_bin.to_csv(args.ybin_out, index=False, header=False)
    y_multi.to_csv(args.ymulti_out, index=False, header=False)

    # --- EK 3: Şema dosyası ---
    schema_path = args.x_out.with_suffix(".columns.txt")
    with open(schema_path, "w") as f:
        for col in X.columns:
            f.write(str(col) + "\n")
    print("[OK] saved schema:", schema_path)

    # 9) Konsol özeti
    print("[OK] X shape:", X.shape)
    print("[OK] y_bin mean (attack rate):", float(y_bin.mean()))
    print("[OK] y_multi top:", y_multi.value_counts().head(10).to_dict())

if __name__ == "__main__":
    main()

