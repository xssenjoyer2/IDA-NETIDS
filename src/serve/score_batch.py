# src/serve/score_batch.py
import argparse, json, glob, yaml
from pathlib import Path
import numpy as np, pandas as pd, joblib

def load_models(models_dir: Path):
    files = sorted(glob.glob(str(models_dir / "bin_lgbm_f*.pkl")))
    if not files:
        raise FileNotFoundError("Model bulunamadı: bin_lgbm_f*.pkl")
    models = [joblib.load(f) for f in files]
    return models

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--X", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--models-dir", type=Path, default=Path("models"))
    ap.add_argument("--calibrator", type=Path, default=Path("models/bin_isotonic.pkl"))
    ap.add_argument("--thresholds", type=Path, default=Path("conf/thresholds.yml"))
    ap.add_argument("--schema", type=Path, default=Path("data/features/X.columns.txt"),
                    help="Eğitimdeki kolon sırası")
    args = ap.parse_args()

    # 1) X'i yükle ve eğitim şemasına göre hizala
    X = pd.read_parquet(args.X)
    if args.schema.exists():
        schema = [l.strip() for l in open(args.schema)]
        X = X.reindex(columns=schema, fill_value=0)
    else:
        print("[WARN] schema bulunamadı, mevcut kolonlarla devam ediyorum")

    # 2) CV modellerini yükle ve olasılıkları ortala
    models = load_models(args.models_dir)
    probs = []
    for m in models:
        p = m.predict_proba(X)[:, 1]
        probs.append(p)
    p_mean = np.mean(probs, axis=0)

    # 3) Isotonic kalibrasyon uygula
    iso = joblib.load(args.calibrator)
    p_cal = iso.transform(np.nan_to_num(p_mean, nan=0.0))

    # 4) Eşik
    thr = 0.5
    if args.thresholds.exists():
        yml = yaml.safe_load(open(args.thresholds))
        thr = float(yml.get("binary", {}).get("threshold", 0.5))

    eps = 1e-12
    pred = (p_cal > thr + eps).astype(int)


    # 5) Kaydet
    out = pd.DataFrame({"p_raw": p_mean, "p_cal": p_cal, "pred": pred})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False)

    # Küçük bir özet
    print(f"[OK] wrote {args.out}  rows={len(out)}  thr={thr:.6f}")
    print(out["pred"].value_counts(dropna=False).rename(index={0:"normal", 1:"attack"}).to_dict())

if __name__ == "__main__":
    main()
