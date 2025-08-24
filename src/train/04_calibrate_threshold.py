# src/train/04_calibrate_threshold.py
import argparse, json, glob, yaml
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.metrics import (
    precision_recall_curve, roc_curve, average_precision_score, roc_auc_score
)
from sklearn.isotonic import IsotonicRegression


# --- Split: StratifiedGroupKFold varsa onu, yoksa greedy fallback ---
def make_group_splits(raw: pd.DataFrame, n_splits=5, seed=42):
    y = (raw["label"].astype(str).str.lower() == "attack").astype(int).values
    groups = raw["orig_h"].astype(str).fillna("unknown").values

    # Tercih edilen: StratifiedGroupKFold (sklearn >= 1.1)
    try:
        from sklearn.model_selection import StratifiedGroupKFold
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        return list(sgkf.split(np.zeros(len(y)), y, groups))
    except Exception:
        # Fallback: global attack oranını fold'lar arasında dengeleyecek greedy host-packing
        tmp = raw.copy()
        tmp["_y"] = y
        g = tmp.groupby("orig_h", dropna=False)["_y"].agg(["sum", "count"]).reset_index()
        g = g.rename(columns={"sum": "pos", "count": "n"})
        g["rate"] = g["pos"] / g["n"]
        G = g["pos"].sum() / g["n"].sum()
        g = g.sort_values(["rate", "n"], ascending=[False, False]).reset_index(drop=True)

        folds_hosts = [[] for _ in range(n_splits)]
        pos = np.zeros(n_splits); n = np.zeros(n_splits)

        for _, r in g.iterrows():
            new_rates = (pos + r["pos"]) / (n + r["n"] + 1e-9)
            i = int(np.argmin(np.abs(new_rates - G)))
            folds_hosts[i].append(str(r["orig_h"]))
            pos[i] += r["pos"]; n[i] += r["n"]

        all_idx = np.arange(len(raw))
        oh = raw["orig_h"].astype(str).fillna("unknown")
        idx = []
        for i in range(n_splits):
            va = np.where(oh.isin(folds_hosts[i]))[0]
            tr = np.setdiff1d(all_idx, va, assume_unique=True)
            idx.append((tr, va))
        return idx


def pick_threshold(y_true, p_cal, precision_target=None, fpr_target=None):
    """Precision ve/veya FPR hedefini sağlayan eşiklerden recall'u maksimize et.
       Hiçbiri sağlamazsa F1'i maksimize eden eşiğe fallback yap."""
    prec, rec, thr = precision_recall_curve(y_true, p_cal)
    thr_full = np.r_[thr, 1.0]  # sklearn davranışı: thr bir eleman kısa

    best = {"threshold": 0.5, "precision": 0.0, "recall": 0.0, "fpr": 1.0}
    for t in thr_full:
        yhat = (p_cal >= t).astype(int)
        tp = np.sum((y_true == 1) & (yhat == 1))
        fp = np.sum((y_true == 0) & (yhat == 1))
        fn = np.sum((y_true == 1) & (yhat == 0))
        tn = np.sum((y_true == 0) & (yhat == 0))
        precision = tp / (tp + fp + 1e-9)
        recall = tp / (tp + fn + 1e-9)
        fpr_now = fp / (fp + tn + 1e-9)

        ok_prec = (precision_target is None) or (precision >= precision_target)
        ok_fpr  = (fpr_target is None) or (fpr_now <= fpr_target)

        if ok_prec and ok_fpr:
            if (recall > best["recall"]) or (recall == best["recall"] and precision > best["precision"]):
                best = dict(threshold=float(t), precision=float(precision),
                            recall=float(recall), fpr=float(fpr_now))

    # Fallback: hiçbir eşik hedefleri sağlamadıysa F1 maks.
    if best["precision"] == 0.0:
        f1 = 2 * prec * rec / (prec + rec + 1e-9)
        j = int(np.nanargmax(f1))
        t = thr_full[j]
        yhat = (p_cal >= t).astype(int)
        tp = np.sum((y_true == 1) & (yhat == 1))
        fp = np.sum((y_true == 0) & (yhat == 1))
        fn = np.sum((y_true == 1) & (yhat == 0))
        tn = np.sum((y_true == 0) & (yhat == 0))
        precision = tp / (tp + fp + 1e-9)
        recall = tp / (tp + fn + 1e-9)
        fpr_now = fp / (fp + tn + 1e-9)
        best = dict(threshold=float(t), precision=float(precision),
                    recall=float(recall), fpr=float(fpr_now))
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--X", required=True, type=Path)
    ap.add_argument("--y", required=True, type=Path)
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--models-dir", type=Path, default=Path("models"))
    ap.add_argument("--n-splits", type=int, default=5)
    ap.add_argument("--precision-target", type=float, default=0.98)
    ap.add_argument("--fpr-target", type=float, default=0.005)
    ap.add_argument("--out-calibrator", type=Path, default=Path("models/bin_isotonic.pkl"))
    ap.add_argument("--out-thresholds", type=Path, default=Path("conf/thresholds.yml"))
    ap.add_argument("--report", type=Path, default=Path("reports/metrics/calibration_summary.json"))
    args = ap.parse_args()

    # Yükle
    X = pd.read_parquet(args.X)
    y = pd.read_csv(args.y, header=None)[0].astype(int).values
    raw = pd.read_csv(args.raw, low_memory=False)
    assert len(X) == len(y) == len(raw), "X/y/raw uzunlukları eşleşmiyor"

    # Aynı split mantığıyla OOF olasılık üret
    splits = make_group_splits(raw, n_splits=args.n_splits, seed=42)
    p_oof = np.zeros(len(y), dtype=float)

    for f, (_, va_idx) in enumerate(splits):
        model_path = args.models_dir / f"bin_lgbm_f{f}.pkl"
        if not model_path.exists():
            raise FileNotFoundError(f"Model bulunamadı: {model_path}")
        m = joblib.load(model_path)
        p = m.predict_proba(X.iloc[va_idx])[:, 1]
        p_oof[va_idx] = p

    # Ham metrikler
    pr_auc_raw = float(average_precision_score(y, p_oof))
    roc_auc_raw = float(roc_auc_score(y, p_oof))

    # Isotonic kalibrasyon
    p_oof = np.nan_to_num(p_oof, nan=0.0)
    iso = IsotonicRegression(out_of_bounds="clip")
    iso.fit(p_oof, y)
    p_cal = iso.transform(p_oof)

    # Kalibre metrikler
    pr_auc_cal = float(average_precision_score(y, p_cal))
    roc_auc_cal = float(roc_auc_score(y, p_cal))

    # Eşik seçimi
    best = pick_threshold(
        y_true=y,
        p_cal=p_cal,
        precision_target=args.precision_target,
        fpr_target=args.fpr_target
    )

    # Kaydet
    args.out_calibrator.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(iso, args.out_calibrator)

    args.out_thresholds.parent.mkdir(parents=True, exist_ok=True)
    thr_payload = {
        "binary": {
            "threshold": best["threshold"],
            "precision_target": args.precision_target,
            "fpr_target": args.fpr_target
        }
    }
    with open(args.out_thresholds, "w") as f:
        yaml.safe_dump(thr_payload, f, sort_keys=False)

    report = {
        "n": int(len(y)),
        "raw_pr_auc": pr_auc_raw,
        "raw_roc_auc": roc_auc_raw,
        "cal_pr_auc": pr_auc_cal,
        "cal_roc_auc": roc_auc_cal,
        "chosen_threshold": best,
        "precision_target": args.precision_target,
        "fpr_target": args.fpr_target,
        "models_dir": str(args.models_dir)
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2))

    print("[OK] saved calibrator:", args.out_calibrator)
    print("[OK] saved thresholds:", args.out_thresholds)
    print("[OK] report:", args.report)
    print("[METRICS]", json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
