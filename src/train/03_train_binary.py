
import argparse, json
from pathlib import Path
import numpy as np, pandas as pd, joblib
from lightgbm import LGBMClassifier, early_stopping, log_evaluation
from sklearn.model_selection import GroupKFold
from sklearn.metrics import roc_auc_score, average_precision_score

def load_xy(x_path: Path, y_path: Path):
    X = pd.read_parquet(x_path)
    y = pd.read_csv(y_path, header=None)[0].astype(int).values
    return X, y

def group_fold_indices(raw_path: Path, n_splits=5):
    import numpy as np
    raw = pd.read_csv(raw_path, low_memory=False)

    # label -> y (0/1), groups -> orig_h
    y = (raw["label"].astype(str).str.lower() == "attack").astype(int).values
    groups = raw["orig_h"].astype(str).fillna("unknown").values

    # 1) Tercih: StratifiedGroupKFold (sklearn >= 1.1)
    try:
        from sklearn.model_selection import StratifiedGroupKFold
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
        idx = list(sgkf.split(np.zeros(len(y)), y, groups))
        return idx, raw
    except Exception:
        pass  # yoksa yedek plana düş

    # 2) Yedek: Greedy host-packing (global oranı fold’larda dengele)
    tmp = raw.copy()
    tmp["_y"] = y
    g = tmp.groupby("orig_h", dropna=False)["_y"].agg(["sum", "count"]).reset_index()
    g = g.rename(columns={"sum": "pos", "count": "n"})
    g["rate"] = g["pos"] / g["n"]
    global_rate = g["pos"].sum() / g["n"].sum()

    # büyük ve attack-rate yüksek hostları önce yerleştir
    g = g.sort_values(["rate", "n"], ascending=[False, False]).reset_index(drop=True)

    fold_hosts = [[] for _ in range(n_splits)]
    fold_pos = np.zeros(n_splits, dtype=float)
    fold_n   = np.zeros(n_splits, dtype=float)

    for _, r in g.iterrows():
        # bu hostu hangi fold'a koyarsam global_rate'e en yakın olur?
        new_rates = (fold_pos + r["pos"]) / (fold_n + r["n"] + 1e-9)
        i = int(np.argmin(np.abs(new_rates - global_rate)))
        fold_hosts[i].append(str(r["orig_h"]))
        fold_pos[i] += r["pos"]; fold_n[i] += r["n"]

    idx = []
    oh = raw["orig_h"].astype(str).fillna("unknown")
    all_idx = np.arange(len(raw))
    for i in range(n_splits):
        va_idx = np.where(oh.isin(fold_hosts[i]))[0]
        tr_idx = np.setdiff1d(all_idx, va_idx, assume_unique=True)
        idx.append((tr_idx, va_idx))
    return idx, raw


def build_type_weights(y: np.ndarray, attack_type: pd.Series, cap: float = 3.0) -> np.ndarray:
    # Normal örnek = 1.0 ; Attack örnek = min(cap, median_count / count[type])
    w = np.ones(len(y), dtype=float)
    atk_mask = (y == 1)
    if attack_type is None:
        return w
    at = attack_type.astype("object").fillna("none")
    at = at.astype(str).str.strip().str.lower().values
    if atk_mask.sum() == 0:
        return w
    counts = pd.Series(at[atk_mask]).value_counts()
    if len(counts) == 0:
        return w
    med = counts.median()
    for k, c in counts.items():
        scale = min(cap, med / max(c, 1))
        w[(at == k) & atk_mask] = scale
    return w

def train_one_fold(X, y, tr_idx, va_idx, raw, use_type_weights=True, type_weight_cap=3.0):
    params = dict(
        num_leaves=63,
        max_depth=-1,
        learning_rate=0.05,
        n_estimators=1200,
        subsample=0.7,
        subsample_freq=1,
        colsample_bytree=0.8,
        class_weight="balanced",
        min_child_samples=40,
        reg_lambda=5.0,
        reg_alpha=0.1,
        random_state=42,
        n_jobs=-1,
    )
    model = LGBMClassifier(**params)

    X_tr, y_tr = X.iloc[tr_idx], y[tr_idx]
    X_va, y_va = X.iloc[va_idx], y[va_idx]

    sw_tr = None
    if use_type_weights and "attack_type" in raw.columns:
        sw_tr = build_type_weights(y_tr, raw["attack_type"].iloc[tr_idx], cap=type_weight_cap)

    model.fit(
        X_tr, y_tr,
        sample_weight=sw_tr,
        eval_set=[(X_va, y_va)],
        eval_metric=["auc","average_precision"],
        callbacks=[early_stopping(100), log_evaluation(50)]
    )

    p_va = model.predict_proba(X_va)[:, 1]
    metrics = {
        "val_roc_auc": float(roc_auc_score(y_va, p_va)),
        "val_pr_auc": float(average_precision_score(y_va, p_va)),
        "n_train": int(len(tr_idx)),
        "n_val": int(len(va_idx)),
        "best_iteration_": int(getattr(model, "best_iteration_", params["n_estimators"]))
    }
    return model, metrics

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--X", required=True, type=Path)
    ap.add_argument("--y", required=True, type=Path)
    ap.add_argument("--raw", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--metrics", required=True, type=Path)
    ap.add_argument("--n-splits", dest="n_splits", type=int, default=5)
    ap.add_argument("--fold", type=int, default=0)
    ap.add_argument("--all-folds", dest="all_folds", action="store_true")
    ap.add_argument("--save-dir", dest="save_dir", type=Path, default=Path("models"))
    ap.add_argument("--type-weights", dest="type_weights", action="store_true")
    ap.add_argument("--type-weight-cap", dest="type_weight_cap", type=float, default=3.0)
    args = ap.parse_args()

    X, y = load_xy(args.X, args.y)
    idx, raw = group_fold_indices(args.raw, n_splits=args.n_splits)
    assert len(X) == len(y) == len(raw), "X/y/raw uzunlukları eşleşmiyor"

    if args.all_folds:
        args.save_dir.mkdir(parents=True, exist_ok=True)
        all_metrics = []
        for f, (tr_idx, va_idx) in enumerate(idx):
            model, m = train_one_fold(
                X, y, tr_idx, va_idx, raw,
                use_type_weights=args.type_weights,
                type_weight_cap=args.type_weight_cap
            )
            fold_model = args.save_dir / f"bin_lgbm_f{f}.pkl"
            joblib.dump(model, fold_model)

            fold_metrics = Path("reports/metrics") / f"binary_f{f}.json"
            fold_metrics.parent.mkdir(parents=True, exist_ok=True)
            fold_metrics.write_text(json.dumps(m, indent=2))
            print(f"[OK] fold {f} saved model: {fold_model}")
            print(f"[OK] fold {f} metrics: {m}")
            all_metrics.append(m)

        dfm = pd.DataFrame(all_metrics)
        summary = {
            "mean_val_roc_auc": float(dfm["val_roc_auc"].mean()),
            "std_val_roc_auc": float(dfm["val_roc_auc"].std()),
            "mean_val_pr_auc": float(dfm["val_pr_auc"].mean()),
            "std_val_pr_auc": float(dfm["val_pr_auc"].std()),
            "folds": all_metrics
        }
        Path("reports/metrics").mkdir(parents=True, exist_ok=True)
        Path("reports/metrics/binary_cv_summary.json").write_text(json.dumps(summary, indent=2))
        print("[OK] CV summary:", summary)
    else:
        tr_idx, va_idx = idx[args.fold]
        model, m = train_one_fold(
            X, y, tr_idx, va_idx, raw,
            use_type_weights=args.type_weights,
            type_weight_cap=args.type_weight_cap
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, args.out)

        args.metrics.parent.mkdir(parents=True, exist_ok=True)
        args.metrics.write_text(json.dumps(m, indent=2))
        print("[OK] saved model:", args.out)
        print("[OK] metrics:", m)

if __name__ == "__main__":
    main()
