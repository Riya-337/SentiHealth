"""
train.py — train the detection models on the windowed features with a TEMPORAL split.

What is trained
---------------
1. XGBoost multiclass (Low / Medium / High) + isotonic calibration fitted on the validation period.
   This is the supervised "known attack pattern" model.
2. Isolation Forest fitted on normal rows only — the unsupervised path for attacks the supervised
   model never saw. Its alert threshold is set on validation normals at a chosen false-alarm rate.
3. A cost-based decision policy: the tier with the lowest expected cost under ml/cost_matrix.py,
   instead of a plain argmax.
4. Optionally (--legacy) the previous five-model ensemble (RF, GB, SVM, LR, XGB) on the same
   features, so the evaluation can show what the ensemble adds or does not add.

Split: rows are ordered by time; the first 70 % of the period is training, the next 15 %
validation (early stopping, calibration, thresholds), the last 15 % test. The held-out attack
family (--holdout-family, default credential_stuffing) is removed from training and validation
and only appears in the test period, to measure detection of an unseen attack type.

No metric is computed here. Run ml/evaluate.py afterwards; it writes the numbers as measured.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import DATA_DIR, MODELS_DIR  # noqa: E402
from features import FEATURE_NAMES, build_feature_table  # noqa: E402
from cost_matrix import COST  # noqa: E402

TIERS = ["Low", "Medium", "High"]
LEGACY_WEIGHTS = {'rf': 0.25, 'gb': 0.20, 'svm': 0.20, 'lr': 0.15, 'xgb': 0.20}


def cost_matrix() -> list[list[float]]:
    """C[true][pred] from the named costs; zero on the diagonal."""
    c = [[0.0] * 3 for _ in range(3)]
    c[2][0], c[2][1] = COST["high_as_low"], COST["high_as_medium"]
    c[1][0], c[1][2] = COST["medium_as_low"], COST["medium_as_high"]
    c[0][1], c[0][2] = COST["low_as_medium"], COST["low_as_high"]
    return c


def load_features(events_path: str, cache: str) -> pd.DataFrame:
    if os.path.exists(cache) and os.path.getmtime(cache) >= os.path.getmtime(events_path):
        F = pd.read_csv(cache, compression="gzip")
    else:
        df = pd.read_json(events_path, lines=True, compression="gzip")
        F = build_feature_table(df)
        F.to_csv(cache, index=False, compression="gzip")
    F["ts"] = pd.to_datetime(F["ts"], utc=True)
    return F


def temporal_split(F: pd.DataFrame, train_frac=0.70, val_frac=0.15) -> dict:
    t = F["ts"].sort_values().to_numpy()
    t_train_end = t[int(len(t) * train_frac)]
    t_val_end = t[int(len(t) * (train_frac + val_frac))]
    split = np.where(F["ts"] < t_train_end, "train", np.where(F["ts"] < t_val_end, "val", "test"))
    return {"split": split, "train_end": str(t_train_end), "val_end": str(t_val_end)}


def sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default=os.path.join(DATA_DIR, "events_sim.jsonl.gz"))
    ap.add_argument("--holdout-family", default="credential_stuffing")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--legacy", action="store_true", help="also train the old five-model ensemble for the ablation")
    ap.add_argument("--max-legacy-rows", type=int, default=20000, help="SVM cannot train on 200k rows; the legacy models use a stratified subsample")
    a = ap.parse_args()

    cache = os.path.join(DATA_DIR, "features_sim.csv.gz")
    F = load_features(a.events, cache)
    sp = temporal_split(F)
    F["split"] = sp["split"]
    X_all = F[FEATURE_NAMES].to_numpy(dtype=float)
    y_all = F["tier_label"].to_numpy(dtype=int)
    fam = F["attack_family"].to_numpy()

    tr = (F["split"] == "train") & (fam != a.holdout_family)
    va = (F["split"] == "val") & (fam != a.holdout_family)
    te = F["split"] == "test"
    print(f"rows train {tr.sum():,} | val {va.sum():,} | test {te.sum():,}  (holdout family '{a.holdout_family}' only in test)")
    print(f"train tier counts {np.bincount(y_all[tr], minlength=3).tolist()}  test tier counts {np.bincount(y_all[te], minlength=3).tolist()}")

    os.makedirs(MODELS_DIR, exist_ok=True)
    manifest: dict[str, str] = {}

    # ---------------------------------------------------------------- 1. XGBoost + calibration
    # The configuration is chosen on the VALIDATION period by macro-F1; the test period is never used here.
    t0 = time.time()
    candidates = [("balanced_d6", True, 6), ("unweighted_d6", False, 6), ("balanced_d8", True, 8), ("unweighted_d8", False, 8)]
    best = None
    for name, weighted, depth in candidates:
        m = XGBClassifier(objective="multi:softprob", num_class=3, n_estimators=1500, learning_rate=0.05,
                          max_depth=depth, subsample=0.8, colsample_bytree=0.8, min_child_weight=2,
                          reg_lambda=1.0, tree_method="hist", random_state=a.seed, n_jobs=-1,
                          early_stopping_rounds=100, eval_metric="mlogloss")
        sw = compute_sample_weight("balanced", y_all[tr]) if weighted else None
        m.fit(X_all[tr], y_all[tr], sample_weight=sw, eval_set=[(X_all[va], y_all[va])], verbose=False)
        f1 = f1_score(y_all[va], m.predict(X_all[va]), average="macro")
        print(f"  xgb {name}: validation macro-F1 {f1:.4f} ({m.best_iteration + 1} trees)")
        if best is None or f1 > best[0]:
            best = (f1, name, m)
    xgb = best[2]
    cal = CalibratedClassifierCV(FrozenEstimator(xgb), method="isotonic")
    cal.fit(X_all[va], y_all[va])
    path = os.path.join(MODELS_DIR, "xgb_calibrated.pkl")
    with open(path, "wb") as f:
        pickle.dump({"name": f"xgb_calibrated[{best[1]}]", "model": cal, "raw": xgb, "feature_names": FEATURE_NAMES,
                     "best_iteration": int(xgb.best_iteration), "val_macro_f1": float(best[0])}, f)
    manifest["xgb_calibrated"] = sha256(path)
    print(f"XGBoost: chose {best[1]} ({xgb.best_iteration + 1} trees), calibrated; {time.time() - t0:.1f}s")

    # ---------------------------------------------------------------- 1b. single Random Forest on the full training period
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
                                random_state=a.seed, n_jobs=-1)
    rf.fit(X_all[tr], y_all[tr])
    rf_f1 = f1_score(y_all[va], rf.predict(X_all[va]), average="macro")
    rf_cal = CalibratedClassifierCV(FrozenEstimator(rf), method="isotonic")
    rf_cal.fit(X_all[va], y_all[va])
    path = os.path.join(MODELS_DIR, "rf_calibrated.pkl")
    with open(path, "wb") as f:
        pickle.dump({"name": "rf_calibrated", "model": rf_cal, "raw": rf, "feature_names": FEATURE_NAMES, "val_macro_f1": float(rf_f1)}, f)
    manifest["rf_calibrated"] = sha256(path)
    print(f"Random Forest: validation macro-F1 {rf_f1:.4f}, calibrated; {time.time() - t0:.1f}s")
    # the live scorer uses whichever single model did better on validation
    supervised_choice = "rf_calibrated" if rf_f1 > best[0] else "xgb_calibrated"
    print(f"-> live model: {supervised_choice}")

    # ---------------------------------------------------------------- 2. Isolation Forest on normal rows
    t0 = time.time()
    normal_tr = tr & (fam == "normal")
    iso = IsolationForest(n_estimators=300, max_samples=min(8192, int(normal_tr.sum())), contamination="auto",
                          random_state=a.seed, n_jobs=-1)
    iso.fit(X_all[normal_tr])
    s_val_normal = -iso.score_samples(X_all[va & (fam == "normal")])
    thresholds = {f"fpr_{int(q * 100)}pct": float(np.quantile(s_val_normal, 1 - q)) for q in (0.01, 0.05, 0.10)}
    path = os.path.join(MODELS_DIR, "iforest.pkl")
    with open(path, "wb") as f:
        pickle.dump({"model": iso, "feature_names": FEATURE_NAMES, "thresholds": thresholds}, f)
    manifest["iforest"] = sha256(path)
    print(f"Isolation Forest fitted on {int(normal_tr.sum()):,} normal rows in {time.time() - t0:.1f}s; thresholds {thresholds}")

    # ---------------------------------------------------------------- 3. decision policy
    policy = {"cost_matrix": cost_matrix(), "tiers": TIERS, "rule": "argmin_j sum_i p_i * C[i][j]",
              "supervised_model": supervised_choice}
    with open(os.path.join(MODELS_DIR, "decision_policy.json"), "w") as f:
        json.dump(policy, f, indent=2)

    # ---------------------------------------------------------------- 4. legacy ensemble (ablation)
    if a.legacy:
        t0 = time.time()
        rng = np.random.default_rng(a.seed)
        idx = np.flatnonzero(tr.to_numpy())
        if len(idx) > a.max_legacy_rows:
            # stratified subsample: keep all attack rows, sample normals
            att = idx[y_all[idx] > 0]
            nor = idx[y_all[idx] == 0]
            keep_n = max(a.max_legacy_rows - len(att), 1000)
            idx = np.concatenate([att, rng.choice(nor, size=min(keep_n, len(nor)), replace=False)])
        Xs, ys = X_all[idx], y_all[idx]
        base = {
            'rf': RandomForestClassifier(n_estimators=200, max_depth=15, class_weight='balanced', random_state=a.seed, n_jobs=-1),
            'gb': GradientBoostingClassifier(n_estimators=150, learning_rate=0.05, max_depth=5, random_state=a.seed),
            'svm': make_pipeline(StandardScaler(), SVC(kernel='rbf', probability=True, class_weight='balanced', random_state=a.seed)),
            'lr': make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight='balanced', random_state=a.seed)),
            'xgb': XGBClassifier(n_estimators=150, learning_rate=0.05, max_depth=5, random_state=a.seed, eval_metric='mlogloss', n_jobs=-1),
        }
        legacy = {}
        for name, est in base.items():
            t1 = time.time()
            m = CalibratedClassifierCV(est, method='isotonic', cv=3)
            m.fit(Xs, ys)
            legacy[name] = m
            print(f"  legacy {name}: {time.time() - t1:.1f}s")
        path = os.path.join(MODELS_DIR, "legacy_ensemble.pkl")
        with open(path, "wb") as f:
            pickle.dump({"models": legacy, "weights": LEGACY_WEIGHTS, "feature_names": FEATURE_NAMES, "n_train_rows": int(len(idx))}, f)
        manifest["legacy_ensemble"] = sha256(path)
        print(f"legacy ensemble trained on {len(idx):,} rows in {time.time() - t0:.1f}s")

    # ---------------------------------------------------------------- bookkeeping
    spec = {
        "feature_names": FEATURE_NAMES, "n_features": len(FEATURE_NAMES), "tiers": TIERS,
        "events": os.path.relpath(a.events, _ROOT), "holdout_family": a.holdout_family, "seed": a.seed,
        "split": {"train_end": sp["train_end"], "val_end": sp["val_end"],
                  "n_train": int(tr.sum()), "n_val": int(va.sum()), "n_test": int(te.sum())},
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "versions": {"python": sys.version.split()[0], "numpy": np.__version__, "pandas": pd.__version__,
                     "sklearn": __import__("sklearn").__version__, "xgboost": __import__("xgboost").__version__},
    }
    with open(os.path.join(MODELS_DIR, "feature_spec.json"), "w") as f:
        json.dump(spec, f, indent=2)
    with open(os.path.join(MODELS_DIR, "model_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    F[["entity", "ts", "split"]].to_csv(os.path.join(DATA_DIR, "splits_sim.csv.gz"), index=False, compression="gzip")
    print("saved:", ", ".join(manifest), "-> models/ ; feature_spec.json ; data/splits_sim.csv.gz")


if __name__ == "__main__":
    main()
