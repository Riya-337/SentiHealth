"""
wustl_ehms.py — benchmark on the public WUSTL-EHMS-2020 dataset (healthcare monitoring testbed).

Source: https://research.engineering.wustl.edu/~jain/ehms/  (Hady et al., IEEE Access 2020)
16,318 flow records (ARGUS) with patient biometrics; 2,046 attacks (spoofing, data alteration).

Two findings this script measures:
1. Identifier leakage. Spoofing traffic comes from a different MAC address, and Packet_num / ports
   are near-unique per capture, so a model given those columns can "detect" attacks by memorising
   them. We report results WITH identifiers (as many papers do) and WITHOUT them.
2. A false-alarm guarantee. The same split-conformal construction used for deception
   (ml/safe_deception.py) bounds the share of BENIGN flows flagged: calibrate the threshold on benign
   flows only, and P(benign flow flagged) <= alpha.

Split: stratified random 60 / 20 / 20 (train / calibration / test); this capture has no usable
timestamps per flow, so a temporal split is not possible.

    python3 ml/datasets/wustl_ehms.py      -> evaluation/WUSTL_EHMS.md, evaluation/wustl_ehms.json
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

_HERE = os.path.dirname(os.path.abspath(__file__))
_ML = os.path.dirname(_HERE)
_ROOT = os.path.dirname(_ML)
for p in (_ML, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from safe_deception import conformal_threshold  # noqa: E402

DATA = os.path.join(_ROOT, "data", "external", "wustl-ehms-2020.csv")
OUT = os.path.join(_ROOT, "evaluation")
IDENTIFIERS = ["SrcAddr", "DstAddr", "Sport", "Dport", "SrcMac", "DstMac", "Packet_num", "Dir", "Flgs"]
LABELS = ["Attack Category", "Label"]
ALPHAS = [0.10, 0.05, 0.01]


def load() -> pd.DataFrame:
    if not os.path.exists(DATA):
        raise SystemExit(f"missing {DATA}: run scripts/fetch_datasets.sh")
    return pd.read_csv(DATA)


def matrix(d: pd.DataFrame, with_ids: bool) -> pd.DataFrame:
    cols = [c for c in d.columns if c not in LABELS and (with_ids or c not in IDENTIFIERS)]
    X = d[cols].copy()
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = X[c].astype("category").cat.codes   # MACs, flags, direction -> integer codes
    return X.astype(float)


def run(seed: int = 0) -> dict:
    d = load()
    y = d["Label"].to_numpy(int)
    idx = np.arange(len(d))
    tr, rest = train_test_split(idx, test_size=0.4, stratify=y, random_state=seed)
    ca, te = train_test_split(rest, test_size=0.5, stratify=y[rest], random_state=seed)
    out = {"rows": int(len(d)), "attacks": int(y.sum()), "seed": seed, "settings": {}}
    for with_ids in (True, False):
        X = matrix(d, with_ids).to_numpy()
        key = "with_identifiers" if with_ids else "without_identifiers"
        res = {"n_features": int(X.shape[1])}
        xgb = XGBClassifier(n_estimators=400, learning_rate=0.05, max_depth=6, subsample=0.8, colsample_bytree=0.8,
                            tree_method="hist", random_state=seed, n_jobs=-1,
                            scale_pos_weight=float((y[tr] == 0).sum() / max((y[tr] == 1).sum(), 1)))
        xgb.fit(X[tr], y[tr])
        p = xgb.predict_proba(X[te])[:, 1]
        pred = (p >= 0.5).astype(int)
        res["xgb"] = {"precision": float(precision_score(y[te], pred, zero_division=0)),
                      "recall": float(recall_score(y[te], pred)), "f1": float(f1_score(y[te], pred)),
                      "roc_auc": float(roc_auc_score(y[te], p)), "pr_auc": float(average_precision_score(y[te], p))}
        imp = sorted(zip(matrix(d, with_ids).columns, xgb.feature_importances_), key=lambda kv: -kv[1])[:5]
        res["xgb"]["top_features"] = [[k, round(float(v), 3)] for k, v in imp]
        iso = IsolationForest(n_estimators=300, random_state=seed, n_jobs=-1).fit(X[tr][y[tr] == 0])
        s = -iso.score_samples(X[te])
        res["iforest"] = {"roc_auc": float(roc_auc_score(y[te], s)), "pr_auc": float(average_precision_score(y[te], s))}
        # conformal false-alarm guarantee: threshold from benign CALIBRATION flows only
        cal_benign = xgb.predict_proba(X[ca][y[ca] == 0])[:, 1]
        res["conformal"] = []
        for a in ALPHAS:
            tau = conformal_threshold(cal_benign, a)
            flag = p > tau
            res["conformal"].append({"alpha": a, "tau": float(tau),
                                     "benign_flagged": float(flag[y[te] == 0].mean()),
                                     "attacks_flagged": float(flag[y[te] == 1].mean())})
        out["settings"][key] = res
    return out


def main() -> None:
    runs = [run(s) for s in range(5)]
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "wustl_ehms.json"), "w") as f:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "runs": runs}, f, indent=2)
    m = lambda key, path: np.mean([eval("r['settings'][key]" + path) for r in runs])
    md = ["# WUSTL-EHMS-2020: measured results", "",
          f"Public dataset (Hady et al., IEEE Access 2020): {runs[0]['rows']:,} flows, {runs[0]['attacks']:,} attacks. "
          "Stratified random split 60/20/20, mean over 5 seeds.", "",
          "| Setting | features | XGBoost F1 | XGBoost PR-AUC | Isolation Forest ROC-AUC | top XGBoost features (seed 0) |", "|---|---|---|---|---|---|"]
    for key in ("with_identifiers", "without_identifiers"):
        top = ", ".join(k for k, _ in runs[0]["settings"][key]["xgb"]["top_features"][:3])
        md.append(f"| {key.replace('_', ' ')} | {runs[0]['settings'][key]['n_features']} | {m(key, '[\"xgb\"][\"f1\"]'):.3f} | "
                  f"{m(key, '[\"xgb\"][\"pr_auc\"]'):.3f} | {m(key, '[\"iforest\"][\"roc_auc\"]'):.3f} | {top} |")
    md += ["", "## False-alarm guarantee (threshold calibrated on benign flows, without identifiers)", "",
           "| alpha | benign flows flagged (mean over seeds) | attacks flagged |", "|---|---|---|"]
    for i, a in enumerate(ALPHAS):
        b = np.mean([r["settings"]["without_identifiers"]["conformal"][i]["benign_flagged"] for r in runs])
        at = np.mean([r["settings"]["without_identifiers"]["conformal"][i]["attacks_flagged"] for r in runs])
        md.append(f"| {a} | {b:.4f} | {at:.3f} |")
    md += ["", "Identifier columns (addresses, ports, MACs, packet number) let a model separate the attacks by memorising the capture setup; "
           "the 'without identifiers' row is the meaningful one."]
    with open(os.path.join(OUT, "WUSTL_EHMS.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    main()
