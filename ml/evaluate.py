"""
evaluate.py — measure the trained models on the TEST period and write the numbers as they are.

Systems compared
----------------
- XGBoost (calibrated), argmax tier
- XGBoost + cost policy (expected-cost minimisation with ml/cost_matrix.py)
- Rules only (ml/rules.py on the legacy eight features)
- XGBoost + rules (the higher of the two tiers)
- Legacy five-model ensemble (if models/legacy_ensemble.pkl exists)
- Isolation Forest: binary attack-vs-normal detection at fixed false-alarm rates, including the
  attack family that was held out of training

Metrics: accuracy, macro and per-class precision/recall/F1, confusion matrix, ROC-AUC (one-vs-rest,
macro), average precision per class, expected calibration error, latency, per-family detection
(row level and campaign level), and the stealthy families on their own.

Outputs
-------
evaluation/evaluation_metrics.json  (the table the dashboard shows)
evaluation/report.json              (everything)
evaluation/REPORT.md                (readable)
"""
from __future__ import annotations

import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import DATA_DIR, MODELS_DIR  # noqa: E402
from features import FEATURE_NAMES, legacy_eight  # noqa: E402
from rules import rule_tier, expert_rule_tier  # noqa: E402

TIERS = ["Low", "Medium", "High"]
STEALTHY = ["brute_force_slow", "exfiltration_slow", "insider_offhours"]
EVAL_DIR = os.path.join(_ROOT, "evaluation")


def ece(probs: np.ndarray, y: np.ndarray, n_bins: int = 10) -> float:
    conf = probs.max(axis=1)
    pred = probs.argmax(axis=1)
    bins = np.linspace(0, 1, n_bins + 1)
    total = 0.0
    for lo, hi in zip(bins[:-1], bins[1:]):
        m = (conf > lo) & (conf <= hi)
        if m.any():
            total += m.mean() * abs((pred[m] == y[m]).mean() - conf[m].mean())
    return float(total)


def cost_policy(probs: np.ndarray, C: list[list[float]]) -> np.ndarray:
    C = np.asarray(C)  # C[true][pred]
    expected = probs @ C  # (n,3): expected cost of each predicted tier
    return expected.argmin(axis=1)


def classification_block(y: np.ndarray, pred: np.ndarray, probs: np.ndarray | None) -> dict:
    p, r, f, s = precision_recall_fscore_support(y, pred, labels=[0, 1, 2], zero_division=0)
    out = {
        "accuracy": float(accuracy_score(y, pred)),
        "precision_macro": float(p.mean()), "recall_macro": float(r.mean()), "f1_macro": float(f.mean()),
        "per_class": {TIERS[i]: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])} for i in range(3)},
        "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1, 2]).tolist(),
        "high_recall": float(r[2]), "high_precision": float(p[2]),
    }
    if probs is not None:
        out["roc_auc_ovr_macro"] = float(roc_auc_score(y, probs, multi_class="ovr", average="macro"))
        out["average_precision"] = {TIERS[i]: float(average_precision_score((y == i).astype(int), probs[:, i])) for i in range(3)}
        out["ece"] = ece(probs, y)
    return out


def family_block(F: pd.DataFrame, pred: np.ndarray) -> dict:
    """Row-level and campaign-level detection per attack family. 'detected' = predicted tier >= Medium
    (for Low-tier families like recon, 'detected' means predicted >= Low, i.e. always; we report
    'correct_tier' for all)."""
    out = {}
    fam = F["attack_family"].to_numpy()
    y = F["tier_label"].to_numpy()
    camp = F["campaign_id"].to_numpy()
    for name in sorted(set(fam)):
        m = fam == name
        rows = int(m.sum())
        correct = float((pred[m] == y[m]).mean())
        entry = {"rows": rows, "correct_tier_rate": correct}
        if name != "normal":
            detected = pred[m] >= 1
            entry["row_detection_rate"] = float(detected.mean())
            camps = pd.Series(detected).groupby(camp[m]).any()
            entry["campaigns"] = int(len(camps))
            entry["campaign_detection_rate"] = float(camps.mean())
        else:
            entry["false_alarm_rate"] = float((pred[m] >= 1).mean())
            entry["false_high_rate"] = float((pred[m] == 2).mean())
        out[name] = entry
    return out


def main() -> None:
    F = pd.read_csv(os.path.join(DATA_DIR, "features_sim.csv.gz"), compression="gzip")
    sp = pd.read_csv(os.path.join(DATA_DIR, "splits_sim.csv.gz"), compression="gzip")
    F["split"] = sp["split"].to_numpy()
    spec = json.load(open(os.path.join(MODELS_DIR, "feature_spec.json")))
    policy = json.load(open(os.path.join(MODELS_DIR, "decision_policy.json")))
    holdout = spec["holdout_family"]
    # main test set: the last 15 % of the period, without the held-out family
    T = F[(F["split"] == "test") & (F["attack_family"] != holdout)].reset_index(drop=True)
    X = T[FEATURE_NAMES].to_numpy(dtype=float)
    y = T["tier_label"].to_numpy(dtype=int)
    fam = T["attack_family"].to_numpy()
    # unseen-family set: every row of the held-out family, from any period (none were used in training)
    H = F[F["attack_family"] == holdout].reset_index(drop=True)
    X_h = H[FEATURE_NAMES].to_numpy(dtype=float)
    print(f"test rows {len(T):,}; tiers {np.bincount(y, minlength=3).tolist()}; held-out family '{holdout}' rows {len(H):,} "
          f"({H['campaign_id'].nunique()} campaigns)")

    xgb = pickle.load(open(os.path.join(MODELS_DIR, "xgb_calibrated.pkl"), "rb"))
    rf_path = os.path.join(MODELS_DIR, "rf_calibrated.pkl")
    rf = pickle.load(open(rf_path, "rb")) if os.path.exists(rf_path) else None
    iso = pickle.load(open(os.path.join(MODELS_DIR, "iforest.pkl"), "rb"))
    legacy_path = os.path.join(MODELS_DIR, "legacy_ensemble.pkl")
    legacy = pickle.load(open(legacy_path, "rb")) if os.path.exists(legacy_path) else None

    systems: dict[str, dict] = {}

    # XGBoost
    t0 = time.time()
    P = xgb["model"].predict_proba(X)
    batch_ms = (time.time() - t0) * 1000 / len(X)
    t0 = time.time()
    for i in range(200):
        xgb["model"].predict_proba(X[i:i + 1])
    single_ms = (time.time() - t0) * 1000 / 200
    pred_argmax = P.argmax(axis=1)
    pred_cost = cost_policy(P, policy["cost_matrix"])
    systems["XGBoost (calibrated)"] = classification_block(y, pred_argmax, P) | {"latency_ms_per_row_batch": batch_ms, "latency_ms_single_row": single_ms, "families": family_block(T, pred_argmax)}
    systems["XGBoost + cost policy"] = classification_block(y, pred_cost, P) | {"families": family_block(T, pred_cost)}

    # single Random Forest on the full training period
    if rf is not None:
        t0 = time.time()
        Pr = rf["model"].predict_proba(X)
        lat_rf = (time.time() - t0) * 1000 / len(X)
        pred_rf = cost_policy(Pr, policy["cost_matrix"])
        systems["Random Forest (single, calibrated) + cost policy"] = classification_block(y, pred_rf, Pr) | {"latency_ms_per_row_batch": lat_rf, "families": family_block(T, pred_rf)}

    # rules
    f8 = [legacy_eight(dict(zip(FEATURE_NAMES, row))) for row in X]
    pred_rules = np.array([rule_tier(f) for f in f8])
    systems["Rules only (deployed: failed logins)"] = classification_block(y, pred_rules, None) | {"families": family_block(T, pred_rules)}
    pred_expert = np.array([expert_rule_tier(f) for f in f8])
    systems["Expert rules only (thresholds)"] = classification_block(y, pred_expert, None) | {"families": family_block(T, pred_expert)}
    pred_comb = np.maximum(pred_cost, pred_rules)
    systems["XGBoost + cost policy + rules (max tier)"] = classification_block(y, pred_comb, None) | {"families": family_block(T, pred_comb)}

    # legacy ensemble
    if legacy is not None:
        t0 = time.time()
        Pl = np.zeros((len(X), 3))
        for name, w in legacy["weights"].items():
            Pl += w * legacy["models"][name].predict_proba(X)
        lat = (time.time() - t0) * 1000 / len(X)
        pred_l = Pl.argmax(axis=1)
        systems["Legacy 5-model ensemble"] = classification_block(y, pred_l, Pl) | {"latency_ms_per_row_batch": lat, "n_train_rows": legacy["n_train_rows"], "families": family_block(T, pred_l)}
        for name in legacy["weights"]:
            Pi = legacy["models"][name].predict_proba(X)
            systems[f"Legacy member: {name}"] = classification_block(y, Pi.argmax(axis=1), Pi)

    # Isolation Forest (binary)
    s = -iso["model"].score_samples(X)
    s_h = -iso["model"].score_samples(X_h) if len(H) else np.array([])
    is_attack = (fam != "normal").astype(int)
    iso_block = {"roc_auc_attack_vs_normal": float(roc_auc_score(is_attack, s)), "at_threshold": {}}
    for k, thr in iso["thresholds"].items():
        flag = s >= thr
        entry = {"threshold": thr, "false_alarm_rate_normal": float(flag[fam == "normal"].mean()),
                 "recall_all_attacks": float(flag[is_attack == 1].mean()),
                 "recall_by_family": {n: float(flag[fam == n].mean()) for n in sorted(set(fam)) if n != "normal"},
                 "recall_on_holdout_family": float((s_h >= thr).mean()) if len(H) else None}
        iso_block["at_threshold"][k] = entry
    # supervised models on the unseen family, for comparison (row level and campaign level)
    iso_block["holdout_family"] = holdout
    iso_block["holdout_rows"] = int(len(H))
    if len(H):
        ph = cost_policy(xgb["model"].predict_proba(X_h), policy["cost_matrix"])
        iso_block["xgb_detection_rate_on_holdout_family"] = float((ph >= 1).mean())
        iso_block["xgb_campaign_detection_on_holdout_family"] = float(pd.Series(ph >= 1).groupby(H["campaign_id"].to_numpy()).any().mean())
        if rf is not None:
            pr = cost_policy(rf["model"].predict_proba(X_h), policy["cost_matrix"])
            iso_block["rf_detection_rate_on_holdout_family"] = float((pr >= 1).mean())
    else:
        iso_block["xgb_detection_rate_on_holdout_family"] = None
    systems["Isolation Forest (binary, unsupervised)"] = iso_block

    # ---------------------------------------------------------------- write
    os.makedirs(EVAL_DIR, exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "data": "SYNTHETIC: ml/simulate_events.py (see its docstring); no real hospital traffic",
        "test_period": {"from": str(T["ts"].min()), "to": str(T["ts"].max()), "rows": int(len(T)),
                        "tier_counts": dict(zip(TIERS, np.bincount(y, minlength=3).tolist()))},
        "split": spec["split"], "holdout_family": holdout, "versions": spec["versions"],
        "stealthy_families": STEALTHY,
        "systems": systems,
    }
    with open(os.path.join(EVAL_DIR, "report.json"), "w") as f:
        json.dump(report, f, indent=2)

    # dashboard table (macro averages; probability systems only have an AUC)
    table = []
    for name in ["XGBoost (calibrated)", "XGBoost + cost policy", "Random Forest (single, calibrated) + cost policy",
                 "Legacy 5-model ensemble", "XGBoost + cost policy + rules (max tier)",
                 "Expert rules only (thresholds)", "Rules only (deployed: failed logins)"]:
        if name in systems:
            b = systems[name]
            table.append({"model": name, "accuracy": b["accuracy"], "precision": b["precision_macro"],
                          "recall": b["recall_macro"], "f1": b["f1_macro"], "auc_roc": b.get("roc_auc_ovr_macro")})
    with open(os.path.join(EVAL_DIR, "evaluation_metrics.json"), "w") as f:
        json.dump(table, f, indent=2)

    # markdown
    md = ["# SentiHealth detection models: measured results", "",
          f"Generated {report['generated_at']}. **Data: synthetic** (`ml/simulate_events.py`), test period {report['test_period']['from']} to {report['test_period']['to']}, "
          f"{len(T):,} rows (Low {report['test_period']['tier_counts']['Low']:,} / Medium {report['test_period']['tier_counts']['Medium']:,} / High {report['test_period']['tier_counts']['High']:,}). "
          f"Attack family held out of training: `{holdout}`.", "",
          "## Tier classification (test period)", "",
          "| System | Accuracy | Macro P | Macro R | Macro F1 | High recall | High precision | ROC-AUC | ECE |",
          "|---|---|---|---|---|---|---|---|---|"]
    for name, b in systems.items():
        if "accuracy" not in b:
            continue
        auc = f"{b['roc_auc_ovr_macro']:.3f}" if "roc_auc_ovr_macro" in b else "n/a"
        e = f"{b['ece']:.3f}" if "ece" in b else "n/a"
        md.append(f"| {name} | {b['accuracy']:.4f} | {b['precision_macro']:.3f} | {b['recall_macro']:.3f} | {b['f1_macro']:.3f} | {b['high_recall']:.3f} | {b['high_precision']:.3f} | {auc} | {e} |")
    md += ["", "## Per-family detection (XGBoost + cost policy)", "",
           "| Family | Rows | Correct tier | Row detection (>= Medium) | Campaign detection |", "|---|---|---|---|---|"]
    for name, e in systems["XGBoost + cost policy"]["families"].items():
        if name == "normal":
            md.append(f"| normal | {e['rows']:,} | {e['correct_tier_rate']:.3f} | false alarms {e['false_alarm_rate']:.4f} (High {e['false_high_rate']:.4f}) | |")
        else:
            md.append(f"| {name}{' (stealthy)' if name in STEALTHY else ''}{' (held out)' if name == holdout else ''} | {e['rows']:,} | {e['correct_tier_rate']:.3f} | {e['row_detection_rate']:.3f} | {e['campaign_detection_rate']:.3f} ({e['campaigns']} campaigns) |")
    ib = systems["Isolation Forest (binary, unsupervised)"]
    md += ["", "## Isolation Forest (unsupervised, trained on normal rows only)", "",
           f"ROC-AUC attack vs normal: {ib['roc_auc_attack_vs_normal']:.3f}", "",
           "| Threshold | False alarms (normal) | Recall (all attacks) | Recall on held-out family |", "|---|---|---|---|"]
    for k, e in ib["at_threshold"].items():
        r_h = e["recall_on_holdout_family"]
        md.append(f"| {k} | {e['false_alarm_rate_normal']:.4f} | {e['recall_all_attacks']:.3f} | {r_h if r_h is None else f'{r_h:.3f}'} |")
    md += ["", f"Held-out family `{holdout}` ({ib['holdout_rows']} rows, never in training): XGBoost row detection "
               f"{ib.get('xgb_detection_rate_on_holdout_family')}, campaign detection {ib.get('xgb_campaign_detection_on_holdout_family')}, "
               f"Random Forest row detection {ib.get('rf_detection_rate_on_holdout_family')}.", "",
           "## Latency", "",
           f"XGBoost (calibrated): {systems['XGBoost (calibrated)']['latency_ms_per_row_batch']:.3f} ms/row in batch, {systems['XGBoost (calibrated)']['latency_ms_single_row']:.2f} ms for a single row."]
    if legacy is not None:
        md.append(f"Legacy 5-model ensemble: {systems['Legacy 5-model ensemble']['latency_ms_per_row_batch']:.3f} ms/row in batch (trained on {legacy['n_train_rows']:,} rows).")
    md += ["", "## Limits", "",
           "- Every number above is on simulated data. Normal behaviour and attacks were written by the same author as the features, so real-world performance is unknown until the pipeline is run on real logs.",
           "- No number in this file is adjusted, filtered or re-sampled to look better or worse; `ml/evaluate.py` writes what it measures."]
    with open(os.path.join(EVAL_DIR, "REPORT.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    print(f"\n-> {EVAL_DIR}/report.json, evaluation_metrics.json, REPORT.md")


if __name__ == "__main__":
    main()
