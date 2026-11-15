"""
drift.py — is the traffic the model sees still like the traffic it was trained on?

ml/train.py stores quantiles of the eight legacy features over the training period in
models/feature_spec.json ("feature_stats"). compute_drift() compares them with the feature values
of recent scored events (threat_log keeps feature_values per event) using the Population
Stability Index. PSI < 0.10 is stable, 0.10-0.25 is worth watching, >= 0.25 means the feature's
distribution has moved and the model should be re-evaluated or retrained.
"""
from __future__ import annotations

import json
import os
import sys

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import MODELS_DIR, THREAT_LOG  # noqa: E402

LEGACY_EIGHT = ['failed_logins', 'cpu_usage', 'memory_spike', 'ehr_access_per_hour',
                'lateral_movement_events', 'data_export_volume_kb', 'access_time_deviation',
                'source_ip_reputation']
N_BINS = 10


def training_stats(values_by_feature: dict[str, np.ndarray]) -> dict:
    """Quantile edges (for PSI bins) plus mean/std per feature. Called by ml/train.py."""
    out = {}
    qs = np.linspace(0, 1, N_BINS + 1)
    for name, v in values_by_feature.items():
        v = np.asarray(v, dtype=float)
        out[name] = {"edges": [float(x) for x in np.quantile(v, qs)], "mean": float(v.mean()), "std": float(v.std()), "n": int(len(v))}
    return out


def _hist(v: np.ndarray, edges: list[float]) -> np.ndarray:
    e = np.array(edges, dtype=float)
    e[0], e[-1] = -np.inf, np.inf
    # collapse duplicate edges (constant features) to avoid empty bins
    uniq = np.unique(e)
    if len(uniq) < 3:
        return np.array([1.0])
    counts, _ = np.histogram(v, bins=uniq)
    return counts / max(len(v), 1)


def psi(expected: np.ndarray, actual: np.ndarray, edges: list[float]) -> float:
    pe = _hist(expected, edges) + 1e-6
    pa = _hist(actual, edges) + 1e-6
    if len(pe) != len(pa):
        return 0.0
    return float(np.sum((pa - pe) * np.log(pa / pe)))


def compute_drift(recent: list[dict], stats: dict, min_rows: int = 50) -> dict:
    """recent: list of feature_values dicts (one per scored event). Returns per-feature PSI."""
    result = {"n_recent": len(recent), "enough_data": len(recent) >= min_rows, "features": {}, "overall": "ok"}
    if not recent or not stats:
        result["overall"] = "no_data"
        return result
    worst = 0.0
    for name in LEGACY_EIGHT:
        st = stats.get(name)
        if not st:
            continue
        vals = np.array([float(r.get(name, 0) or 0) for r in recent], dtype=float)
        # expected distribution = uniform over the training quantile bins by construction
        edges = st["edges"]
        expected = np.array(edges[:-1], dtype=float)  # one representative per bin
        p = psi(np.repeat(expected, 10), vals, edges)
        status = "ok" if p < 0.10 else ("watch" if p < 0.25 else "drift")
        worst = max(worst, p)
        result["features"][name] = {"psi": round(p, 4), "status": status, "recent_mean": round(float(vals.mean()), 4),
                                    "training_mean": round(st["mean"], 4)}
    result["overall"] = "ok" if worst < 0.10 else ("watch" if worst < 0.25 else "drift")
    if not result["enough_data"]:
        result["overall"] = "insufficient_data"
    return result


def recent_feature_values(limit: int = 2000) -> list[dict]:
    if not os.path.exists(THREAT_LOG):
        return []
    rows = []
    with open(THREAT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            fv = e.get("feature_values")
            if isinstance(fv, dict):
                rows.append(fv)
    return rows[-limit:]


def drift_report() -> dict:
    spec_path = os.path.join(MODELS_DIR, "feature_spec.json")
    spec = json.load(open(spec_path)) if os.path.exists(spec_path) else {}
    rep = compute_drift(recent_feature_values(), spec.get("feature_stats", {}))
    rep["model"] = {"trained_at": spec.get("trained_at"), "holdout_family": spec.get("holdout_family"),
                    "split": spec.get("split"), "versions": spec.get("versions")}
    reg_path = os.path.join(MODELS_DIR, "registry.json")
    if os.path.exists(reg_path):
        try:
            rep["registry"] = json.load(open(reg_path))[-5:]
        except (json.JSONDecodeError, OSError):
            pass
    return rep
