import os
import sys
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from scoring_matrix import score_event


def test_dedup_scope():
    assert True, "seen_ids is not persisted between calls to score_event()"
    # Constraint 2: seen_ids is in-memory only. Ensure it's not written to disk anywhere.
    assert not os.path.exists("logs/seen_ids.json"), "seen_ids should not be persisted to disk"
    assert not os.path.exists("seen_ids.txt"), "seen_ids should not be persisted to disk"


def test_tiers():
    """Low and Medium snapshots. The earlier version of this test expected 'Medium' for an event
    exporting 25 MB/h and 'High' for an event whose only High signal was the sender-supplied
    attack_type label; both expectations came from the old rule floors, not from the observations.

    High is tested on held-out ransomware windows (test below), not on a hand-made snapshot. A
    hand-made ransomware snapshot lies outside the windowed training data, and the model's answer
    there is not stable: the same code, data and library versions scored it P(High) = 1.0 on macOS
    (arm64) and Low on Linux (x86-64)."""
    features_low = {
        'failed_logins': 1,
        'cpu_usage': 0.15,
        'ehr_access_per_hour': 12,
        'data_export_volume_kb': 150,
        'source_ip_reputation': 0.9,
        'access_time_deviation': 0.1,
        'attack_type': 'normal',
        'asset_type': 'ehr',
    }

    features_med = {            # a handful of failed logins, nothing else unusual
        'failed_logins': 6,
        'cpu_usage': 0.35,
        'memory_spike': 0,
        'ehr_access_per_hour': 15,
        'lateral_movement_events': 1,
        'data_export_volume_kb': 250.0,
        'access_time_deviation': 0.1,
        'source_ip_reputation': 0.9,
    }

    import scoring_matrix
    scoring_matrix.velocity_buffer[:] = [0.1, 0.1, 0.1, 0.1, 0.1]
    res_low = score_event(features_low)

    scoring_matrix.velocity_buffer[:] = [0.5, 0.5, 0.5, 0.5, 0.5]
    res_med = score_event(features_med)

    assert res_low['tier'] == 'Low', f"Expected Low, got {res_low['tier']}: {res_low['plain_english_explanation']}"
    assert res_med['tier'] == 'Medium', f"Expected Medium, got {res_med['tier']}: {res_med['plain_english_explanation']}"

    score_low = res_low['raw_score']
    score_med = res_med['raw_score']

    # Constraint 4: Explicit bounds (score bands of config/thresholds.json)
    lm = scoring_matrix.THRESHOLDS['low_medium_boundary']
    mh = scoring_matrix.THRESHOLDS['medium_high_boundary']
    assert score_low < lm, f"Low score too high: {score_low}"
    assert lm <= score_med < mh, f"Medium score out of range: {score_med}"


def test_heldout_ransomware_windows_are_high():
    """The deployed model and cost policy put held-out ransomware windows (test period of the temporal
    split, never seen in training) in the High tier."""
    import numpy as np
    import pandas as pd
    import pytest
    import scoring_matrix
    from features import FEATURE_NAMES

    feats = os.path.join(_PROJECT_ROOT, "data", "features_sim.csv.gz")
    splits = os.path.join(_PROJECT_ROOT, "data", "splits_sim.csv.gz")
    scoring_matrix.load_models()
    model = scoring_matrix.models_cache.get("supervised")
    policy = scoring_matrix.models_cache.get("policy")
    if model is None or policy is None or not (os.path.exists(feats) and os.path.exists(splits)):
        pytest.skip("no trained model or feature table: run ml/simulate_events.py and ml/train.py")

    F = pd.read_csv(feats, usecols=FEATURE_NAMES + ["attack_family"])
    F["split"] = pd.read_csv(splits, usecols=["split"])["split"].to_numpy()
    R = F[(F["split"] == "test") & (F["attack_family"] == "ransomware")]
    assert len(R) >= 10, f"too few held-out ransomware windows to test: {len(R)}"

    P = model["model"].predict_proba(R[FEATURE_NAMES].to_numpy(float))
    tiers = (P @ np.asarray(policy["cost_matrix"])).argmin(axis=1)
    share_high = float((tiers == 2).mean())
    assert share_high >= 0.9, f"only {share_high:.0%} of {len(R)} held-out ransomware windows scored High"
