"""Fast checks of the detection pipeline that do not need the trained models."""
import os
import sys

import numpy as np
import pandas as pd

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_PROJECT_ROOT, os.path.join(_PROJECT_ROOT, "ml")):
    if p not in sys.path:
        sys.path.insert(0, p)

from simulate_events import Simulator, FAMILY_TIER  # noqa: E402
from features import FEATURE_NAMES, build_feature_table, FeatureWindower, snapshot_to_features, legacy_eight  # noqa: E402
from rules import rule_tier, expert_rule_tier, heuristic_attack_type  # noqa: E402


def _small_dataset():
    recs = Simulator(days=2, n_users=12, seed=3).run()
    return pd.DataFrame(recs)


def test_simulator_is_deterministic_and_labels_by_campaign():
    a = Simulator(days=1, n_users=6, seed=1).run()
    b = Simulator(days=1, n_users=6, seed=1).run()
    assert a == b
    for r in a:
        assert r["tier_label"] == FAMILY_TIER[r["attack_family"]]
        assert r["is_attack"] == (r["attack_family"] != "normal")


def test_online_matches_batch():
    df = _small_dataset()
    F = build_feature_table(df)
    assert not F[FEATURE_NAMES].isna().any().any()
    w = FeatureWindower()
    raw_cols = ["ts", "user_id", "role", "ip", "shift", "logins", "login_failures", "ehr_reads", "export_kb",
                "requests", "distinct_endpoints", "internal_hosts", "cpu_usage", "mem_spike"]
    worst = 0.0
    for _, row in F.sort_values(["entity", "ts"]).iterrows():
        f = w.update({c: row[c] for c in raw_cols})
        for k in FEATURE_NAMES:
            worst = max(worst, abs(f[k] - float(row[k])) / (abs(float(row[k])) + 1e-6))
    assert worst < 1e-9, worst


def test_snapshot_mapping_and_legacy_eight_roundtrip():
    snap = {"failed_logins": 12, "cpu_usage": 0.7, "memory_spike": 1, "ehr_access_per_hour": 90,
            "lateral_movement_events": 2, "data_export_volume_kb": 800, "access_time_deviation": 0.9,
            "source_ip_reputation": 0.5}
    f = snapshot_to_features(snap, role="nurse", ip="8.8.8.8")
    assert list(f) == FEATURE_NAMES
    back = legacy_eight(f)
    assert back["failed_logins"] == 12 and back["ehr_access_per_hour"] == 90
    assert back["data_export_volume_kb"] == 800 and back["lateral_movement_events"] == 2
    assert back["access_time_deviation"] == 0.9 and back["cpu_usage"] == 0.7


def test_rules_layers():
    assert rule_tier({"failed_logins": 0}) == 0
    assert rule_tier({"failed_logins": 6}) == 1
    assert rule_tier({"failed_logins": 40}) == 2
    assert expert_rule_tier({"failed_logins": 1, "data_export_volume_kb": 5000}) == 2
    assert expert_rule_tier({"failed_logins": 1, "cpu_usage": 0.72}) == 1
    assert heuristic_attack_type({"failed_logins": 7}) == "brute_force"
    assert heuristic_attack_type({"data_export_volume_kb": 2000}) == "exfiltration"


def test_attack_type_label_does_not_change_the_decision():
    """The old scorer forced High whenever the event said attack_type=exfiltration. That label is
    written by the event's sender, so it must not move the tier."""
    import scoring_matrix
    scoring_matrix.velocity_buffer[:] = [0.1] * 5
    base = {"failed_logins": 1, "cpu_usage": 0.2, "ehr_access_per_hour": 5, "data_export_volume_kb": 40,
            "source_ip_reputation": 0.9, "access_time_deviation": 0.1}
    r1 = scoring_matrix.score_event(dict(base))
    scoring_matrix.velocity_buffer[:] = [0.1] * 5
    r2 = scoring_matrix.score_event(dict(base, attack_type="exfiltration"))
    assert r1["tier"] == r2["tier"] == "Low"
    assert abs(r1["raw_score"] - r2["raw_score"]) < 1e-9
    assert "not used for the decision" in r2["plain_english_explanation"]


def test_score_is_deterministic():
    import scoring_matrix
    f = {"failed_logins": 42, "cpu_usage": 0.3, "ehr_access_per_hour": 5, "data_export_volume_kb": 20}
    scoring_matrix.velocity_buffer[:] = [0.1] * 5
    a = scoring_matrix.score_event(dict(f))
    scoring_matrix.velocity_buffer[:] = [0.1] * 5
    b = scoring_matrix.score_event(dict(f))
    assert a["tier"] == b["tier"] == "High" and a["raw_score"] == b["raw_score"]
    assert a["raw_score"] >= scoring_matrix.THRESHOLDS["medium_high_boundary"]
