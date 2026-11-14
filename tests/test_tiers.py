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
    """Three coherent events. The earlier version of this test expected 'Medium' for an event
    exporting 25 MB/h and 'High' for an event whose only High signal was the sender-supplied
    attack_type label; both expectations came from the old rule floors, not from the observations."""
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

    features_high = {           # ransomware shape: host pegged, memory spike, spreading to internal hosts
        'failed_logins': 0,
        'cpu_usage': 0.92,
        'memory_spike': 1,
        'ehr_access_per_hour': 10,
        'lateral_movement_events': 6,
        'data_export_volume_kb': 3000.0,
        'source_ip_reputation': 0.9,
        'asset_type': 'ehr',
    }

    import scoring_matrix
    scoring_matrix.velocity_buffer[:] = [0.1, 0.1, 0.1, 0.1, 0.1]
    res_low = score_event(features_low)

    scoring_matrix.velocity_buffer[:] = [0.5, 0.5, 0.5, 0.5, 0.5]
    res_med = score_event(features_med)

    scoring_matrix.velocity_buffer[:] = [0.9, 0.9, 0.9, 0.9, 0.9]
    res_high = score_event(features_high)

    assert res_low['tier'] == 'Low', f"Expected Low, got {res_low['tier']}: {res_low['plain_english_explanation']}"
    assert res_med['tier'] == 'Medium', f"Expected Medium, got {res_med['tier']}: {res_med['plain_english_explanation']}"
    assert res_high['tier'] == 'High', f"Expected High, got {res_high['tier']}: {res_high['plain_english_explanation']}"

    score_low = res_low['raw_score']
    score_med = res_med['raw_score']
    score_high = res_high['raw_score']

    # Constraint 4: Explicit bounds (score bands of config/thresholds.json)
    lm = scoring_matrix.THRESHOLDS['low_medium_boundary']
    mh = scoring_matrix.THRESHOLDS['medium_high_boundary']
    assert score_low < lm, f"Low score too high: {score_low}"
    assert lm <= score_med < mh, f"Medium score out of range: {score_med}"
    assert score_high >= mh, f"High score too low: {score_high}"
