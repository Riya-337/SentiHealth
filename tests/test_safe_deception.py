"""The conformal deception gate: the bound, the session-level (anytime) property, per-role
thresholds, fail-safe behaviour, contamination, persistence, and Mirage's use of it."""
import json
import os
import sys

import numpy as np
import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (_ROOT, os.path.join(_ROOT, "ml")):
    if p not in sys.path:
        sys.path.insert(0, p)
from safe_deception import DeceptionGate, conformal_pvalue, conformal_threshold, monitor  # noqa: E402


def test_marginal_bound_holds_on_exchangeable_data():
    rng = np.random.default_rng(0)
    rates = []
    for _ in range(400):
        cal = rng.gamma(2.0, 1.0, 300)
        new = rng.gamma(2.0, 1.0, 300)
        rates.append(np.mean(new > conformal_threshold(cal, 0.05)))
    assert np.mean(rates) <= 0.05 + 0.004          # expectation <= alpha (small Monte-Carlo slack)
    assert np.mean(rates) >= 0.05 - 1 / 301 - 0.004  # and not wildly conservative


def test_threshold_is_infinite_when_too_few_calibration_points():
    assert conformal_threshold(np.arange(50.0), 0.01) == float("inf")   # needs >= 99 points
    assert np.isfinite(conformal_threshold(np.arange(99.0), 0.01))


def test_session_level_bound_covers_every_event_in_the_session():
    """Calibrating on whole-session maxima bounds 'ever deceived', even though the decision is
    re-taken at every event. Calibrating on per-event scores would not."""
    rng = np.random.default_rng(1)
    def sessions(n, length=40):
        return [rng.normal(0, 1, length) for _ in range(n)]
    cal, test = sessions(1000), sessions(4000)
    alpha = 0.05
    tau_session = conformal_threshold(np.array([s.max() for s in cal]), alpha)
    tau_event = conformal_threshold(np.concatenate(cal), alpha)
    ever_session = np.mean([s.max() > tau_session for s in test])
    ever_event = np.mean([s.max() > tau_event for s in test])
    assert ever_session <= alpha + 0.01
    assert ever_event > 0.5            # per-event calibration deceives most legitimate sessions at some point


def test_mondrian_bound_per_group_and_failsafe_for_unknown_groups():
    rng = np.random.default_rng(2)
    # group B is much "noisier" than A: a pooled threshold over-deceives B
    cal = np.concatenate([rng.normal(0, 1, 2000), rng.normal(1.5, 1, 2000)])
    grp = np.array(["A"] * 2000 + ["B"] * 2000)
    pooled = DeceptionGate(alpha_noise=0.02, alpha_full=0.004).fit(cal)
    mond = DeceptionGate(alpha_noise=0.02, alpha_full=0.004).fit(cal, grp)
    newB = rng.normal(1.5, 1, 20000)
    assert np.mean(newB > pooled.tau_noise) > 0.03          # pooled: group B over its budget
    assert np.mean(newB > mond.thresholds("B")[0]) <= 0.025  # per-group: within budget
    assert mond.thresholds("never-seen-role") == (float("inf"), float("inf"))
    assert mond.level(1e9, "never-seen-role") == "none"
    assert mond.thresholds("unauthenticated") == (pooled.tau_noise, pooled.tau_full)


def test_levels_and_persistence():
    g = DeceptionGate(alpha_noise=0.1, alpha_full=0.01).fit(np.arange(1000.0), np.array(["x"] * 1000))
    tn, tf = g.thresholds("x")
    assert tf >= tn
    assert g.level(tn - 1, "x") == "none" and g.level(tn + 0.5, "x") == "noise_only" and g.level(tf + 1, "x") == "full"
    g2 = DeceptionGate.from_json(g.to_json())
    assert g2.thresholds("x") == (tn, tf) and g2.alpha_full == 0.01


def test_contamination_only_makes_it_more_conservative():
    rng = np.random.default_rng(3)
    legit = rng.normal(0, 1, 2000)
    attacks = rng.normal(4, 1, 100)
    clean = conformal_threshold(legit, 0.01)
    dirty = conformal_threshold(np.concatenate([legit, attacks]), 0.01)
    assert dirty >= clean


def test_pvalue_and_monitor():
    cal = np.arange(100.0)
    assert conformal_pvalue(cal, 1000.0) == pytest.approx(1 / 101)
    assert conformal_pvalue(cal, -1.0) == 1.0
    ok = monitor(np.array([True] * 5 + [False] * 995), alpha=0.01)
    bad = monitor(np.array([True] * 40 + [False] * 960), alpha=0.01)
    assert not ok["violated"] and bad["violated"]


def test_mirage_is_failsafe_without_gate_and_uses_running_max(tmp_path, monkeypatch):
    sys.path.insert(0, os.path.join(_ROOT, "deception"))
    import mirage
    monkeypatch.setattr(mirage, "_GATE_PATH", str(tmp_path / "gate.json"))
    mirage._gate_cache.update({"mtime": None, "gate": None})
    mirage._RUNNING_MAX.clear()
    v = mirage.decide("s1", "High", 0.99, source_vlan="external")
    assert v.mode == "none" and "no_calibrated_gate" in v.reason
    gate = DeceptionGate(alpha_noise=0.1, alpha_full=0.02).fit(np.linspace(0, 0.5, 1000))
    (tmp_path / "gate.json").write_text(gate.to_json())
    assert mirage.decide("s2", "Medium", 0.40, source_vlan="external").mode == "none"
    assert mirage.decide("s2", "High", 0.70, source_vlan="external").mode == "full"
    # the running maximum keeps the session deceived even when a later event looks harmless
    assert mirage.decide("s2", "Low", 0.05, source_vlan="external").mode == "full"
    # the clinical-network safety gate still comes first
    assert mirage.decide("s3", "High", 0.99, source_vlan="clinical").mode == "none"
