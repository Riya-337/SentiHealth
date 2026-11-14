"""
rules.py — hand-written rule layers, kept separate from the models so they can be switched off
and evaluated on their own.

Two rule sets are defined:

rule_tier (the DEPLOYED rules)
    What the earlier scoring_matrix.py actually enforced on the features themselves: more than 15
    failed logins forced High, 4-15 forced Medium. (The old code also forced High whenever the
    event said attack_type = ransomware / exfiltration, but that label was supplied by the event's
    own sender, so it is not a rule on observations and is no longer used for decisions.)

expert_rule_tier (a FULLER threshold baseline)
    The thresholds an analyst might write down for this system: failed logins, export volume,
    CPU with memory spike, lateral movement. Used in ml/evaluate.py as a stronger rules-only
    baseline; not applied in the live path unless SENTIHEALTH_RULES=expert.

heuristic_attack_type
    The web app's heuristic label (>= 5 failed logins -> brute_force, > 1000 KB export ->
    exfiltration). Display only.
"""
from __future__ import annotations

TIER_NAMES = ["Low", "Medium", "High"]


def _f(f8: dict, key: str) -> float:
    try:
        return float(f8.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def rule_tier(f8: dict) -> int:
    """Deployed rules on the legacy eight features. 0 Low, 1 Medium, 2 High."""
    fl = _f(f8, "failed_logins")
    if fl > 15:
        return 2
    if 4 <= fl <= 15:
        return 1
    return 0


def expert_rule_tier(f8: dict) -> int:
    fl, cpu, mem = _f(f8, "failed_logins"), _f(f8, "cpu_usage"), _f(f8, "memory_spike")
    export, hosts = _f(f8, "data_export_volume_kb"), _f(f8, "lateral_movement_events")
    if fl > 15 or export > 1000 or (cpu >= 0.8 and mem >= 1) or hosts >= 3:
        return 2
    if 4 <= fl <= 15 or cpu >= 0.7 or export > 500:
        return 1
    return 0


def rule_reason(f8: dict, expert: bool = False) -> str:
    fl, cpu, mem = _f(f8, "failed_logins"), _f(f8, "cpu_usage"), _f(f8, "memory_spike")
    export, hosts = _f(f8, "data_export_volume_kb"), _f(f8, "lateral_movement_events")
    hits = []
    if fl > 15:
        hits.append(f"failed logins {fl:.0f} > 15")
    elif 4 <= fl <= 15:
        hits.append(f"failed logins {fl:.0f} in 4-15")
    if expert:
        if export > 1000:
            hits.append(f"export {export:.0f} KB > 1000")
        elif export > 500:
            hits.append(f"export {export:.0f} KB > 500")
        if cpu >= 0.8 and mem >= 1:
            hits.append(f"CPU {cpu:.2f} with memory spike")
        elif cpu >= 0.7:
            hits.append(f"CPU {cpu:.2f} >= 0.7")
        if hosts >= 3:
            hits.append(f"{hosts:.0f} internal hosts touched")
    return "; ".join(hits)


def heuristic_attack_type(f8: dict) -> str:
    if _f(f8, "data_export_volume_kb") > 1000:
        return "exfiltration"
    if _f(f8, "failed_logins") >= 5:
        return "brute_force"
    return "normal"
