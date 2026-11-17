"""
Mirage — Adaptive Deception Decision Engine.

Inserts a deception tier between detection and terminal lockdown.
Once a session is flagged with high confidence but BEFORE terminal block,
route it to a deception path that:
  1. Wastes attacker time/resources.
  2. Pollutes their stolen dataset (data poisoning of THEIR exfil).
  3. Embeds canary tokens — if a fake record surfaces later, breach is traced.
  4. Captures high-confidence labeled attack data for model retraining.

Non-negotiable patient-safety invariant (healthcare critical):
  A real clinician must NEVER receive fake medical data.
  In a Level 1 Trauma Center, wrong data can kill a patient.
  Mirage ALWAYS fails safe to real data when uncertain.
  The clinical_allowlist in config/deception_policy.json is consulted first;
  if any doubt exists, real data is served and the session is flagged only.

Legal guardrail:
  Deception stays inside owned systems only.
  No payload is EVER sent TO the attacker's machine.
  Defensive deception within your own infrastructure is legal (IT Act, CFAA).
  "Hacking back" is not — this boundary is enforced in decide().

Activation criteria (all must be true):
  - The session's running-maximum risk exceeds the conformal threshold for its role
    (models/deception_gate.json, fitted by scripts/calibrate_deception.py). This bounds the probability
    that a legitimate session is ever deceived by alpha; without a fitted gate, nothing is deceived.
  - Session is NOT on the clinical_allowlist.
  - source_vlan is not "clinical" OR contradiction_flags are present
    (i.e. there's positive evidence this is NOT a real clinician).
  - deception_enabled == True in config/deception_policy.json.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

logger = logging.getLogger(__name__)

_POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "deception_policy.json")

DeceptionMode = Literal["none", "noise_only", "decoy", "full"]


@dataclass
class DeceptionVerdict:
    mode: DeceptionMode = "none"
    serve_decoy: bool = False
    apply_noise: bool = False
    apply_jitter: bool = False
    session_id: str = ""
    reason: str = ""
    canary_id: str = ""
    threat_tier: str = "Low"
    raw_score: float = 0.0
    logged_as_attack: bool = False


_GATE_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "deception_gate.json")
_RUNNING_MAX: dict[str, float] = {}
_gate_cache: dict = {"mtime": None, "gate": None}


def _load_gate():
    """The conformal gate written by scripts/calibrate_deception.py (reloaded when the file changes)."""
    try:
        mtime = os.path.getmtime(_GATE_PATH)
    except OSError:
        return None
    if _gate_cache["mtime"] != mtime:
        import sys as _sys
        _ml = os.path.join(os.path.dirname(__file__), "..", "ml")
        if _ml not in _sys.path:
            _sys.path.insert(0, _ml)
        from safe_deception import DeceptionGate
        with open(_GATE_PATH) as f:
            _gate_cache["gate"] = DeceptionGate.from_json(f.read())
        _gate_cache["mtime"] = mtime
    return _gate_cache["gate"]


def _load_policy() -> dict:
    if not os.path.exists(_POLICY_PATH):
        return _default_policy()
    try:
        with open(_POLICY_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[Mirage] Could not load policy: {e}")
        return _default_policy()


def _default_policy() -> dict:
    return {
        "deception_enabled": True,
        "activation_threshold": 0.55,
        "full_decoy_threshold": 0.75,
        "clinical_allowlist": [],
        "safe_vlans": ["clinical"],
        "noise_epsilon": 2.0,
    }


# ---------------------------------------------------------------------------
# Main decision function
# ---------------------------------------------------------------------------

def decide(
    session_id: str,
    tier: str,
    raw_score: float,
    source_vlan: str = "unknown",
    user_id: str = "",
    context: dict | None = None,
    endpoint: str = "",
) -> DeceptionVerdict:
    """
    Decide the deception mode for an incoming request.

    Called by the webapp deception middleware for every request on a flagged
    session.  Returns immediately — never blocks.

    Patient-safety fail-safe:
      If the session is in the clinical_allowlist OR source_vlan == "clinical"
      AND there are no contradiction_flags, always return mode="none".
    """
    policy = _load_policy()
    verdict = DeceptionVerdict(
        session_id=session_id,
        threat_tier=tier,
        raw_score=raw_score,
    )

    if not policy.get("deception_enabled", True):
        verdict.reason = "deception_disabled_in_policy"
        return verdict

    # --- Patient-safety gate (most important check) ---
    allowlist: list[str] = policy.get("clinical_allowlist", [])
    contradiction_flags: list[str] = (context or {}).get("contradiction_flags", [])
    is_clinical_vlan = source_vlan in policy.get("safe_vlans", ["clinical"])

    if session_id in allowlist or user_id in allowlist:
        verdict.reason = "session_on_clinical_allowlist"
        return verdict

    if is_clinical_vlan and not contradiction_flags:
        # Looks like a real clinician on the clinical network — do not deceive.
        verdict.reason = "clinical_vlan_no_contradiction"
        return verdict

    # --- Conformal safety gate (ml/safe_deception.py) ---
    # The session's RUNNING MAXIMUM risk is compared with thresholds calibrated on this installation's
    # legitimate sessions, which bounds P(a legitimate session is ever deceived) by alpha (per role when
    # role thresholds exist). Without a fitted gate Mirage never serves decoys: the old fixed
    # thresholds carried no such bound.
    gate = _load_gate()
    group = (context or {}).get("role") or ("unauthenticated" if not user_id else None)
    running = max(_RUNNING_MAX.get(session_id, 0.0), float(raw_score))
    _RUNNING_MAX[session_id] = running
    if gate is None:
        verdict.reason = "no_calibrated_gate (run scripts/calibrate_deception.py); fail-safe: no deception"
        return verdict
    level = gate.level(running, group)
    if level == "none":
        tn, _ = gate.thresholds(group)
        verdict.reason = f"below_conformal_threshold (session max {running:.3f} <= {tn}) alpha={gate.alpha_noise}"
        return verdict
    if level == "full":
        verdict.mode = "full"
        verdict.serve_decoy = True
        verdict.apply_noise = True
        verdict.apply_jitter = True
    else:
        verdict.mode = "noise_only"
        verdict.serve_decoy = False
        verdict.apply_noise = True
        verdict.apply_jitter = True

    # Assign canary ID for tracking (used by honey_data to embed in records)
    if verdict.serve_decoy:
        import secrets
        verdict.canary_id = f"canary_{secrets.token_hex(8)}"

    verdict.logged_as_attack = True
    verdict.reason = (
        f"tier={tier} score={raw_score:.3f} vlan={source_vlan} "
        f"contradictions={contradiction_flags}"
    )
    logger.info(
        f"[Mirage] session={session_id[:12]} mode={verdict.mode} "
        f"canary={verdict.canary_id or 'none'} reason={verdict.reason}"
    )
    return verdict
