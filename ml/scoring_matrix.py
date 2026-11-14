import os
import json
import pickle
import random
import warnings
import hashlib
import numpy as np
import pandas as pd
import hmac as _hmac
from uuid import uuid4
from datetime import datetime, timezone

from _paths import THRESHOLDS_FILE, MODEL_MANIFEST, MODELS_DIR, CHAIN_KEY_FILE, CONFIG_DIR

# Suppress sklearn feature-name UserWarnings (cosmetic noise — doesn't affect accuracy).
warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

DEBUG = False

os.makedirs(CONFIG_DIR, exist_ok=True)
if not os.path.exists(THRESHOLDS_FILE):
    with open(THRESHOLDS_FILE, 'w') as f:
        json.dump({"low_medium_boundary": 0.3, "medium_high_boundary": 0.7}, f)

assert os.path.exists(THRESHOLDS_FILE)
THRESHOLDS = json.load(open(THRESHOLDS_FILE))
assert 'low_medium_boundary' in THRESHOLDS
assert 'medium_high_boundary' in THRESHOLDS

manifest = {}
if os.path.exists(MODEL_MANIFEST):
    manifest = json.load(open(MODEL_MANIFEST))
    for name, expected_sha in manifest.items():
        path = os.path.join(MODELS_DIR, f'calibrated_{name}.pkl')
        if os.path.exists(path):
            with open(path, 'rb') as f:
                sha = hashlib.sha256(f.read()).hexdigest()
            if sha != expected_sha:
                raise SystemExit(f"MODEL TAMPERED: {name}")

# Persistent HMAC key — managed by secrets_vault.py (0600 permission-restricted vault).
try:
    from secrets_vault import get_secret
    SESSION_SECRET: bytes = get_secret("SESSION_SECRET")
except Exception:
    _SECRET_PATH = CHAIN_KEY_FILE
    if os.path.exists(_SECRET_PATH):
        with open(_SECRET_PATH, 'rb') as _f:
            SESSION_SECRET: bytes = _f.read()
    else:
        SESSION_SECRET = os.urandom(32)
        os.makedirs(os.path.dirname(_SECRET_PATH), exist_ok=True)
        with open(_SECRET_PATH, 'wb') as _f:
            _f.write(SESSION_SECRET)


DAMAGE = {
    'normal': 0.1, 'brute_force': 0.4,
    'exfiltration': 0.7, 'ddos': 0.5, 'ransomware': 1.0
}

CRITICALITY = {
    'workstation': 1.0, 'clinical_app': 1.2, 'ehr': 1.5
}

WEIGHTS = {'rf': 0.25, 'gb': 0.20, 'svm': 0.20, 'lr': 0.15, 'xgb': 0.20}

models_cache = {}
def load_models():
    """Load calibrated models; skip any whose pickle is incompatible with the current
    scikit-learn version (e.g. _loss module path changed across sklearn releases).
    Missing or broken models fall back to the feature-intensity heuristic in score_event().
    """
    if not models_cache:
        for name in WEIGHTS:
            path = os.path.join(MODELS_DIR, f'calibrated_{name}.pkl')
            if os.path.exists(path):
                try:
                    with open(path, 'rb') as f:
                        models_cache[name] = pickle.load(f)
                except Exception as _e:
                    warnings.warn(
                        f"[scoring_matrix] Skipping model '{name}': {_e}. "
                        "Run model_trainer.py to rebuild with current scikit-learn.",
                        RuntimeWarning, stacklevel=2,
                    )
load_models()

velocity_buffer = [0.1, 0.1, 0.1, 0.1, 0.1]
last_audit_hash = hashlib.sha256(b"init").hexdigest()

import uuid
from context import build_context, apply_context_modifier


# ---------------------------------------------------------------------------
# Per-event explanation.
# Each feature is compared with the normal operating range of healthy hospital traffic
# (the ranges data_generator.py uses for normal rows). Only the part of a value that lies
# OUTSIDE that range counts, weighted by the Random Forest's feature importance, so the
# explanation names the indicators that actually pushed this event up.
# ---------------------------------------------------------------------------
_FEATURE_COLS = ['failed_logins', 'cpu_usage', 'memory_spike',
                 'ehr_access_per_hour', 'lateral_movement_events',
                 'data_export_volume_kb', 'access_time_deviation',
                 'source_ip_reputation']

# (low, high) of normal traffic. source_ip_reputation is the one feature where LOWER is worse.
NORMAL_RANGE = {
    'failed_logins':           (0.0, 5.0),
    'cpu_usage':               (0.10, 0.60),
    'memory_spike':            (0.0, 0.0),
    'ehr_access_per_hour':     (0.0, 30.0),
    'lateral_movement_events': (0.0, 1.0),
    'data_export_volume_kb':   (0.0, 500.0),
    'access_time_deviation':   (0.0, 0.30),
    'source_ip_reputation':    (0.80, 1.0),
}
_LOWER_IS_WORSE = {'source_ip_reputation'}
FEATURE_LABEL = {
    'failed_logins':           'failed logins',
    'cpu_usage':               'CPU usage',
    'memory_spike':            'memory spike',
    'ehr_access_per_hour':     'EHR records accessed per hour',
    'lateral_movement_events': 'lateral-movement events',
    'data_export_volume_kb':   'data exported (KB)',
    'access_time_deviation':   'access-time deviation',
    'source_ip_reputation':    'source IP reputation',
}


def _feature_importances() -> dict:
    """Random Forest importances from the calibrated model; equal weights if unavailable."""
    try:
        cc = models_cache['rf'].calibrated_classifiers_[0]
        base = getattr(cc, 'estimator', None) or getattr(cc, 'base_estimator', None)
        imp = list(base.feature_importances_)
        if len(imp) == len(_FEATURE_COLS) and sum(imp) > 0:
            return dict(zip(_FEATURE_COLS, imp))
    except Exception:
        pass
    return {c: 1.0 / len(_FEATURE_COLS) for c in _FEATURE_COLS}


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if abs(v) >= 10 else f"{v:.2f}".rstrip('0').rstrip('.')


def explain_event(features: dict) -> tuple[list, dict]:
    """Return (top_features, feature_values). top_features: up to 3 dicts, largest share first,
    only for indicators outside their normal range; empty list means nothing was abnormal."""
    imp = _feature_importances()
    values, contrib = {}, {}
    for col in _FEATURE_COLS:
        try:
            v = float(features.get(col, 0.0) or 0.0)
        except (TypeError, ValueError):
            v = 0.0
        values[col] = v
        lo, hi = NORMAL_RANGE[col]
        width = max(hi - lo, 1e-6)
        excess = (lo - v) if col in _LOWER_IS_WORSE else (v - hi)
        contrib[col] = imp[col] * max(0.0, excess) / width
    total = sum(contrib.values())
    top = []
    if total > 0:
        for col, c in sorted(contrib.items(), key=lambda kv: -kv[1])[:3]:
            if c <= 0:
                break
            lo, hi = NORMAL_RANGE[col]
            top.append({
                "feature": col,
                "label": FEATURE_LABEL[col],
                "value": round(values[col], 3),
                "normal_range": [lo, hi],
                "share": round(float(c / total), 3),
            })
    return top, values


def plain_english(tier: str, score: float, top: list, attack_type: str, recommended_action: str) -> str:
    if top:
        parts = []
        for t in top:
            lo, hi = t["normal_range"]
            parts.append(f"{t['label']} {_fmt(t['value'])} (normal {_fmt(lo)}-{_fmt(hi)})")
        indicators = "Main indicators: " + "; ".join(parts) + "."
    else:
        indicators = "All eight indicators are inside their normal range."
    sensor = f" Sensor-reported attack type: {attack_type}." if attack_type and attack_type != 'normal' else ""
    return f"{tier} tier, risk score {score:.3f}. {indicators}{sensor} Recommended action: {recommended_action}."

def score_event(features: dict, context: dict | None = None) -> dict:
    """
    Score an event and return a risk classification.

    Parameters
    ----------
    features : dict  — raw sensor features from the EHR/network monitor.
    context  : dict  — optional context object from context.build_context().
                       When provided, modulates raw_score to suppress false
                       positives on legitimate clinician activity and escalate
                       on contradictory context (internal-attacker signal).
                       If None, context is auto-built from features if user_id
                       and source_ip are present; otherwise scoring is unchanged.
    """
    event_id = str(uuid.uuid4())
    global velocity_buffer
    global last_audit_hash

    # Auto-build context if not explicitly provided
    if context is None:
        user_id = features.get('user_id', '')
        source_ip = features.get('source_ip', features.get('ip_address', ''))
        vlan = features.get('vlan', 'unknown')
        if user_id:
            try:
                context = build_context(user_id, source_ip, vlan)
            except Exception:
                context = None

    attack_type = features.get('attack_type', 'normal')
    asset_type = features.get('asset_type', 'workstation')
    
    # Named DataFrame preserves the column order models were trained with and
    # suppresses sklearn's "no valid feature names" warning.
    feature_vec = pd.DataFrame([{col: features.get(col, 0.0) for col in _FEATURE_COLS}])

    probs = {}
    for m in WEIGHTS:
        if m in models_cache:
            p = models_cache[m].predict_proba(feature_vec)[0]
            if len(p) == 3:
                probs[m] = {'Low': p[0], 'Medium': p[1], 'High': p[2]}
            else:
                probs[m] = {'Low': p[0], 'Medium': 0.0, 'High': p[1]}
        else:
            # Compute feature intensity from actual values so each event
            # gets a unique probability distribution.
            fl  = features.get('failed_logins', 0)
            cpu = features.get('cpu_usage', 0.0)
            ehr = features.get('ehr_access_per_hour', 0)
            exp = features.get('data_export_volume_kb', 0)
            lm  = features.get('lateral_movement_events', 0)
            # Normalise each feature to a 0-1 intensity signal.
            intensity = min(1.0, (
                min(fl, 20) / 20.0 * 0.35 +
                min(cpu, 1.0)        * 0.20 +
                min(ehr, 200) / 200.0 * 0.20 +
                min(exp, 3000) / 3000.0 * 0.15 +
                min(lm, 10) / 10.0   * 0.10
            ))
            # Add per-model jitter so models disagree slightly, which
            # produces a realistic confidence_interval value.
            jitter = 0.0  # no invented disagreement between models
            i = max(0.0, min(1.0, intensity))

            if attack_type in ['ransomware']:
                probs[m] = {'Low': max(0.01, 0.05 - jitter), 'Medium': 0.10, 'High': min(0.99, 0.85 + jitter)}
            elif attack_type == 'exfiltration' or fl > 7:
                high_p = min(0.95, 0.55 + i * 0.40)
                probs[m] = {'Low': max(0.01, 1 - high_p - 0.08), 'Medium': 0.08, 'High': high_p}
            elif i >= 0.45 or attack_type in ['ddos']:
                # Medium-range events — base starts at 0.50 so they clear the 0.3 threshold
                med_p = min(0.85, 0.50 + i * 0.45)
                probs[m] = {'Low': max(0.01, 1 - med_p - 0.10), 'Medium': med_p, 'High': 0.10}
            else:
                # Low-range events — still vary with intensity
                low_p = min(0.95, 0.60 + (1 - i) * 0.35)
                probs[m] = {'Low': low_p, 'Medium': max(0.01, 1 - low_p - 0.05), 'High': 0.05}

    if DEBUG:
        print(f"DEBUG PROBS BEFORE SUM: {probs}")

    current_weights = WEIGHTS.copy()
    if attack_type not in ['brute_force'] and features.get('source_ip_reputation', 1.0) >= 0.2:
        lr_w = current_weights.pop('lr')
        current_weights['rf'] += lr_w / 2
        current_weights['gb'] += lr_w / 2
        
    dissent_flag = any(probs[m]['High'] > 0.85 for m in current_weights)
    
    # We weight Medium probability at 0.55 and High at 1.0 to get a raw value that maps into the thresholds
    raw = sum(current_weights[m] * (probs[m].get('Medium', 0.0) * 0.55 + probs[m].get('High', 0.0)) for m in current_weights)
    
    # DAMAGE weights attack severity context, but must not override strong ML signals.
    # Formula: score = raw * (0.5 + 0.5 * damage_factor) so even 'normal' (0.1) still
    # passes 55% of the ML signal through. This prevents the multiplier from masking
    # genuine anomalies when attack_type hasn't been labelled by the webapp heuristic.
    damage_factor = DAMAGE.get(attack_type, 0.1)
    raw_score = raw * (0.5 + 0.5 * damage_factor)
    raw_score = raw_score * CRITICALITY.get(asset_type, 1.0)
    # Deterministic: the same features always give the same score, so the number shown on the
    # dashboard can be reproduced and explained.
    raw_score = max(0.01, min(0.99, raw_score))
    
    if features.get('failed_logins', 0) > 15 or attack_type in ['ransomware', 'exfiltration']:
        # High-tier floor with proportional feature scaling + unique jitter
        fl_bonus = min(0.04, features.get('failed_logins', 0) * 0.001)
        raw_score = min(0.99, 0.82 + (raw_score * 0.12) + fl_bonus)
    elif attack_type in ['ddos', 'brute_force'] or (4 <= features.get('failed_logins', 0) <= 14):
        # Medium-tier floor — ensures these events consistently land above the 0.3 boundary
        # while still varying (σ=0.025 jitter keeps every event unique).
        fl_ratio = min(1.0, (features.get('failed_logins', 0) - 4) / 10.0)
        raw_score = min(0.68, max(
            THRESHOLDS['low_medium_boundary'] + 0.05 + fl_ratio * 0.30,
            raw_score
        ))

    # Apply Context Fusion modifier BEFORE tier assignment.
    # Legitimate clinical context (on-shift + badge) suppresses the score.
    # Contradictory context (on-roster but no badge + external VLAN) raises it.
    # Raw score is preserved in the return dict for forensic transparency.
    raw_score_pre_context = raw_score
    raw_score = apply_context_modifier(raw_score, context)

    if raw_score >= THRESHOLDS['medium_high_boundary']: tier = 'High'
    elif raw_score >= THRESHOLDS['low_medium_boundary']: tier = 'Medium'
    else: tier = 'Low'

    # Keep the score inside its tier band (no random jitter).
    _lo_med = THRESHOLDS['low_medium_boundary']
    _med_hi = THRESHOLDS['medium_high_boundary']
    if tier == 'Low':
        raw_score = max(0.01, min(_lo_med - 0.01, raw_score))
    elif tier == 'Medium':
        raw_score = max(_lo_med + 0.01, min(_med_hi - 0.02, raw_score))
    else:  # High
        raw_score = max(_med_hi + 0.01, min(0.99, raw_score))

    context_suppressed_escalation = False

    # emergency_status (legacy boolean from old features dict) and the richer
    # context both suppress dissent-driven escalation.
    has_legitimate_context = (
        features.get('emergency_status', False)
        or (context is not None and (
            (context.get('on_shift') and context.get('badge_entry_recent'))
            or context.get('emergency_active')
            or context.get('proxy_registered')
        ))
    )

    if dissent_flag and tier == 'Low':
        if not has_legitimate_context:
            tier = 'Medium'
            raw_score = max(raw_score, THRESHOLDS['low_medium_boundary'] + 0.05)
        else:
            context_suppressed_escalation = True
            
    velocity_buffer.append(raw_score)
    last_5 = velocity_buffer[-5:]
    slope = np.polyfit(range(5), last_5, 1)[0]
    # Threshold raised from 0.06 to 0.15: a single score jump (e.g. 0→0.5) was
    # triggering false escalation. 0.15 requires 3+ sustained rising events to fire.
    velocity_escalation = slope > 0.15
    
    if velocity_escalation and tier != 'High':
        tier = 'Medium' if tier == 'Low' else 'High'
        if tier == 'Medium':
            raw_score = max(raw_score, THRESHOLDS['low_medium_boundary'] + 0.05)
        elif tier == 'High':
            raw_score = max(raw_score, THRESHOLDS['medium_high_boundary'] + 0.05)
        
    high_probs = [probs[m]['High'] for m in current_weights]
    confidence_interval = float(np.std(high_probs))
    
    if tier == 'Low': recommended_action = "log_only"
    elif tier == 'Medium': recommended_action = "restrict_and_alert"
    else: recommended_action = "throttle_and_await_human"

    top_features, feature_values = explain_event(features)
    top_3_features = [f"{t['feature']}: {t['share']:.2f}" for t in top_features]  # legacy string form
    plain_english_explanation = plain_english(tier, raw_score, top_features, attack_type, recommended_action)
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    core = json.dumps({
        'event_id': event_id, 'tier': tier,
        'raw_score': raw_score, 'timestamp': timestamp
    }, sort_keys=True)
    hmac_token = _hmac.new(SESSION_SECRET, core.encode(), hashlib.sha256).hexdigest()
    
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "tier": tier,
        "raw_score": float(raw_score),
        "raw_score_pre_context": float(raw_score_pre_context),
        "confidence_interval": confidence_interval,
        "dissent_flag": bool(dissent_flag),
        "context_suppressed_escalation": context_suppressed_escalation,
        "velocity_escalation": bool(velocity_escalation),
        "context": context,
        "attack_type": attack_type,
        "asset_type": asset_type,
        "top_3_features": top_3_features,
        "top_features": top_features,
        "feature_values": feature_values,
        "plain_english_explanation": plain_english_explanation,
        "recommended_action": recommended_action,
        "audit_hash": last_audit_hash,
        "hmac_token": hmac_token,
    }
