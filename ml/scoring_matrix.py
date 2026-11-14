"""
scoring_matrix.py — turn one event into a tier (Low / Medium / High), a score and an explanation.

Decision path (every step is deterministic and reported in the result):

 1. Features. A raw minute record (user, ip, ts, counts) goes through the online FeatureWindower,
    which keeps that entity's last 24 h and computes the same windowed features used in training.
    A legacy eight-feature snapshot (attack scripts, web app, tests) is mapped onto the same names.
 2. Supervised model: the calibrated model chosen by ml/train.py -> P(Low), P(Medium), P(High);
    the tier is the one with the lowest expected cost under ml/cost_matrix.py
    (models/decision_policy.json).
 3. Unsupervised model: Isolation Forest trained on normal traffic only. If it flags the event as
    anomalous while the supervised model says Low, the event is raised to Medium (dissent_flag).
 4. Deployed rules (ml/rules.py): failed-login thresholds. The higher of the model tier and the
    rule tier wins. Set SENTIHEALTH_RULES=0 to disable, =expert for the fuller threshold set.
 5. Clinical context (core/context.py): on-shift + badge, emergency or registered proxy can lower
    the tier by one when the model is not confident; on-roster-but-external raises it by one.
 6. Velocity: a steep rise across the last five scores raises the tier by one.

What is deliberately NOT used for the decision: the `attack_type` field carried by the event. It
is written by whoever produced the event, so it is kept only as "sensor-reported" metadata.

Public interface kept from the previous version: score_event(features, context=None),
SESSION_SECRET, velocity_buffer, THRESHOLDS. The returned keys are unchanged (plus a few new ones).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import pickle
import sys
import uuid
import warnings
from datetime import datetime, timezone

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _paths import THRESHOLDS_FILE, MODEL_MANIFEST, MODELS_DIR, CHAIN_KEY_FILE, CONFIG_DIR  # noqa: E402
from features import FEATURE_NAMES, RAW_COLS, FeatureWindower, legacy_eight, snapshot_to_features  # noqa: E402
from rules import rule_tier, expert_rule_tier, rule_reason  # noqa: E402
from context import build_context, apply_context_modifier  # noqa: E402

warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

DEBUG = False
TIERS = ["Low", "Medium", "High"]

# --------------------------------------------------------------------------- thresholds (score bands)
os.makedirs(CONFIG_DIR, exist_ok=True)
if not os.path.exists(THRESHOLDS_FILE):
    with open(THRESHOLDS_FILE, 'w') as f:
        json.dump({"low_medium_boundary": 0.45, "medium_high_boundary": 0.75}, f)
THRESHOLDS = json.load(open(THRESHOLDS_FILE))
assert 'low_medium_boundary' in THRESHOLDS and 'medium_high_boundary' in THRESHOLDS

# --------------------------------------------------------------------------- model integrity + loading
manifest: dict = {}
if os.path.exists(MODEL_MANIFEST):
    manifest = json.load(open(MODEL_MANIFEST))
    for _name, _expected in manifest.items():
        _path = os.path.join(MODELS_DIR, f"{_name}.pkl")
        if os.path.exists(_path):
            with open(_path, 'rb') as _f:
                if hashlib.sha256(_f.read()).hexdigest() != _expected:
                    raise SystemExit(f"MODEL TAMPERED: {_name}")

models_cache: dict = {}


def load_models() -> None:
    """Load the supervised model named in models/decision_policy.json, the Isolation Forest and
    the decision policy (whichever exist)."""
    if models_cache:
        return
    pol_path = os.path.join(MODELS_DIR, "decision_policy.json")
    policy = json.load(open(pol_path)) if os.path.exists(pol_path) else {}
    if policy:
        models_cache["policy"] = policy
    supervised = policy.get("supervised_model", "xgb_calibrated")
    for key, name in (("supervised", supervised), ("iforest", "iforest")):
        path = os.path.join(MODELS_DIR, f"{name}.pkl")
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    models_cache[key] = pickle.load(f)
            except Exception as e:  # incompatible pickle, missing dependency
                warnings.warn(f"[scoring_matrix] cannot load {name}: {e}. Run ml/train.py.", RuntimeWarning, stacklevel=2)
    if "supervised" not in models_cache:
        warnings.warn("[scoring_matrix] no trained model found: using the rules and a simple heuristic. Run ml/train.py.",
                      RuntimeWarning, stacklevel=2)


load_models()

# --------------------------------------------------------------------------- HMAC key (audit chain)
try:
    from secrets_vault import get_secret
    SESSION_SECRET: bytes = get_secret("SESSION_SECRET")
except Exception:
    if os.path.exists(CHAIN_KEY_FILE):
        with open(CHAIN_KEY_FILE, 'rb') as _f:
            SESSION_SECRET = _f.read()
    else:
        SESSION_SECRET = os.urandom(32)
        os.makedirs(os.path.dirname(CHAIN_KEY_FILE), exist_ok=True)
        with open(CHAIN_KEY_FILE, 'wb') as _f:
            _f.write(SESSION_SECRET)

CRITICALITY = {'workstation': 1.0, 'clinical_app': 1.2, 'ehr': 1.5}   # asset weight, shown in the explanation

_NEUTRAL_TS = datetime(2025, 3, 4, 10, 0, tzinfo=timezone.utc)   # a Tuesday, 10:00: on shift for every role

velocity_buffer: list[float] = [0.1, 0.1, 0.1, 0.1, 0.1]
last_audit_hash = hashlib.sha256(b"init").hexdigest()
_WINDOWER = FeatureWindower()

# --------------------------------------------------------------------------- explanation
_FEATURE_COLS = ['failed_logins', 'cpu_usage', 'memory_spike', 'ehr_access_per_hour',
                 'lateral_movement_events', 'data_export_volume_kb', 'access_time_deviation',
                 'source_ip_reputation']
NORMAL_RANGE = {
    'failed_logins': (0.0, 5.0), 'cpu_usage': (0.10, 0.60), 'memory_spike': (0.0, 0.0),
    'ehr_access_per_hour': (0.0, 30.0), 'lateral_movement_events': (0.0, 1.0),
    'data_export_volume_kb': (0.0, 500.0), 'access_time_deviation': (0.0, 0.30),
    'source_ip_reputation': (0.80, 1.0),
}
_LOWER_IS_WORSE = {'source_ip_reputation'}
FEATURE_LABEL = {
    'failed_logins': 'failed logins', 'cpu_usage': 'CPU usage', 'memory_spike': 'memory spike',
    'ehr_access_per_hour': 'EHR records accessed per hour', 'lateral_movement_events': 'lateral-movement events',
    'data_export_volume_kb': 'data exported (KB)', 'access_time_deviation': 'access-time deviation',
    'source_ip_reputation': 'source IP reputation',
}
# importance of each legacy feature = summed importance of the windowed features it is derived from
_LEGACY_SOURCES = {
    'failed_logins': ['f5_login_failures', 'f1h_login_failures', 'f5_fail_ratio', 'f1h_fail_ratio', 'f5_logins', 'f1h_logins'],
    'cpu_usage': ['f5_cpu_max', 'f1h_cpu_mean'], 'memory_spike': ['f5_mem_spike'],
    'ehr_access_per_hour': ['f5_ehr_reads', 'f1h_ehr_reads', 'ratio_reads_1h_vs_base', 'b24_reads_per_hour'],
    'lateral_movement_events': ['f5_internal_hosts_max', 'f1h_internal_hosts_max', 'f5_distinct_endpoints_max', 'f1h_distinct_endpoints_max'],
    'data_export_volume_kb': ['f5_export_kb', 'f1h_export_kb', 'ratio_export_1h_vs_base', 'b24_export_per_hour'],
    'access_time_deviation': ['offshift_score', 'hour_sin', 'hour_cos', 'is_weekend'],
    'source_ip_reputation': ['ip_reputation', 'is_internal_ip'],
}


def _feature_importances() -> dict:
    try:
        raw = models_cache["supervised"]["raw"]
        imp = dict(zip(FEATURE_NAMES, raw.feature_importances_))
        out = {k: float(sum(imp.get(s, 0.0) for s in srcs)) for k, srcs in _LEGACY_SOURCES.items()}
        if sum(out.values()) > 0:
            return out
    except Exception:
        pass
    return {c: 1.0 / len(_FEATURE_COLS) for c in _FEATURE_COLS}


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if abs(v) >= 10 else f"{v:.2f}".rstrip('0').rstrip('.')


def explain_event(f8: dict) -> tuple[list, dict]:
    """(top_features, feature_values): up to three indicators outside their normal range, largest
    share first. An empty list means nothing was abnormal."""
    imp = _feature_importances()
    values, contrib = {}, {}
    for col in _FEATURE_COLS:
        try:
            v = float(f8.get(col, 0.0) or 0.0)
        except (TypeError, ValueError):
            v = 0.0
        values[col] = v
        lo, hi = NORMAL_RANGE[col]
        excess = (lo - v) if col in _LOWER_IS_WORSE else (v - hi)
        contrib[col] = imp[col] * max(0.0, excess) / max(hi - lo, 1e-6)
    total = sum(contrib.values())
    top = []
    if total > 0:
        for col, c in sorted(contrib.items(), key=lambda kv: -kv[1])[:3]:
            if c <= 0:
                break
            lo, hi = NORMAL_RANGE[col]
            top.append({"feature": col, "label": FEATURE_LABEL[col], "value": round(values[col], 3),
                        "normal_range": [lo, hi], "share": round(float(c / total), 3)})
    return top, values


def plain_english(tier: str, score: float, top: list, notes: list[str], recommended_action: str) -> str:
    if top:
        parts = [f"{t['label']} {_fmt(t['value'])} (normal {_fmt(t['normal_range'][0])}-{_fmt(t['normal_range'][1])})" for t in top]
        indicators = "Main indicators: " + "; ".join(parts) + "."
    else:
        indicators = "All eight indicators are inside their normal range."
    extra = (" " + " ".join(notes)) if notes else ""
    return f"{tier} tier, risk score {score:.3f}. {indicators}{extra} Recommended action: {recommended_action}."


# --------------------------------------------------------------------------- scoring pieces
def _feature_vector(features: dict) -> tuple[np.ndarray, dict, str]:
    """Returns (vector in FEATURE_NAMES order, legacy eight dict, source)."""
    ip = str(features.get('source_ip') or features.get('ip_address') or features.get('ip') or '0.0.0.0')
    if 'ts' in features and any(c in features for c in RAW_COLS):
        rec = dict(features)
        rec.setdefault('ip', ip)
        f = _WINDOWER.update(rec)
        source = "stream"
        f8 = legacy_eight(f)
    else:
        # time of the event: the sentinel passes the event's timestamp; a bare snapshot has none, and
        # unknown time must not count for or against it, so a neutral on-shift weekday moment is used
        ts = _NEUTRAL_TS
        raw_ts = features.get('timestamp') or features.get('ts')
        if raw_ts:
            try:
                ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except ValueError:
                ts = _NEUTRAL_TS
        f = snapshot_to_features(features, ts=ts, role=str(features.get('role', 'unknown')), ip=ip)
        source = "snapshot"
        # missing fields take the same neutral defaults the feature mapping uses
        defaults = {'source_ip_reputation': f["ip_reputation"], 'access_time_deviation': f["offshift_score"]}
        f8 = {}
        for c in _FEATURE_COLS:
            v = features.get(c)
            f8[c] = float(defaults.get(c, 0.0)) if v is None else float(v or 0.0)
    return np.array([f[k] for k in FEATURE_NAMES], dtype=float), f8, source


def _heuristic_probs(f8: dict) -> np.ndarray:
    """Used only when no trained model is available. Intensity of the abnormal signal -> probabilities."""
    i = min(1.0, (min(f8['failed_logins'], 20) / 20.0 * 0.35 + min(f8['cpu_usage'], 1.0) * 0.20
                  + min(f8['ehr_access_per_hour'], 200) / 200.0 * 0.20
                  + min(f8['data_export_volume_kb'], 3000) / 3000.0 * 0.15
                  + min(f8['lateral_movement_events'], 10) / 10.0 * 0.10))
    if i >= 0.6:
        return np.array([0.05, 0.25, 0.70])
    if i >= 0.3:
        return np.array([0.20, 0.65, 0.15])
    return np.array([0.85, 0.12, 0.03])


def _predict(vec: np.ndarray, f8: dict) -> tuple[np.ndarray, int, str]:
    """-> (probabilities, tier index from the decision policy, engine)."""
    m = models_cache.get("supervised")
    if m is None:
        p = _heuristic_probs(f8)
        return p, int(p.argmax()), "heuristic"
    p = m["model"].predict_proba(vec.reshape(1, -1))[0]
    pol = models_cache.get("policy")
    if pol and "cost_matrix" in pol:
        C = np.asarray(pol["cost_matrix"])
        tier = int((p @ C).argmin())
    else:
        tier = int(p.argmax())
    return p, tier, str(m.get("name", "supervised"))


def _anomaly(vec: np.ndarray) -> tuple[float | None, bool]:
    m = models_cache.get("iforest")
    if m is None:
        return None, False
    s = float(-m["model"].score_samples(vec.reshape(1, -1))[0])
    # escalate only at the strictest threshold (1 % false alarms on validation normals)
    return s, s >= m["thresholds"].get("fpr_1pct", float("inf"))


def _band(tier: int, base: float) -> float:
    """Place the continuous risk (0..1) inside the score band of the final tier."""
    lm, mh = THRESHOLDS['low_medium_boundary'], THRESHOLDS['medium_high_boundary']
    lo, hi = {0: (0.01, lm - 0.01), 1: (lm + 0.01, mh - 0.02), 2: (mh + 0.01, 0.99)}[tier]
    return float(lo + (hi - lo) * max(0.0, min(1.0, base)))


# --------------------------------------------------------------------------- main entry
def score_event(features: dict, context: dict | None = None) -> dict:
    global last_audit_hash
    event_id = str(uuid.uuid4())

    if context is None:
        user_id = features.get('user_id', '')
        source_ip = features.get('source_ip', features.get('ip_address', ''))
        if user_id:
            try:
                context = build_context(user_id, source_ip, features.get('vlan', 'unknown'))
            except Exception:
                context = None

    sensor_attack_type = str(features.get('attack_type', 'normal') or 'normal')   # metadata only
    asset_type = str(features.get('asset_type', 'workstation') or 'workstation')

    vec, f8, source = _feature_vector(features)
    probs, ml_tier, engine = _predict(vec, f8)
    iso_score, anomalous = _anomaly(vec)

    rules_mode = os.environ.get("SENTIHEALTH_RULES", "1")
    if rules_mode == "0":
        rule_t, rule_txt = 0, ""
    elif rules_mode == "expert":
        rule_t, rule_txt = expert_rule_tier(f8), rule_reason(f8, expert=True)
    else:
        rule_t, rule_txt = rule_tier(f8), rule_reason(f8)

    tier_idx = max(ml_tier, rule_t)
    notes: list[str] = []
    if rule_t > ml_tier:
        notes.append(f"Raised to {TIERS[rule_t]} by rule ({rule_txt}).")

    # unsupervised path: anomalous but the supervised model says Low. Only for stream records: a bare
    # snapshot has no history for this user/IP, so "unusual for this entity" cannot be judged.
    dissent_flag = bool(anomalous and ml_tier == 0 and source == "stream")
    has_legit_context = bool(
        features.get('emergency_status', False)
        or (context is not None and ((context.get('on_shift') and context.get('badge_entry_recent'))
                                     or context.get('emergency_active') or context.get('proxy_registered')))
    )
    context_suppressed_escalation = False
    if dissent_flag and tier_idx == 0:
        if has_legit_context:
            context_suppressed_escalation = True
        else:
            tier_idx = 1
            notes.append("Raised to Medium: unusual for this user/IP (unsupervised anomaly detector).")

    # continuous risk and clinical context
    base = float(0.55 * probs[1] + probs[2])
    raw_score_pre_context = _band(tier_idx, base)
    base_ctx = apply_context_modifier(base, context)
    if base_ctx < base - 1e-9 and tier_idx > 0 and probs[tier_idx] < 0.9:
        tier_idx -= 1
        notes.append("Lowered one tier: legitimate clinical context (on shift with badge, emergency, or registered proxy).")
    elif base_ctx > base + 1e-9 and tier_idx < 2:
        tier_idx += 1
        notes.append("Raised one tier: on the roster but accessing from outside without a badge entry.")

    # velocity across the last five events
    velocity_buffer.append(base_ctx)
    last_5 = velocity_buffer[-5:]
    slope = float(np.polyfit(range(5), last_5, 1)[0])
    velocity_escalation = slope > 0.15
    if velocity_escalation and tier_idx < 2:
        tier_idx += 1
        notes.append("Raised one tier: risk rising steeply over the last five events.")

    tier = TIERS[tier_idx]
    raw_score = _band(tier_idx, base_ctx)
    recommended_action = {0: "log_only", 1: "restrict_and_alert", 2: "throttle_and_await_human"}[tier_idx]

    top_features, feature_values = explain_event(f8)
    top_3_features = [f"{t['feature']}: {t['share']:.2f}" for t in top_features]
    if sensor_attack_type != 'normal':
        notes.append(f"Sensor-reported attack type: {sensor_attack_type} (not used for the decision).")
    plain_english_explanation = plain_english(tier, raw_score, top_features, notes, recommended_action)

    timestamp = datetime.now(timezone.utc).isoformat()
    core = json.dumps({'event_id': event_id, 'tier': tier, 'raw_score': raw_score, 'timestamp': timestamp}, sort_keys=True)
    hmac_token = _hmac.new(SESSION_SECRET, core.encode(), hashlib.sha256).hexdigest()

    if DEBUG:
        print(f"DEBUG probs={probs} ml_tier={ml_tier} rule={rule_t} iso={iso_score} final={tier}")

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "tier": tier,
        "raw_score": float(raw_score),
        "raw_score_pre_context": float(raw_score_pre_context),
        "probabilities": {TIERS[i]: float(probs[i]) for i in range(3)},
        "ml_tier": TIERS[ml_tier],
        "rule_tier": TIERS[rule_t],
        "anomaly_score": iso_score,
        "engine": engine,
        "feature_source": source,
        "confidence_interval": float(1.0 - float(probs.max())),   # model uncertainty (1 - top probability)
        "dissent_flag": dissent_flag,
        "context_suppressed_escalation": context_suppressed_escalation,
        "velocity_escalation": bool(velocity_escalation),
        "context": context,
        "attack_type": sensor_attack_type,
        "asset_type": asset_type,
        "asset_criticality": CRITICALITY.get(asset_type, 1.0),
        "features": {**f8, "attack_type": sensor_attack_type, "asset_type": asset_type},
        "top_3_features": top_3_features,
        "top_features": top_features,
        "feature_values": feature_values,
        "plain_english_explanation": plain_english_explanation,
        "recommended_action": recommended_action,
        "audit_hash": last_audit_hash,
        "hmac_token": hmac_token,
    }
