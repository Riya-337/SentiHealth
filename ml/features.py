"""
features.py — windowed, per-entity features from raw minute-level activity records.

An "entity" is a (user_id, ip) pair. For every record we look back over sliding windows of
5 minutes, 1 hour and 24 hours of that entity's own history, so a slow attack that stays under a
per-minute limit still shows up as an abnormal hourly total or as a departure from the entity's
own 24-hour baseline. The same code produces features in batch (training/evaluation) and online
(one record at a time, in the live sentinel); `test_online_matches_batch` in the tests checks that
the two agree.

Legacy mapping: the eight feature names the rest of the system already uses (failed_logins,
cpu_usage, ...) are derived from the windowed features by `legacy_eight()`, so the rules layer and
the dashboard keep working unchanged.
"""
from __future__ import annotations

import math
import re
from collections import deque
from datetime import datetime, timezone

import numpy as np
import pandas as pd

RAW_SUM_COLS = ["logins", "login_failures", "ehr_reads", "export_kb", "requests"]
RAW_MAX_COLS = ["distinct_endpoints", "internal_hosts", "cpu_usage", "mem_spike"]
RAW_COLS = RAW_SUM_COLS + RAW_MAX_COLS

WINDOWS_MIN = {"f5": 5, "f1h": 60}
BASELINE_MIN = 1440

# shifts per role, used for the off-shift score (same table as the simulator; real deployments
# read it from the staff roster in config/staff_roster.json)
ROLE_SHIFTS = {
    "nurse": [(7, 19), (19, 7)], "doctor": [(7, 19)], "admin": [(9, 17)],
    "billing": [(9, 17)], "it_staff": [(9, 17), (17, 1)],
}

FEATURE_NAMES: list[str] = (
    [f"f5_{c}" for c in RAW_SUM_COLS] + ["f5_fail_ratio", "f5_distinct_endpoints_max", "f5_internal_hosts_max", "f5_cpu_max", "f5_mem_spike"]
    + [f"f1h_{c}" for c in RAW_SUM_COLS] + ["f1h_fail_ratio", "f1h_distinct_endpoints_max", "f1h_internal_hosts_max", "f1h_cpu_mean"]
    + ["b24_reads_per_hour", "b24_export_per_hour", "ratio_reads_1h_vs_base", "ratio_export_1h_vs_base"]
    + ["hour_sin", "hour_cos", "is_weekend", "offshift_score", "ip_reputation", "is_internal_ip"]
)

LEGACY_EIGHT = ['failed_logins', 'cpu_usage', 'memory_spike', 'ehr_access_per_hour',
                'lateral_movement_events', 'data_export_volume_kb', 'access_time_deviation',
                'source_ip_reputation']


# --------------------------------------------------------------------------- small helpers
def _hours_from_shift(hour: float, shifts) -> float:
    """0 inside a shift; otherwise the distance in hours to the nearest shift edge."""
    best = 24.0
    for s, e in shifts or []:
        if s < e:
            inside = s <= hour < e
            d = min(abs(hour - s), abs(hour - e))
        else:
            inside = hour >= s or hour < e
            d = min(abs(hour - s), abs(hour - e), abs(hour - s + 24), abs(hour - e - 24))
        if inside:
            return 0.0
        best = min(best, d)
    return best


def _parse_shift(shift) -> list[tuple[int, int]] | None:
    """A user's own shift as [start_hour, end_hour] (from the roster); None if unknown."""
    if shift is None or (isinstance(shift, float) and np.isnan(shift)):
        return None
    if isinstance(shift, str):
        nums = re.findall(r"-?\d+", shift)
        return [(int(nums[0]), int(nums[1]))] if len(nums) >= 2 else None
    try:
        s, e = shift
        return [(int(s), int(e))]
    except (TypeError, ValueError):
        return None


def offshift_score(hour: float, role: str, shift=None) -> float:
    """0.1 on shift, 0.5 within two hours of a shift edge, 0.9 well outside (matches the web app's scale).
    Uses the user's own shift when known, otherwise the shifts possible for the role."""
    shifts = _parse_shift(shift) or ROLE_SHIFTS.get(role)
    if not shifts:
        return 0.5  # unknown role (anonymous / external): neither clearly on nor off shift
    d = _hours_from_shift(hour, shifts)
    return 0.1 if d == 0 else (0.5 if d <= 2 else 0.9)


def ip_reputation(ip: str) -> float:
    """Static reputation: internal addresses 0.9, anything else 0.5. (A threat-intel feed can
    lower this for known-bad ranges; none is bundled, so the value is honest but weak.)"""
    return 0.9 if ip.startswith(("10.", "192.168.", "172.16.", "127.")) else 0.5


def _time_feats(ts: datetime, role: str, shift=None) -> dict:
    h = ts.hour + ts.minute / 60.0
    return {
        "hour_sin": math.sin(2 * math.pi * h / 24), "hour_cos": math.cos(2 * math.pi * h / 24),
        "is_weekend": 1.0 if ts.weekday() >= 5 else 0.0, "offshift_score": offshift_score(h, role, shift),
    }


def legacy_eight(f: dict) -> dict:
    """The eight feature names used by the rules layer, the dashboard and the attack scripts."""
    return {
        'failed_logins': f["f5_login_failures"],
        'cpu_usage': f["f5_cpu_max"],
        'memory_spike': f["f5_mem_spike"],
        'ehr_access_per_hour': f["f1h_ehr_reads"],
        'lateral_movement_events': f["f1h_internal_hosts_max"],
        'data_export_volume_kb': f["f1h_export_kb"],
        'access_time_deviation': f["offshift_score"],
        'source_ip_reputation': f["ip_reputation"],
    }


# --------------------------------------------------------------------------- batch
def build_feature_table(df: pd.DataFrame) -> pd.DataFrame:
    """df: raw records (one per entity-minute) with the columns written by simulate_events.py.
    Returns a copy with FEATURE_NAMES added, one row per input row, in (entity, ts) order."""
    d = df.copy()
    d["ts"] = pd.to_datetime(d["ts"], utc=True)
    d["entity"] = d["user_id"].astype(str) + "@" + d["ip"].astype(str)
    # merge duplicates of the same entity-minute (a compromised user and its normal session can overlap)
    agg = {c: "sum" for c in RAW_SUM_COLS} | {c: "max" for c in RAW_MAX_COLS}
    keep_first = [c for c in d.columns if c not in RAW_COLS + ["entity", "ts"]]
    agg |= {c: "first" for c in keep_first}
    if "tier_label" in d:
        agg["tier_label"] = "max"
    if "is_attack" in d:
        agg["is_attack"] = "max"
    d = d.groupby(["entity", "ts"], as_index=False, sort=True).agg(agg)
    d = d.sort_values(["entity", "ts"], kind="stable").reset_index(drop=True)

    g = d.set_index("ts").groupby("entity", sort=True)
    out = {}
    for pre, mins in WINDOWS_MIN.items():
        w = f"{mins}min"
        sums = g[RAW_SUM_COLS].rolling(w).sum().to_numpy()
        for i, c in enumerate(RAW_SUM_COLS):
            out[f"{pre}_{c}"] = sums[:, i]
        out[f"{pre}_fail_ratio"] = out[f"{pre}_login_failures"] / np.maximum(out[f"{pre}_logins"], 1.0)
        out[f"{pre}_distinct_endpoints_max"] = g["distinct_endpoints"].rolling(w).max().to_numpy()
        out[f"{pre}_internal_hosts_max"] = g["internal_hosts"].rolling(w).max().to_numpy()
    out["f5_cpu_max"] = g["cpu_usage"].rolling("5min").max().to_numpy()
    out["f5_mem_spike"] = g["mem_spike"].rolling("5min").max().to_numpy()
    out["f1h_cpu_mean"] = g["cpu_usage"].rolling("60min").mean().to_numpy()
    r24_reads = g["ehr_reads"].rolling("1440min").sum().to_numpy()
    r24_export = g["export_kb"].rolling("1440min").sum().to_numpy()
    # baseline = the 23 hours before the current hour
    out["b24_reads_per_hour"] = np.maximum(r24_reads - out["f1h_ehr_reads"], 0.0) / 23.0
    out["b24_export_per_hour"] = np.maximum(r24_export - out["f1h_export_kb"], 0.0) / 23.0
    out["ratio_reads_1h_vs_base"] = out["f1h_ehr_reads"] / (out["b24_reads_per_hour"] + 1.0)
    out["ratio_export_1h_vs_base"] = out["f1h_export_kb"] / (out["b24_export_per_hour"] + 1.0)

    ts = d["ts"]
    h = ts.dt.hour + ts.dt.minute / 60.0
    out["hour_sin"] = np.sin(2 * np.pi * h / 24).to_numpy()
    out["hour_cos"] = np.cos(2 * np.pi * h / 24).to_numpy()
    out["is_weekend"] = (ts.dt.weekday >= 5).astype(float).to_numpy()
    shifts = d["shift"] if "shift" in d else [None] * len(d)
    out["offshift_score"] = np.array([offshift_score(hh, r, sh) for hh, r, sh in zip(h, d["role"], shifts)])
    out["ip_reputation"] = d["ip"].map(ip_reputation).to_numpy()
    out["is_internal_ip"] = d["ip"].str.startswith("10.").astype(float).to_numpy()

    for name in FEATURE_NAMES:
        d[name] = np.asarray(out[name], dtype=float)
    return d


# --------------------------------------------------------------------------- online
class FeatureWindower:
    """Incremental version of build_feature_table: feed records one at a time (any order of
    entities, ascending time within an entity) and get the same feature vector back."""

    def __init__(self):
        self._hist: dict[str, deque] = {}

    def update(self, rec: dict) -> dict:
        ts = rec["ts"] if isinstance(rec["ts"], datetime) else datetime.fromisoformat(str(rec["ts"]))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        key = f"{rec.get('user_id', 'anonymous')}@{rec.get('ip', '0.0.0.0')}"
        hist = self._hist.setdefault(key, deque())
        row = {c: float(rec.get(c, 0) or 0) for c in RAW_COLS}
        # merge with an existing record at the same minute
        if hist and hist[-1][0] == ts:
            prev = hist.pop()[1]
            for c in RAW_SUM_COLS:
                row[c] += prev[c]
            for c in RAW_MAX_COLS:
                row[c] = max(row[c], prev[c])
        hist.append((ts, row))
        cutoff = ts - pd.Timedelta(minutes=BASELINE_MIN)
        while hist and hist[0][0] <= cutoff:
            hist.popleft()

        f: dict = {}
        for pre, mins in WINDOWS_MIN.items():
            lo = ts - pd.Timedelta(minutes=mins)
            rows = [r for t, r in hist if t > lo]
            for c in RAW_SUM_COLS:
                f[f"{pre}_{c}"] = float(sum(r[c] for r in rows))
            f[f"{pre}_fail_ratio"] = f[f"{pre}_login_failures"] / max(f[f"{pre}_logins"], 1.0)
            f[f"{pre}_distinct_endpoints_max"] = float(max(r["distinct_endpoints"] for r in rows))
            f[f"{pre}_internal_hosts_max"] = float(max(r["internal_hosts"] for r in rows))
            if pre == "f5":
                f["f5_cpu_max"] = float(max(r["cpu_usage"] for r in rows))
                f["f5_mem_spike"] = float(max(r["mem_spike"] for r in rows))
            else:
                f["f1h_cpu_mean"] = float(np.mean([r["cpu_usage"] for r in rows]))
        r24_reads = float(sum(r["ehr_reads"] for _, r in hist))
        r24_export = float(sum(r["export_kb"] for _, r in hist))
        f["b24_reads_per_hour"] = max(r24_reads - f["f1h_ehr_reads"], 0.0) / 23.0
        f["b24_export_per_hour"] = max(r24_export - f["f1h_export_kb"], 0.0) / 23.0
        f["ratio_reads_1h_vs_base"] = f["f1h_ehr_reads"] / (f["b24_reads_per_hour"] + 1.0)
        f["ratio_export_1h_vs_base"] = f["f1h_export_kb"] / (f["b24_export_per_hour"] + 1.0)
        f.update(_time_feats(ts, str(rec.get("role", "unknown")), rec.get("shift")))
        ip = str(rec.get("ip", "0.0.0.0"))
        f["ip_reputation"] = ip_reputation(ip)
        f["is_internal_ip"] = 1.0 if ip.startswith("10.") else 0.0
        return {k: float(f[k]) for k in FEATURE_NAMES}


def snapshot_to_features(snapshot: dict, ts: datetime | None = None, role: str = "unknown", ip: str = "0.0.0.0") -> dict:
    """Best-effort mapping of a legacy eight-feature snapshot (attack scripts, web app, tests) onto
    the windowed feature names, so the model can score it. Treats the snapshot as the current
    5-minute window and (for hourly quantities) the current hour; no baseline history is known."""
    ts = ts or datetime.now(timezone.utc)
    fl = float(snapshot.get("failed_logins", 0) or 0)
    cpu = float(snapshot.get("cpu_usage", 0.0) or 0.0)
    mem = float(snapshot.get("memory_spike", 0) or 0)
    reads_h = float(snapshot.get("ehr_access_per_hour", 0) or 0)
    hosts = float(snapshot.get("lateral_movement_events", 0) or 0)
    export_h = float(snapshot.get("data_export_volume_kb", 0) or 0)
    req_h = reads_h + fl
    f = {
        "f5_logins": fl + (1.0 if reads_h > 0 else 0.0), "f5_login_failures": fl, "f5_ehr_reads": reads_h / 12.0,
        "f5_export_kb": export_h / 12.0, "f5_requests": req_h / 12.0 + fl,
        "f5_fail_ratio": fl / max(fl + 1.0, 1.0),
        "f5_distinct_endpoints_max": max(1.0, hosts), "f5_internal_hosts_max": max(1.0, hosts),
        "f5_cpu_max": cpu, "f5_mem_spike": mem,
        "f1h_logins": fl + 1.0, "f1h_login_failures": fl, "f1h_ehr_reads": reads_h, "f1h_export_kb": export_h,
        "f1h_requests": req_h, "f1h_fail_ratio": fl / max(fl + 1.0, 1.0),
        "f1h_distinct_endpoints_max": max(1.0, hosts), "f1h_internal_hosts_max": max(1.0, hosts), "f1h_cpu_mean": cpu,
        # no history is known, so the current hour is taken as its own baseline (no claimed deviation)
        "b24_reads_per_hour": reads_h, "b24_export_per_hour": export_h,
        "ratio_reads_1h_vs_base": reads_h / (reads_h + 1.0), "ratio_export_1h_vs_base": export_h / (export_h + 1.0),
    }
    f.update(_time_feats(ts, role))
    if snapshot.get("access_time_deviation") is not None:
        f["offshift_score"] = float(snapshot["access_time_deviation"])
    elif role not in ROLE_SHIFTS:
        f["offshift_score"] = 0.1   # no roster entry and no deviation given: do not assume off-shift
    # Keep reputation and the internal flag consistent with each other. In training an internal
    # address always has reputation 0.9 and is_internal_ip 1; an inconsistent pair is a combination
    # the models never saw. A snapshot with no address at all is taken as internal.
    known_ip = ip not in ("", "0.0.0.0")
    rep = snapshot.get("source_ip_reputation")
    if rep is not None:
        f["ip_reputation"] = float(rep)
        f["is_internal_ip"] = 1.0 if (ip.startswith("10.") if known_ip else float(rep) >= 0.8) else 0.0
    elif known_ip:
        f["ip_reputation"] = ip_reputation(ip)
        f["is_internal_ip"] = 1.0 if ip.startswith("10.") else 0.0
    else:
        f["ip_reputation"], f["is_internal_ip"] = 0.9, 1.0
    return {k: float(f[k]) for k in FEATURE_NAMES}
