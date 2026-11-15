"""
incidents.py — group threat_log events into incidents, and manage snoozes.

The dashboard used to show one row per scored minute, so a ten-minute attack produced ten
rows to triage. An incident is all events from one source IP with no gap longer than
GAP_MINUTES between them; it carries the peak tier and score, the latest action, and the
explanation of its peak event. Snoozes let an analyst mute Low/Medium alerts for a known-benign
entity for a limited time, with a recorded reason; High-tier events are never snoozed.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import THREAT_LOG, BLOCKED_IPS, DATA_DIR  # noqa: E402

GAP_MINUTES = 10
TIER_RANK = {"Low": 0, "Medium": 1, "High": 2}
SNOOZE_FILE = os.path.join(DATA_DIR, "snoozes.json")
MAX_SNOOZE_HOURS = 72


def _parse_ts(s: str) -> datetime:
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def load_threats() -> list[dict]:
    if not os.path.exists(THREAT_LOG):
        return []
    out = []
    with open(THREAT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def blocked_ips() -> set[str]:
    out: set[str] = set()
    if not os.path.exists(BLOCKED_IPS):
        return out
    with open(BLOCKED_IPS, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return out
    try:
        if text.startswith("["):
            for e in json.loads(text):
                out.add(e.get("ip") if isinstance(e, dict) else str(e))
            return out
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                out.add(json.loads(line).get("ip", ""))
            except json.JSONDecodeError:
                continue
    out.discard("")
    return out


# --------------------------------------------------------------------------- snoozes
def load_snoozes() -> dict:
    if not os.path.exists(SNOOZE_FILE):
        return {}
    try:
        with open(SNOOZE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}
    now = datetime.now(timezone.utc)
    return {ip: s for ip, s in data.items() if _parse_ts(s.get("until", "")) > now}


def is_snoozed(ip: str) -> dict | None:
    return load_snoozes().get(ip)


def set_snooze(ip: str, hours: float, reason: str, by: str) -> dict:
    hours = max(0.25, min(float(hours), MAX_SNOOZE_HOURS))
    data = load_snoozes()
    entry = {"until": (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat(timespec="seconds"),
             "reason": reason.strip()[:300], "by": by, "set_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    data[ip] = entry
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SNOOZE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, SNOOZE_FILE)
    return entry


def clear_snooze(ip: str) -> bool:
    data = load_snoozes()
    if ip not in data:
        return False
    del data[ip]
    tmp = SNOOZE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, SNOOZE_FILE)
    return True


# --------------------------------------------------------------------------- incidents
def build_incidents(entries: list[dict], gap_minutes: int = GAP_MINUTES) -> list[dict]:
    """Newest first. Each entry needs ip, tier, score, timestamp, action; other fields optional."""
    by_ip: dict[str, list[dict]] = {}
    for e in entries:
        ip = str(e.get("ip") or "unknown")
        by_ip.setdefault(ip, []).append(e)
    blocked = blocked_ips()
    snoozes = load_snoozes()
    incidents: list[dict] = []
    gap = timedelta(minutes=gap_minutes)
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: _parse_ts(e.get("timestamp", "")))
        group: list[dict] = []
        last_t = None
        for e in evs:
            t = _parse_ts(e.get("timestamp", ""))
            if group and last_t is not None and t - last_t > gap:
                incidents.append(_summarise(ip, group, blocked, snoozes))
                group = []
            group.append(e)
            last_t = t
        if group:
            incidents.append(_summarise(ip, group, blocked, snoozes))
    incidents.sort(key=lambda i: (i["status"] != "pending", -TIER_RANK[i["peak_tier"]], i["end"]), reverse=False)
    # pending first, then by severity, newest first within the same severity
    incidents.sort(key=lambda i: (0 if i["status"] == "pending" else 1, -TIER_RANK[i["peak_tier"]], -i["end_epoch"]))
    return incidents


def _summarise(ip: str, group: list[dict], blocked: set[str], snoozes: dict) -> dict:
    peak = max(group, key=lambda e: (TIER_RANK.get(e.get("tier", "Low"), 0), float(e.get("score", 0) or 0)))
    start, end = _parse_ts(group[0].get("timestamp", "")), _parse_ts(group[-1].get("timestamp", ""))
    tiers = {"Low": 0, "Medium": 0, "High": 0}
    for e in group:
        tiers[e.get("tier", "Low")] = tiers.get(e.get("tier", "Low"), 0) + 1
    actions = [str(e.get("action", "")) for e in group]
    if "pending" in actions:
        status = "pending"
    elif "auto-locked" in actions and "forensics_generated" not in actions and "admin_released" not in actions:
        status = "auto-locked"
    else:
        status = actions[-1] or "resolved"
    iid = hashlib.sha1(f"{ip}|{start.isoformat()}".encode()).hexdigest()[:12]
    users = sorted({str(e.get("user_id")) for e in group if e.get("user_id")})
    return {
        "id": iid,
        "ip": ip,
        "users": users,
        "start": start.isoformat(timespec="seconds"),
        "end": end.isoformat(timespec="seconds"),
        "end_epoch": end.timestamp(),
        "duration_s": max(0.0, (end - start).total_seconds()),
        "n_events": len(group),
        "tiers": tiers,
        "peak_tier": peak.get("tier", "Low"),
        "peak_score": float(peak.get("score", 0) or 0),
        "status": status,
        "blocked": ip in blocked,
        "snoozed": snoozes.get(ip),
        "reason": peak.get("reason", ""),
        "top_features": peak.get("top_features", []),
        "attack_types": sorted({str(e.get("attack_type", "normal")) for e in group} - {"normal"}),
        "shap_url": f"/api/shap/{peak['shap_file']}" if peak.get("shap_file") else "",
        "peak_timestamp": peak.get("timestamp", ""),
    }


def incident_by_id(iid: str) -> dict | None:
    for inc in build_incidents(load_threats()):
        if inc["id"] == iid:
            return inc
    return None


def entity_timeline(ip: str, limit: int = 200) -> list[dict]:
    """Scores over time for one IP, oldest first (for the sparkline)."""
    rows = [e for e in load_threats() if str(e.get("ip")) == ip]
    rows.sort(key=lambda e: _parse_ts(e.get("timestamp", "")))
    return [{"t": e.get("timestamp", ""), "score": float(e.get("score", 0) or 0), "tier": e.get("tier", "Low"),
             "action": e.get("action", "")} for e in rows[-limit:]]
