"""Tests for the hardening modules: event signing, SQLite sessions, chain anchoring, incidents and
snoozes, response adapters (dry run), drift, and the dashboard's new security behaviour."""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("", "security", "core", "ml", "api"):
    p = os.path.join(_PROJECT_ROOT, sub) if sub else _PROJECT_ROOT
    if p not in sys.path:
        sys.path.insert(0, p)

from event_signing import sign_event, verify_line, split_line  # noqa: E402
from sessions import SessionStore  # noqa: E402
import anchoring  # noqa: E402
import incidents  # noqa: E402
import response_adapters as ra  # noqa: E402
from drift import compute_drift, training_stats  # noqa: E402


# --------------------------------------------------------------------------- event signing
def test_event_signing_roundtrip_and_tamper():
    key = bytes(range(32))
    line = sign_event({"event_id": "e1", "features": {"failed_logins": 3}}, key)
    ev, status = verify_line(line, key)
    assert status == "ok" and ev["event_id"] == "e1"
    text, sig = split_line(line)
    assert '"failed_logins":3' in text            # compact serialisation
    tampered = text.replace('"failed_logins":3', '"failed_logins":300') + "\tsig=" + sig
    assert verify_line(tampered, key) == (None, "bad_signature")
    ev2, status2 = verify_line(text, key)
    assert status2 == "unsigned" and ev2["event_id"] == "e1"
    assert verify_line("{not json", key) == (None, "malformed")
    _, wrong = verify_line(line, bytes(32))
    assert wrong == "bad_signature"


# --------------------------------------------------------------------------- sessions
def test_sqlite_sessions_expire_and_are_hashed():
    with tempfile.TemporaryDirectory() as d:
        store = SessionStore(os.path.join(d, "app.db"))
        tok = store.create("alice", False)
        assert store.get(tok)["username"] == "alice"
        rows = store._conn.execute("SELECT token_hash FROM sessions").fetchall()
        assert rows and rows[0][0] != tok and len(rows[0][0]) == 64
        assert store.get("nope") is None
        # idle timeout
        store._conn.execute("UPDATE sessions SET last_seen = ?", (time.time() - 3600,))
        store._conn.commit()
        assert store.get(tok) is None
        tok2 = store.create("bob", True)
        store.delete(tok2)
        assert store.get(tok2) is None


# --------------------------------------------------------------------------- anchoring
def test_anchor_detects_rewritten_chain(monkeypatch):
    with tempfile.TemporaryDirectory() as d:
        chain_path = os.path.join(d, "chain.json")
        anchor_path = os.path.join(d, "anchors.jsonl")
        chain = [{"block_index": i, "entry_hash": f"h{i}"} for i in range(3)]
        json.dump(chain, open(chain_path, "w"))
        monkeypatch.setattr(anchoring, "AUDIT_CHAIN", chain_path)
        rec = anchoring.anchor_now("t", anchor_path)
        assert rec["block_index"] == 2 and rec["entry_hash"] == "h2"
        assert anchoring.verify_anchors(anchor_path)["ok"]
        chain[2]["entry_hash"] = "rewritten"
        json.dump(chain, open(chain_path, "w"))
        rep = anchoring.verify_anchors(anchor_path)
        assert not rep["ok"] and "differs" in rep["mismatches"][0]["problem"]
        json.dump(chain[:1], open(chain_path, "w"))
        assert "shorter" in anchoring.verify_anchors(anchor_path)["mismatches"][0]["problem"]


# --------------------------------------------------------------------------- incidents + snoozes
def _ev(ip, minutes_ago, tier, score, action="resolved"):
    return {"ip": ip, "tier": tier, "score": score, "action": action,
            "timestamp": (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()}


def test_incident_grouping_by_gap(monkeypatch, tmp_path):
    monkeypatch.setattr(incidents, "BLOCKED_IPS", str(tmp_path / "blocked.json"))
    monkeypatch.setattr(incidents, "SNOOZE_FILE", str(tmp_path / "snoozes.json"))
    entries = [_ev("1.1.1.1", 60, "Low", 0.1), _ev("1.1.1.1", 58, "Medium", 0.5),   # one incident
               _ev("1.1.1.1", 5, "High", 0.9, "pending"),                            # new incident (gap > 10 min)
               _ev("2.2.2.2", 3, "Low", 0.2)]
    incs = incidents.build_incidents(entries)
    assert len(incs) == 3
    assert incs[0]["status"] == "pending" and incs[0]["peak_tier"] == "High" and incs[0]["ip"] == "1.1.1.1"
    old = [i for i in incs if i["ip"] == "1.1.1.1" and i["status"] != "pending"][0]
    assert old["n_events"] == 2 and old["peak_tier"] == "Medium" and old["tiers"] == {"Low": 1, "Medium": 1, "High": 0}
    # snoozes
    entry = incidents.set_snooze("2.2.2.2", 2, "scheduled backup job", "admin")
    assert incidents.is_snoozed("2.2.2.2")["reason"] == "scheduled backup job"
    assert incidents.build_incidents(entries)[-1]["snoozed"]["by"] == "admin"
    assert incidents.set_snooze("3.3.3.3", 1000, "x", "a")["until"] <= (datetime.now(timezone.utc) + timedelta(hours=incidents.MAX_SNOOZE_HOURS, minutes=1)).isoformat()
    assert incidents.clear_snooze("2.2.2.2") and incidents.is_snoozed("2.2.2.2") is None
    assert entry["reason"] == "scheduled backup job"


# --------------------------------------------------------------------------- response adapters
def test_response_adapters_dry_run_and_ttl(monkeypatch, tmp_path):
    monkeypatch.setattr(ra, "ACTIONS_LOG", str(tmp_path / "actions.jsonl"))
    monkeypatch.delenv("SENTIHEALTH_DRY_RUN", raising=False)   # default: dry run
    fw = ra.FirewallAdapter()
    rec = fw.block_ip("203.0.113.9", ttl_min=1, reason="test")
    assert rec["ok"] and rec["dry_run"] and "dry-run" in rec["detail"] and rec["expires_at"]
    assert fw.block_ip("not-an-ip")["ok"] is False
    # nothing expired yet
    assert ra.expire_actions() == []
    # force the TTL into the past and check the block is reversed exactly once
    acts = ra.load_actions()
    acts[0]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="seconds")
    with open(ra.ACTIONS_LOG, "w") as f:
        for a in acts:
            f.write(json.dumps(a) + "\n")
    undone = ra.expire_actions()
    assert len(undone) == 1 and undone[0]["action"] == "unblock_ip"
    assert ra.expire_actions() == []
    assert ra.DirectoryAdapter().lock_account("u1")["detail"].startswith("recorded only")
    st = ra.status()
    assert st["dry_run"] is True and st["actions_total"] >= 3


# --------------------------------------------------------------------------- drift
def test_drift_flags_shifted_feature():
    rng = np.random.default_rng(0)
    train = {"failed_logins": rng.poisson(1.0, 5000).astype(float), "cpu_usage": rng.uniform(0.1, 0.6, 5000)}
    stats = training_stats(train)
    same = [{"failed_logins": float(v), "cpu_usage": float(c)} for v, c in zip(rng.poisson(1.0, 500), rng.uniform(0.1, 0.6, 500))]
    rep = compute_drift(same, stats)
    assert rep["enough_data"] and rep["features"]["cpu_usage"]["status"] == "ok"
    shifted = [{"failed_logins": float(v), "cpu_usage": float(c)} for v, c in zip(rng.poisson(1.0, 500), rng.uniform(0.7, 1.0, 500))]
    rep2 = compute_drift(shifted, stats)
    assert rep2["features"]["cpu_usage"]["status"] == "drift" and rep2["overall"] == "drift"
    assert compute_drift([], stats)["overall"] == "no_data"


# --------------------------------------------------------------------------- dashboard routes
@pytest.fixture
def client(tmp_path, monkeypatch):
    """Dashboard app with isolated user store, sessions and logs."""
    monkeypatch.setenv("SENTIHEALTH_DRY_RUN", "1")
    import importlib
    import _paths
    monkeypatch.setattr(_paths, "USERS_FILE", str(tmp_path / "users.json"))
    monkeypatch.setattr(_paths, "APP_DB", str(tmp_path / "app.db"))
    monkeypatch.setattr(_paths, "LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(_paths, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(_paths, "THREAT_LOG", str(tmp_path / "logs" / "threat_log.json"))
    monkeypatch.setattr(_paths, "BLOCKED_IPS", str(tmp_path / "logs" / "blocked_ips.json"))
    monkeypatch.setattr(_paths, "LOCKED_ACCOUNTS", str(tmp_path / "logs" / "locked_accounts.json"))
    monkeypatch.setattr(_paths, "TAMPER_ALERTS", str(tmp_path / "logs" / "tamper_alerts.log"))
    monkeypatch.setattr(_paths, "AUDIT_CHAIN", str(tmp_path / "data" / "audit_chain.json"))
    monkeypatch.setattr(_paths, "AUDIT_CHAIN_REPLICA", str(tmp_path / "data" / "audit_chain_replica.json"))
    import sessions
    monkeypatch.setattr(sessions, "APP_DB", str(tmp_path / "app.db"))
    # Other test modules hold references to these modules, so patch their path globals in place
    # instead of re-importing them.
    import incidents as _inc, response_adapters as _ra, anchoring as _anc, self_healing_responder as _shr
    monkeypatch.setattr(_inc, "THREAT_LOG", str(tmp_path / "logs" / "threat_log.json"))
    monkeypatch.setattr(_inc, "BLOCKED_IPS", str(tmp_path / "logs" / "blocked_ips.json"))
    monkeypatch.setattr(_inc, "DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setattr(_inc, "SNOOZE_FILE", str(tmp_path / "data" / "snoozes.json"))
    monkeypatch.setattr(_ra, "LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.setattr(_ra, "ACTIONS_LOG", str(tmp_path / "logs" / "response_actions.jsonl"))
    monkeypatch.setattr(_anc, "AUDIT_CHAIN", str(tmp_path / "data" / "audit_chain.json"))
    monkeypatch.setattr(_anc, "ANCHOR_FILE", str(tmp_path / "data" / "anchors.jsonl"))
    for name in ("AUDIT_CHAIN", "AUDIT_CHAIN_REPLICA", "BLOCKED_IPS", "LOCKED_ACCOUNTS", "LOGS_DIR", "DATA_DIR"):
        monkeypatch.setattr(_shr, name, getattr(_paths, name))
    _shr._bootstrap_chain()
    sys.modules.pop("dashboard", None)
    import dashboard
    importlib.reload(dashboard)
    dashboard.USERS_HMAC_FILE = str(tmp_path / ".users.json.hmac")
    dashboard._session_store = sessions.SessionStore(str(tmp_path / "app.db"))
    dashboard.init_db()
    dashboard.app.config["TESTING"] = True
    return dashboard.app.test_client(), dashboard


def _admin_token(client, dashboard):
    users = dashboard.load_users()
    users["admin"]["password"] = dashboard._hash_password("Str0ng-admin-pass!")
    dashboard.save_users(users)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Str0ng-admin-pass!"})
    assert r.status_code == 200, r.get_json()
    import pyotp
    code = pyotp.TOTP(dashboard.load_users()["admin"]["totp_secret"]).now()
    r = client.post("/api/auth/verify-otp", json={"username": "admin", "code": code})
    assert r.status_code == 200 and r.get_json()["token"], r.get_json()
    return r.get_json()["token"]


def test_setup_wizard_only_runs_once(client):
    c, d = client
    assert c.get("/api/setup/status").get_json()["needs_setup"] is True
    r = c.post("/api/setup/complete", json={"password": "short"})
    assert r.status_code == 400
    r = c.post("/api/setup/complete", json={"password": "A-much-longer-password-1"})
    body = r.get_json()
    assert r.status_code == 200 and body["otpauth_uri"].startswith("otpauth://") and len(body["backup_codes"]) == 8
    assert "<svg" in body["qr_svg"]
    assert c.get("/api/setup/status").get_json()["needs_setup"] is False
    assert c.post("/api/setup/complete", json={"password": "Another-long-password-2"}).status_code == 403
    # the new password works, the default does not
    assert c.post("/api/auth/login", json={"username": "admin", "password": "adminpass123"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "admin", "password": "A-much-longer-password-1"}).status_code == 200


def test_token_not_accepted_in_query_and_stream_ticket_is_single_use(client):
    c, d = client
    token = _admin_token(c, d)
    assert c.get("/api/status").status_code == 401
    assert c.get(f"/api/status?token={token}").status_code == 401          # no tokens in URLs any more
    assert c.get("/api/status", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    t = c.post("/api/stream/ticket", headers={"Authorization": f"Bearer {token}"}).get_json()["ticket"]
    assert d._redeem_stream_ticket(t)             # valid once
    assert d._redeem_stream_ticket(t) == ""       # and never again
    c.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert c.get("/api/status", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_validation_and_rate_limit(client):
    c, d = client
    assert c.post("/api/auth/register", data="not json", content_type="text/plain").status_code == 400
    assert c.post("/api/auth/register", json={"username": "x", "password": "p"}).status_code == 400
    assert c.post("/api/auth/register", json={"username": "ok.user", "password": "long-enough-pw"}).status_code == 200
    for _ in range(4):
        c.post("/api/auth/register", json={"username": "someone.else", "password": "long-enough-pw"})
    assert c.post("/api/auth/register", json={"username": "another.one", "password": "long-enough-pw"}).status_code == 429


def test_approved_user_gets_totp_not_static_code(client):
    c, d = client
    token = _admin_token(c, d)
    c.post("/api/auth/register", json={"username": "nurse.k", "password": "a-strong-password"})
    r = c.post("/api/admin/users/nurse.k/approve", headers={"Authorization": f"Bearer {token}"})
    body = r.get_json()
    assert r.status_code == 200 and body["otpauth_uri"] and len(body["backup_codes"]) == 8 and "access_code" not in body
    r = c.post("/api/auth/login", json={"username": "nurse.k", "password": "a-strong-password"})
    assert r.get_json()["otp_channel"] == "authenticator"
    assert c.post("/api/auth/verify-otp", json={"username": "nurse.k", "code": "000000"}).status_code == 401
    import pyotp
    code = pyotp.TOTP(d.load_users()["nurse.k"]["totp_secret"]).now()
    r = c.post("/api/auth/verify-otp", json={"username": "nurse.k", "code": code})
    assert r.status_code == 200 and r.get_json()["is_admin"] is False


def test_release_block_needs_step_up_mfa_and_is_audited(client):
    c, d = client
    token = _admin_token(c, d)
    os.makedirs(os.path.dirname(d.BLOCKED_IPS), exist_ok=True)
    with open(d.BLOCKED_IPS, "w") as f:
        f.write(json.dumps({"ip": "198.51.100.7", "time": "t"}) + "\n")
    h = {"Authorization": f"Bearer {token}"}
    assert c.post("/api/blocked/198.51.100.7/release", json={"totp_code": "000000"}, headers=h).status_code == 401
    import pyotp
    code = pyotp.TOTP(d.load_users()["admin"]["totp_secret"]).now()
    r = c.post("/api/blocked/198.51.100.7/release", json={"totp_code": code, "reason": "false positive"}, headers=h)
    assert r.status_code == 200 and r.get_json()["removed_from_blocklist"] is True
    assert open(d.BLOCKED_IPS).read().strip() == ""
    chain = json.load(open(d.AUDIT_CHAIN))
    assert chain[-1]["action"] == "release_block" and chain[-1]["details"]["ip"] == "198.51.100.7"
    # snooze route + audit
    r = c.post("/api/entities/10.0.0.5/snooze", json={"hours": 2, "reason": "backup job"}, headers=h)
    assert r.status_code == 200
    assert c.get("/api/incidents", headers=h).get_json()["snoozes"]["10.0.0.5"]["reason"] == "backup job"
    assert c.delete("/api/entities/10.0.0.5/snooze", headers=h).get_json()["removed"] is True
    assert c.get("/healthz").get_json()["status"] == "ok"
