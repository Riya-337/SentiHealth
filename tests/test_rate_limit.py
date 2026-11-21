"""
tests/test_rate_limit.py — Test rate limiting and account lockout after 5 failed attempts.
"""

import sys
import os
import pytest
import json

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from datetime import datetime, timedelta, timezone

import dashboard as _dashboard
from dashboard import app, init_db, _failed_login_attempts, _failed_attempts_lock


@pytest.fixture
def client(tmp_path, monkeypatch):
    # A lockout written to the real logs/locked_accounts.json would lock 127.0.0.1 for every later run.
    # test_hardening reloads the dashboard module, so patch the module this file's `app` came from.
    monkeypatch.setattr(_dashboard, "LOCKED_ACCOUNTS", str(tmp_path / "locked_accounts.json"))
    _dashboard._rl_buckets.clear()
    app.config["TESTING"] = True
    with app.test_client() as client:
        init_db()
        with _failed_attempts_lock:
            _failed_login_attempts.clear()
        yield client


def test_rate_limiting_after_5_failed_logins(client):
    test_user = "admin"
    bad_payload = {"username": test_user, "password": "wrongpassword123"}

    # 1. Attempt 4 invalid logins — should receive 401 Unauthorized
    for i in range(4):
        res = client.post("/api/auth/login", json=bad_payload)
        assert res.status_code == 401, f"Attempt {i+1} expected 401, got {res.status_code}"

    # 2. 5th invalid login attempt — triggers 5th failure threshold
    res5 = client.post("/api/auth/login", json=bad_payload)
    assert res5.status_code in (401, 429), f"5th attempt expected 401 or 429, got {res5.status_code}"

    # 3. 6th login attempt — MUST be blocked with 429 Too Many Requests (Account Locked)
    res6 = client.post("/api/auth/login", json=bad_payload)
    assert res6.status_code == 429, f"6th attempt expected 429, got {res6.status_code}"
    data = res6.get_json()
    assert "locked" in data["message"].lower() or "5 consecutive" in data["message"].lower()


def test_rate_limiting_verify_otp(client):
    test_user = "admin"
    bad_otp_payload = {"username": test_user, "code": "999999"}

    # 1. Attempt 5 invalid OTP verifications
    for i in range(5):
        client.post("/api/auth/verify-otp", json=bad_otp_payload)

    # 2. 6th OTP attempt — MUST be blocked with 429
    res = client.post("/api/auth/verify-otp", json=bad_otp_payload)
    assert res.status_code == 429
    data = res.get_json()
    assert "locked" in data["message"].lower()


def _write_locks(entries):
    with open(_dashboard.LOCKED_ACCOUNTS, "w", encoding="utf-8") as f:
        json.dump(entries, f)


def test_automatic_lockout_records_expiry(client):
    bad_payload = {"username": "admin", "password": "wrongpassword123"}
    for _ in range(6):
        client.post("/api/auth/login", json=bad_payload)
    with open(_dashboard.LOCKED_ACCOUNTS, encoding="utf-8") as f:
        entry = json.load(f)[0]
    locked_at = datetime.fromisoformat(entry["locked_at"])
    assert datetime.fromisoformat(entry["expires_at"]) - locked_at == timedelta(minutes=15)


def test_expired_lockout_no_longer_blocks(client):
    past = datetime.now(timezone.utc) - timedelta(minutes=20)
    _write_locks([{"username": "admin", "ip": "127.0.0.1", "status": "locked",
                   "reason": "Excessive failed authentication attempts (5 in 15m)",
                   "locked_at": past.isoformat(), "expires_at": (past + timedelta(minutes=15)).isoformat()}])
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword123"})
    assert res.status_code == 401


def test_legacy_lockout_without_expiry_lifts_after_15_minutes(client):
    _write_locks([{"username": "admin", "ip": "127.0.0.1", "status": "locked",
                   "reason": "Excessive failed authentication attempts (5 in 15m)",
                   "locked_at": (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()}])
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword123"})
    assert res.status_code == 401


def test_responder_lock_stays_until_removed(client):
    # tiered-response locks are written as JSON lines with no expiry and must keep blocking
    with open(_dashboard.LOCKED_ACCOUNTS, "w", encoding="utf-8") as f:
        f.write(json.dumps({"user_id": "admin", "username": "admin", "status": "locked",
                            "time": "2020-01-01T00:00:00+00:00", "source": "self_healing_responder"}) + "\n")
    res = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword123"})
    assert res.status_code == 429
