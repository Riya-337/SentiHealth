"""
sessions.py — dashboard sessions in SQLite instead of a Python dict.

Before: sessions lived in memory, so a restart logged everyone out and a second worker process
could not see them. Now only a SHA-256 of the token is stored (a leaked database does not yield
usable tokens), with an absolute lifetime of 8 hours and an idle timeout of 30 minutes.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)
from _paths import APP_DB  # noqa: E402

ABSOLUTE_LIFETIME_SEC = 8 * 3600
IDLE_TIMEOUT_SEC = 30 * 60


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SessionStore:
    def __init__(self, db_path: str = APP_DB):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, "
            "is_admin INTEGER NOT NULL, created_at REAL NOT NULL, last_seen REAL NOT NULL)"
        )
        self._conn.commit()

    def create(self, username: str, is_admin: bool) -> str:
        token = secrets.token_hex(32)
        now = time.time()
        with self._lock:
            self._conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                               (_hash(token), username, 1 if is_admin else 0, now, now))
            self._conn.commit()
        return token

    def get(self, token: str) -> dict | None:
        if not token:
            return None
        h = _hash(token)
        now = time.time()
        with self._lock:
            row = self._conn.execute(
                "SELECT username, is_admin, created_at, last_seen FROM sessions WHERE token_hash = ?", (h,)).fetchone()
            if row is None:
                return None
            username, is_admin, created_at, last_seen = row
            if now - created_at > ABSOLUTE_LIFETIME_SEC or now - last_seen > IDLE_TIMEOUT_SEC:
                self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (h,))
                self._conn.commit()
                return None
            self._conn.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, h))
            self._conn.commit()
        return {"username": username, "is_admin": bool(is_admin), "created_at": created_at}

    def delete(self, token: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash(token),))
            self._conn.commit()

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM sessions WHERE ? - created_at > ? OR ? - last_seen > ?",
                (now, ABSOLUTE_LIFETIME_SEC, now, IDLE_TIMEOUT_SEC))
            self._conn.commit()
            return cur.rowcount
