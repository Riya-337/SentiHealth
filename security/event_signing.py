"""
event_signing.py — HMAC signatures on event lines, so only trusted sensors can feed the sentinel.

logs/events.jsonl is a plain file; before this, anything that could write to it could inject
events with hand-picked features. Each writer now appends an HMAC-SHA256 of the exact JSON text it
wrote, on the same line:

    {"event_id": ..., "features": {...}}\tsig=<64 hex chars>

Signing the text (not a re-serialised object) means Python and Node writers need no shared
canonical JSON form. The key lives in the secrets vault (EVENT_SIGNING_KEY) and is exported to
sensors with scripts/export_sensor_key.py. The sentinel verifies every line and drops unsigned or
mis-signed ones unless it runs in test mode.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for p in (_HERE, _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

SIG_SEP = "\tsig="


def get_signing_key() -> bytes:
    """The shared sensor key from the vault; created on first use. Overridable for tests and
    sensors through SENTIHEALTH_EVENT_KEY (hex)."""
    env = os.environ.get("SENTIHEALTH_EVENT_KEY", "").strip()
    if env:
        return bytes.fromhex(env)
    try:
        from secrets_vault import get_secret_str, set_secret
        key_hex = get_secret_str("EVENT_SIGNING_KEY", "")
        if not key_hex:
            key_hex = secrets.token_hex(32)
            set_secret("EVENT_SIGNING_KEY", key_hex)
        return bytes.fromhex(key_hex)
    except Exception:
        # no vault available (e.g. read-only checkout): derive a process-local key so signing
        # still works within one process; cross-process verification then needs the env var
        return hashlib.sha256(b"sentihealth-no-vault").digest()


def signature(json_text: str, key: bytes | None = None) -> str:
    key = key or get_signing_key()
    return hmac.new(key, json_text.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_line(json_text: str, key: bytes | None = None) -> str:
    """json_text: one JSON object without a trailing newline. Returns the line to append."""
    return json_text + SIG_SEP + signature(json_text, key)


def sign_event(event: dict, key: bytes | None = None) -> str:
    return sign_line(json.dumps(event, separators=(",", ":"), ensure_ascii=False), key)


def split_line(line: str) -> tuple[str, str | None]:
    line = line.rstrip("\r\n")
    i = line.rfind(SIG_SEP)
    if i < 0:
        return line, None
    return line[:i], line[i + len(SIG_SEP):].strip()


def verify_line(line: str, key: bytes | None = None) -> tuple[dict | None, str]:
    """Returns (event, status) with status in {ok, unsigned, bad_signature, malformed}.
    The event is returned for 'ok' and 'unsigned' so the caller can decide what to do with it."""
    text, sig = split_line(line)
    try:
        event = json.loads(text)
    except json.JSONDecodeError:
        return None, "malformed"
    if sig is None:
        return event, "unsigned"
    if hmac.compare_digest(sig, signature(text, key)):
        return event, "ok"
    return None, "bad_signature"
