"""
SentiHealth Dashboard -- Flask backend.

Changes from original:
  - Telegram poller removed entirely.  OTP is printed to server console
    (the on-prem out-of-band channel) and exposed via the SSHA SSE stream.
  - Auth token is tracked server-side so admin-only endpoints can be protected.
  - /api/status and /api/metrics require a valid session token so that real
    IP addresses and threat data are only visible to authenticated admins.
    (Custodian principle: authenticated disclosure, not pseudonymized obscurity.)
  - /api/alerts   -- list pending SSHA authorization challenges (admin only).
  - /api/alerts/<id>/respond -- admin approve/deny a High-tier threat (admin only).
  - /api/admin/users -- list + approve/reject pending registrations (admin only).
  - /api/stream   -- SSE stream for real-time alert pushes to the dashboard.
  - Mirage deception status exposed at /api/deception/status (admin only).
"""

import hashlib
import hmac as _hmac
import json
import os
import re
import sys
import random
import secrets
import threading
import time
from functools import wraps
from datetime import datetime, timedelta, timezone

# Ensure project root is on sys.path so _paths and sibling modules are importable
# from any working directory the user launches this script from.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # this file lives one level below the root
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Load .env so TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are available for DualNotifier
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv(os.path.join(_PROJECT_ROOT, ".env"))
except ImportError:
    pass

try:
    import pyotp
    _HAS_PYOTP = True
except ImportError:
    _HAS_PYOTP = False


from notifications import get_notifier as _get_notifier

from _paths import (
    LOGS_DIR, DATA_DIR, CONFIG_DIR, USERS_FILE, AUDIT_CHAIN,
    THREAT_LOG, BLOCKED_IPS, EVENTS_LOG, CHALLENGES_FILE,
    ALERT_QUEUE, CANARY_LOG, TAMPER_ALERTS, LOCKED_ACCOUNTS, p as _p,
)



from flask import Flask, Response, jsonify, request, send_file, stream_with_context

try:
    from flask_cors import CORS
    _has_cors = True
except ImportError:
    _has_cors = False


# ---------------------------------------------------------------------------
# Password hashing — PBKDF2-HMAC-SHA256 (OWASP 2023: 260 000 iterations)
#
# Stored format:  pbkdf2:sha256:<iterations>:<salt_hex>:<key_hex>
# Legacy plaintext passwords (no "pbkdf2:" prefix) are accepted on login and
# transparently upgraded to the hashed form so existing users aren't locked out.
# ---------------------------------------------------------------------------

_PBKDF2_ITERS = 260_000
_PBKDF2_ALGO  = 'sha256'


def _hash_password(password: str) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash string for `password`."""
    salt = secrets.token_bytes(16)
    key  = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode('utf-8'), salt, _PBKDF2_ITERS)
    return f"pbkdf2:{_PBKDF2_ALGO}:{_PBKDF2_ITERS}:{salt.hex()}:{key.hex()}"


def _check_password(password: str, stored: str) -> bool:
    """Verify `password` against `stored`.  Handles both hashed and legacy
    plaintext stored values (plaintext support removed after first login upgrade).
    """
    if not stored:
        return False
    if not stored.startswith('pbkdf2:'):
        # Legacy plaintext — constant-time compare to prevent timing attacks
        return _hmac.compare_digest(stored.encode('utf-8'), password.encode('utf-8'))
    try:
        _prefix, algo, iters_str, salt_hex, key_hex = stored.split(':', 4)
        salt        = bytes.fromhex(salt_hex)
        expected    = bytes.fromhex(key_hex)
        iters       = int(iters_str)
        candidate   = hashlib.pbkdf2_hmac(algo, password.encode('utf-8'), salt, iters)
        return _hmac.compare_digest(expected, candidate)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = Flask(__name__)
# Browsers may call the API only from these origins (the dashboard's dev server, a local build, and
# whatever SENTIHEALTH_ALLOWED_ORIGINS adds, e.g. the Vercel site). No wildcard.
_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "SENTIHEALTH_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173",
).split(",") if o.strip()]
if _has_cors:
    CORS(app, resources={r"/api/*": {"origins": _ALLOWED_ORIGINS}}, supports_credentials=False)

# ---------------------------------------------------------------------------
# Session store  (token -> {username, role, is_admin, created_at})
# ---------------------------------------------------------------------------

# Sessions are stored (hashed) in SQLite, so they survive restarts and are shared between worker
# processes. 8 h absolute lifetime, 30 min idle timeout. See security/sessions.py.
from sessions import SessionStore as _SessionStore
_session_store = _SessionStore()


def _create_session(username: str, is_admin: bool) -> str:
    return _session_store.create(username, is_admin)


def _get_session(token: str) -> dict | None:
    return _session_store.get(token)


# ---------------------------------------------------------------------------
# Per-IP rate limiting for API routes and a small JSON body validator
# ---------------------------------------------------------------------------
_rl_buckets: dict[tuple[str, str], list[float]] = {}
_rl_lock = threading.Lock()


def _rate_limit(per_minute: int):
    """Allow at most per_minute calls of the decorated route per client IP."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = (fn.__name__, request.remote_addr or "?")
            now = time.time()
            with _rl_lock:
                hist = [t for t in _rl_buckets.get(key, []) if now - t < 60]
                if len(hist) >= per_minute:
                    _rl_buckets[key] = hist
                    return jsonify({"success": False, "message": "Too many requests; try again in a minute."}), 429
                hist.append(now)
                _rl_buckets[key] = hist
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _json_body(spec: dict) -> tuple[dict | None, tuple | None]:
    """spec: {field: (type, limit, required)}. For str the limit is the max length, for numbers the
    max absolute value. Returns (clean_data, None) or (None, (response, status))."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"success": False, "message": "A JSON object body is required."}), 400)
    out: dict = {}
    for name, (typ, limit, required) in spec.items():
        v = data.get(name)
        if v is None or (isinstance(v, str) and not v.strip() and required):
            if required:
                return None, (jsonify({"success": False, "message": f"'{name}' is required."}), 400)
            continue
        if typ is str:
            if not isinstance(v, str) or len(v) > limit:
                return None, (jsonify({"success": False, "message": f"'{name}' must be a string of at most {limit} characters."}), 400)
            out[name] = v.strip()
        elif typ is bool:
            if not isinstance(v, bool):
                return None, (jsonify({"success": False, "message": f"'{name}' must be true or false."}), 400)
            out[name] = v
        else:
            try:
                num = float(v)
            except (TypeError, ValueError):
                return None, (jsonify({"success": False, "message": f"'{name}' must be a number."}), 400)
            if abs(num) > limit:
                return None, (jsonify({"success": False, "message": f"'{name}' is out of range."}), 400)
            out[name] = num
    return out, None


def _require_auth(admin_only: bool = False):
    """Decorator factory.  Reads Bearer token from Authorization header."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.startswith("Bearer ") else ""
            # EventSource cannot set headers, so the stream route exchanges a one-time ticket
            # (issued to an authenticated session, valid 60 s) instead of putting the token in the URL.
            if not token and request.endpoint == "api_stream":
                token = _redeem_stream_ticket(request.args.get("ticket", "").strip())

            sess = _get_session(token)
            if sess is None:
                return jsonify({"success": False, "message": "Authentication required."}), 401
            if admin_only and not sess["is_admin"]:
                return jsonify({"success": False, "message": "Admin access required."}), 403
            request.session = sess
            return fn(*args, **kwargs)
        return wrapper
    return decorator


_stream_tickets: dict[str, tuple[str, float]] = {}   # ticket -> (session token, issued_at)
_stream_tickets_lock = threading.Lock()
STREAM_TICKET_TTL_SEC = 60


def _issue_stream_ticket(session_token: str) -> str:
    ticket = secrets.token_urlsafe(24)
    now = time.time()
    with _stream_tickets_lock:
        for t, (_tok, issued) in list(_stream_tickets.items()):
            if now - issued > STREAM_TICKET_TTL_SEC:
                _stream_tickets.pop(t, None)
        _stream_tickets[ticket] = (session_token, now)
    return ticket


def _redeem_stream_ticket(ticket: str) -> str:
    if not ticket:
        return ""
    with _stream_tickets_lock:
        entry = _stream_tickets.pop(ticket, None)   # single use
    if entry is None or time.time() - entry[1] > STREAM_TICKET_TTL_SEC:
        return ""
    return entry[0]


# ---------------------------------------------------------------------------
# OTP store  (username -> {otp: str, issued_at: float})
# OTPs expire after OTP_TTL_SECS (default 5 minutes) for replay protection.
# ---------------------------------------------------------------------------

OTP_TTL_SECS = 300   # 5 minutes

_active_otps: dict[str, dict] = {}   # { username: {otp, issued_at} }
_otps_lock = threading.Lock()


def _otp_valid(username: str, code: str) -> bool:
    """Return True iff the stored OTP matches `code` and has not expired."""
    entry = _active_otps.get(username)
    if entry is None:
        return False
    if time.time() - entry["issued_at"] > OTP_TTL_SECS:
        _active_otps.pop(username, None)   # expired -- purge
        return False
    return entry["otp"] == code


# ---------------------------------------------------------------------------
# TOTP & Backup Code MFA Helpers
# ---------------------------------------------------------------------------

def _generate_totp_secret() -> str:
    if _HAS_PYOTP:
        return pyotp.random_base32()
    return secrets.token_hex(16)


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def _generate_backup_codes(count: int = 8) -> tuple[list[str], list[str]]:
    raw_codes = [f"{secrets.randbelow(100000000):08d}" for _ in range(count)]
    hashed_codes = [_hash_backup_code(c) for c in raw_codes]
    return raw_codes, hashed_codes


def _verify_mfa_code(username: str, code: str, user: dict) -> bool:
    """Verify code against TOTP, backup recovery codes, or dynamic OTP."""
    code = code.strip()
    if not code:
        return False

    totp_secret = user.get("totp_secret")
    if totp_secret and _HAS_PYOTP:
        try:
            if pyotp.TOTP(totp_secret).verify(code, valid_window=1):
                return True
        except Exception:
            pass

    # Check emergency backup recovery codes (hashed)
    code_hash = _hash_backup_code(code)
    backup_codes = list(user.get("mfa_backup_codes", []))
    if code_hash in backup_codes:
        backup_codes.remove(code_hash)
        users = load_users()
        if username in users:
            users[username]["mfa_backup_codes"] = backup_codes
            save_users(users)
        print(f"[MFA] Backup recovery code redeemed for user '{username}'. {len(backup_codes)} codes remaining.")
        return True

    # Fall back to dynamic console OTP
    return _otp_valid(username, code)


# ---------------------------------------------------------------------------
# User store helpers
# ---------------------------------------------------------------------------

_users_lock = threading.Lock()
USERS_HMAC_FILE = _p("data", ".users.json.hmac")


def load_users() -> dict:
    with _users_lock:
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, "rb") as f:
                content_bytes = f.read()

            # Verify HMAC signature to detect out-of-band tampering
            if os.path.exists(USERS_HMAC_FILE):
                try:
                    with open(USERS_HMAC_FILE, "r") as hf:
                        stored_hmac = hf.read().strip()
                    from scoring_matrix import SESSION_SECRET
                    computed_hmac = _hmac.new(SESSION_SECRET, content_bytes, hashlib.sha256).hexdigest()
                    if not _hmac.compare_digest(stored_hmac, computed_hmac):
                        msg = f"[USERS.JSON TAMPERING DETECTED] Out-of-band edit to {USERS_FILE} detected!"
                        print(f"\033[91m{msg}\033[0m", flush=True)
                        os.makedirs(LOGS_DIR, exist_ok=True)
                        with open(TAMPER_ALERTS, "a") as af:
                            af.write(f"{datetime.now(timezone.utc).isoformat()} -- {msg}\n")
                except Exception as hexc:
                    print(f"[AUTH WARNING] HMAC verification check error: {hexc}")

            return json.loads(content_bytes.decode('utf-8'))
        except Exception as e:
            print(f"[AUTH] Error loading users: {e}")
            return {}


def save_users(users: dict) -> bool:
    with _users_lock:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            content_str = json.dumps(users, indent=2)
            content_bytes = content_str.encode('utf-8')
            with open(USERS_FILE, "wb") as f:
                f.write(content_bytes)

            from scoring_matrix import SESSION_SECRET
            computed_hmac = _hmac.new(SESSION_SECRET, content_bytes, hashlib.sha256).hexdigest()
            with open(USERS_HMAC_FILE, "w") as hf:
                hf.write(computed_hmac)
            return True
        except Exception as e:
            print(f"[AUTH] Error saving users: {e}")
            return False



def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    users = load_users()
    if not users or "admin" not in users:
        totp_secret = _generate_totp_secret()
        raw_codes, hashed_codes = _generate_backup_codes(8)
        users["admin"] = {
            "password": _hash_password("adminpass123"),

            "role": "admin",
            "status": "approved",
            "access_code": None,
            "totp_secret": totp_secret,
            "mfa_backup_codes": hashed_codes,
        }
        save_users(users)
        print(
            f"\n[AUTH] Default admin created (username: admin  password: adminpass123 -- change it)\n"
            f"  TOTP Secret Key       : {totp_secret}\n"
            f"  Backup Recovery Codes : {', '.join(raw_codes)}\n",
            flush=True,
        )
    else:
        admin_user = users.get("admin")
        if admin_user and not admin_user.get("totp_secret"):
            totp_secret = _generate_totp_secret()
            raw_codes, hashed_codes = _generate_backup_codes(8)
            admin_user["totp_secret"] = totp_secret
            admin_user["mfa_backup_codes"] = hashed_codes
            users["admin"] = admin_user
            save_users(users)
            print(
                f"\n[AUTH] Initialized TOTP MFA for admin:\n"
                f"  TOTP Secret Key       : {totp_secret}\n"
                f"  Backup Recovery Codes : {', '.join(raw_codes)}\n",
                flush=True,
            )


# ---------------------------------------------------------------------------
# SSE -- push real-time alerts to connected admin browsers
# ---------------------------------------------------------------------------

_sse_clients: list[object] = []
_sse_lock = threading.Lock()


def _push_sse(event_type: str, data: dict):
    """Append an event to all active SSE client queues."""
    import queue
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        for q in list(_sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
@_rate_limit(5)
def api_register():
    data, err = _json_body({"username": (str, 64, True), "password": (str, 256, True)})
    if err:
        return err
    username = data["username"]
    password = data["password"]
    if not re.fullmatch(r"[A-Za-z0-9._@-]{3,64}", username):
        return jsonify({"success": False, "message": "Username: 3-64 letters, digits, . _ @ -"}), 400
    if len(password) < 10:
        return jsonify({"success": False, "message": "Password must be at least 10 characters."}), 400

    users = load_users()
    if username in users:
        return jsonify({"success": False, "message": "Username already exists."}), 400

    # Custodian: pseudonymize the requester IP before writing to the pending log
    try:
        from privacy.pseudonymize import tokenize as _tok
        logged_ip = _tok(request.remote_addr or "unknown")
    except Exception:
        logged_ip = "unknown"

    users[username] = {
        "password": _hash_password(password),   # PBKDF2-HMAC-SHA256; never store plaintext
        "role": "user",
        "status": "pending",
        "access_code": None,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "request_ip_token": logged_ip,   # pseudonymized -- real IP not stored
    }
    save_users(users)

    # Notify all active admin dashboard sessions via SSE
    _push_sse("registration_request", {
        "username": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    try:
        _get_notifier().send_alert(
            f"📋 NEW ACCOUNT REQUEST\n"
            f"Username: {username}\n"
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"→ Open the admin dashboard to approve or reject."
        )
    except Exception:
        pass

    print(
        f"\n[SENTINEL REGISTRATION] New request from '{username}' "

        f"(IP token: {logged_ip[:8]}...)\n"
        f"  -> Approve via dashboard /api/admin/users/{username}/approve\n"
    )
    return jsonify({
        "success": True,
        "message": "Registration submitted. Awaiting administrator approval via the dashboard.",
    })


# ---------------------------------------------------------------------------
# Rate Limiting & Account Lockout Tracker (5 failed attempts in 15 mins)
# ---------------------------------------------------------------------------
_failed_login_attempts: dict[str, list[float]] = {}
_failed_attempts_lock = threading.Lock()
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_WINDOW_SEC = 900  # 15 minutes
# Automatic lockouts lift on their own. A permanent one would let anyone lock the admin out by
# typing 5 wrong passwords (denial of service). Locks from the tiered responder have no expiry.
_LOCKOUT_DURATION_SEC = _LOCKOUT_WINDOW_SEC
_AUTO_LOCK_REASON = "Excessive failed authentication attempts"


def _read_lock_entries() -> list:
    """locked_accounts.json is a JSON array (written here) or JSON lines (self_healing_responder)."""
    if not os.path.exists(LOCKED_ACCOUNTS):
        return []
    with open(LOCKED_ACCOUNTS, "r", encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            return [e for e in json.loads(text) if isinstance(e, dict)]
        except json.JSONDecodeError:
            pass
    entries = []
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(e, dict):
            entries.append(e)
    return entries


def _lock_expiry(entry: dict) -> datetime | None:
    """When an automatic lockout lifts; None for locks that stay until an admin removes them.
    An unreadable timestamp also gives None, so a damaged entry stays locked (fail closed)."""
    def parse(s: str) -> datetime:
        d = datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    try:
        if entry.get("expires_at"):
            return parse(entry["expires_at"])
        # automatic lockouts written before expiry existed
        if str(entry.get("reason", "")).startswith(_AUTO_LOCK_REASON) and entry.get("locked_at"):
            return parse(entry["locked_at"]) + timedelta(seconds=_LOCKOUT_DURATION_SEC)
    except (TypeError, ValueError):
        return None
    return None


def _lock_active(entry: dict, now: datetime) -> bool:
    if entry.get("status") != "locked":
        return False
    expiry = _lock_expiry(entry)
    return expiry is None or now < expiry


def _is_rate_limited_or_locked(username: str, ip: str) -> tuple[bool, str]:
    """Check if username or IP is rate-limited / locked out."""
    now = time.time()

    # 1. Check locked_accounts.json file
    try:
        now_dt = datetime.now(timezone.utc)
        for entry in _read_lock_entries():
            if (entry.get("username") == username or entry.get("ip") == ip) and _lock_active(entry, now_dt):
                expiry = _lock_expiry(entry)
                if expiry is None:
                    return True, f"Account or IP '{username}' is locked. Contact administrator or use recovery."
                minutes = max(1, int((expiry - now_dt).total_seconds() // 60) + 1)
                return True, f"Account locked after 5 failed login attempts. Try again in {minutes} minute(s) or use recovery."
    except Exception:
        pass

    # 2. Check in-memory rolling window (5 failures in 15 mins)
    with _failed_attempts_lock:
        for key in (username, ip):
            if key and key in _failed_login_attempts:
                recent = [t for t in _failed_login_attempts[key] if now - t < _LOCKOUT_WINDOW_SEC]
                _failed_login_attempts[key] = recent
                if len(recent) >= _MAX_FAILED_ATTEMPTS:
                    _lock_account_persistent(username, ip, f"Excessive failed authentication attempts ({len(recent)} in 15m)")
                    return True, "Account locked due to 5 consecutive failed login attempts. Try again in 15 minutes or use recovery."
                    
    return False, ""


def _record_failed_attempt(username: str, ip: str):
    """Record a failed login/OTP attempt."""
    now = time.time()
    with _failed_attempts_lock:
        for key in (username, ip):
            if key:
                if key not in _failed_login_attempts:
                    _failed_login_attempts[key] = []
                _failed_login_attempts[key].append(now)


def _record_success_attempt(username: str, ip: str):
    """Clear failed attempts on successful login."""
    with _failed_attempts_lock:
        _failed_login_attempts.pop(username, None)
        _failed_login_attempts.pop(ip, None)


def _lock_account_persistent(username: str, ip: str, reason: str):
    """Write lockout entry to locked_accounts.json and tamper_alerts.log."""
    try:
        now = datetime.now(timezone.utc)
        # expired automatic lockouts are dropped; every other entry is kept
        locked_list = [e for e in _read_lock_entries() if e.get("status") != "locked" or _lock_active(e, now)]

        existing = next((e for e in locked_list if e.get("username") == username and _lock_active(e, now)), None)
        if not existing:
            entry = {
                "username": username,
                "ip": ip,
                "status": "locked",
                "reason": reason,
                "locked_at": now.isoformat(),
                "expires_at": (now + timedelta(seconds=_LOCKOUT_DURATION_SEC)).isoformat(),
            }
            locked_list.append(entry)
            with open(LOCKED_ACCOUNTS, "w", encoding="utf-8") as f:
                json.dump(locked_list, f, indent=2)
                
            if os.path.exists(TAMPER_ALERTS):
                with open(TAMPER_ALERTS, "a", encoding="utf-8") as tf:
                    tf.write(f"[{datetime.now(timezone.utc).isoformat()}] ACCOUNT_LOCKOUT: {reason} for user '{username}' (IP: {ip})\n")
    except Exception as e:
        print(f"[ERROR] Failed to persist lockout: {e}")


@app.after_request
def apply_security_headers(response):
    """Apply strict security headers to all Flask responses."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' ws: wss:; "
        "font-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/api/auth/login", methods=["POST"])
@_rate_limit(20)
def api_login():
    data, err = _json_body({"username": (str, 64, True), "password": (str, 256, True)})
    if err:
        return err
    username = data["username"]
    password = data["password"]
    client_ip = request.remote_addr or "127.0.0.1"

    # ── Check Rate Limiting & Account Lockout ─────────────────────────────
    is_locked, lock_msg = _is_rate_limited_or_locked(username, client_ip)
    if is_locked:
        return jsonify({"success": False, "message": lock_msg}), 429

    users = load_users()
    if username not in users:
        _record_failed_attempt(username, client_ip)
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    user = users[username]
    if not _check_password(password, user["password"]):
        _record_failed_attempt(username, client_ip)
        return jsonify({"success": False, "message": "Invalid username or password."}), 401


    # Transparently upgrade plaintext passwords to PBKDF2 on first successful login
    if not user["password"].startswith("pbkdf2:"):
        user["password"] = _hash_password(password)
        users[username]  = user
        save_users(users)

    if user["status"] == "pending":
        return jsonify({
            "success": False,
            "message": "Your registration is pending administrator approval.",
        }), 403
    if user["status"] == "rejected":
        return jsonify({
            "success": False,
            "message": "Your registration request was rejected by the administrator.",
        }), 403

    is_admin = (user.get("role") == "admin")

    if is_admin:
        # Generate dynamic OTP and deliver to server console + SSE stream
        otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
        with _otps_lock:
            _active_otps[username] = {"otp": otp, "issued_at": time.time()}

        # Primary delivery: server console (on-prem, no cloud dependency)
        # flush=True ensures this reaches the log file even when stdout is file-buffered
        print(
            f"\n[SSHA MFA] Admin OTP for '{username}': {otp}\n"
            f"  (displayed on server console -- no external channel needed)\n",
            flush=True,
        )

        # Always write OTP directly to logs_dashboard.txt so it's visible
        # regardless of how the process was launched (with or without stdout redirect).
        _dashboard_log = os.path.join(LOGS_DIR, "logs_dashboard.txt")
        try:
            with open(_dashboard_log, "a", encoding="utf-8") as _lf:
                _lf.write(
                    f"\n[SENTINEL MFA] Admin OTP for '{username}': {otp}\n"

                    f"  (displayed on server console -- no external channel needed)\n\n"
                )
        except Exception:
            pass
            
        # Telegram: Send OTP to phone
        try:
            _get_notifier().send_alert(f"🔐 ADMIN MFA LOGIN\nUser: {username}\nOTP Code: {otp}")
        except Exception:
            pass

        # Secondary: push to any already-open admin SSE streams (e.g. second screen)
        _push_sse("admin_otp", {
            "username": username,
            "otp": otp,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return jsonify({
            "success": True,
            "stage": "otp",
            "username": username,
            "is_admin": True,
            "otp_channel": "server_console",
        })

    # Regular approved user: authenticator app if enrolled, otherwise the legacy static access code
    return jsonify({
        "success": True,
        "stage": "otp",
        "username": username,
        "is_admin": False,
        "otp_channel": "authenticator" if user.get("totp_secret") else "static_code",
    })


@app.route("/api/auth/verify-otp", methods=["POST"])
@_rate_limit(20)
def api_verify_otp():
    data, err = _json_body({"username": (str, 64, True), "code": (str, 16, True)})
    if err:
        return err
    username = data["username"]
    code = data["code"]
    client_ip = request.remote_addr or "127.0.0.1"

    # ── Check Rate Limiting & Account Lockout ─────────────────────────────
    is_locked, lock_msg = _is_rate_limited_or_locked(username, client_ip)
    if is_locked:
        return jsonify({"success": False, "message": lock_msg}), 429

    users = load_users()
    if username not in users:
        _record_failed_attempt(username, client_ip)
        return jsonify({"success": False, "message": "User not found."}), 404

    user = users[username]
    is_admin = (user.get("role") == "admin")

    if is_admin:
        with _otps_lock:
            valid = _verify_mfa_code(username, code, user)
            if not valid:
                _record_failed_attempt(username, client_ip)
                return jsonify({"success": False, "message": "Invalid MFA TOTP or backup recovery code."}), 401
            _active_otps.pop(username, None)

    elif user.get("totp_secret"):
        with _otps_lock:
            if not _verify_mfa_code(username, code, user):
                _record_failed_attempt(username, client_ip)
                return jsonify({"success": False, "message": "Invalid authenticator or backup code."}), 401
    else:
        expected = user.get("access_code")
        if not expected or not _hmac.compare_digest(str(expected), code):
            _record_failed_attempt(username, client_ip)
            return jsonify({"success": False, "message": "Incorrect access code."}), 401

    _record_success_attempt(username, client_ip)
    token = _create_session(username, is_admin)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "is_admin": is_admin,
        "client_ip": client_ip,  # the address the server saw; the browser cannot know its own IP
    })



# ---------------------------------------------------------------------------
# Core sentinel data routes (auth required -- custodian gate)
# ---------------------------------------------------------------------------

@app.route("/api/status")
@_require_auth()
def api_status():
    """
    Real IP addresses and threat data -- authenticated admins only.
    This is the custodian gate: unauthenticated callers receive 401.
    """
    state = get_system_state()

    # Ensure these keys are always present even if an older cached module
    # omitted them — compute directly here as a safety net.
    if "total_threat_count" not in state or "all_tier_counts" not in state:
        _all_tiers = {"High": 0, "Medium": 0, "Low": 0}
        _total = 0
        if os.path.exists(THREAT_LOG):
            with open(THREAT_LOG, "r") as _f:
                _lines = [json.loads(_l) for _l in _f if _l.strip()]
            _total = len(_lines)
            for _e in _lines:
                _t = _e.get("tier", "")
                if _t in _all_tiers:
                    _all_tiers[_t] += 1
        state["total_threat_count"] = _total
        state["all_tier_counts"] = _all_tiers

    return jsonify(state)


@app.route("/api/metrics")
@_require_auth()
def api_metrics():
    metrics_file = _p("evaluation", "evaluation_metrics.json")
    if not os.path.exists(metrics_file):
        return jsonify([])
    with open(metrics_file, "r") as f:
        return jsonify(json.load(f))


# ---------------------------------------------------------------------------
# MFA enrolment (QR code), first-run setup wizard, logout, stream tickets
# ---------------------------------------------------------------------------
DEFAULT_ADMIN_PASSWORD = "adminpass123"


def _qr_svg(text: str) -> str:
    try:
        import segno
        return segno.make(text, error="m").svg_inline(scale=5, dark="#111827", light=None)
    except Exception:
        return ""


def _enrol_mfa(username: str, user: dict) -> dict:
    """Generate a fresh TOTP secret and backup codes for the user record (caller saves)."""
    secret = _generate_totp_secret()
    raw_codes, hashed = _generate_backup_codes(8)
    user["totp_secret"] = secret
    user["mfa_backup_codes"] = hashed
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SentiHealth") if _HAS_PYOTP else ""
    return {"otpauth_uri": uri, "qr_svg": _qr_svg(uri) if uri else "", "backup_codes": raw_codes, "totp_secret": secret}


def _needs_setup(users: dict) -> bool:
    admin = users.get("admin")
    if not admin:
        return True
    if admin.get("setup_complete"):
        return False
    return _check_password(DEFAULT_ADMIN_PASSWORD, admin.get("password", ""))


@app.route("/api/setup/status")
@_rate_limit(60)
def api_setup_status():
    return jsonify({"needs_setup": _needs_setup(load_users())})


@app.route("/api/setup/complete", methods=["POST"])
@_rate_limit(5)
def api_setup_complete():
    """First run only: set the admin password and show the authenticator QR + backup codes once.
    Refused as soon as the default password has been changed."""
    users = load_users()
    if not _needs_setup(users):
        return jsonify({"success": False, "message": "Setup is already complete."}), 403
    data, err = _json_body({"password": (str, 256, True)})
    if err:
        return err
    if len(data["password"]) < 12 or data["password"] == DEFAULT_ADMIN_PASSWORD:
        return jsonify({"success": False, "message": "Choose a new password of at least 12 characters."}), 400
    admin = users.setdefault("admin", {"role": "admin", "status": "approved", "access_code": None})
    admin["password"] = _hash_password(data["password"])
    enrol = _enrol_mfa("admin", admin)
    admin["setup_complete"] = True
    admin["setup_at"] = datetime.now(timezone.utc).isoformat()
    save_users(users)
    _log_to_file("[SETUP] Admin password set and TOTP enrolled through the setup wizard.")
    return jsonify({"success": True, **enrol})


@app.route("/api/admin/users/<username>/mfa/reset", methods=["POST"])
@_rate_limit(10)
@_require_auth(admin_only=True)
def api_admin_reset_mfa(username: str):
    """Re-enrol a user (lost phone). Shows a new QR once; old codes stop working."""
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404
    enrol = _enrol_mfa(username, users[username])
    save_users(users)
    _log_to_file(f"[MFA] '{request.session.get('username')}' reset MFA for '{username}'.")
    return jsonify({"success": True, "username": username, **enrol})


@app.route("/api/auth/logout", methods=["POST"])
@_require_auth()
def api_logout():
    auth = request.headers.get("Authorization", "")
    _session_store.delete(auth[7:].strip() if auth.startswith("Bearer ") else "")
    return jsonify({"success": True})


@app.route("/api/stream/ticket", methods=["POST"])
@_rate_limit(30)
@_require_auth()
def api_stream_ticket():
    auth = request.headers.get("Authorization", "")
    return jsonify({"ticket": _issue_stream_ticket(auth[7:].strip()), "ttl_sec": STREAM_TICKET_TTL_SEC})


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "service": "dashboard", "time": datetime.now(timezone.utc).isoformat(timespec="seconds")})


# ---------------------------------------------------------------------------
# SSHA Alert Authorization routes (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/alerts", methods=["GET"])
@_require_auth(admin_only=True)
def api_list_alerts():
    """Return pending SSHA authorization challenges + recent alert queue."""
    from notifications.sentinel_notifier import list_pending

    pending = list_pending()

    recent_alerts = []
    if os.path.exists(ALERT_QUEUE):
        with open(ALERT_QUEUE, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        for line in reversed(lines[-50:]):
            try:
                recent_alerts.append(json.loads(line))
            except Exception:
                pass

    return jsonify({
        "pending_challenges": pending,
        "recent_alerts": recent_alerts[:20],
    })


@app.route("/api/alerts/<incident_id>/respond", methods=["POST"])
@_rate_limit(30)
@_require_auth(admin_only=True)
def api_respond_alert(incident_id: str):
    """Admin approves or denies a High-tier threat authorization challenge.
    Enforces step-up MFA confirmation: totp_code or code is required in body.
    """
    from notifications.sentinel_notifier import resolve_challenge

    data, err = _json_body({"decision": (str, 8, True), "totp_code": (str, 16, False), "code": (str, 16, False)})
    if err:
        return err
    decision = data["decision"].upper()
    if decision not in ("YES", "IGNORE", "DENY"):
        return jsonify({"success": False, "message": "decision must be YES, IGNORE, or DENY"}), 400

    totp_code = (data.get("totp_code") or data.get("code") or "").strip()
    admin_user = request.session.get("username", "admin")
    users = load_users()
    admin_data = users.get(admin_user, {})

    if not totp_code or not _verify_mfa_code(admin_user, totp_code, admin_data):
        return jsonify({
            "success": False,
            "message": "Step-up MFA authorization failed. Valid TOTP or backup recovery code is required.",
        }), 401

    resolved = resolve_challenge(incident_id, decision)
    if not resolved:
        return jsonify({
            "success": False,
            "message": "Challenge not found or already resolved.",
        }), 404

    print(
        f"\n[SENTINEL AUTH] Admin '{admin_user}' resolved challenge {incident_id[:8]} -> {decision} (MFA Verified)\n"

    )
    return jsonify({"success": True, "decision": decision, "incident_id": incident_id})



# ---------------------------------------------------------------------------
# Stasis queue — expired/auto-locked challenges the admin can still review
# ---------------------------------------------------------------------------

@app.route("/api/alerts/stasis", methods=["GET"])
@_require_auth(admin_only=True)
def api_stasis_list():
    """
    Return all challenges that expired (90s window elapsed) and were auto-locked.
    The admin can retroactively request forensics generation or dismiss them.
    """
    from notifications.sentinel_notifier import list_stasis
    items = list_stasis()
    return jsonify({"stasis": items})


@app.route("/api/alerts/<incident_id>/retroactive", methods=["POST"])
@_rate_limit(30)
@_require_auth(admin_only=True)
def api_retroactive_action(incident_id: str):
    """
    Admin retroactively acts on an auto-locked (stasis) threat.

    Body: {"action": "release" | "confirm"}

    release — Admin decides to restore access for this IP.
              Removes the IP from blocked_ips.json, updates threat_log to
              "admin_released", generates a forensic report, and pushes SSE.

    confirm — Admin confirms the auto-lock was correct; IP stays blocked.
              Marks the challenge as reviewed and pushes SSE.
    """
    from notifications.sentinel_notifier import resolve_challenge, list_stasis

    body   = request.json or {}
    action = body.get("action", "").lower().strip()
    if action not in ("release", "confirm"):
        return jsonify({"success": False, "message": "action must be 'release' or 'confirm'"}), 400

    # Resolve the challenge first (marks it retroactive so it disappears from queue)
    decision = "RELEASE" if action == "release" else "CONFIRM_BLOCK"
    resolved = resolve_challenge(incident_id, decision, allow_expired=True)
    if not resolved:
        return jsonify({
            "success": False,
            "message": "Stasis challenge not found or already reviewed.",
        }), 404

    admin = request.session.get("username", "unknown")

    # Get enriched item (includes IP resolved from metadata or threat_log fallback)
    stasis_items = list_stasis()
    # list_stasis now excludes just-resolved challenge (status changed to "retroactive")
    # so we re-fetch the raw challenge to get the IP
    from notifications.sentinel_notifier import _read_challenges
    ch    = _read_challenges().get(incident_id, {})
    meta  = ch.get("metadata") or {}
    ip    = meta.get("ip", "")

    # If metadata didn't have IP, search threat_log by timestamp proximity
    if not ip:
        ch_ts = ch.get("timestamp", "")[:16]
        try:
            if os.path.exists(THREAT_LOG):
                with open(THREAT_LOG, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        if entry.get("action") == "auto-locked" and entry.get("timestamp", "")[:16] == ch_ts:
                            ip = entry.get("ip", "")
                            break
        except Exception:
            pass

    if action == "release":
        # ── 1. Remove IP from blocked_ips.json ───────────────────────────
        if ip and os.path.exists(BLOCKED_IPS):
            try:
                with open(BLOCKED_IPS, "r", encoding="utf-8") as f:
                    lines = [l for l in f if l.strip() and json.loads(l).get("ip") != ip]
                with open(BLOCKED_IPS, "w", encoding="utf-8") as f:
                    f.writelines(lines)
            except Exception as exc:
                pass  # non-fatal — log but don't crash

        # ── 2. Update threat_log: mark matching auto-locked entry as admin_released ──
        if ip and os.path.exists(THREAT_LOG):
            try:
                with open(THREAT_LOG, "r", encoding="utf-8") as f:
                    all_lines = f.readlines()
                for i in range(len(all_lines) - 1, -1, -1):
                    if not all_lines[i].strip():
                        continue
                    entry = json.loads(all_lines[i])
                    if entry.get("ip") == ip and entry.get("action") == "auto-locked":
                        entry["action"]      = "admin_released"
                        entry["reviewed_by"] = admin
                        entry["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                        all_lines[i] = json.dumps(entry) + "\n"
                        break
                with open(THREAT_LOG, "w", encoding="utf-8") as f:
                    f.writelines(all_lines)
            except Exception:
                pass

        # ── 3. Generate forensic report ───────────────────────────────────
        try:
            report_path = _p("logs", f"forensic_report_{incident_id}_{(ip or 'unknown').replace('.', '_')}.json")
            forensic = {
                "incident_id":   incident_id,
                "ip":            ip or "unknown",
                "tier":          meta.get("tier", "High"),
                "score":         meta.get("score"),
                "reason":        meta.get("reason", ""),
                "auto_locked_at": ch.get("resolved_at", ""),
                "released_by":   admin,
                "released_at":   datetime.now(timezone.utc).isoformat(),
                "action":        "admin_released",
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(forensic, f, indent=2)
        except Exception:
            pass

        _push_sse("stasis_resolved", {
            "incident_id": incident_id,
            "action":      "released",
            "ip":          ip,
            "reviewed_by": admin,
        })
        _log_to_file(f"[SENTINEL RETROACTIVE] Admin '{admin}' released block on IP {ip} (incident {incident_id[:8]})")
        return jsonify({"success": True, "action": "released", "ip": ip, "incident_id": incident_id})

    else:  # confirm — keep blocked, just mark reviewed
        _push_sse("stasis_resolved", {
            "incident_id": incident_id,
            "action":      "confirmed_block",
            "ip":          ip,
            "reviewed_by": admin,
        })
        _log_to_file(f"[SENTINEL RETROACTIVE] Admin '{admin}' confirmed block on IP {ip} (incident {incident_id[:8]})")

        return jsonify({"success": True, "action": "confirmed_block", "ip": ip, "incident_id": incident_id})


# ---------------------------------------------------------------------------
# Admin user management (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
@_require_auth(admin_only=True)
def api_admin_list_users():
    users = load_users()
    result = []
    for uname, udata in users.items():
        result.append({
            "username": uname,
            "role": udata.get("role", "user"),
            "status": udata.get("status", "unknown"),
            "requested_at": udata.get("requested_at", ""),
        })
    return jsonify(result)


@app.route("/api/admin/users/<username>/approve", methods=["POST"])
@_require_auth(admin_only=True)
def api_admin_approve_user(username: str):
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404
    if users[username]["status"] != "pending":
        return jsonify({"success": False, "message": f"User is already {users[username]['status']}."}), 400

    enrol = _enrol_mfa(username, users[username])
    users[username]["status"] = "approved"
    users[username]["access_code"] = None
    save_users(users)

    admin = request.session.get("username", "unknown")
    print(f"\n[AUTH] Admin '{admin}' approved user '{username}'; TOTP enrolment generated (show the QR to the user in person).\n")
    _push_sse("user_approved", {"username": username})

    try:
        _get_notifier().send_alert(f"✅ ACCOUNT APPROVED\nUsername: {username}\nApproved by: {admin}\n→ The user must scan the enrolment QR shown on the admin dashboard.")
    except Exception:
        pass

    return jsonify({"success": True, "username": username, **enrol})


@app.route("/api/admin/users/<username>/reject", methods=["POST"])
@_require_auth(admin_only=True)
def api_admin_reject_user(username: str):
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404

    users[username]["status"] = "rejected"
    save_users(users)
    admin = request.session.get("username", "unknown")
    print(f"\n[AUTH] Admin '{admin}' rejected user '{username}'.\n")

    try:
        _get_notifier().send_alert(
            f"❌ ACCOUNT REJECTED\n"
            f"Username: {username}\n"
            f"Rejected by: {admin}"
        )
    except Exception:
        pass

    return jsonify({"success": True, "username": username})


# ---------------------------------------------------------------------------
# SHAP chart serving (admin only -- behind the custodian gate)
# ---------------------------------------------------------------------------

@app.route("/api/shap/<filename>")
@_require_auth(admin_only=True)
def api_shap_image(filename: str):
    """Serve a SHAP PNG chart to authenticated admins only."""
    # Sanitize: only allow simple filenames, no path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400
    path = _p("logs", filename)
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path, mimetype="image/png")


# ---------------------------------------------------------------------------
# Mirage deception status (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/deception/status", methods=["GET"])
@_require_auth(admin_only=True)
def api_deception_status():
    """Return active Mirage deception sessions and canary registry summary."""
    canary_count = 0
    if os.path.exists(CANARY_LOG):
        with open(CANARY_LOG, "r") as f:
            canary_count = sum(1 for l in f if l.strip())

    return jsonify({
        "deception_enabled": _get_deception_policy().get("deception_enabled", True),
        "activation_threshold": _get_deception_policy().get("activation_threshold", 0.55),
        "full_decoy_threshold": _get_deception_policy().get("full_decoy_threshold", 0.75),
        "canaries_minted": canary_count,
        "description": (
            "Mirage serves synthetic decoy patient records to confirmed attackers. "
            "Each record carries a canary token. If a token surfaces in a data breach "
            "disclosure, the breach is traced back to this deployment."
        ),
    })


def _get_deception_policy() -> dict:
    path = _p("config", "deception_policy.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# SSE stream (auth required)
# ---------------------------------------------------------------------------

@app.route("/api/stream")
@_require_auth()
def api_stream():
    """Server-Sent Events stream for real-time alerts pushed to the dashboard."""
    import queue

    q: queue.Queue = queue.Queue()
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except Exception:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Legacy threat-coordination routes (used by self_healing_responder via HTTP)
# Kept for backward compatibility; internally bridged to SSHA.
# ---------------------------------------------------------------------------

_threat_await_active = False
_threat_approval_status = "PENDING"
_threat_await_start = 0.0
_threat_await_timeout = 90.0
_threat_coord_lock = threading.Lock()


@app.route("/api/telegram/start-threat-await", methods=["POST"])
def api_start_threat_await():
    global _threat_await_active, _threat_approval_status, _threat_await_start, _threat_await_timeout
    data = request.json or {}
    with _threat_coord_lock:
        _threat_await_timeout = data.get("timeout", 90.0)
        _threat_await_start = time.time()
        _threat_await_active = True
        _threat_approval_status = "PENDING"
    return jsonify({"success": True})


@app.route("/api/telegram/threat-status", methods=["GET"])
def api_threat_status():
    global _threat_await_active, _threat_approval_status
    with _threat_coord_lock:
        if _threat_await_active and (time.time() - _threat_await_start > _threat_await_timeout):
            _threat_await_active = False
            _threat_approval_status = "TIMEOUT"
        status = _threat_approval_status
    return jsonify({"status": status})


@app.route("/api/telegram/resolve", methods=["POST"])
@_require_auth(admin_only=True)
def api_resolve_threat():
    """Admin resolves the legacy threat-await via dashboard (replaces Telegram YES/IGNORE)."""
    global _threat_await_active, _threat_approval_status
    data = request.json or {}
    decision = data.get("decision", "IGNORE").upper()
    with _threat_coord_lock:
        _threat_approval_status = decision
        _threat_await_active = False
    return jsonify({"success": True, "decision": decision})


# ---------------------------------------------------------------------------
# System state (reads threat_log, blocked_ips, audit chain)
# ---------------------------------------------------------------------------

def get_system_state() -> dict:
    status = "NORMAL"
    threats = []
    blocked_count = 0
    blockchain_status = "INTACT"

    all_tier_counts = {"High": 0, "Medium": 0, "Low": 0}
    total_threat_count = 0

    if os.path.exists(THREAT_LOG):
        with open(THREAT_LOG, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        # Count ALL entries for the real totals shown in the donut chart
        total_threat_count = len(lines)
        for entry in lines:
            t = entry.get("tier", "")
            if t in all_tier_counts:
                all_tier_counts[t] += 1

        # Only send the 50 most-recent entries to the table
        threats = list(reversed(lines))[:50]
        if threats and threats[0]["action"] == "pending":
            status = "LOCKDOWN"
        elif threats:
            status = "THREAT"

        # Badge pending-count per IP for the table
        pending_counts: dict[str, int] = {}
        for t in threats:
            if t["action"] == "pending":
                pending_counts[t["ip"]] = pending_counts.get(t["ip"], 0) + 1
        for t in threats:
            if t["action"] == "pending" and pending_counts.get(t["ip"], 0) > 1:
                t["display_action"] = f"pending x{pending_counts[t['ip']]}"
            else:
                t["display_action"] = t["action"]
            # Expose SHAP chart as a URL the frontend can fetch (auth-gated)
            shap_file = t.get("shap_file", "")
            t["shap_url"] = f"/api/shap/{shap_file}" if shap_file else ""

    if os.path.exists(BLOCKED_IPS):
        with open(BLOCKED_IPS, "r") as f:
            blocked_count = sum(1 for line in f if line.strip())

    # Three-layer chain verification
    blockchain_status = "INTACT"
    if os.path.exists(AUDIT_CHAIN):
        try:
            import hmac as _hmac
            import hashlib as _hl
            from scoring_matrix import SESSION_SECRET as _secret

            with open(AUDIT_CHAIN, "r") as f:
                chain = json.load(f)
            for i, entry in enumerate(chain[1:], 1):
                if entry.get("block_index") is not None and entry["block_index"] != i:
                    blockchain_status = "COMPROMISED"
                    break
                prev_hash = chain[i - 1]["entry_hash"]
                e_clean = {k: v for k, v in entry.items() if k not in ("entry_hash", "block_hmac")}
                expected = _hl.sha256(
                    (prev_hash + json.dumps(e_clean, sort_keys=True)).encode()
                ).hexdigest()
                if entry["entry_hash"] != expected:
                    blockchain_status = "COMPROMISED"
                    break
                if "block_hmac" in entry:
                    payload = {k: v for k, v in entry.items() if k not in ("entry_hash", "block_hmac")}
                    exp_hmac = _hmac.new(
                        _secret, json.dumps(payload, sort_keys=True).encode(), _hl.sha256
                    ).hexdigest()
                    if not _hmac.compare_digest(entry["block_hmac"], exp_hmac):
                        blockchain_status = "COMPROMISED"
                        break
        except Exception:
            blockchain_status = "UNKNOWN"

    return {
        "status": status,
        "threats": threats,
        "blocked_count": blocked_count,
        "blockchain_status": blockchain_status,
        "total_threat_count": total_threat_count,
        "all_tier_counts": all_tier_counts,
    }



# ---------------------------------------------------------------------------
# Incidents, snoozes, block release, identifier reveals, analyst labels, model health, tabletop
# ---------------------------------------------------------------------------
from incidents import (build_incidents, load_threats, incident_by_id, entity_timeline,
                       set_snooze, clear_snooze, load_snoozes)
from response_adapters import FirewallAdapter as _Firewall, status as _response_status
from anchoring import verify_anchors as _verify_anchors
from drift import drift_report as _drift_report
from _paths import RETRAINING_QUEUE as _RETRAINING_QUEUE, RETRAINING_DIR as _RETRAINING_DIR


def _audit_admin(action: str, payload: dict) -> None:
    """Append an HMAC-signed block for an administrative action to the audit chain."""
    try:
        from self_healing_responder import append_admin_block
        append_admin_block(action, payload, request.session.get("username", "unknown"))
    except Exception as exc:
        _log_to_file(f"[AUDIT] could not append admin block for {action}: {exc}")


@app.route("/api/incidents")
@_require_auth()
def api_incidents():
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    return jsonify({"incidents": build_incidents(load_threats())[:limit], "snoozes": load_snoozes()})


@app.route("/api/incidents/<iid>")
@_require_auth()
def api_incident(iid: str):
    inc = incident_by_id(iid)
    if not inc:
        return jsonify({"success": False, "message": "Incident not found."}), 404
    inc["timeline"] = entity_timeline(inc["ip"])
    return jsonify(inc)


@app.route("/api/incidents/<iid>/report")
@_require_auth(admin_only=True)
def api_incident_report(iid: str):
    """Self-contained HTML incident report (no external scripts), downloadable."""
    import html as _html
    inc = incident_by_id(iid)
    if not inc:
        return jsonify({"success": False, "message": "Incident not found."}), 404
    tl = entity_timeline(inc["ip"])
    rows = "".join(f"<tr><td>{_html.escape(t['t'][:19])}</td><td>{_html.escape(t['tier'])}</td><td>{t['score']:.3f}</td><td>{_html.escape(t['action'])}</td></tr>" for t in tl)
    feats = "".join(f"<li>{_html.escape(f['label'])}: {f['value']} (normal {f['normal_range'][0]}-{f['normal_range'][1]}), share {round(f['share'] * 100)} %</li>" for f in inc.get("top_features") or [])
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>SentiHealth incident {iid}</title>
<style>body{{font-family:-apple-system,Segoe UI,sans-serif;margin:32px;color:#111}}table{{border-collapse:collapse}}td,th{{border:1px solid #ccc;padding:4px 8px;font-size:13px}}h1{{font-size:20px}}</style></head><body>
<h1>SentiHealth incident report</h1>
<p><b>Incident</b> {iid} &nbsp; <b>Source IP</b> {_html.escape(inc['ip'])} &nbsp; <b>Users</b> {_html.escape(', '.join(inc['users']) or '-')}</p>
<p><b>Window</b> {_html.escape(inc['start'])} to {_html.escape(inc['end'])} ({inc['n_events']} events) &nbsp; <b>Peak</b> {_html.escape(inc['peak_tier'])} {inc['peak_score']:.3f} &nbsp; <b>Status</b> {_html.escape(inc['status'])} &nbsp; <b>Blocked now</b> {'yes' if inc['blocked'] else 'no'}</p>
<p><b>Explanation of the peak event</b><br>{_html.escape(inc.get('reason') or '-')}</p>
<ul>{feats}</ul>
<h2>Timeline</h2><table><tr><th>Time (UTC)</th><th>Tier</th><th>Score</th><th>Action</th></tr>{rows}</table>
<p style="color:#666;font-size:12px">Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} by {_html.escape(request.session.get('username', ''))}. Detection results are produced by the SentiHealth models; see evaluation/REPORT.md for their measured accuracy.</p>
</body></html>"""
    _audit_admin("incident_report", {"incident_id": iid, "ip": inc["ip"]})
    return Response(doc, mimetype="text/html", headers={"Content-Disposition": f'attachment; filename="sentihealth_incident_{iid}.html"'})


@app.route("/api/entities/<ip>/timeline")
@_require_auth()
def api_entity_timeline(ip: str):
    return jsonify({"ip": ip, "timeline": entity_timeline(ip), "snooze": load_snoozes().get(ip)})


@app.route("/api/entities/<ip>/snooze", methods=["POST", "DELETE"])
@_rate_limit(30)
@_require_auth(admin_only=True)
def api_snooze(ip: str):
    if request.method == "DELETE":
        removed = clear_snooze(ip)
        _audit_admin("unsnooze", {"ip": ip})
        return jsonify({"success": True, "removed": removed})
    data, err = _json_body({"hours": (float, 72, True), "reason": (str, 300, True)})
    if err:
        return err
    entry = set_snooze(ip, data["hours"], data["reason"], request.session.get("username", "unknown"))
    _audit_admin("snooze", {"ip": ip, "hours": data["hours"], "reason": data["reason"]})
    _push_sse("snooze_changed", {"ip": ip, "snooze": entry})
    return jsonify({"success": True, "snooze": entry})


@app.route("/api/blocked/<ip>/release", methods=["POST"])
@_rate_limit(30)
@_require_auth(admin_only=True)
def api_release_block(ip: str):
    """Undo a block from the dashboard. Step-up MFA, reason recorded, chain block written."""
    data, err = _json_body({"totp_code": (str, 16, True), "reason": (str, 300, False)})
    if err:
        return err
    admin = request.session.get("username", "admin")
    if not _verify_mfa_code(admin, data["totp_code"], load_users().get(admin, {})):
        return jsonify({"success": False, "message": "Step-up MFA failed."}), 401
    removed = False
    if os.path.exists(BLOCKED_IPS):
        with open(BLOCKED_IPS, "r", encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        keep = []
        for l in lines:
            try:
                if json.loads(l).get("ip") == ip:
                    removed = True
                    continue
            except json.JSONDecodeError:
                pass
            keep.append(l if l.endswith("\n") else l + "\n")
        with open(BLOCKED_IPS, "w", encoding="utf-8") as f:
            f.writelines(keep)
    if os.path.exists(THREAT_LOG):
        with open(THREAT_LOG, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
        changed = False
        for i in range(len(all_lines) - 1, -1, -1):
            if not all_lines[i].strip():
                continue
            try:
                entry = json.loads(all_lines[i])
            except json.JSONDecodeError:
                continue
            if entry.get("ip") == ip and entry.get("action") in ("blocked", "auto-locked", "forensics_generated", "pending"):
                entry["action"] = "admin_released"
                entry["reviewed_by"] = admin
                entry["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                all_lines[i] = json.dumps(entry) + "\n"
                changed = True
                break
        if changed:
            with open(THREAT_LOG, "w", encoding="utf-8") as f:
                f.writelines(all_lines)
    fw = _Firewall().unblock_ip(ip, reason=f"released by {admin}: {data.get('reason', '')}")
    _audit_admin("release_block", {"ip": ip, "reason": data.get("reason", ""), "firewall": fw.get("detail", "")})
    _push_sse("block_released", {"ip": ip, "by": admin})
    _log_to_file(f"[RELEASE] '{admin}' released block on {ip}: {data.get('reason', '')}")
    return jsonify({"success": True, "ip": ip, "removed_from_blocklist": removed, "firewall": fw})


@app.route("/api/audit/reveal", methods=["POST"])
@_rate_limit(60)
@_require_auth()
def api_reveal():
    """The dashboard shows identifiers pseudonymised; revealing one is itself an audited event."""
    data, err = _json_body({"identifier": (str, 128, True), "context": (str, 128, False)})
    if err:
        return err
    _audit_admin("reveal_identifier", {"identifier": data["identifier"], "context": data.get("context", "")})
    return jsonify({"success": True})


@app.route("/api/review", methods=["POST"])
@_rate_limit(30)
@_require_auth(admin_only=True)
def api_review():
    """Analyst label for an incident -> retraining queue (core/review_queue.py applies the poisoning check)."""
    data, err = _json_body({"incident_id": (str, 32, True), "label": (str, 16, True), "note": (str, 300, False)})
    if err:
        return err
    if data["label"] not in ("benign", "attack"):
        return jsonify({"success": False, "message": "label must be 'benign' or 'attack'."}), 400
    inc = incident_by_id(data["incident_id"])
    if not inc:
        return jsonify({"success": False, "message": "Incident not found."}), 404
    peak = next((e for e in load_threats() if e.get("ip") == inc["ip"] and e.get("timestamp") == inc.get("peak_timestamp")), {})
    entry = {
        "source": "dashboard", "incident_id": inc["id"], "ip": inc["ip"], "label": data["label"],
        "tier_label": 0 if data["label"] == "benign" else 2, "model_tier": inc["peak_tier"], "score": inc["peak_score"],
        "features": peak.get("feature_values", {}), "note": data.get("note", ""),
        "by": request.session.get("username", "unknown"), "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    os.makedirs(_RETRAINING_DIR, exist_ok=True)
    queue = []
    if os.path.exists(_RETRAINING_QUEUE):
        try:
            queue = json.load(open(_RETRAINING_QUEUE))
        except (json.JSONDecodeError, OSError):
            queue = []
    queue.append(entry)
    with open(_RETRAINING_QUEUE, "w", encoding="utf-8") as f:
        json.dump(queue, f, indent=2)
    _audit_admin("analyst_label", {"incident_id": inc["id"], "ip": inc["ip"], "label": data["label"]})
    return jsonify({"success": True, "queued": len(queue)})


@app.route("/api/ml/health")
@_require_auth(admin_only=True)
def api_ml_health():
    return jsonify({"drift": _drift_report(), "anchors": _verify_anchors(), "response": _response_status()})


_SIMULATIONS = {"brute_force", "ddos", "exfiltration", "port_scan"}


@app.route("/api/admin/simulate/<name>", methods=["POST"])
@_rate_limit(5)
@_require_auth(admin_only=True)
def api_simulate(name: str):
    """Tabletop mode: run one of the bundled attack simulators against this installation.
    The sentinel must run with SENTIHEALTH_TEST_MODE=1 to accept the simulator's events."""
    import subprocess
    if name not in _SIMULATIONS:
        return jsonify({"success": False, "message": f"unknown simulation; choose one of {sorted(_SIMULATIONS)}"}), 400
    script = _p("attack_scripts", f"{name}.py")
    if not os.path.exists(script):
        return jsonify({"success": False, "message": "simulator script missing"}), 404
    try:
        subprocess.Popen([sys.executable, script], cwd=_PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return jsonify({"success": False, "message": str(exc)}), 500
    _audit_admin("tabletop_simulation", {"simulation": name})
    return jsonify({"success": True, "started": name, "note": "the sentinel must run with SENTIHEALTH_TEST_MODE=1 to score these events"})

# ---------------------------------------------------------------------------
# Legacy HTML dashboard (kept for terminal access)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    state = get_system_state()

    bg = "#121212"
    sc = "#4CAF50" if state["status"] == "NORMAL" else (
        "#F44336" if state["status"] == "THREAT" else "#FF9800"
    )
    bc = "#4CAF50" if state["blockchain_status"] == "INTACT" else "#F44336"

    rows_html = ""
    for t in state["threats"]:
        tc = "#F44336" if t["tier"] == "High" else "#FF9800"
        rows_html += (
            f"<tr><td>{t['timestamp']}</td>"
            f"<td style='font-family:monospace'>{t['ip']}</td>"
            f"<td style='color:{tc}'>{t['tier']}</td>"
            f"<td>{t['score']:.3f}</td>"
            f"<td>{t.get('display_action', t.get('action',''))}</td></tr>"
        )
    if not rows_html:
        rows_html = "<tr><td colspan='5' style='text-align:center;color:#888'>No threats detected yet.</td></tr>"

    return f"""<!DOCTYPE html><html><head>
<title>SentiHealth Console</title>
<meta http-equiv="refresh" content="5">
<style>body{{font-family:-apple-system,sans-serif;background:{bg};color:#fff;padding:20px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #333}}
th{{color:#aaa}}.badge{{padding:6px 14px;border-radius:4px;font-weight:bold;display:inline-block}}</style>
</head><body>
<h1> SentiHealth  Secure Console</h1>
<p style="color:#aaa;font-size:0.85em">Live threat data. Authenticated admins only via React dashboard on :5173.</p>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>System Status</h2><div class="badge" style="background:{sc}">{state['status']}</div></div>
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>Blockchain Ledger</h2><span class="badge" style="background:{bc}">{state['blockchain_status']}</span>
<p style="color:#aaa">Blocked IPs: {state['blocked_count']}</p></div></div>
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>Recent Threat Detections (Last 10)</h2>
<table><thead><tr><th>Timestamp</th><th>IP Address</th><th>Tier</th><th>Score</th><th>Action</th></tr></thead>
<tbody>{rows_html}</tbody></table></div></body></html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _start_challenge_watcher():
    """
    Background thread: watches logs/ssha_challenges.json for new pending
    authorization challenges and pushes a 'high_alert' SSE event to every
    connected admin browser so they see an instant toast — no page refresh needed.
    """
    from notifications.sentinel_notifier import _read_challenges

    seen_ids: set = set()

    def _watch():
        while True:
            time.sleep(2)
            try:
                challenges = _read_challenges()
                for iid, ch in challenges.items():
                    if iid in seen_ids:
                        continue
                    seen_ids.add(iid)
                    if ch.get("status") == "pending":
                        _push_sse("high_alert", {
                            "incident_id": iid,
                            "prompt": ch.get("prompt", "High-tier threat — Admin decision required."),
                            "timestamp": ch.get("timestamp", ""),
                            "timeout_sec": ch.get("timeout_sec", 90),
                        })
            except Exception:
                pass

    threading.Thread(target=_watch, daemon=True).start()


def _start_threat_log_watcher():
    """
    Background thread: tail-follows logs/threat_log.json and pushes a
    'threat_update' SSE event to every connected browser the instant
    live_sentinel.py writes a new scored event — no 5-second poll lag.
    """
    _THREAT_LOG = THREAT_LOG

    def _watch():
        pos = 0
        # Start at EOF — only forward events that arrive after dashboard boot
        if os.path.exists(_THREAT_LOG):
            with open(_THREAT_LOG, "rb") as _f:
                _f.seek(0, 2)
                pos = _f.tell()

        while True:
            time.sleep(0.8)
            try:
                if not os.path.exists(_THREAT_LOG):
                    continue
                with open(_THREAT_LOG, "r", encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Attach a shap_url so the frontend can fetch it right away
                        shap_file = entry.get("shap_file", "")
                        entry["shap_url"] = f"/api/shap/{shap_file}" if shap_file else ""
                        _push_sse("threat_update", entry)
                    except Exception:
                        pass
            except Exception:
                pass

    threading.Thread(target=_watch, daemon=True).start()


def _log_to_file(msg: str) -> None:
    """Write a startup/status message directly to logs_dashboard.txt as UTF-8.
    Bypasses stdout so the file never gets PowerShell's UTF-16 LE encoding."""
    try:
        _lf_path = os.path.join(LOGS_DIR, "logs_dashboard.txt")
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(_lf_path, "a", encoding="utf-8") as _lf:
            _lf.write(msg + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    init_db()
    _start_challenge_watcher()
    _start_threat_log_watcher()
    _log_to_file("[DASHBOARD] SentiHealth Dashboard starting...")
    _log_to_file("[DASHBOARD] SSHA active -- no Telegram required.")
    _log_to_file("[DASHBOARD] OTP will appear below when admin logs in.")

    try:
        from pyngrok import ngrok as _ngrok_lib, conf as _ngrok_conf
        _ngrok_token = os.environ.get("NGROK_AUTHTOKEN", "").strip()
        if _ngrok_token:
            _ngrok_conf.get_default().auth_token = _ngrok_token

        # NGROK_DOMAIN: the free static domain from the ngrok dashboard (e.g. my-name.ngrok-free.app).
        # With it the public URL never changes, so the Vercel VITE_API_BASE_URL setting stays valid.
        _ngrok_domain = os.environ.get("NGROK_DOMAIN", "").strip()
        if _ngrok_domain:
            _tunnel = _ngrok_lib.connect(5001, "http", domain=_ngrok_domain)
        else:
            _tunnel = _ngrok_lib.connect(5001, "http")
        _ngrok_url = _tunnel.public_url

        _log_to_file(f"[NGROK] Public URL: {_ngrok_url}")
        print(f"\n{'='*60}", flush=True)
        print(f"  🌐  Backend public URL:", flush=True)
        print(f"      {_ngrok_url}", flush=True)
        print(f"  Set VITE_API_BASE_URL={_ngrok_url} in the Vercel project, then redeploy.", flush=True)
        print(f"{'='*60}\n", flush=True)

        try:
            _get_notifier().send_alert(
                f"🌐 DASHBOARD IS LIVE\n"
                f"Public URL: {_ngrok_url}\n"
                f"Open this link on any device to access the SentiHealth dashboard."
            )
        except Exception:
            pass

    except ImportError:
        print("[NGROK] pyngrok not installed -- backend reachable on this network only (pip install pyngrok).", flush=True)
    except Exception as _ngrok_err:
        print(f"[NGROK] Tunnel not started: {_ngrok_err}", flush=True)

    app.run(port=5001, debug=False, host="0.0.0.0")
