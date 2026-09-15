from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import hmac
import secrets
import string
import threading
import time
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from collections import deque
from typing import Deque, Dict, Any

from flask import Flask, abort, jsonify, make_response, redirect, render_template_string, request, url_for

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = 5066
THREADED = True

# Function 2 Pass Key minimum. Change this one value and the UI updates.
PASS_KEY_MIN_LENGTH = 16
PASS_KEY_MAX_LENGTH = 1024  # Generous safety ceiling; long passphrases are encouraged.

# Function 2 password minimum. Per the requested behaviour, blank / invalid
# lengths are treated as this minimum.
DERIVED_PASSWORD_MIN_LENGTH = 16

# History has no fixed item-count limit. The browser reports how many fixed-height
# entries fit in the history card, and the server discards older entries beyond it.

# Global hard-coded safety rate limit. Per-account Function 1/2 quotas are configured by an administrator.
# This global limit always applies, even when an account quota is disabled.
GLOBAL_RATE_LIMIT_RPS = 100

# Login brute-force protection.
# Password submissions are limited to one attempt per second for BOTH the
# browser session ID and source IP address. After this many incorrect passwords,
# both identifiers are locked out for LOGIN_LOCKOUT_SECONDS.
LOGIN_PASSWORD_SUBMISSION_RPS = 1
LOGIN_MAX_FAILED_ATTEMPTS = 5
# CHANGE THIS VALUE to alter the login lockout duration (currently 5 minutes).
LOGIN_LOCKOUT_SECONDS = 5 * 60

# PBKDF2 work factor. This is deliberately configurable from code.
PBKDF2_ITERATIONS = 600_000

# Function 2 application-instance secret. IMPORTANT: replace this value with a
# unique, high-entropy secret for each copy of the application before use.
# Changing this value changes every Function 2 derived password. Keep it backed
# up securely: losing it means existing Function 2 passwords cannot be reproduced.
APP_INSTANCE_SECRET = os.environ.get("PASSGEN_APP_SECRET", "CHANGE-ME-TO-A-UNIQUE-LONG-RANDOM-SECRET-FOR-THIS-APP-COPY")

# Basic Authentication. Set ENABLE_AUTH = False to protect the application.
# Keep this behind HTTPS when exposed beyond a trusted local network.
ENABLE_AUTH = False
APP_USERS = {
    "omer":"password",
}

# Local account/settings database. This is the only persistent storage used.
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "passgen_users.sqlite3")
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "changeme"
ACCOUNT_SESSION_TTL_SECONDS = int(os.environ.get("PASSGEN_SESSION_TTL_SECONDS", str(60 * 60 * 8)))
# Production: set PASSGEN_SECURE_COOKIES=1 and serve only through HTTPS.
SECURE_COOKIES = os.environ.get("PASSGEN_SECURE_COOKIES", "1") == "1"


# Characters considered visually ambiguous for the general generator.
AMBIGUOUS_CHARACTERS = set("0Oo1Il|5S2Z8B6G9q")

# Character classes. Characters are intentionally plain ASCII for portability.
UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SPECIALS = "!@#$%^&*()-_=+[]{}:,.?~;/'\\|<>"

# Function 2 always excludes visually ambiguous characters.
DERIVED_POOLS = {
    "upper": "".join(c for c in UPPER if c not in AMBIGUOUS_CHARACTERS),
    "lower": "".join(c for c in LOWER if c not in AMBIGUOUS_CHARACTERS),
    "digit": "".join(c for c in DIGITS if c not in AMBIGUOUS_CHARACTERS),
    "special": "".join(c for c in SPECIALS if c not in AMBIGUOUS_CHARACTERS),
}

# -----------------------------------------------------------------------------
# Persistent local accounts / encrypted generator settings
# -----------------------------------------------------------------------------
def _db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
    return base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()


def _password_ok(password: str, stored: str) -> bool:
    try:
        a, b = stored.split("$", 1)
        salt = base64.urlsafe_b64decode(a.encode())
        expected = base64.urlsafe_b64decode(b.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _vault_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000, dklen=32)


def _seal(value: str, key: bytes) -> str:
    """Encrypt settings with standard AES-256-GCM authenticated encryption."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, value.encode("utf-8"), b"passgen-v18")
    return "gcm:" + base64.urlsafe_b64encode(nonce + ct).decode()


def _open(value: str, key: bytes) -> str:
    """Open AES-GCM values; retain read compatibility with pre-v18 sealed values."""
    if value.startswith("gcm:"):
        blob = base64.urlsafe_b64decode(value[4:].encode())
        return AESGCM(key).decrypt(blob[:12], blob[12:], b"passgen-v18").decode("utf-8")
    # Legacy v17 authenticated XOR/HMAC format, used only to migrate existing saved Pass Keys.
    blob = base64.urlsafe_b64decode(value.encode())
    nonce, tag, ct = blob[:16], blob[16:48], blob[48:]
    if not hmac.compare_digest(tag, hmac.new(key, b"vault" + nonce + ct, hashlib.sha256).digest()):
        raise ValueError("Encrypted data authentication failed.")
    out = bytearray(); counter = 0
    while len(out) < len(ct):
        counter += 1
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
    return bytes(a ^ b for a, b in zip(ct, out)).decode("utf-8")


def _init_db():
    with _db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          display_name TEXT NOT NULL, password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
          must_change_password INTEGER NOT NULL DEFAULT 0, vault_salt BLOB NOT NULL,
          saved_pass_key TEXT, secret_override TEXT,
          quota_enabled INTEGER NOT NULL DEFAULT 0, quota_per_minute INTEGER NOT NULL DEFAULT 0,
          quota_per_hour INTEGER NOT NULL DEFAULT 0, quota_per_day INTEGER NOT NULL DEFAULT 0,
          quota_per_week INTEGER NOT NULL DEFAULT 0, quota_per_month INTEGER NOT NULL DEFAULT 0, quota_function1 INTEGER NOT NULL DEFAULT 1,
          quota_function2 INTEGER NOT NULL DEFAULT 1, service_history_enabled INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS quota_usage (
          id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, function_name TEXT NOT NULL, used_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_quota_usage_subject_time ON quota_usage(subject, used_at);
        CREATE INDEX IF NOT EXISTS idx_quota_usage_subject_function_time ON quota_usage(subject, function_name, used_at);
        CREATE TABLE IF NOT EXISTS service_history (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          service TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_used_at TEXT NOT NULL,
          UNIQUE(user_id, service)
        );
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "saved_pass_key" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN saved_pass_key TEXT")
        if "secret_override" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN secret_override TEXT")
        if "service_history_enabled" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN service_history_enabled INTEGER NOT NULL DEFAULT 1")
        quota_columns = {
            "quota_enabled": "INTEGER NOT NULL DEFAULT 0", "quota_per_minute": "INTEGER NOT NULL DEFAULT 0",
            "quota_per_hour": "INTEGER NOT NULL DEFAULT 0", "quota_per_day": "INTEGER NOT NULL DEFAULT 0",
            "quota_per_week": "INTEGER NOT NULL DEFAULT 0", "quota_per_month": "INTEGER NOT NULL DEFAULT 0", "quota_function1": "INTEGER NOT NULL DEFAULT 1",
            "quota_function2": "INTEGER NOT NULL DEFAULT 1"
        }
        for name, definition in quota_columns.items():
            if name not in columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")
        guest_defaults = {
            "guest_quota_enabled":"0", "guest_quota_per_minute":"0", "guest_quota_per_hour":"0",
            "guest_quota_per_day":"0", "guest_quota_per_week":"0", "guest_quota_per_month":"0",
            "guest_quota_function1":"1", "guest_quota_function2":"1"
        }
        if not db.execute("SELECT 1 FROM settings WHERE key='account_session_ttl_seconds'").fetchone():
            db.execute("INSERT INTO settings(key,value) VALUES('account_session_ttl_seconds',?)", (str(ACCOUNT_SESSION_TTL_SECONDS),))
        for k, v in guest_defaults.items():
            if not db.execute("SELECT 1 FROM settings WHERE key=?", (k,)).fetchone():
                db.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k,v))
        # v18 schema cleanup: remove obsolete pre-Pass-Key fields when SQLite supports DROP COLUMN.
        for legacy in ("saved_master", "saved_keyword", "personal_secret", "use_default_secret"):
            current = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
            if legacy in current:
                try:
                    db.execute(f"ALTER TABLE users DROP COLUMN {legacy}")
                except sqlite3.OperationalError:
                    # Older SQLite builds may not support DROP COLUMN; the obsolete field is never read.
                    pass
        if not db.execute("SELECT 1 FROM settings WHERE key='default_secret'").fetchone():
            db.execute("INSERT INTO settings(key,value) VALUES('default_secret',?)", (APP_INSTANCE_SECRET,))
        if not db.execute("SELECT 1 FROM users WHERE is_admin=1").fetchone():
            db.execute("INSERT INTO users(username,display_name,password_hash,is_admin,must_change_password,vault_salt) VALUES(?,?,?,?,?,?)",
                       (DEFAULT_ADMIN_USERNAME, "Administrator", _password_hash(DEFAULT_ADMIN_PASSWORD), 1, 1, secrets.token_bytes(16)))


_init_db()
ACCOUNT_SESSIONS: Dict[str, Dict[str, Any]] = {}
ACCOUNT_LOCK = threading.RLock()

# In-memory login protection state. Nothing here is persisted to disk.
# key -> {failures: int, locked_until: float, submissions: deque[float]}
LOGIN_PROTECTION: Dict[str, Dict[str, Any]] = {}
LOGIN_PROTECTION_LOCK = threading.RLock()


def _login_protection_keys() -> tuple[str, str]:
    """Return independent protection keys for this browser session and IP."""
    sid = getattr(request, "_pg_sid", "") or "missing"
    ip = request.remote_addr or "unknown"
    return "sid:" + sid, "ip:" + ip


def _login_state(key: str) -> dict[str, Any]:
    return LOGIN_PROTECTION.setdefault(key, {"failures": 0, "locked_until": 0.0, "submissions": deque()})


def _login_lock_remaining(keys: tuple[str, str]) -> int:
    now = time.monotonic()
    with LOGIN_PROTECTION_LOCK:
        remaining = max(max(0.0, _login_state(k)["locked_until"] - now) for k in keys)
    return int(remaining + 0.999)


def _login_submission_allowed(keys: tuple[str, str]) -> bool:
    """Enforce the configured password-submission rate against session AND IP."""
    now = time.monotonic()
    window = 1.0
    with LOGIN_PROTECTION_LOCK:
        states = [_login_state(k) for k in keys]
        for state in states:
            q = state["submissions"]
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= LOGIN_PASSWORD_SUBMISSION_RPS:
                return False
        # Count the submission against both identifiers only after both checks pass.
        for state in states:
            state["submissions"].append(now)
        return True


def _record_login_failure(keys: tuple[str, str]):
    now = time.monotonic()
    with LOGIN_PROTECTION_LOCK:
        for k in keys:
            state = _login_state(k)
            state["failures"] += 1
            if state["failures"] >= LOGIN_MAX_FAILED_ATTEMPTS:
                state["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
                state["failures"] = 0
                state["submissions"].clear()


def _clear_login_failures(keys: tuple[str, str]):
    with LOGIN_PROTECTION_LOCK:
        for k in keys:
            state = _login_state(k)
            state["failures"] = 0
            state["locked_until"] = 0.0
            state["submissions"].clear()


def _session_ttl() -> int:
    try:
        with _db() as db:
            row=db.execute("SELECT value FROM settings WHERE key='account_session_ttl_seconds'").fetchone()
        return max(300, int(row["value"])) if row else ACCOUNT_SESSION_TTL_SECONDS
    except Exception:
        return ACCOUNT_SESSION_TTL_SECONDS


def _account():
    token = request.cookies.get("pg_account")
    if not token: return None
    with ACCOUNT_LOCK:
        state = ACCOUNT_SESSIONS.get(token)
        if not state or time.time() - state["last_seen"] > _session_ttl():
            ACCOUNT_SESSIONS.pop(token, None); return None
        state["last_seen"] = time.time()
        return state


def _current_user():
    state = _account()
    if not state: return None
    with _db() as db:
        return db.execute("SELECT * FROM users WHERE id=?", (state["user_id"],)).fetchone()


def _effective_secret(user) -> str:
    if user and user["secret_override"]:
        return user["secret_override"]
    with _db() as db:
        row=db.execute("SELECT value FROM settings WHERE key='default_secret'").fetchone()
        return row["value"] if row else APP_INSTANCE_SECRET

# -----------------------------------------------------------------------------
# Flask app and strictly in-memory session store
# -----------------------------------------------------------------------------
app = Flask(__name__)

# A fresh secret is created every process start and is never written to disk.
# This intentionally means all sessions are invalidated when the process restarts.
APP_SECRET = secrets.token_bytes(32)
app.config.update(
    SECRET_KEY=APP_SECRET,
    SESSION_COOKIE_NAME="pg_sid",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=SECURE_COOKIES,  # Set PASSGEN_SECURE_COOKIES=1 behind HTTPS.
    MAX_CONTENT_LENGTH=64 * 1024,
)

# session_id -> {csrf, random_history, derived_history, request_times, last_seen}
SESSIONS: Dict[str, Dict[str, Any]] = {}
SESSIONS_LOCK = threading.RLock()
RATE_LIMIT_LOCK = threading.RLock()
GLOBAL_REQUEST_TIMES = deque()
SESSION_TTL_SECONDS = 60 * 60 * 8  # 8 hours of inactivity.


def _new_session() -> tuple[str, dict[str, Any]]:
    sid = secrets.token_urlsafe(32)
    state = {
        "csrf": secrets.token_urlsafe(32),
        "random_history": deque(),
        "derived_history": deque(),
        "last_seen": time.time(),
        "request_times": deque(),
    }
    with SESSIONS_LOCK:
        SESSIONS[sid] = state
    return sid, state


def _get_session() -> tuple[str, dict[str, Any]]:
    sid = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
    now = time.time()
    with SESSIONS_LOCK:
        if sid and sid in SESSIONS:
            state = SESSIONS[sid]
            if now - state["last_seen"] <= SESSION_TTL_SECONDS:
                state["last_seen"] = now
                return sid, state
            del SESSIONS[sid]
        return _new_session()


def _set_session_cookie(response, sid: str):
    response.set_cookie(
        app.config["SESSION_COOKIE_NAME"],
        sid,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=app.config["SESSION_COOKIE_SECURE"],
        samesite="Strict",
        path="/",
    )


def _cleanup_sessions():
    cutoff = time.time() - SESSION_TTL_SECONDS
    with SESSIONS_LOCK:
        stale = [sid for sid, state in SESSIONS.items() if state["last_seen"] < cutoff]
        for sid in stale:
            SESSIONS.pop(sid, None)


def _basic_auth_ok() -> bool:
    """Validate HTTP Basic Authentication without storing credentials in a session."""
    auth = request.authorization
    if not auth or auth.type.lower() != "basic" or auth.username is None or auth.password is None:
        return False

    supplied_username = auth.username
    supplied_password = auth.password

    # Compare against every configured user without early success disclosure.
    matched = False
    for configured_username, configured_password in APP_USERS.items():
        username_match = hmac.compare_digest(
            supplied_username.encode("utf-8"), configured_username.encode("utf-8")
        )
        password_match = hmac.compare_digest(
            supplied_password.encode("utf-8"), configured_password.encode("utf-8")
        )
        if username_match and password_match:
            matched = True
    return matched


def _auth_required_response():
    response = jsonify(ok=False, error="Authentication required.")
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Basic realm="Password Generator"'
    return response


@app.before_request
def ensure_session():
    if ENABLE_AUTH and not _basic_auth_ok():
        return _auth_required_response()

    if request.endpoint not in {"login", "guest_login", "health"} and not _account() and request.cookies.get("pg_guest") != "1":
        return redirect(url_for("login"))

    # Nothing sensitive is sent to a third party and nothing is persisted.
    sid, state = _get_session()
    request._pg_sid = sid
    request._pg_state = state

    # Hard-coded global sliding one-second safety limit. Account quotas are enforced
    # separately on successful Function 1/2 generation requests.
    now = time.monotonic()
    with RATE_LIMIT_LOCK:
        while GLOBAL_REQUEST_TIMES and now - GLOBAL_REQUEST_TIMES[0] >= 1.0:
            GLOBAL_REQUEST_TIMES.popleft()
        if len(GLOBAL_REQUEST_TIMES) >= GLOBAL_RATE_LIMIT_RPS:
            return jsonify(ok=False, error="Global rate limit exceeded. Please try again shortly."), 429
        GLOBAL_REQUEST_TIMES.append(now)

    # Opportunistic cleanup, amortised across requests.
    if secrets.randbelow(100) == 0:
        _cleanup_sessions()


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers[
        "Content-Security-Policy"
    ] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    return response


# -----------------------------------------------------------------------------
# Validation / generation helpers
# -----------------------------------------------------------------------------
def _csrf_ok() -> bool:
    supplied = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
    expected = request._pg_state["csrf"]
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def _class_pool(exclude_ambiguous: bool) -> dict[str, str]:
    pools = {
        "upper": UPPER,
        "lower": LOWER,
        "digit": DIGITS,
        "special": SPECIALS,
    }
    if exclude_ambiguous:
        pools = {k: "".join(c for c in v if c not in AMBIGUOUS_CHARACTERS) for k, v in pools.items()}
    return pools


def _parse_nonnegative_int(value: str, field: str, default: int | None = None) -> int:
    value = (value or "").strip()
    if value == "" and default is not None:
        return default
    try:
        result = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a number.")
    if result < 0:
        raise ValueError(f"{field} cannot be negative.")
    return result


def generate_random_password(
    length: int,
    upper_count: int,
    lower_count: int,
    digit_count: int,
    special_count: int,
    exclude_ambiguous: bool,
) -> str:
    if length < 1:
        raise ValueError("Password length must be at least 1.")
    counts = upper_count + lower_count + digit_count + special_count
    if counts > length:
        raise ValueError("The requested character counts exceed the total password length.")

    pools = _class_pool(exclude_ambiguous)
    for name, count in (
        ("uppercase", upper_count),
        ("lowercase", lower_count),
        ("numbers", digit_count),
        ("special characters", special_count),
    ):
        pool_key = {
            "uppercase": "upper",
            "lowercase": "lower",
            "numbers": "digit",
            "special characters": "special",
        }[name]
        if count > 0 and not pools[pool_key]:
            raise ValueError(f"No usable {name} remain with ambiguous characters excluded.")

    # Unspecified positions are filled from every requested/general pool.
    # This preserves the exact minimum counts requested while keeping the
    # remaining positions random.
    all_pool = "".join(pools.values())
    if not all_pool:
        raise ValueError("No usable characters are available.")

    chars = []
    for pool_key, count in (
        ("upper", upper_count),
        ("lower", lower_count),
        ("digit", digit_count),
        ("special", special_count),
    ):
        for _ in range(count):
            chars.append(secrets.choice(pools[pool_key]))

    for _ in range(length - counts):
        chars.append(secrets.choice(all_pool))

    # CSPRNG-backed Fisher-Yates shuffle via SystemRandom.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _validate_service(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Service is required.")
    if not value.isascii() or not all(ch.isalnum() or ch.isspace() or ch == "-" for ch in value):
        raise ValueError("Service may contain letters, numbers, spaces, and hyphens (-) only.")
    # Service identity is deliberately case-insensitive. Normalise before any
    # deterministic password derivation or history storage takes place.
    return value.lower()


def _record_service_history(user_id: int, service: str):
    """Record a successfully used, already-normalised Service for a signed-in user."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as db:
        db.execute(
            "INSERT INTO service_history(user_id,service,created_at,last_used_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_id,service) DO UPDATE SET last_used_at=excluded.last_used_at",
            (user_id, service, now, now),
        )


def _validate_username(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Username is required.")
    if value != value.lower():
        raise ValueError("Username must contain lowercase characters only.")
    if any(ch.isspace() for ch in value):
        raise ValueError("Username must not contain spaces.")
    if not value.isascii():
        raise ValueError("Username must contain ASCII lowercase characters only.")
    return value


def _validate_email(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Email address is required.")
    if value != value.lower():
        raise ValueError("Email address must contain lowercase characters only.")
    if "@" not in value or value.count("@") != 1:
        raise ValueError("Enter a valid email address such as x@x.x.")
    local, domain = value.split("@", 1)
    if not local or not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Enter a valid email address such as x@x.x.")
    if ".." in value or any(ch.isspace() for ch in value):
        raise ValueError("Enter a valid email address such as x@x.x.")
    return value


def _derive_bytes(pass_key: str, service: str, email: str, username: str, version: int, length: int) -> bytes:
    """Derive deterministic bytes using PBKDF2-HMAC-SHA256.

    The Pass Key is user secret key material. Service, email, username, and
    version are deterministic credential context.
    """
    secret_material = (_effective_secret(_current_user()) + "\x00" + pass_key).encode("utf-8")
    salt_material = (
        "PasswordGenerator/v2\x00" + service + "\x00" + email + "\x00" + username + "\x00" + str(version)
    ).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", secret_material, salt_material, PBKDF2_ITERATIONS, dklen=max(length * 8, 64))


def _expand_deterministic_stream(pass_key: str, service: str, email: str, username: str, version: int):
    """Yield an effectively unbounded deterministic HMAC stream."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        (_effective_secret(_current_user()) + "\x00" + pass_key).encode("utf-8"),
        ("PasswordGenerator/v2\x00" + service + "\x00" + email + "\x00" + username + "\x00" + str(version)).encode("utf-8"),
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    counter = 0
    while True:
        counter += 1
        yield hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha256).digest()


def _next_deterministic_byte(stream, state: dict[str, Any]) -> int:
    if state["available"] == 0:
        state["block"] = next(stream)
        state["index"] = 0
        state["available"] = len(state["block"])
    b = state["block"][state["index"]]
    state["index"] += 1
    state["available"] -= 1
    return b


def _deterministic_choice(stream, pool: str, state: dict[str, Any]) -> str:
    """Uniformly choose from a string pool using rejection sampling."""
    if not pool:
        raise ValueError("Character pool is empty.")
    n = len(pool)
    limit = (256 // n) * n
    while True:
        b = _next_deterministic_byte(stream, state)
        if b < limit:
            return pool[b % n]


def generate_derived_password(
    pass_key: str,
    service: str,
    email: str,
    username: str,
    version: int,
    length: int,
) -> str:
    # Always emit all four categories for a complex result.
    pools = DERIVED_POOLS
    stream = _expand_deterministic_stream(pass_key, service, email, username, version)
    state = {"block": b"", "index": 0, "available": 0}

    # Guarantee at least one character from each category.
    chars = [
        _deterministic_choice(stream, pools["upper"], state),
        _deterministic_choice(stream, pools["lower"], state),
        _deterministic_choice(stream, pools["digit"], state),
        _deterministic_choice(stream, pools["special"], state),
    ]

    all_pool = "".join(pools.values())
    for _ in range(length - 4):
        chars.append(_deterministic_choice(stream, all_pool, state))

    # Deterministically shuffle using Fisher-Yates and the same derived stream.
    for i in range(len(chars) - 1, 0, -1):
        j = _next_deterministic_byte(stream, state) % (i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def _quota_values_from_form(prefix: str = "") -> dict[str, int]:
    def n(name):
        raw=(request.form.get(prefix+name, "0") or "0").strip()
        try: value=int(raw)
        except ValueError: raise ValueError("Quota values must be whole numbers.")
        if value < 0: raise ValueError("Quota values cannot be negative.")
        return value
    q={"enabled":1 if request.form.get(prefix+"quota_enabled")=="1" else 0,
       "per_minute":n("quota_per_minute"), "per_hour":n("quota_per_hour"),
       "per_day":n("quota_per_day"), "per_week":n("quota_per_week"), "per_month":n("quota_per_month"),
       "function1":1 if request.form.get(prefix+"quota_function1")=="1" else 0,
       "function2":1 if request.form.get(prefix+"quota_function2")=="1" else 0}
    if q["enabled"]:
        vals=[q[x] for x in ("per_minute","per_hour","per_day","per_week","per_month") if q[x] > 0]
        if not vals: raise ValueError("When quotas are enabled, at least one quota value must be greater than 0.")
        if not (q["function1"] or q["function2"]): raise ValueError("Select Function 1 and/or Function 2 for the quota.")
        ordered=[q[x] for x in ("per_minute","per_hour","per_day","per_week","per_month") if q[x] > 0]
        if any(b < a for a,b in zip(ordered,ordered[1:])):
            raise ValueError("Quota values conflict: longer time periods cannot have a lower limit than shorter time periods.")
    return q


def _quota_config_for_request():
    user=_current_user()
    if user:
        return "user:"+str(user["id"]), {"enabled":user["quota_enabled"],"per_minute":user["quota_per_minute"],"per_hour":user["quota_per_hour"],"per_day":user["quota_per_day"],"per_week":user["quota_per_week"],"per_month":user["quota_per_month"],"function1":user["quota_function1"],"function2":user["quota_function2"]}
    with _db() as db:
        rows={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings WHERE key LIKE 'guest_quota_%'").fetchall()}
    return "guest", {k:int(rows.get("guest_quota_"+k,"0")) for k in ("enabled","per_minute","per_hour","per_day","per_week","per_month","function1","function2")}


def _consume_generation_quota(function_name: str):
    subject,q=_quota_config_for_request()
    fnkey="function1" if function_name=="function1" else "function2"
    if not q["enabled"] or not q[fnkey]: return
    now=time.time(); windows=(("per_minute",60),("per_hour",3600),("per_day",86400),("per_week",7*86400),("per_month",30*86400))
    with _db() as db:
        db.execute("DELETE FROM quota_usage WHERE used_at < ?", (now-31*86400,))
        for key,seconds in windows:
            limit=q[key]
            if limit > 0:
                count=db.execute("SELECT COUNT(*) FROM quota_usage WHERE subject=? AND function_name=? AND used_at>=?",(subject,function_name,now-seconds)).fetchone()[0]
                if count >= limit:
                    label=key.replace("per_","")
                    raise ValueError(f"{function_name.replace('function','Function ')} quota reached: {limit} request(s) per {label}.")
        db.execute("INSERT INTO quota_usage(subject,function_name,used_at) VALUES(?,?,?)",(subject,function_name,now))


# -----------------------------------------------------------------------------
# Templates (all embedded; no template/static files required)
# -----------------------------------------------------------------------------
BASE_CSS = r"""
:root {
  color-scheme: dark;
  --bg: #0b0e13;
  --panel: #121722;
  --panel2: #171d2a;
  --border: #293244;
  --text: #e8edf7;
  --muted: #98a2b3;
  --accent: #68a5ff;
  --accent2: #4f86d9;
  --danger: #ff6b6b;
  --success: #62d196;
  --shadow: 0 18px 55px rgba(0,0,0,.35);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: radial-gradient(circle at top, #151b27 0, var(--bg) 42%);
  color: var(--text);
  min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.container { max-width: 1250px; margin: 0 auto; padding: 28px 20px 48px; }
header {
  display: flex; justify-content: space-between; align-items: center; gap: 16px;
  margin-bottom: 22px;
}
h1 { margin: 0; font-size: 28px; letter-spacing: .2px; }
.subtitle { color: var(--muted); margin-top: 6px; font-size: 14px; }
.nav { display: flex; gap: 8px; }
.nav a, button {
  border: 1px solid var(--border); background: var(--panel2); color: var(--text);
  border-radius: 9px; padding: 9px 13px; cursor: pointer; font: inherit;
}
.nav a:hover, button:hover { background: #1c2432; text-decoration: none; }
.grid { display: grid; grid-template-columns: 1fr 330px; gap: 18px; align-items: start; }
.card {
  background: rgba(18, 23, 34, .94); border: 1px solid var(--border); border-radius: 14px;
  padding: 18px; box-shadow: var(--shadow);
}
.card + .card { margin-top: 18px; }
.card h2 { margin: 0 0 14px; font-size: 18px; }
.card h3 { margin: 20px 0 10px; font-size: 14px; color: #cfd7e6; }
.tabs { display: flex; gap: 8px; margin-bottom: 16px; }
.tab {
  flex: 1; text-align: center; padding: 10px; border-radius: 9px; border: 1px solid var(--border);
  color: var(--muted); cursor: pointer; user-select: none;
}
.tab.active { background: #1c2737; color: var(--text); border-color: #3a4e6d; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 13px; }
.field { display: flex; flex-direction: column; gap: 6px; }
.field.full { grid-column: 1 / -1; }
label { font-size: 13px; color: #cdd5e2; }
input[type="text"], input[type="password"], input[type="number"], input[type="email"] {
  width: 100%; border-radius: 9px; border: 1px solid var(--border); background: #0d121b;
  color: var(--text); padding: 10px 11px; outline: none;
}
input:focus { border-color: #456792; box-shadow: 0 0 0 3px rgba(83,132,193,.15); }
.hint { font-size: 12px; color: var(--muted); }
.inline { display: flex; align-items: center; gap: 9px; }
.inline input { flex: 1; }
.check { display: flex; align-items: center; gap: 7px; color: var(--muted); font-size: 12px; white-space: nowrap; }
.controls { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 10px; }
.output-wrap { display: flex; gap: 10px; }
.output {
  flex: 1; min-height: 48px; display: flex; align-items: center; padding: 11px 13px;
  background: #0a0f17; border: 1px solid var(--border); border-radius: 9px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  word-break: break-all; color: #eef3fb;
}
.primary { background: var(--accent2); border-color: #6c9cda; color: white; }
.primary:hover { background: #5d94de; }
.danger { color: #ffdada; border-color: #563238; }
.message { min-height: 18px; margin: 10px 0 0; color: var(--danger); font-size: 13px; }
.success { color: var(--success); }
.history-item {
  height: 37px; padding: 10px 0; border-bottom: 1px solid #222a38; cursor: pointer;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #d8e0ee;
}
#history-card { display: flex; flex-direction: column; overflow: hidden; }
#history { flex: 1 1 auto; min-height: 0; overflow: hidden; }
.history-item:last-child { border-bottom: 0; }
.service-suggest-wrap { position: relative; }
.service-suggest-box { position: absolute; z-index: 30; left: 0; right: 0; top: 100%; margin-top: 4px; max-height: 220px; overflow-y: auto; background: #0d121b; border: 1px solid var(--border); border-radius: 9px; box-shadow: var(--shadow); display: none; }
.service-suggest-item { padding: 9px 11px; cursor: pointer; font-size: 13px; color: var(--text); }
.service-suggest-item:hover, .service-suggest-item.active { background: #1c2737; }
.history-empty { color: var(--muted); font-size: 13px; padding: 6px 0; }
.small { font-size: 11px; color: var(--muted); }
.help { max-width: 950px; }
.help h2 { margin-top: 28px; }
.help pre {
  background: #0a0f17; border: 1px solid var(--border); padding: 12px; border-radius: 8px;
  overflow-x: auto; color: #d8e0ee;
}
.toc { background: var(--panel2); padding: 14px 18px; border-radius: 10px; border: 1px solid var(--border); }
.toc ol { margin: 8px 0 0 20px; }
.note { border-left: 3px solid #5b83b4; padding: 10px 13px; background: #101722; color: #cad3e1; }
footer { color: var(--muted); font-size: 12px; margin-top: 18px; }
@media (max-width: 880px) {
  .grid { grid-template-columns: 1fr; }
  .form-grid, .controls { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 560px) {
  .form-grid, .controls { grid-template-columns: 1fr; }
  header { align-items: flex-start; flex-direction: column; }
}
"""

LOGIN_HTML = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Password Generator - Sign in</title><style>{{ css|safe }}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}.login-card{width:min(760px,94vw);padding:32px}.profiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:16px;margin:22px 0}.profile{padding:20px 10px;text-align:center;border:1px solid var(--border);border-radius:12px;background:var(--panel2);cursor:pointer}.avatar{width:72px;height:72px;border-radius:10px;background:#263247;margin:0 auto 10px;display:flex;align-items:center;justify-content:center;font-size:28px}.guest{background:#172335}.login-fields{display:flex;gap:10px}.login-fields input,.login-fields select{flex:1}.user-select{width:100%;border-radius:9px;border:1px solid var(--border);background:#0d121b;color:var(--text);padding:10px 11px;margin-bottom:10px}</style></head><body><div class="login-wrap"><div class="card login-card"><h1>Who's using Password Generator?</h1><div class="subtitle">Choose a registered profile or continue as Guest.</div><div class="profiles"><div class="profile guest" onclick="location.href='{{ url_for('guest_login') }}'"><div class="avatar">G</div><div>Guest</div></div></div><form method="post" action="{{ url_for('login') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><select class="user-select" name="user_id" required><option value="" selected disabled>Select a registered user...</option>{% for u in users %}<option value="{{ u['id'] }}">{{ u['display_name'] }}</option>{% endfor %}</select><div class="login-fields"><input name="password" type="password" placeholder="Password" autocomplete="current-password" required><button class="primary">Sign in</button></div>{% if error %}<div class="message">{{ error }}</div>{% endif %}</form></div></div></body></html>
"""

ACCOUNT_HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Account</title><style>{{ css|safe }}
.reveal-box{margin-top:12px;padding:12px;border:1px solid var(--border);border-radius:10px;background:#0d121b}.reveal-grid{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end}@media(max-width:560px){.reveal-grid{grid-template-columns:1fr}}</style></head><body><div class="container help"><header><div><h1>{{ user['display_name'] }}</h1><div class="subtitle">Account & generator settings</div></div><nav class="nav"><a href="/">Generator</a><a href="/service-history">Service History</a>{% if user['is_admin'] %}<a href="/admin">Admin</a>{% endif %}<a href="/logout">Log out</a></nav></header>{% if msg %}<div class="note">{{ msg }}</div>{% endif %}<div class="card"><h2>Account security</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="password"><div class="form-grid"><div class="field"><label>Current password</label><input type="password" name="current" autocomplete="current-password" required></div><div class="field"><label>New password</label><input type="password" name="new" minlength="12" autocomplete="new-password" required></div></div><button style="margin-top:12px">Change password</button></form>
<h3>Saved Pass Key</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="pass_key"><div class="field"><label>Pass Key</label><input type="password" name="pass_key" autocomplete="off" maxlength="{{ pass_key_max|default(1024) }}" placeholder="{% if user['saved_pass_key'] %}Saved - leave blank to keep current{% else %}Enter Pass Key{% endif %}"></div><button style="margin-top:12px">Save encrypted Pass Key</button></form>
{% if user['saved_pass_key'] %}<h3>View saved Pass Key</h3><div class="reveal-box"><div class="reveal-grid"><div class="field"><label>Pass Key</label><input id="view-pass-key" type="password" readonly value="{% if revealed %}{{ revealed }}{% else %}saved-value{% endif %}"></div><button type="button" onclick="toggleView('view-pass-key',this)" {% if not revealed %}disabled{% endif %}>Show</button></div><form method="post" style="margin-top:12px"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="reveal_pass_key"><div class="field"><label>Enter your account password to unlock viewing</label><input type="password" name="verify" autocomplete="current-password" required></div><button style="margin-top:8px">Unlock Pass Key</button></form><form method="post" style="margin-top:12px" onsubmit="return confirm('Remove your saved Pass Key? You will need to enter it manually for Function 2. This action cannot be undone.');"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="remove_pass_key"><div class="field"><label>Enter your account password to remove saved Pass Key</label><input type="password" name="verify" autocomplete="current-password" required></div><button class="danger" style="margin-top:8px">Remove Saved Pass Key</button></form></div>{% endif %}<h3>Service History</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="service_history_setting"><label class="check"><input type="checkbox" name="service_history_enabled" value="1" {% if user['service_history_enabled'] %}checked{% endif %}> Enable Service History</label><div class="hint">When disabled, successful Function 2 requests will not save Service values and Service suggestions will be unavailable. Existing Service History is kept unless you delete it.</div><button style="margin-top:8px">Save Service History setting</button></form><h3>Sessions</h3><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="logout_all"><div class="field"><label>Account password</label><input type="password" name="verify" autocomplete="current-password" required></div><button style="margin-top:8px">Log out all other sessions</button></form></div></div><script>
function toggleView(id,button){const el=document.getElementById(id);if(el.type==='password'){el.type='text';button.textContent='Hide';}else{el.type='password';button.textContent='Show';}}
function hotkeyTypingTarget(el){if(!el)return false;const tag=(el.tagName||'').toLowerCase();return tag==='input'||tag==='textarea'||tag==='select'||el.isContentEditable;}
document.addEventListener('keydown',function(e){if(e.ctrlKey||e.metaKey||e.altKey||hotkeyTypingTarget(e.target))return;const k=e.key.toLowerCase();if(k==='1'){e.preventDefault();location.href='/?mode=random';}else if(k==='2'){e.preventDefault();location.href='/?mode=derived';}else if(k==='c'){e.preventDefault();location.href='/?hotkey=clear';}else if(k==='m'){e.preventDefault();location.href='/?hotkey=mask';}else if(k==='s'){e.preventDefault();location.href='/service-history';}else if(k==='p'){e.preventDefault();location.href='/account';}else if(k==='h'){e.preventDefault();location.href='/help';}{% if user['is_admin'] %}else if(k==='a'){e.preventDefault();location.href='/admin';}{% endif %}});
</script></body></html>
"""

ADMIN_HTML = r"""
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin</title><style>{{ css|safe }}</style></head><body><div class="container help"><header><div><h1>Administration</h1><div class="subtitle">Users, Function 2 secrets and generation quotas</div></div><nav class="nav"><a href="/">Generator</a><a href="/account">Account</a><a href="/logout">Log out</a></nav></header>{% if msg %}<div class="note">{{ msg }}</div>{% endif %}<div class="card"><h2>Default Function 2 secret</h2><div class="note danger"><strong>Warning:</strong> Changing this secret changes Function 2 passwords for accounts using it. Existing outputs cannot be reproduced with the new secret.</div><form method="post" onsubmit="return confirm('Change the default Function 2 secret? Existing deterministic passwords using the old secret will no longer be reproducible.');"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="default_secret"><input type="password" name="secret" placeholder="New default secret" required><input type="password" name="admin_password" placeholder="Your administrator password" autocomplete="current-password" required><button>Change default secret</button></form><div class="hint">Changing this changes derived passwords for every account without a user-specific secret override.</div>
<h2>Session security</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="session_ttl"><div class="field"><label>Account session timeout (minutes)</label><input type="number" min="5" name="session_minutes" value="{{ session_ttl // 60 }}" required></div><button style="margin-top:8px">Save session timeout</button></form><h2>Guest quotas</h2><div class="small">Usage — F1: {{ guest_usage['function1']['day'] }} today / {{ guest_usage['function1']['week'] }} week / {{ guest_usage['function1']['month'] }} month · F2: {{ guest_usage['function2']['day'] }} today / {{ guest_usage['function2']['week'] }} week / {{ guest_usage['function2']['month'] }} month</div><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="guest_quota"><label class="check"><input type="checkbox" name="quota_enabled" value="1" {% if guestq.enabled %}checked{% endif %}> Enable generation quotas</label><div class="form-grid"><div class="field"><label>Requests per minute (0 = unset)</label><input type="number" min="0" name="quota_per_minute" value="{{ guestq.per_minute }}"></div><div class="field"><label>Requests per hour (0 = unset)</label><input type="number" min="0" name="quota_per_hour" value="{{ guestq.per_hour }}"></div><div class="field"><label>Requests per day (0 = unset)</label><input type="number" min="0" name="quota_per_day" value="{{ guestq.per_day }}"></div><div class="field"><label>Requests per week (rolling 7 days; 0 = unset)</label><input type="number" min="0" name="quota_per_week" value="{{ guestq.per_week }}"></div><div class="field"><label>Requests per month (rolling 30 days; 0 = unset)</label><input type="number" min="0" name="quota_per_month" value="{{ guestq.per_month }}"></div><label class="check"><input type="checkbox" name="quota_function1" value="1" {% if guestq.function1 %}checked{% endif %}> Function 1</label><label class="check"><input type="checkbox" name="quota_function2" value="1" {% if guestq.function2 %}checked{% endif %}> Function 2</label></div><button style="margin-top:8px">Save guest quotas</button></form><div class="hint">Disabled means no account quota is applied; the hard-coded global safety rate limit still applies.</div>
<h2>Create user</h2><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="add"><div class="form-grid"><input name="username" placeholder="Login username" required><input name="display_name" placeholder="Display name" required><input type="password" name="password" placeholder="Temporary password" required><label class="check"><input type="checkbox" name="is_admin" value="1"> Administrator</label></div><button style="margin-top:10px">Add user</button></form><h2>Users</h2><div class="field"><label for="admin-user-select">Select user to edit</label><select id="admin-user-select" class="user-select" onchange="showAdminUser(this.value)">{% for u in users %}<option value="{{ u['id'] }}">{{ u['display_name'] }} ({{ u['username'] }})</option>{% endfor %}</select></div>{% for u in users %}<div class="note admin-user-editor" id="admin-user-{{ u['id'] }}" style="margin-top:10px;{% if not loop.first %}display:none;{% endif %}"><form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="edit"><input type="hidden" name="user_id" value="{{ u['id'] }}"><div class="form-grid"><input name="username" value="{{ u['username'] }}"><input name="display_name" value="{{ u['display_name'] }}"><input type="password" name="reset_password" placeholder="New password (optional)"><label class="check"><input type="checkbox" name="is_admin" value="1" {% if u['is_admin'] %}checked{% endif %}> Administrator</label><div class="field full"><label>User-specific Function 2 secret override</label><div class="hint">Changing or clearing this override changes this user's Function 2 outputs. Administrator password confirmation is required.</div><input type="password" name="secret_override" placeholder="{% if u['secret_override'] %}Override set - leave blank to keep{% else %}Leave blank to use default secret{% endif %}"><label class="check"><input type="checkbox" name="clear_secret_override" value="1"> Clear override and use default secret</label><input type="password" name="admin_password" placeholder="Administrator password (required for secret change)" autocomplete="current-password"></div><div class="field full"><strong>Generation quotas</strong><label class="check"><input type="checkbox" name="quota_enabled" value="1" {% if u['quota_enabled'] %}checked{% endif %}> Enable generation quotas</label></div><div class="field"><label>Requests per minute (0 = unset)</label><input type="number" min="0" name="quota_per_minute" value="{{ u['quota_per_minute'] }}"></div><div class="field"><label>Requests per hour (0 = unset)</label><input type="number" min="0" name="quota_per_hour" value="{{ u['quota_per_hour'] }}"></div><div class="field"><label>Requests per day (0 = unset)</label><input type="number" min="0" name="quota_per_day" value="{{ u['quota_per_day'] }}"></div><div class="field"><label>Requests per week (rolling 7 days; 0 = unset)</label><input type="number" min="0" name="quota_per_week" value="{{ u['quota_per_week'] }}"></div><div class="field"><label>Requests per month (rolling 30 days; 0 = unset)</label><input type="number" min="0" name="quota_per_month" value="{{ u['quota_per_month'] }}"></div><label class="check"><input type="checkbox" name="quota_function1" value="1" {% if u['quota_function1'] %}checked{% endif %}> Function 1</label><label class="check"><input type="checkbox" name="quota_function2" value="1" {% if u['quota_function2'] %}checked{% endif %}> Function 2</label></div><div class="small">Usage — F1: {{ quota_usage[u['id']]['function1']['day'] }} today / {{ quota_usage[u['id']]['function1']['week'] }} week / {{ quota_usage[u['id']]['function1']['month'] }} month · F2: {{ quota_usage[u['id']]['function2']['day'] }} today / {{ quota_usage[u['id']]['function2']['week'] }} week / {{ quota_usage[u['id']]['function2']['month'] }} month</div><button style="margin-top:8px">Save user</button></form>{% if u['id'] != user['id'] %}<form method="post"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="{{ u['id'] }}"><button class="danger">Delete user</button></form>{% endif %}</div>{% endfor %}</div></div><script>function showAdminUser(id){document.querySelectorAll('.admin-user-editor').forEach(function(el){el.style.display=el.id==='admin-user-'+id?'':'none';});}function hotkeyTypingTarget(el){if(!el)return false;const tag=(el.tagName||'').toLowerCase();return tag==='input'||tag==='textarea'||tag==='select'||el.isContentEditable;}document.addEventListener('keydown',function(e){if(e.ctrlKey||e.metaKey||e.altKey||hotkeyTypingTarget(e.target))return;const k=e.key.toLowerCase();if(k==='1'){e.preventDefault();location.href='/?mode=random';}else if(k==='2'){e.preventDefault();location.href='/?mode=derived';}else if(k==='c'){e.preventDefault();location.href='/?hotkey=clear';}else if(k==='m'){e.preventDefault();location.href='/?hotkey=mask';}else if(k==='s'){e.preventDefault();location.href='/service-history';}else if(k==='p'){e.preventDefault();location.href='/account';}else if(k==='a'){e.preventDefault();location.href='/admin';}else if(k==='h'){e.preventDefault();location.href='/help';}});</script></body></html>
"""

INDEX_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Password Generator</title>
  <style>{{ css|safe }}</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>Password Generator</h1>
      <div class="subtitle">Cryptographically random passwords or deterministic, versioned credential-derived passwords.</div>
    </div>
    <nav class="nav"><a href="{{ url_for('help_page') }}">Help</a>{% if account_user %}<a href="{{ url_for('service_history_page') }}">Service History</a><a href="{{ url_for('account_page') }}">{{ account_user['display_name'] }}</a>{% endif %}<a href="{{ url_for('logout') }}">Log out</a></nav>
  </header>

  <div class="grid">
    <main>
      <div class="card">
        <div class="tabs">
          <div id="tab-random" class="tab active" onclick="switchMode('random')">Function 1: General Generator</div>
          <div id="tab-derived" class="tab" onclick="switchMode('derived')">Function 2: Credentials Generator</div>
        </div>

        <section id="random-pane">
          <h2>General Password Generator</h2>
          <div class="form-grid">
            <div class="field">
              <label for="r-length">Total characters</label>
              <input id="r-length" type="number" min="1" value="64">
            </div>
            <div class="field">
              <label for="r-upper">Uppercase letters</label>
              <input id="r-upper" type="number" min="0" value="4">
            </div>
            <div class="field">
              <label for="r-lower">Lowercase letters</label>
              <input id="r-lower" type="number" min="0" value="4">
            </div>
            <div class="field">
              <label for="r-digit">Numbers</label>
              <input id="r-digit" type="number" min="0" value="4">
            </div>
            <div class="field">
              <label for="r-special">Special characters</label>
              <input id="r-special" type="number" min="0" value="4">
            </div>
            <div class="field" style="justify-content:end">
              <label class="check"><input id="r-ambiguous" type="checkbox" checked> Exclude ambiguous characters</label>
              <div class="hint">Excludes visually confusing characters such as O/0, I/l/1, etc.</div>
            </div>
          </div>
          <div style="height:14px"></div>
          <div class="output-wrap">
            <div id="random-output" class="output" aria-live="polite">No password generated.</div>
          </div>
          <div class="controls" style="margin-top:10px">
            <button class="primary" onclick="generateRandom()">Generate</button>
            <button onclick="copyOutput('random-output')">Copy Output</button>
            <button onclick="clearOutput('random-output')">Clear Output</button>
          </div>
          <div id="random-message" class="message"></div>
        </section>

        <section id="derived-pane" style="display:none">
          <h2>Credentials-Based Password Generator</h2>
          <div class="note">
            Identical inputs reproduce the same password. Changing <strong>Version</strong> changes the derived password.
            Your <strong>Pass Key</strong> is the private input used with the credential details below. Function 2 always excludes visually ambiguous characters. Please read the <a href="{{ url_for('help_page') }}">Help page</a> before relying on deterministic retrieval.
          </div>
          <div style="height:14px"></div>
          <div class="form-grid">
            <div class="field full">
              <label for="d-pass-key">Pass Key</label>
              <input id="d-pass-key" type="password" autocomplete="off" value="{{ saved_pass_key }}">
              <div class="hint">Mandatory; minimum <span id="pass-key-min">{{ pass_key_min }}</span> characters.</div>
            </div>
            <div class="field">
              <label for="d-service">Service</label>
              <div class="service-suggest-wrap">
                <input id="d-service" type="text" autocapitalize="none" autocomplete="off" aria-autocomplete="list" aria-controls="service-suggestions" aria-expanded="false">
                <div id="service-suggestions" class="service-suggest-box" role="listbox"></div>
              </div>
              <div class="hint">Letters, numbers, spaces, and hyphens (-) only. Service is converted to lowercase before password generation. Spacing and hyphens remain significant and must be entered consistently.</div>
            </div>
            <div class="field">
              <label for="d-email">Email address</label>
              <input id="d-email" type="email" autocapitalize="none" autocomplete="off">
              <div class="hint">Optional. Lowercase only; minimum format x@x.x. At least Email or Username must be provided.</div>
            </div>
            <div class="field">
              <label for="d-username">Username</label>
              <input id="d-username" type="text" autocapitalize="none" autocomplete="off">
              <div class="hint">Optional. Lowercase only; no spaces. At least Email or Username must be provided.</div>
            </div>
            <div class="field">
              <label for="d-version">Version</label>
              <input id="d-version" type="number" min="0" step="1" value="0">
              <div class="hint">Non-negative integer; 0 is valid.</div>
            </div>
            <div class="field">
              <label for="d-length">Password Length</label>
              <input id="d-length" type="number" min="{{ derived_min }}" value="32">
              <div class="hint">Minimum {{ derived_min }}. Blank or below minimum becomes {{ derived_min }}.</div>
            </div>
          </div>
          <div style="height:14px"></div>
          <div class="output-wrap">
            <div id="derived-output" class="output" aria-live="polite">No password generated.</div>
          </div>
          <div class="controls" style="margin-top:10px">
            <button class="primary" onclick="generateDerived()">Generate</button>
            <button onclick="copyOutput('derived-output')">Copy Output</button>
            <button onclick="clearOutput('derived-output')">Clear Output</button>
          </div>
          <div id="derived-message" class="message"></div>
        </section>
      </div>

      <div class="card">
        <h2>Security & Privacy</h2>
        <div class="small">
          Password history is stored only in server RAM for this browser session, separately for each generator mode.
          Generated password values, IP addresses, and browser fingerprints are not persisted to disk. Signed-in users may optionally store their Pass Key encrypted for Function 2 retrieval.
          The browser receives only a random opaque session identifier.
        </div>
      </div>
    </main>

    <aside id="history-card" class="card">
      <h2>Session History</h2>
      <div id="history-summary" class="small" style="margin-bottom:10px">Generated passwords for Function 1 in this browser session.</div>
      <label class="check" style="margin-bottom:10px"><input id="reveal-history" type="checkbox" onchange="renderHistory()"> Reveal history</label>
      <div id="history"></div>
      <button class="danger" style="margin-top:10px;width:100%" onclick="clearHistory()">Clear History</button>
    </aside>
  </div>
  <footer>Runs in memory only. Listening on {{ host }}:{{ port }}.{% if not secure_cookies %} Development mode: Secure cookies are disabled; use HTTPS and PASSGEN_SECURE_COOKIES=1 for network deployment.{% endif %}</footer>
</div>

<script>
let CSRF = {{ csrf|tojson }};
let activeMode = 'random';
let currentHistory = [];
let HOTKEY_ACCOUNT = {{ (account_user is not none)|tojson }};
let HOTKEY_ADMIN = {{ (account_user and account_user['is_admin'])|tojson }};
const SERVICE_HISTORY = {{ service_suggestions|tojson }};
let serviceSuggestionIndex = -1;

function setMessage(id, text, ok=false) {
  const el = document.getElementById(id);
  el.textContent = text || '';
  el.className = ok ? 'message success' : 'message';
}

function renderServiceSuggestions() {
  const input = document.getElementById('d-service');
  const box = document.getElementById('service-suggestions');
  if (!input || !box) return;
  const q = input.value.toLowerCase();
  if (q.length < 1) {
    box.style.display = 'none';
    box.innerHTML = '';
    input.setAttribute('aria-expanded', 'false');
    serviceSuggestionIndex = -1;
    return;
  }
  const matches = SERVICE_HISTORY.filter(service => service.toLowerCase().includes(q));
  if (!matches.length) {
    box.style.display = 'none';
    box.innerHTML = '';
    input.setAttribute('aria-expanded', 'false');
    serviceSuggestionIndex = -1;
    return;
  }
  serviceSuggestionIndex = -1;
  box.innerHTML = matches.map((service, i) => '<div class="service-suggest-item" role="option" data-index="' + i + '">' + escapeHtml(service) + '</div>').join('');
  box.style.display = 'block';
  input.setAttribute('aria-expanded', 'true');
  box.querySelectorAll('.service-suggest-item').forEach((item, i) => {
    item.addEventListener('mousedown', event => {
      event.preventDefault();
      input.value = matches[i];
      box.style.display = 'none';
      input.setAttribute('aria-expanded', 'false');
      serviceSuggestionIndex = -1;
      input.focus();
    });
  });
}

function moveServiceSuggestion(direction) {
  const box = document.getElementById('service-suggestions');
  const items = Array.from(box.querySelectorAll('.service-suggest-item'));
  if (!items.length || box.style.display === 'none') return false;
  serviceSuggestionIndex = (serviceSuggestionIndex + direction + items.length) % items.length;
  items.forEach((item, i) => item.classList.toggle('active', i === serviceSuggestionIndex));
  items[serviceSuggestionIndex].scrollIntoView({block:'nearest'});
  return true;
}

async function api(path, payload={}) {
  const body = new URLSearchParams();
  body.set('csrf', CSRF);
  Object.entries(payload).forEach(([k,v]) => body.set(k, v));
  const res = await fetch(path, {
    method: 'POST',
    headers: {'X-CSRF-Token': CSRF, 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
    body,
    cache: 'no-store'
  });
  const data = await res.json().catch(() => ({ok:false, error:'Unexpected server response.'}));
  if (!res.ok || !data.ok) throw new Error(data.error || 'Request failed.');
  return data;
}

function switchMode(mode) {
  const random = mode === 'random';
  document.getElementById('random-pane').style.display = random ? '' : 'none';
  document.getElementById('derived-pane').style.display = random ? 'none' : '';
  document.getElementById('tab-random').classList.toggle('active', random);
  document.getElementById('tab-derived').classList.toggle('active', !random);
  activeMode = mode;
  document.getElementById('history-summary').textContent = random
    ? 'Generated passwords for Function 1 in this browser session.'
    : 'Generated passwords for Function 2 in this browser session.';
  refreshHistory().then(syncHistoryHeight);
  requestAnimationFrame(syncHistoryHeight);
}

async function generateRandom() {
  setMessage('random-message', '');
  try {
    const data = await api('{{ url_for("generate_random_api") }}', {
      length: document.getElementById('r-length').value,
      upper: document.getElementById('r-upper').value,
      lower: document.getElementById('r-lower').value,
      digits: document.getElementById('r-digit').value,
      special: document.getElementById('r-special').value,
      ambiguous: document.getElementById('r-ambiguous').checked ? '1' : '0',
      history_capacity: historyCapacity()
    });
    document.getElementById('random-output').textContent = data.password;
    await refreshHistory();
  } catch (e) {
    setMessage('random-message', e.message);
  }
}

async function generateDerived() {
  setMessage('derived-message', '');
  const length = document.getElementById('d-length').value;
  try {
    const data = await api('{{ url_for("generate_derived_api") }}', {
      pass_key: document.getElementById('d-pass-key').value,
      service: document.getElementById('d-service').value,
      email: document.getElementById('d-email').value,
      username: document.getElementById('d-username').value,
      version: document.getElementById('d-version').value,
      length: length,
      history_capacity: historyCapacity()
    });
    document.getElementById('d-length').value = data.length;
    document.getElementById('d-service').value = data.service;
    document.getElementById('derived-output').textContent = data.password;
    await refreshHistory();
  } catch (e) {
    setMessage('derived-message', e.message);
  }
}

async function refreshHistory() {
  const res = await fetch('{{ url_for("history_api") }}?mode=' + encodeURIComponent(activeMode), {cache:'no-store'});
  const data = await res.json();
  currentHistory = data.history || [];
  renderHistory();
}

function renderHistory() {
  const el = document.getElementById('history');
  const reveal = document.getElementById('reveal-history').checked;
  if (!currentHistory.length) {
    el.innerHTML = '<div class="history-empty">No passwords generated in this session.</div>';
    return;
  }
  const visibleHistory = currentHistory.slice(0, historyCapacity());
  el.innerHTML = visibleHistory.map((x, i) => {
    if (!reveal) {
      return '<div class="history-item" title="History item masked">' + '•'.repeat(Math.min(Math.max(x.password.length, 8), 64)) + '</div>';
    }
    return '<div class="history-item" title="Click to copy" onclick="copyText(currentHistory[' + i + '].password)">' + escapeHtml(x.password) + '</div>';
  }).join('');
}

async function clearHistory() {
  try {
    const data = await api('{{ url_for("clear_history_api") }}');
    if (data.csrf) CSRF = data.csrf;
    currentHistory = [];
    document.getElementById('reveal-history').checked = false;
    renderHistory();
  } catch (e) {
    alert(e.message);
  }
}

function clearOutput(id) {
  document.getElementById(id).textContent = 'No password generated.';
}

async function copyOutput(id) {
  const text = document.getElementById(id).textContent;
  if (!text || text === 'No password generated.') return;
  await copyText(text);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
  }
}


function escapeHtml(s) {
  return s.replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

const serviceInput = document.getElementById('d-service');
if (serviceInput) {
  serviceInput.addEventListener('input', renderServiceSuggestions);
  serviceInput.addEventListener('focus', renderServiceSuggestions);
  serviceInput.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' && moveServiceSuggestion(1)) event.preventDefault();
    else if (event.key === 'ArrowUp' && moveServiceSuggestion(-1)) event.preventDefault();
    else if (event.key === 'Enter' && serviceSuggestionIndex >= 0) {
      const item = document.querySelectorAll('#service-suggestions .service-suggest-item')[serviceSuggestionIndex];
      if (item) { event.preventDefault(); serviceInput.value = item.textContent; document.getElementById('service-suggestions').style.display='none'; serviceInput.setAttribute('aria-expanded','false'); serviceSuggestionIndex=-1; }
    } else if (event.key === 'Escape') {
      document.getElementById('service-suggestions').style.display='none'; serviceInput.setAttribute('aria-expanded','false'); serviceSuggestionIndex=-1;
    }
  });
  serviceInput.addEventListener('blur', () => setTimeout(() => { const box=document.getElementById('service-suggestions'); box.style.display='none'; serviceInput.setAttribute('aria-expanded','false'); serviceSuggestionIndex=-1; }, 100));
}

refreshHistory().then(syncHistoryHeight);
window.addEventListener('resize', syncHistoryHeight);

function hotkeyTypingTarget(el) {
  if (!el) return false;
  const tag = (el.tagName || '').toLowerCase();
  return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
}

document.addEventListener('keydown', function(e) {
  if (e.ctrlKey || e.metaKey || e.altKey || hotkeyTypingTarget(e.target)) return;
  const key = e.key.toLowerCase();
  if (key === '1') { e.preventDefault(); switchMode('random'); return; }
  if (key === '2') { e.preventDefault(); switchMode('derived'); return; }
  if (key === 's' && HOTKEY_ACCOUNT) { e.preventDefault(); location.href='{{ url_for("service_history_page") }}'; return; }
  if (key === 'c') { e.preventDefault(); clearHistory(); return; }
  if (key === 'p' && HOTKEY_ACCOUNT) { e.preventDefault(); location.href='{{ url_for("account_page") }}'; return; }
  if (key === 'a' && HOTKEY_ADMIN) { e.preventDefault(); location.href='{{ url_for("admin_page") }}'; return; }
  if (key === 'h') { e.preventDefault(); location.href='{{ url_for("help_page") }}'; return; }
  if (key === 'm') {
    e.preventDefault();
    const box=document.getElementById('reveal-history');
    if (box) { box.checked=!box.checked; renderHistory(); }
  }
});

const urlParams = new URLSearchParams(window.location.search);
const requestedService = urlParams.get('service');
if (requestedService && document.getElementById('d-service')) document.getElementById('d-service').value=requestedService;
const requestedMode = urlParams.get('mode');
if (requestedMode === 'derived') switchMode('derived');
else if (requestedMode === 'random') switchMode('random');
const requestedHotkey = urlParams.get('hotkey');
if (requestedHotkey === 'clear') clearHistory();
else if (requestedHotkey === 'mask') { const box=document.getElementById('reveal-history'); if(box){box.checked=!box.checked;renderHistory();} }
function historyCapacity() {
  const history = document.getElementById('history');
  if (!history) return 1;
  return Math.max(1, Math.floor(history.clientHeight / 37));
}

function syncHistoryHeight() {
  const main = document.querySelector('.grid > main');
  const historyCard = document.getElementById('history-card');
  if (main && historyCard && window.innerWidth > 880) {
    historyCard.style.height = main.offsetHeight + 'px';
  } else if (historyCard) {
    historyCard.style.height = '';
  }
  renderHistory();
}
</script>
</body>
</html>
"""

HELP_HTML = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Password Generator - Help</title><style>{{ css|safe }}</style></head><body><div class="container help"><header><div><h1>Password Generator Help</h1><div class="subtitle">How the two generator modes work.</div></div><nav class="nav"><a href="{{ url_for('index') }}">Generator</a></nav></header><div class="card"><div class="toc"><strong>Table of contents</strong><ol><li><a href="#general">General Password Generator</a></li><li><a href="#derived">Credentials-Based Password Generator</a></li><li><a href="#versioning">Versioning and reproducibility</a></li><li><a href="#howto">How to</a></li><li><a href="#examples">Dummy examples</a></li></ol></div>
<h2 id="general">1. General Password Generator</h2><p>Choose the total length and the exact minimum counts for uppercase, lowercase, numeric, and special characters. The remaining positions are filled randomly from the complete available character pool.</p><p>When ambiguous characters are excluded, characters commonly confused visually are removed from the relevant pools. Generate uses Python's cryptographically secure <code>secrets</code> module.</p>
<h2 id="derived">2. Credentials-Based Password Generator</h2><p>Function 2 deterministically derives a password from your Pass Key and the credential context: Service, email, username, version, and requested password length. The same complete input set reproduces the same password. Function 2 always excludes visually ambiguous characters from generated passwords.</p><p>Your Pass Key must be entered exactly the same way whenever you need to retrieve the same password. Email and Username are optional individually, but at least one must be supplied.</p>
<h2 id="versioning">3. Versioning and reproducibility</h2><p>Use Version <code>0</code> for an initial version if desired, then increment it whenever you need a new derived password. Keep the exact same other inputs when rotating, and change only the version.</p><pre>Version 1 -> deterministic password A
Version 2 -> deterministic password B
Version 1 again -> deterministic password A</pre>
<h2 id="howto">4. How to</h2><p><strong>Function 1:</strong> Set your desired password requirements, then press <strong>Generate</strong>. Generate again at any time for a new random password using the same settings.</p><p><strong>Function 2:</strong> Keep your Pass Key secure and consistent. Enter the same Service and account details used originally to retrieve the same generated password.</p><p>For <strong>Service</strong>, use letters, numbers, whitespace, and hyphens only. Service is automatically converted to lowercase before password generation, so capitalisation does not change the result. Spacing and hyphens remain significant: for example, <strong>miller and carter</strong> and <strong>miller-and-carter</strong> are different Service values and will generate different passwords.</p><p>This app is a password generator and deterministic retriever, not a password manager. It does not store generated passwords.</p>
<h2 id="examples">5. Dummy examples</h2><h3>Example 1</h3><pre>Input:
Pass Key: [dummy]
Service: [dummy service]
Version: 1
Email: [dummy@example.test]
Username: [dummy]
Password Length: 32

Output:
[dummy generated output]</pre><h3>Example 2</h3><pre>Input:
Pass Key: [dummy]
Service: [dummy-service-2]
Version: 2
Email: [dummy@example.test]
Username: [dummy]
Password Length: 32

Output:
[dummy generated output]</pre><h3>Example 3</h3><pre>Input:
Pass Key: [dummy]
Service: [Dummy Service 3]
Version: 3
Email: [dummy@example.test]
Username: [dummy]
Password Length: 32

Output:
[dummy generated output]</pre></div></div></body></html>
"""


def _saved_pass_key() -> str:
    """Return the signed-in user's saved Function 2 Pass Key."""
    user = _current_user()
    state = _account()
    if not user or not state:
        return ""
    try:
        return _open(user["saved_pass_key"], state["vault_key"]) if user["saved_pass_key"] else ""
    except Exception:
        return ""


def _service_suggestions() -> list[str]:
    """Return this signed-in user's Service History for browser suggestions."""
    user = _current_user()
    if not user or not user["service_history_enabled"]:
        return []
    with _db() as db:
        rows = db.execute(
            "SELECT service FROM service_history WHERE user_id=? ORDER BY last_used_at DESC, service COLLATE NOCASE",
            (user["id"],),
        ).fetchall()
    return [row["service"] for row in rows]


SERVICE_HISTORY_HTML = r"""
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Service History</title><style>{{ css|safe }}
.service-row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:10px}.service-name{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;word-break:break-word}.service-actions{flex:0 0 auto}@media(max-width:560px){.service-row{align-items:flex-start;flex-direction:column}}
</style></head><body><div class="container help"><header><div><h1>Service History</h1><div class="subtitle">Services successfully used with Function 2.</div></div><nav class="nav"><a href="/">Generator</a><a href="/account">Account</a>{% if user['is_admin'] %}<a href="/admin">Admin</a>{% endif %}<a href="/logout">Log out</a></nav></header>{% if msg %}<div class="note">{{ msg }}</div>{% endif %}<div class="card"><h2>Saved Services</h2><div class="hint">Only Service values are stored here. No Pass Keys, email addresses, usernames, or generated passwords are included in Service History.</div><form method="post" style="margin-top:14px"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="setting"><label class="check"><input type="checkbox" name="service_history_enabled" value="1" {% if user['service_history_enabled'] %}checked{% endif %}> Enable Service History</label><div class="hint">When disabled, new Service values are not recorded and Service suggestions are disabled. Existing entries remain here until you delete them.</div><button style="margin-top:8px">Save setting</button></form>{% if services %}{% for item in services %}<div class="note service-row"><div><div class="service-name"><a href="/?mode=derived&amp;service={{ item['service']|urlencode }}" title="Open Function 2 with this Service">{{ item['service'] }}</a></div><div class="small">Last used {{ item['last_used_at'] }}</div></div><form method="post" class="service-actions" onsubmit="return confirm('Delete this Service History entry? This action cannot be undone.');"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="delete"><input type="hidden" name="service_id" value="{{ item['id'] }}"><button class="danger">Delete</button></form></div>{% endfor %}<form method="post" style="margin-top:18px" onsubmit="return confirm('Clear your entire Service History? This action cannot be undone.');"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="action" value="clear"><button class="danger">Clear All Service History</button></form>{% else %}<div class="history-empty" style="margin-top:12px">No Service History yet. A Service is added after Function 2 successfully generates a password.</div>{% endif %}</div></div><script>
function hotkeyTypingTarget(el){if(!el)return false;const tag=(el.tagName||'').toLowerCase();return tag==='input'||tag==='textarea'||tag==='select'||el.isContentEditable;}
document.addEventListener('keydown',function(e){if(e.ctrlKey||e.metaKey||e.altKey||hotkeyTypingTarget(e.target))return;const k=e.key.toLowerCase();if(k==='1'){e.preventDefault();location.href='/?mode=random';return;}if(k==='2'){e.preventDefault();location.href='/?mode=derived';return;}if(k==='c'){e.preventDefault();location.href='/?hotkey=clear';return;}if(k==='m'){e.preventDefault();location.href='/?hotkey=mask';return;}if(k==='s'){e.preventDefault();location.href='/service-history';return;}if(k==='p'){e.preventDefault();location.href='/account';return;}if(k==='h'){e.preventDefault();location.href='/help';return;}{% if user and user['is_admin'] %}if(k==='a'){e.preventDefault();location.href='/admin';return;}{% endif %}});
</script></body></html>
"""


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error=""
    keys = _login_protection_keys()
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        remaining = _login_lock_remaining(keys)
        if remaining > 0:
            error=f"Too many incorrect password attempts. Login is locked for another {remaining} seconds."
        elif not _login_submission_allowed(keys):
            error="Login password submissions are limited to 1 per second. Please wait and try again."
        else:
            raw_uid=(request.form.get("user_id") or "").strip()
            if not raw_uid:
                error="Please select a registered user."
            else:
                try:
                    uid=int(raw_uid)
                except ValueError:
                    uid=0
                with _db() as db:
                    user=db.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
                password=request.form.get("password","")
                if user and _password_ok(password, user["password_hash"]):
                    _clear_login_failures(keys)
                    token=secrets.token_urlsafe(32)
                    key=_vault_key(password, user["vault_salt"])
                    if user["saved_pass_key"] and not user["saved_pass_key"].startswith("gcm:"):
                        try:
                            migrated=_seal(_open(user["saved_pass_key"],key),key)
                            with _db() as mdb: mdb.execute("UPDATE users SET saved_pass_key=? WHERE id=?",(migrated,user["id"]))
                        except Exception:
                            pass
                    with ACCOUNT_LOCK:
                        ACCOUNT_SESSIONS[token]={"user_id":user["id"],"vault_key":key,"last_seen":time.time()}
                    resp=redirect(url_for("account_page") if user["must_change_password"] else url_for("index"))
                    resp.set_cookie("pg_account",token,max_age=_session_ttl(),httponly=True,samesite="Strict",secure=app.config["SESSION_COOKIE_SECURE"])
                    _set_session_cookie(resp, request._pg_sid)
                    return resp
                _record_login_failure(keys)
                remaining = _login_lock_remaining(keys)
                error=(f"Too many incorrect password attempts. Login is locked for {LOGIN_LOCKOUT_SECONDS // 60} minutes."
                       if remaining > 0 else "Invalid password.")
    with _db() as db: users=db.execute("SELECT id,display_name FROM users ORDER BY display_name COLLATE NOCASE").fetchall()
    resp=make_response(render_template_string(LOGIN_HTML,css=BASE_CSS,users=users,error=error,csrf=request._pg_state["csrf"]))
    _set_session_cookie(resp, request._pg_sid)
    return resp

@app.route("/guest")
def guest_login():
    resp=redirect(url_for("index")); resp.set_cookie("pg_guest","1",max_age=_session_ttl(),httponly=True,samesite="Strict",secure=app.config["SESSION_COOKIE_SECURE"]); return resp

@app.route("/logout")
def logout():
    token=request.cookies.get("pg_account")
    with ACCOUNT_LOCK: ACCOUNT_SESSIONS.pop(token,None)
    resp=redirect(url_for("login")); resp.delete_cookie("pg_account"); resp.delete_cookie("pg_guest"); return resp

@app.route("/account", methods=["GET","POST"])
def account_page():
    user=_current_user()
    if not user: return redirect(url_for("login"))
    msg=""; revealed=None; state=_account(); key=state["vault_key"]
    if request.method=="POST":
        if not _csrf_ok(): abort(403)
        action=request.form.get("action")
        with _db() as db:
            if action=="password":
                if not _password_ok(request.form.get("current",""),user["password_hash"]): msg="Current password is incorrect."
                elif len(request.form.get("new",""))<12: msg="New password must be at least 12 characters."
                else:
                    oldkey=key; newpw=request.form["new"]; newkey=_vault_key(newpw,user["vault_salt"])
                    def reseal(v): return _seal(_open(v,oldkey),newkey) if v else v
                    db.execute("UPDATE users SET password_hash=?,must_change_password=0,saved_pass_key=? WHERE id=?",(_password_hash(newpw),reseal(user["saved_pass_key"]),user["id"]))
                    state["vault_key"]=newkey; key=newkey
                    with ACCOUNT_LOCK:
                        for tok,st in list(ACCOUNT_SESSIONS.items()):
                            if st.get("user_id")==user["id"] and tok != request.cookies.get("pg_account"): ACCOUNT_SESSIONS.pop(tok,None)
                    msg="Password changed. Other sessions were logged out."
            elif action=="pass_key":
                pass_key=request.form.get("pass_key","")
                if pass_key and len(pass_key) < PASS_KEY_MIN_LENGTH: msg=f"Pass Key must be at least {PASS_KEY_MIN_LENGTH} characters."; pass_key=""
                if len(pass_key) > PASS_KEY_MAX_LENGTH: msg=f"Pass Key must not exceed {PASS_KEY_MAX_LENGTH} characters."; pass_key=""
                saved_pass_key=_seal(pass_key,key) if pass_key else user["saved_pass_key"]
                db.execute("UPDATE users SET saved_pass_key=? WHERE id=?",(saved_pass_key,user["id"])); msg="Pass Key saved encrypted."
            elif action=="reveal_pass_key":
                if not _password_ok(request.form.get("verify",""),user["password_hash"]): msg="Account password is incorrect."
                else: revealed=_open(user["saved_pass_key"],key) if user["saved_pass_key"] else ""
            elif action=="service_history_setting":
                enabled=1 if request.form.get("service_history_enabled")=="1" else 0
                db.execute("UPDATE users SET service_history_enabled=? WHERE id=?",(enabled,user["id"]))
                msg="Service History enabled." if enabled else "Service History disabled. Existing history has been kept."
            elif action=="logout_all":
                if not _password_ok(request.form.get("verify",""),user["password_hash"]): msg="Account password is incorrect."
                else:
                    with ACCOUNT_LOCK:
                        for tok,st in list(ACCOUNT_SESSIONS.items()):
                            if st.get("user_id")==user["id"] and tok != request.cookies.get("pg_account"): ACCOUNT_SESSIONS.pop(tok,None)
                    msg="All other sessions logged out."
            elif action=="remove_pass_key":
                if not _password_ok(request.form.get("verify",""),user["password_hash"]):
                    msg="Account password is incorrect. Saved Pass Key was not removed."
                else:
                    db.execute("UPDATE users SET saved_pass_key=NULL WHERE id=?",(user["id"],))
                    msg="Saved Pass Key removed. Function 2 will now require manual Pass Key entry."
        user=_current_user()
    return render_template_string(ACCOUNT_HTML,css=BASE_CSS,user=user,msg=msg,revealed=revealed,csrf=request._pg_state["csrf"],pass_key_max=PASS_KEY_MAX_LENGTH)

@app.route("/service-history", methods=["GET", "POST"])
def service_history_page():
    user = _current_user()
    if not user:
        return redirect(url_for("login"))
    msg = ""
    if request.method == "POST":
        if not _csrf_ok(): abort(403)
        action = request.form.get("action")
        with _db() as db:
            if action == "setting":
                enabled = 1 if request.form.get("service_history_enabled") == "1" else 0
                db.execute("UPDATE users SET service_history_enabled=? WHERE id=?", (enabled, user["id"]))
                msg = "Service History enabled." if enabled else "Service History disabled. Existing history has been kept."
            elif action == "delete":
                db.execute(
                    "DELETE FROM service_history WHERE id=? AND user_id=?",
                    (request.form.get("service_id"), user["id"]),
                )
                msg = "Service History entry deleted."
            elif action == "clear":
                db.execute("DELETE FROM service_history WHERE user_id=?", (user["id"],))
                msg = "Service History cleared."
    user = _current_user()
    with _db() as db:
        services = db.execute(
            "SELECT id,service,created_at,last_used_at FROM service_history WHERE user_id=? ORDER BY last_used_at DESC, id DESC",
            (user["id"],),
        ).fetchall()
    return render_template_string(SERVICE_HISTORY_HTML, css=BASE_CSS, user=user, services=services, msg=msg, csrf=request._pg_state["csrf"])


@app.route("/admin",methods=["GET","POST"])
def admin_page():
    user=_current_user()
    if not user or not user["is_admin"]: abort(403)
    msg=""
    if request.method=="POST":
        if not _csrf_ok(): abort(403)
        a=request.form.get("action")
        try:
            with _db() as db:
                if a=="default_secret":
                    if not _password_ok(request.form.get("admin_password",""),user["password_hash"]): msg="Administrator password is incorrect. Secret was not changed."
                    else: db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('default_secret',?)",(request.form.get("secret",""),)); msg="Default secret changed. Function 2 outputs using the old secret will no longer be reproducible with the new secret."
                elif a=="session_ttl":
                    minutes=_parse_nonnegative_int(request.form.get("session_minutes",""),"Session timeout")
                    if minutes < 5: raise ValueError("Session timeout must be at least 5 minutes.")
                    db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('account_session_ttl_seconds',?)",(str(minutes*60),)); msg="Session timeout saved."
                elif a=="guest_quota":
                    q=_quota_values_from_form()
                    for k,v in q.items(): db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",("guest_quota_"+k,str(v)))
                    msg="Guest quotas saved."
                elif a=="add": db.execute("INSERT INTO users(username,display_name,password_hash,is_admin,must_change_password,vault_salt) VALUES(?,?,?,?,1,?)",(request.form.get("username",""),request.form.get("display_name",""),_password_hash(request.form.get("password","")),1 if request.form.get("is_admin")=="1" else 0,secrets.token_bytes(16))); msg="User added."
                elif a=="edit":
                    uid=int(request.form.get("user_id","0")); reset=request.form.get("reset_password",""); override=request.form.get("secret_override",""); q=_quota_values_from_form()
                    vals=[request.form.get("username",""),request.form.get("display_name",""),1 if request.form.get("is_admin")=="1" else 0]
                    db.execute("UPDATE users SET username=?,display_name=?,is_admin=?,quota_enabled=?,quota_per_minute=?,quota_per_hour=?,quota_per_day=?,quota_per_week=?,quota_per_month=?,quota_function1=?,quota_function2=? WHERE id=?",(*vals,q["enabled"],q["per_minute"],q["per_hour"],q["per_day"],q["per_week"],q["per_month"],q["function1"],q["function2"],uid))
                    secret_change = request.form.get("clear_secret_override")=="1" or bool(override)
                    if secret_change and not _password_ok(request.form.get("admin_password",""),user["password_hash"]):
                        raise ValueError("Administrator password is required to change a user secret override.")
                    if request.form.get("clear_secret_override")=="1": db.execute("UPDATE users SET secret_override=NULL WHERE id=?",(uid,))
                    elif override: db.execute("UPDATE users SET secret_override=? WHERE id=?",(override,uid))
                    if reset:
                        db.execute("UPDATE users SET password_hash=?,must_change_password=1,saved_pass_key=NULL WHERE id=?",(_password_hash(reset),uid)); msg="User updated. Password reset clears that user's saved encrypted Pass Key because the old encryption key is unavailable."
                    else: msg="User updated."
                elif a=="delete" and int(request.form.get("user_id","0"))!=user["id"]: db.execute("DELETE FROM users WHERE id=?",(request.form.get("user_id"),)); msg="User deleted."
        except ValueError as exc: msg=str(exc)
    with _db() as db:
        users=db.execute("SELECT id,username,display_name,is_admin,secret_override,quota_enabled,quota_per_minute,quota_per_hour,quota_per_day,quota_per_week,quota_per_month,quota_function1,quota_function2 FROM users ORDER BY display_name COLLATE NOCASE").fetchall()
        gr={r["key"]:r["value"] for r in db.execute("SELECT key,value FROM settings WHERE key LIKE 'guest_quota_%'").fetchall()}
    guestq={k:int(gr.get("guest_quota_"+k,"0")) for k in ("enabled","per_minute","per_hour","per_day","per_week","per_month","function1","function2")}
    now=time.time(); quota_usage={}; guest_usage={}
    with _db() as db:
        for fn in ("function1","function2"):
            guest_usage[fn]={label:db.execute("SELECT COUNT(*) FROM quota_usage WHERE subject='guest' AND function_name=? AND used_at>=?",(fn,now-secs)).fetchone()[0] for label,secs in (("minute",60),("hour",3600),("day",86400),("week",7*86400),("month",30*86400))}
        for u in users:
            subject="user:"+str(u["id"]); quota_usage[u["id"]]={}
            for fn in ("function1","function2"):
                quota_usage[u["id"]][fn]={label:db.execute("SELECT COUNT(*) FROM quota_usage WHERE subject=? AND function_name=? AND used_at>=?",(subject,fn,now-secs)).fetchone()[0] for label,secs in (("minute",60),("hour",3600),("day",86400),("week",7*86400),("month",30*86400))}
    return render_template_string(ADMIN_HTML,css=BASE_CSS,user=user,users=users,msg=msg,guestq=guestq,csrf=request._pg_state["csrf"],quota_usage=quota_usage,guest_usage=guest_usage,session_ttl=_session_ttl())

@app.route("/", methods=["GET"])
def index():
    response = make_response(
        render_template_string(
            INDEX_HTML,
            css=BASE_CSS,
            csrf=request._pg_state["csrf"],
            pass_key_min=PASS_KEY_MIN_LENGTH,
            derived_min=DERIVED_PASSWORD_MIN_LENGTH,
            host=HOST,
            port=PORT,
            account_user=_current_user(),
            saved_pass_key=_saved_pass_key(),
            service_suggestions=_service_suggestions(),
            secure_cookies=app.config["SESSION_COOKIE_SECURE"],
        )
    )
    _set_session_cookie(response, request._pg_sid)
    return response


@app.route("/help", methods=["GET"])
def help_page():
    response = make_response(
        render_template_string(
            HELP_HTML,
            css=BASE_CSS,
            user=_current_user(),
        )
    )
    _set_session_cookie(response, request._pg_sid)
    return response


@app.route("/api/history", methods=["GET"])
def history_api():
    state = request._pg_state
    mode = request.args.get("mode", "random")
    key = "derived_history" if mode == "derived" else "random_history"
    history = [{"password": p, "created": ts} for p, ts in state[key]]
    return jsonify(ok=True, history=history)


@app.route("/api/history/clear", methods=["POST"])
def clear_history_api():
    if not _csrf_ok():
        abort(403)
    sid = request._pg_sid
    state = request._pg_state
    state["random_history"].clear()
    state["derived_history"].clear()
    state["request_times"].clear()
    # Remove the complete server-side session record, including both histories, CSRF,
    # rate-limit timestamps and other session metadata. A fresh session is created
    # immediately so the current page can continue operating without persistence.
    with SESSIONS_LOCK:
        SESSIONS.pop(sid, None)
    new_sid, new_state = _new_session()
    request._pg_sid = new_sid
    request._pg_state = new_state
    response = jsonify(ok=True, csrf=new_state["csrf"])
    _set_session_cookie(response, new_sid)
    return response


def _history_capacity_from_request() -> int:
    # Capacity is layout-derived in the browser rather than a fixed history limit.
    # The upper guard only prevents an unreasonable client value consuming memory.
    try:
        capacity = int(request.form.get("history_capacity", "1"))
    except (TypeError, ValueError):
        capacity = 1
    return max(1, min(capacity, 500))


def _add_history(password: str, mode: str):
    key = "derived_history" if mode == "derived" else "random_history"
    history = request._pg_state[key]
    history.appendleft((password, time.strftime("%Y-%m-%d %H:%M:%S")))
    capacity = _history_capacity_from_request()
    while len(history) > capacity:
        history.pop()


@app.route("/api/generate/random", methods=["POST"])
def generate_random_api():
    if not _csrf_ok():
        abort(403)
    try:
        _consume_generation_quota("function1")
        length = _parse_nonnegative_int(request.form.get("length", ""), "Total characters")
        upper = _parse_nonnegative_int(request.form.get("upper", "0"), "Uppercase letters")
        lower = _parse_nonnegative_int(request.form.get("lower", "0"), "Lowercase letters")
        digits = _parse_nonnegative_int(request.form.get("digits", "0"), "Numbers")
        special = _parse_nonnegative_int(request.form.get("special", "0"), "Special characters")
        ambiguous = request.form.get("ambiguous") == "1"
        password = generate_random_password(length, upper, lower, digits, special, ambiguous)
        _add_history(password, "random")
        return jsonify(ok=True, password=password)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400


@app.route("/api/generate/derived", methods=["POST"])
def generate_derived_api():
    if not _csrf_ok():
        abort(403)
    try:
        _consume_generation_quota("function2")
        pass_key = request.form.get("pass_key", "")
        service = _validate_service(request.form.get("service", ""))
        # Normalize identity context before validation and deterministic password generation.
        email_raw = (request.form.get("email", "") or "").strip().lower()
        username_raw = (request.form.get("username", "") or "").strip().lower()
        email = _validate_email(email_raw) if email_raw else "0"
        username = _validate_username(username_raw) if username_raw else "0"
        if email == "0" and username == "0":
            raise ValueError("At least one of Email address or Username must be provided.")
        if len(pass_key) > PASS_KEY_MAX_LENGTH:
            raise ValueError(f"Pass Key must not exceed {PASS_KEY_MAX_LENGTH} characters.")
        if len(pass_key) < PASS_KEY_MIN_LENGTH:
            raise ValueError(f"Pass Key must be at least {PASS_KEY_MIN_LENGTH} characters long.")
        version = _parse_nonnegative_int(request.form.get("version", "0"), "Version", default=0)
        raw_length = (request.form.get("length") or "").strip()
        if not raw_length:
            length = DERIVED_PASSWORD_MIN_LENGTH
        else:
            try: length = int(raw_length)
            except ValueError: raise ValueError("Password Length must be a number.")
            if length < DERIVED_PASSWORD_MIN_LENGTH: length = DERIVED_PASSWORD_MIN_LENGTH
        password = generate_derived_password(pass_key, service, email, username, version, length)
        _add_history(password, "derived")
        user = _current_user()
        if user and user["service_history_enabled"]:
            _record_service_history(user["id"], service)
        return jsonify(ok=True, password=password, length=length, service=service)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400


@app.route("/health", methods=["GET"])
def health():
    return jsonify(ok=True)


# -----------------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(_):
    return jsonify(ok=False, error="Forbidden."), 403


@app.errorhandler(429)
def too_many_requests(_):
    return jsonify(ok=False, error="Rate limit exceeded. Please try again shortly."), 429


@app.errorhandler(413)
def too_large(_):
    return jsonify(ok=False, error="Request too large."), 413


# -----------------------------------------------------------------------------
# Entry point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # threaded=True satisfies the requested multithreaded mode.
    # debug/reloader are deliberately disabled because passwords and secrets
    # are held only in process memory and should not be duplicated by a reloader.
    app.run(host=HOST, port=PORT, threaded=THREADED, debug=False, use_reloader=False)
