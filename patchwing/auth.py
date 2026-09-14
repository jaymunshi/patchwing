"""Login and sessions for the PatchWing web control plane.

Deliberately minimal: single-tenant, one shared login (email + password),
DB-backed. No user management UI, no roles, no password reset flow. Ships as
the smallest thing that blocks unauthenticated access; hardening comes
before publish.

Passwords are stored as PBKDF2-HMAC-SHA256 with a per-user salt (stdlib only,
no bcrypt dependency). Sessions are opaque random tokens stored in the DB
with an expiry; the cookie is HttpOnly and SameSite=Lax.

Bootstrap: on first visit to /login when no users exist, the page becomes a
"create admin" form. After that first user is created the same page is a
regular login. That removes the CLI setup step that everyone forgets.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional

_PBKDF_ROUNDS = 200_000    # ~150ms on the target VM; slow enough to blunt
                           # brute force, fast enough for interactive login.
_ALGO = "sha256"
_SESSION_TTL_SEC = 30 * 24 * 3600     # 30 days idle-refresh
_SESSION_COOKIE = "pw_session"


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return an encoded string suitable for storage: algo$rounds$salt$hash."""
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, _PBKDF_ROUNDS)
    return f"{_ALGO}${_PBKDF_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of `password` against a stored hash."""
    if not stored or "$" not in stored:
        return False
    try:
        algo, rounds_s, salt_hex, hash_hex = stored.split("$", 3)
        rounds = int(rounds_s)
    except (ValueError, AttributeError):
        return False
    if algo != _ALGO or rounds < 1000:
        return False
    dk = hashlib.pbkdf2_hmac(algo, password.encode("utf-8"),
                             bytes.fromhex(salt_hex), rounds)
    return hmac.compare_digest(dk.hex(), hash_hex)


def new_session_token() -> str:
    """Opaque, URL-safe token used as the pw_session cookie value."""
    return secrets.token_urlsafe(32)


# --- DB schema ------------------------------------------------------------
# Kept in this module rather than store.py so the auth story is one file.
# Store.__init__ runs these via CREATE TABLE IF NOT EXISTS on every open.

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    email        TEXT NOT NULL UNIQUE,
    password     TEXT NOT NULL,        -- pbkdf2-encoded
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token        TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_by_user ON sessions(user_id);
"""


# --- Store-facing helpers -------------------------------------------------

def count_users(conn) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])


def add_user(conn, email: str, password: str) -> int:
    """Create a user; returns the row id. Raises ValueError on bad input.

    Accepts a plain username or an email. Length checks are the only
    validation — this is pre-publish and the shipped default is `admin`. The
    login form field is labelled "Username or email" to match.
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("username is required")
    if not password:
        raise ValueError("password is required")
    ph = hash_password(password)
    cur = conn.execute(
        "INSERT INTO users (email, password, created_at) VALUES (?, ?, ?)",
        (email, ph, time.time()))
    conn.commit()
    return cur.lastrowid


def authenticate(conn, email: str, password: str) -> Optional[int]:
    """Return user id on success, None on failure. Same time cost either way."""
    email = (email or "").strip().lower()
    row = conn.execute(
        "SELECT id, password FROM users WHERE email = ?", (email,)).fetchone()
    if row is None:
        # Still burn a pbkdf2 to blunt user-enumeration timing attacks.
        hash_password(password or "irrelevant-placeholder-for-timing")
        return None
    if verify_password(password, row["password"] if hasattr(row, "keys")
                       else row[1]):
        return row["id"] if hasattr(row, "keys") else row[0]
    return None


def start_session(conn, user_id: int, ttl_sec: int = _SESSION_TTL_SEC) -> str:
    token = new_session_token()
    now = time.time()
    conn.execute(
        "INSERT INTO sessions (token, user_id, created_at, expires_at) "
        "VALUES (?, ?, ?, ?)",
        (token, user_id, now, now + ttl_sec))
    conn.commit()
    return token


def end_session(conn, token: str) -> None:
    if not token:
        return
    conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()


def resolve_session(conn, token: str) -> Optional[dict]:
    """Return {id, email} if the session is valid, None otherwise.

    Idle sessions expire on-read. No sliding TTL — a session valid past its
    expires_at is deleted here.
    """
    if not token:
        return None
    row = conn.execute(
        "SELECT s.token, s.user_id, s.expires_at, u.email "
        "FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token = ?", (token,)).fetchone()
    if row is None:
        return None
    if row["expires_at"] < time.time():
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        return None
    return {"id": row["user_id"], "email": row["email"]}


# --- Cookie helpers -------------------------------------------------------

def parse_cookie(header: str) -> dict:
    """Minimal Cookie header parser. Missing → empty dict."""
    out: dict[str, str] = {}
    for part in (header or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k.strip()] = v.strip()
    return out


def session_cookie(token: str, *, ttl_sec: int = _SESSION_TTL_SEC) -> str:
    """Set-Cookie header value for a fresh session."""
    return (f"{_SESSION_COOKIE}={token}; Path=/; Max-Age={ttl_sec}; "
            f"HttpOnly; SameSite=Lax")


def logout_cookie() -> str:
    return f"{_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"


COOKIE_NAME = _SESSION_COOKIE
