"""Security helpers for authentication and request protections."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from fastapi import HTTPException, Request, status

PBKDF2_ITERATIONS = 210_000


def hash_password(password: str) -> str:
    """Return password hash using PBKDF2-HMAC-SHA256 (stdlib only)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password hash supporting legacy passlib hashes when present."""
    if password_hash.startswith("$2"):
        # Legacy bcrypt hash from older installs.
        try:
            import bcrypt
        except ImportError:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    try:
        algorithm, rounds, salt_b64, digest_b64 = password_hash.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False

    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    calculated = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
    return hmac.compare_digest(expected, calculated)


def ensure_authenticated(request: Request):
    if not request.session.get("user"):
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})


def issue_csrf_token(request: Request) -> str:
    token = secrets.token_urlsafe(24)
    request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, token: str):
    expected = request.session.get("csrf_token")
    if not expected or token != expected:
        raise HTTPException(status_code=400, detail="Invalid CSRF token")
