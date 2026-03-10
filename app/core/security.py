import secrets

from fastapi import HTTPException, Request, status
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


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
