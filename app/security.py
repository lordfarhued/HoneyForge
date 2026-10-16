from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models import User, UserRole, UserSession, utcnow

COOKIE_NAME = "honeyforge_session"
LOGIN_CSRF_COOKIE = "honeyforge_login_csrf"
password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Пароль должен содержать не менее 12 символов")
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User) -> tuple[UserSession, str]:
    raw_token = secrets.token_urlsafe(48)
    settings = get_settings()
    session = UserSession(
        user_id=user.id,
        token_hash=token_hash(raw_token),
        csrf_token=secrets.token_urlsafe(32),
        expires_at=utcnow() + timedelta(hours=settings.session_hours),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session, raw_token


@dataclass
class AuthContext:
    user: User
    session: UserSession


def get_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется вход")
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash(raw_token)))
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия истекла")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utcnow():
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Сессия истекла")
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пользователь недоступен")
    session.last_seen_at = utcnow()
    db.commit()
    return AuthContext(user=user, session=session)


def get_ui_auth_context(request: Request, db: Session = Depends(get_db)) -> AuthContext:
    try:
        return get_auth_context(request, db)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_401_UNAUTHORIZED:
            raise HTTPException(status_code=303, headers={"Location": "/login"}) from exc
        raise


def require_roles(*allowed: UserRole):
    def dependency(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if context.user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
        return context

    return dependency


def require_ui_roles(*allowed: UserRole):
    def dependency(context: AuthContext = Depends(get_ui_auth_context)) -> AuthContext:
        if context.user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
        return context

    return dependency


def verify_csrf(context: AuthContext, supplied: str | None) -> None:
    if not supplied or not secrets.compare_digest(context.session.csrf_token, supplied):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Некорректный CSRF-токен")


def make_login_csrf() -> str:
    serializer = URLSafeTimedSerializer(get_settings().secret_key, salt="login-csrf")
    return serializer.dumps(secrets.token_urlsafe(24))


def verify_login_csrf(form_token: str | None, cookie_token: str | None) -> bool:
    if not form_token or not cookie_token or not secrets.compare_digest(form_token, cookie_token):
        return False
    serializer = URLSafeTimedSerializer(get_settings().secret_key, salt="login-csrf")
    try:
        serializer.loads(form_token, max_age=600)
        return True
    except (BadSignature, SignatureExpired):
        return False
