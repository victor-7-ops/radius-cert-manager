"""Login, session cookie, role dependency, lockout.

Handoff §5.4/§6: session lives in an HttpOnly/Secure/SameSite=Strict
cookie (not a token in browser storage). The cookie is a signed, timed
token carrying admin id + token_version; it slides forward (silent
refresh) on every authenticated request up to an absolute cap, and is
invalidated instantly by bumping token_version (deactivate, password
change, force logout) — role checks live in a dependency, never inside
handler bodies, so the API rejects direct calls even without the UI.
"""

from __future__ import annotations

import datetime

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, HTTPException, Response, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Admin, AdminRole

SESSION_COOKIE = "cm_session"
SESSION_MAX_AGE_SECONDS = 15 * 60  # sliding inactivity timeout
SESSION_ABSOLUTE_SECONDS = 12 * 60 * 60  # hard cap regardless of activity

LOCKOUT_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 15

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _aware(dt: datetime.datetime | None) -> datetime.datetime | None:
    # SQLite drops tzinfo on round-trip; treat naive values as UTC.
    if dt is None or dt.tzinfo is not None:
        return dt
    return dt.replace(tzinfo=datetime.timezone.utc)


def _serializer(secret_key: str) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(secret_key, salt="cm-session")


def issue_session_cookie(response: Response, secret_key: str, admin: Admin) -> None:
    payload = {
        "sub": admin.id,
        "tv": admin.token_version,
        "session_start": _now().isoformat(),
    }
    token = _serializer(secret_key).dumps(payload)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)


class LoginResult:
    def __init__(self, ok: bool, admin: Admin | None = None, locked: bool = False):
        self.ok = ok
        self.admin = admin
        self.locked = locked


def attempt_login(session: Session, username: str, password: str) -> LoginResult:
    admin = session.scalar(select(Admin).where(Admin.username == username))
    now = _now()

    if admin is None:
        return LoginResult(ok=False)

    if _aware(admin.locked_until) is not None and _aware(admin.locked_until) > now:
        return LoginResult(ok=False, locked=True)

    if not admin.is_active:
        return LoginResult(ok=False)

    if not verify_password(password, admin.password_hash):
        admin.failed_login_count += 1
        if admin.failed_login_count >= LOCKOUT_MAX_ATTEMPTS:
            admin.locked_until = now + datetime.timedelta(minutes=LOCKOUT_WINDOW_MINUTES)
        session.commit()
        locked = _aware(admin.locked_until) is not None and _aware(admin.locked_until) > now
        return LoginResult(ok=False, locked=locked)

    admin.failed_login_count = 0
    admin.locked_until = None
    session.commit()
    return LoginResult(ok=True, admin=admin)


def bump_token_version(session: Session, admin: Admin) -> None:
    admin.token_version += 1
    session.commit()


class SessionData:
    def __init__(self, admin_id: str, token_version: int, session_start: datetime.datetime):
        self.admin_id = admin_id
        self.token_version = token_version
        self.session_start = session_start


def decode_session_cookie(secret_key: str, token: str) -> SessionData | None:
    try:
        payload = _serializer(secret_key).loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    session_start = datetime.datetime.fromisoformat(payload["session_start"])
    if _now() - session_start > datetime.timedelta(seconds=SESSION_ABSOLUTE_SECONDS):
        return None
    return SessionData(
        admin_id=payload["sub"], token_version=payload["tv"], session_start=session_start
    )


def get_current_admin_factory(get_db_session, get_secret_key):
    """Build the require_admin FastAPI dependency, bound to app-specific
    session-factory and settings providers (kept out of module globals
    so auth.py has no hidden app-wide state — testable in isolation)."""

    def require_admin(
        response: Response,
        cm_session: str | None = Cookie(default=None),
    ) -> Admin:
        secret_key = get_secret_key()
        if cm_session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
        data = decode_session_cookie(secret_key, cm_session)
        if data is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")

        db_session = get_db_session()
        admin = db_session.get(Admin, data.admin_id)
        if admin is None or not admin.is_active or admin.token_version != data.token_version:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid")

        # Silent refresh: slide the inactivity window forward.
        issue_session_cookie(response, secret_key, admin)
        return admin

    def require_super_admin(admin: Admin = Depends(require_admin)) -> Admin:
        if admin.role != AdminRole.super_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Super admin required")
        return admin

    return require_admin, require_super_admin
