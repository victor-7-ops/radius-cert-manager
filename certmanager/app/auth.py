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
from fastapi import Cookie, Depends, HTTPException, Request, Response, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import Admin, AdminRole, AdminSession

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


def issue_session_cookie(
    response: Response, secret_key: str, admin: Admin, session_id: str, session_start: str | None = None
) -> None:
    payload = {
        "sub": admin.id,
        "tv": admin.token_version,
        "sid": session_id,
        "session_start": session_start or _now().isoformat(),
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


_USER_AGENT_MAX_LEN = 200


def create_admin_session(db_session: Session, admin: Admin, user_agent: str | None, ip_address: str | None) -> AdminSession:
    record = AdminSession(
        admin_id=admin.id,
        user_agent=(user_agent or "")[:_USER_AGENT_MAX_LEN] or None,
        ip_address=ip_address,
    )
    db_session.add(record)
    db_session.commit()
    db_session.refresh(record)
    return record


def revoke_admin_session(db_session: Session, record: AdminSession) -> None:
    record.revoked_at = _now()
    db_session.commit()


_LAST_SEEN_UPDATE_THRESHOLD = datetime.timedelta(seconds=30)


def touch_admin_session(db_session: Session, record: AdminSession) -> None:
    # Silent refresh happens on every authenticated request — throttle
    # the write so a busy admin doesn't hammer the DB with an UPDATE per
    # click. Precision to the minute is plenty for a "last seen" display.
    if _now() - _aware(record.last_seen_at) >= _LAST_SEEN_UPDATE_THRESHOLD:
        record.last_seen_at = _now()
        db_session.commit()


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)


BUNDLE_QR_TOKEN_MAX_AGE_SECONDS = 600


def _bundle_qr_serializer(secret_key: str) -> URLSafeTimedSerializer:
    # Separate salt from the session cookie serializer so a leaked/expired
    # QR token can never be replayed as a session token or vice versa.
    return URLSafeTimedSerializer(secret_key, salt="cm-bundle-qr")


def make_bundle_qr_token(secret_key: str, serial: str) -> str:
    return _bundle_qr_serializer(secret_key).dumps({"serial": serial})


def verify_bundle_qr_token(secret_key: str, token: str) -> str | None:
    """Returns the serial the token was minted for, or None if the token
    is missing, tampered with, or older than BUNDLE_QR_TOKEN_MAX_AGE_SECONDS.
    This lets the QR link work on a device with no admin session — the
    underlying bundle is still one-time-consumable, so it carries no more
    exposure than the existing authenticated download link."""
    try:
        payload = _bundle_qr_serializer(secret_key).loads(token, max_age=BUNDLE_QR_TOKEN_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    return payload.get("serial")


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
    # Every session row for this admin is now unusable regardless of
    # whether its own revoked_at ever gets set explicitly — but set it
    # anyway so the sessions list reads correctly rather than showing
    # stale "active" rows for a deactivated/reset admin.
    now = _now()
    for record in session.scalars(select(AdminSession).where(AdminSession.admin_id == admin.id, AdminSession.revoked_at.is_(None))):
        record.revoked_at = now
    session.commit()


class SessionData:
    def __init__(self, admin_id: str, token_version: int, session_id: str, session_start: datetime.datetime):
        self.admin_id = admin_id
        self.token_version = token_version
        self.session_id = session_id
        self.session_start = session_start


def decode_session_cookie(secret_key: str, token: str) -> SessionData | None:
    try:
        payload = _serializer(secret_key).loads(token, max_age=SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    session_start = datetime.datetime.fromisoformat(payload["session_start"])
    if _now() - session_start > datetime.timedelta(seconds=SESSION_ABSOLUTE_SECONDS):
        return None
    sid = payload.get("sid")
    if sid is None:
        return None  # pre-session-tracking cookie — treat as expired, forces a re-login
    return SessionData(
        admin_id=payload["sub"], token_version=payload["tv"], session_id=sid, session_start=session_start
    )


# A temp password (new admin, or a Super Admin's reset) sets
# must_change_password — these are the only paths a request carrying
# that flag is allowed to reach; everything else redirects to the
# change-password page first. Kept as an app.auth constant since the
# 428 handler in main.py needs the same target path.
PASSWORD_CHANGE_PATH = "/account/change-password"
PASSWORD_CHANGE_EXEMPT_PATHS = {PASSWORD_CHANGE_PATH, "/auth/logout", "/auth/ping"}
PASSWORD_CHANGE_REQUIRED_STATUS = 428  # Precondition Required
MIN_PASSWORD_LENGTH = 12


def get_current_admin_factory(get_db_session, get_secret_key):
    """Build the require_admin FastAPI dependency, bound to app-specific
    session-factory and settings providers (kept out of module globals
    so auth.py has no hidden app-wide state — testable in isolation)."""

    def require_admin(
        request: Request,
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

        record = db_session.get(AdminSession, data.session_id)
        if record is None or record.admin_id != admin.id or record.revoked_at is not None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session invalid")
        touch_admin_session(db_session, record)

        # Silent refresh: slide the inactivity window forward, same session id.
        issue_session_cookie(response, secret_key, admin, session_id=record.id)

        if (
            admin.must_change_password
            and not request.url.path.startswith("/api")
            and request.url.path not in PASSWORD_CHANGE_EXEMPT_PATHS
        ):
            raise HTTPException(PASSWORD_CHANGE_REQUIRED_STATUS, "Password change required")

        return admin

    def require_super_admin(admin: Admin = Depends(require_admin)) -> Admin:
        if admin.role != AdminRole.super_admin:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Super admin required")
        return admin

    return require_admin, require_super_admin
