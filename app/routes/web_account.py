"""Self-service account routes: change your own password, manage your
own sessions. Split out of app/routes/web.py."""

from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import auth, crl_health, db
from app.routes import web_helpers as h


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-account"])

    _crl_banner_context = crl_health.banner_context

    # --- Change your own password (self-service; also where
    # must_change_password redirects, see auth.require_admin) ---

    @router.get(auth.PASSWORD_CHANGE_PATH)
    def change_password_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request,
            "change_password.html",
            {
                "admin": admin,
                "forced": admin.must_change_password,
                "min_length": auth.MIN_PASSWORD_LENGTH,
                **_crl_banner_context(session),
            },
        )

    @router.post(auth.PASSWORD_CHANGE_PATH)
    def change_password_submit(
        request: Request,
        current_password: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        error = None
        if not auth.verify_password(current_password, admin.password_hash):
            error = "Current password is incorrect."
        elif new_password != confirm_password:
            error = "New password and confirmation don't match."
        elif len(new_password) < auth.MIN_PASSWORD_LENGTH:
            error = f"New password must be at least {auth.MIN_PASSWORD_LENGTH} characters."
        elif new_password == current_password:
            error = "New password must be different from your current password."

        if error:
            return templates.TemplateResponse(
                request,
                "change_password.html",
                {
                    "admin": admin,
                    "forced": admin.must_change_password,
                    "min_length": auth.MIN_PASSWORD_LENGTH,
                    "error": error,
                    **_crl_banner_context(session),
                },
                status_code=400,
            )

        admin.password_hash = auth.hash_password(new_password)
        admin.must_change_password = False
        db.audit(session, actor=admin.username, action="change_password", target=admin.username)
        session.commit()
        return RedirectResponse(h.flash("/dashboard", "Password changed.", "success"), status_code=303)

    # --- Your sessions (any admin, own sessions only) ---

    @router.get("/account/sessions")
    def account_sessions(
        request: Request,
        cm_session: str | None = Cookie(default=None),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        current_id = None
        if cm_session is not None:
            data = auth.decode_session_cookie(deps.secret_key, cm_session)
            if data is not None:
                current_id = data.session_id
        rows = session.scalars(
            select(db.AdminSession)
            .where(db.AdminSession.admin_id == admin.id, db.AdminSession.revoked_at.is_(None))
            .order_by(db.AdminSession.last_seen_at.desc())
        ).all()
        return templates.TemplateResponse(
            request,
            "account_sessions.html",
            {
                "admin": admin,
                "sessions": [
                    {
                        "id": s.id,
                        "is_current": s.id == current_id,
                        "user_agent": s.user_agent,
                        "ip_address": s.ip_address,
                        "created_at": s.created_at,
                        "last_seen_at": s.last_seen_at,
                    }
                    for s in rows
                ],
                **_crl_banner_context(session),
            },
        )

    @router.post("/account/sessions/{session_id}/revoke")
    def account_session_revoke(
        request: Request,
        session_id: str,
        cm_session: str | None = Cookie(default=None),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        record = session.get(db.AdminSession, session_id)
        if record is None or record.admin_id != admin.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        current_id = None
        if cm_session is not None:
            data = auth.decode_session_cookie(deps.secret_key, cm_session)
            if data is not None:
                current_id = data.session_id
        if record.id == current_id:
            # Ending your own current session isn't "revoke a device",
            # it's "log out" — send them through the real logout path so
            # the cookie gets cleared too, not just the DB row.
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "use logout to end your current session")
        auth.revoke_admin_session(session, record)
        return RedirectResponse(h.flash("/account/sessions", "Session ended.", "warn"), status_code=303)

    return router
