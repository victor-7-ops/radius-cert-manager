from __future__ import annotations

from fastapi import APIRouter, Cookie, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import auth, db

LOCKOUT_MINUTES = auth.LOCKOUT_WINDOW_MINUTES


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(prefix="/auth", tags=["web-auth"])

    @router.post("/login")
    def login(request: Request, username: str = Form(...), password: str = Form(...)):
        session = deps.get_db_session()
        result = auth.attempt_login(session, username, password)
        if not result.ok:
            return templates.TemplateResponse(
                request,
                "login.html",
                {"error": not result.locked, "locked": result.locked, "lockout_minutes": LOCKOUT_MINUTES},
                status_code=401,
            )
        record = auth.create_admin_session(
            session, result.admin,
            user_agent=request.headers.get("user-agent"),
            ip_address=request.client.host if request.client else None,
        )
        response = RedirectResponse("/dashboard", status_code=303)
        auth.issue_session_cookie(response, deps.secret_key, result.admin, session_id=record.id)
        return response

    @router.post("/logout")
    def logout(cm_session: str | None = Cookie(default=None)):
        if cm_session is not None:
            data = auth.decode_session_cookie(deps.secret_key, cm_session)
            if data is not None:
                session = deps.get_db_session()
                record = session.get(db.AdminSession, data.session_id)
                if record is not None and record.revoked_at is None:
                    auth.revoke_admin_session(session, record)
        response = RedirectResponse("/login", status_code=303)
        auth.clear_session_cookie(response)
        return response

    @router.get("/ping")
    def ping(response: Response, admin: db.Admin = Depends(deps.require_admin)):
        # No-op beyond the require_admin dependency itself, which does the
        # actual work: it silently reissues the session cookie on every
        # authenticated call. This route exists so the "stay signed in"
        # toast has something to fetch() that isn't a full navigation.
        return Response(status_code=204)

    return router
