from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

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
        response = RedirectResponse("/dashboard", status_code=303)
        auth.issue_session_cookie(response, deps.secret_key, result.admin)
        return response

    @router.post("/logout")
    def logout():
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
