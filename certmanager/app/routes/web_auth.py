from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app import auth

router = APIRouter(prefix="/auth", tags=["web-auth"])

LOCKOUT_MINUTES = auth.LOCKOUT_WINDOW_MINUTES


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
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

    return router
