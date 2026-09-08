"""Admin management routes (Super Admin only). Split out of
app/routes/web.py."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app import auth, crl_health, db
from app.routes import web_helpers as h


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-admins"])

    _crl_banner_context = crl_health.banner_context

    def _active_super_admin_count(session) -> int:
        return session.scalar(
            select(func.count()).select_from(db.Admin).where(
                db.Admin.role == db.AdminRole.super_admin, db.Admin.is_active == True  # noqa: E712
            )
        )

    @router.get("/admins")
    def admin_list(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        rows = session.scalars(select(db.Admin)).all()
        super_count = _active_super_admin_count(session)
        items = []
        for a in rows:
            is_last = a.role == db.AdminRole.super_admin and a.is_active and super_count == 1
            items.append({
                "id": a.id, "username": a.username, "role": a.role.value, "is_active": a.is_active,
                "is_last_super_admin": is_last, "subsidiary_scope": a.subsidiary_scope,
            })
        return templates.TemplateResponse(
            request,
            "admin_list.html",
            {"admin": admin, "admins": items, "only_one_super_admin": super_count <= 1, **_crl_banner_context(session)},
        )

    @router.get("/admins/new-form")
    def admin_new_form(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        return templates.TemplateResponse(request, "admin_new_form.html", {"subsidiaries": db.SUBSIDIARIES})

    @router.post("/admins")
    def admin_create(
        request: Request,
        username: str = Form(...),
        role: str = Form(...),
        subsidiary_scope: str = Form(""),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        temp_password = secrets.token_urlsafe(12)
        new_admin = db.Admin(
            username=username,
            password_hash=auth.hash_password(temp_password),
            role=db.AdminRole(role),
            must_change_password=True,
            created_by=admin.username,
            subsidiary_scope=subsidiary_scope.strip() or None,
        )
        session.add(new_admin)
        db.audit(session, actor=admin.username, action="create_admin", target=username)
        session.commit()
        return templates.TemplateResponse(request, "admin_created.html", {"username": username, "temp_password": temp_password})

    @router.post("/admins/{admin_id}/deactivate")
    def admin_deactivate(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        if target.role == db.AdminRole.super_admin and _active_super_admin_count(session) <= 1:
            raise HTTPException(status.HTTP_409_CONFLICT, "cannot deactivate the last active Super Admin")
        target.is_active = False
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="deactivate_admin", target=target.username)
        session.commit()
        return RedirectResponse(h.flash("/admins", f"{target.username} deactivated.", "warn"), status_code=303)

    @router.post("/admins/{admin_id}/reset-password")
    def admin_reset_password(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        temp_password = secrets.token_urlsafe(12)
        target.password_hash = auth.hash_password(temp_password)
        target.must_change_password = True
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="reset_password", target=target.username)
        session.commit()
        return templates.TemplateResponse(
            request, "admin_created.html", {"username": target.username, "temp_password": temp_password}
        )

    @router.post("/admins/{admin_id}/force-logout")
    def admin_force_logout(request: Request, admin_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        target = session.get(db.Admin, admin_id)
        if target is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        auth.bump_token_version(session, target)
        db.audit(session, actor=admin.username, action="force_logout", target=target.username)
        session.commit()
        return RedirectResponse(h.flash("/admins", f"{target.username} logged out everywhere.", "success"), status_code=303)

    return router
