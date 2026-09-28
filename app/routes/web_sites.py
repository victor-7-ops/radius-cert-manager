"""Site management UI (HANDOFF-COMPLIANCE.md §4) — Super Admin only.

Before this, standing up a site meant hand-crafting a call to the JSON
API (app/routes/sites_admin.py), which doesn't survive being handed to
anyone else. This reuses that same service layer (app/site_service.py)
and the fleet-view status derivation (app/fleet_health.py) — no new
status logic here, just a form and a table over what already exists.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import crl_health, db, fleet_health, site_service
from app.routes import web_helpers as h
from app.validation import CN_RE


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-sites"])

    _crl_banner_context = crl_health.banner_context

    @router.get("/sites")
    def sites_list(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        sites = session.scalars(select(db.Site).order_by(db.Site.name)).all()
        crl_last_generated_at = crl_health.get_health(session).last_generated_at

        rows = []
        for site in sites:
            if site.is_active:
                cert = session.get(db.Certificate, site.server_cert_id) if site.server_cert_id else None
                health = fleet_health.evaluate_site(site, cert, crl_last_generated_at)
                rows.append({"site": site, "status": health.status.value, "minutes_since_checkin": health.minutes_since_checkin})
            else:
                rows.append({"site": site, "status": "INACTIVE", "minutes_since_checkin": None})

        return templates.TemplateResponse(
            request,
            "sites_list.html",
            {"admin": admin, "rows": rows, **_crl_banner_context(session)},
        )

    @router.get("/sites/new-form")
    def site_new_form(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        return templates.TemplateResponse(request, "site_new_form.html", {"subsidiaries": db.SUBSIDIARIES})

    @router.post("/sites")
    def site_create(
        request: Request,
        name: str = Form(...),
        radius_cn: str = Form(...),
        subsidiary: str = Form(""),
        address: str = Form(""),
        crl_validity_days: int = Form(30),
        checkin_interval_seconds: int = Form(3600),
        notes: str = Form(""),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        if not CN_RE.match(radius_cn):
            # Same charset restriction as app/routes/sites_admin.py — this
            # ends up unvalidated in a filesystem path at server-cert
            # issuance/renewal time otherwise.
            return templates.TemplateResponse(
                request, "site_new_form.html",
                {"subsidiaries": db.SUBSIDIARIES, "error": "Invalid radius_cn format."},
                status_code=400,
            )
        stripped_subsidiary = subsidiary.strip() or None
        if stripped_subsidiary is not None and stripped_subsidiary not in db.SUBSIDIARIES:
            return templates.TemplateResponse(
                request, "site_new_form.html",
                {"subsidiaries": db.SUBSIDIARIES, "error": "Invalid subsidiary."},
                status_code=400,
            )

        session = deps.get_db_session()
        try:
            result = site_service.create_site(
                session, name=name, radius_cn=radius_cn, actor=admin.username,
                subsidiary=stripped_subsidiary, address=address.strip() or None,
                crl_validity_days=crl_validity_days,
                checkin_interval_seconds=checkin_interval_seconds,
                notes=notes.strip() or None,
            )
        except site_service.SiteCNConflictError as e:
            return templates.TemplateResponse(
                request, "site_new_form.html",
                {"subsidiaries": db.SUBSIDIARIES, "error": str(e)},
                status_code=409,
            )

        return templates.TemplateResponse(
            request, "site_token_shown.html",
            {"name": result.site.name, "token": result.token},
        )

    def _load_site_or_404(session, site_id: str) -> db.Site:
        site = session.get(db.Site, site_id)
        if site is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return site

    @router.post("/sites/{site_id}/rotate-token")
    def site_rotate_token(request: Request, site_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        site = _load_site_or_404(session, site_id)
        token = site_service.rotate_token(session, site, actor=admin.username)
        return templates.TemplateResponse(
            request, "site_token_shown.html",
            {"name": site.name, "token": token},
        )

    @router.post("/sites/{site_id}/deactivate")
    def site_deactivate(request: Request, site_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        site = _load_site_or_404(session, site_id)
        site_service.deactivate(session, site, actor=admin.username)
        return RedirectResponse(h.flash("/sites", f"{site.name} deactivated.", "warn"), status_code=303)

    @router.post("/sites/{site_id}/reactivate")
    def site_reactivate(request: Request, site_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        site = _load_site_or_404(session, site_id)
        site_service.reactivate(session, site, actor=admin.username)
        return RedirectResponse(h.flash("/sites", f"{site.name} reactivated.", "success"), status_code=303)

    return router
