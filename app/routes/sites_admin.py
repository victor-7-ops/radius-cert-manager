"""Admin-facing site registry management — create a site, rotate its
token, deactivate it. Super Admin only. JSON API; no template UI in this
pass (HANDOFF-FLEET.md doesn't require one — the fleet view in §5 is the
UI surface for sites, this is just CRUD to stand a site up)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app import db, site_service


def get_router(deps) -> APIRouter:
    router = APIRouter(prefix="/api/admin/sites", tags=["sites-admin"])

    @router.get("")
    def list_sites(admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        sites = session.scalars(select(db.Site)).all()
        return [
            {
                "id": s.id, "name": s.name, "radius_cn": s.radius_cn,
                "subsidiary": s.subsidiary, "is_active": s.is_active,
                "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
                "agent_version": s.agent_version,
            }
            for s in sites
        ]

    @router.post("")
    def create_site(payload: dict, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        name = payload.get("name")
        radius_cn = payload.get("radius_cn")
        if not name or not radius_cn:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "name and radius_cn are required")

        try:
            result = site_service.create_site(
                session, name=name, radius_cn=radius_cn, actor=admin.username,
                subsidiary=payload.get("subsidiary"), address=payload.get("address"),
                crl_validity_days=payload.get("crl_validity_days", 30),
                checkin_interval_seconds=payload.get("checkin_interval_seconds", 3600),
                notes=payload.get("notes"),
            )
        except site_service.SiteCNConflictError as e:
            raise HTTPException(status.HTTP_409_CONFLICT, str(e))

        return {
            "id": result.site.id,
            "name": result.site.name,
            "radius_cn": result.site.radius_cn,
            "token": result.token,  # shown once — caller must capture it now
        }

    @router.post("/{site_id}/rotate-token")
    def rotate_token(site_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        site = session.get(db.Site, site_id)
        if site is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
        token = site_service.rotate_token(session, site, actor=admin.username)
        return {"id": site.id, "token": token}

    @router.post("/{site_id}/deactivate")
    def deactivate_site(site_id: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        site = session.get(db.Site, site_id)
        if site is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
        site_service.deactivate(session, site, actor=admin.username)
        return {"id": site.id, "is_active": site.is_active}

    return router
