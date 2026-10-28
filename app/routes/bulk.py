"""Bulk reissue result viewing — handoff §6.5 / §6b.

The actual "bulk issue new identities" flow (CSV paste/upload, preview,
confirm) was removed: it only ever produced certs with no
subsidiary_id/network_role_id, so they could never match a VLAN
binding at RADIUS auth time. Real bulk onboarding now lives at
/bulk/employees + /bulk/devices (app/routes/bulk_network.py).

What's left here is still live: "Reissue selected" on the Certificates
list (app/routes/web_certs.py's cert_bulk_action, action=renew) calls
bulk_service.renew_batch for a batch of EXISTING certs and redirects
here to show the result and offer the ZIP download -- same result
page/API whichever path produced the batch.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.templating import Jinja2Templates

from app import crl_health, db


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["bulk"])

    @router.get("/certs/bulk/{batch_id}")
    def bulk_result(request: Request, batch_id: str, admin: db.Admin = Depends(deps.require_admin)):
        entry = deps.peek_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
        result, _ = entry
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request,
            "bulk_result.html",
            {"admin": admin, "batch_id": batch_id, "result": result, **crl_health.banner_context(session)},
        )

    @router.get("/api/batches/{batch_id}")
    def batch_status(batch_id: str, admin: db.Admin = Depends(deps.require_admin)):
        entry = deps.peek_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
        result, _ = entry
        return {
            "batch_id": batch_id,
            "status": "done",
            "succeeded": [{"cn": r.cn, "serial": r.serial} for r in result.succeeded],
            "failed": [{"cn": r.cn, "error": r.error} for r in result.failed],
        }

    @router.get("/api/batches/{batch_id}/bundle")
    def batch_bundle(batch_id: str, admin: db.Admin = Depends(deps.require_write)):
        entry = deps.take_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_410_GONE, "batch bundle already consumed or not found")
        _, zip_bytes = entry
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{batch_id}.zip"'},
        )

    return router
