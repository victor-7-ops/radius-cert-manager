"""Bulk issue routes — handoff §6.5 / §6b.

Preview (classify, no signing) -> confirm (issue_batch, synchronous —
batches are capped at 100 and signing is fast, so there is no real async
job here; the batch is "done" by the time /api/batches/{id} is first
polled) -> one-time ZIP download, 410 on replay.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app import bulk_service, db


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["bulk"])

    @router.get("/certs/bulk")
    def bulk_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        return templates.TemplateResponse(request, "bulk.html", {"admin": admin})

    @router.post("/certs/bulk/preview")
    async def bulk_preview(
        request: Request,
        identifiers_text: str = Form(""),
        csv_file: UploadFile | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        identifiers = bulk_service.parse_identifiers(identifiers_text)
        if csv_file is not None and csv_file.filename:
            identifiers = bulk_service.parse_csv(await csv_file.read())

        try:
            rows = bulk_service.classify(session, identifiers)
        except bulk_service.BatchTooLargeError as e:
            return templates.TemplateResponse(
                request, "bulk.html", {"admin": admin, "error": str(e)}, status_code=400
            )

        batch_token = str(uuid.uuid4())
        valid_identifiers = [r.identifier for r in rows if r.classification == "valid"]
        deps.store_pending_preview(batch_token, valid_identifiers)

        return templates.TemplateResponse(
            request,
            "bulk_preview.html",
            {
                "admin": admin,
                "rows": rows,
                "batch_token": batch_token,
                "valid_count": sum(1 for r in rows if r.classification == "valid"),
            },
        )

    @router.post("/certs/bulk/confirm")
    def bulk_confirm(
        request: Request,
        batch_token: str = Form(...),
        export_password: str = Form(...),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        identifiers = deps.take_pending_preview(batch_token)
        if identifiers is None:
            raise HTTPException(status.HTTP_410_GONE, "preview expired or already confirmed")

        session = deps.get_db_session()
        batch_id = str(uuid.uuid4())
        result, zip_bytes = bulk_service.issue_batch(
            session,
            deps.pki_path,
            deps.inter_cert,
            deps.inter_key,
            identifiers,
            batch_id=batch_id,
            export_password=export_password,
            issued_by=admin.username,
            days=deps.client_cert_days,
        )
        deps.store_pending_batch(batch_id, result, zip_bytes)
        deps.regenerate_and_push_crl()
        return RedirectResponse(f"/certs/bulk/{batch_id}", status_code=303)

    @router.get("/certs/bulk/{batch_id}")
    def bulk_result(request: Request, batch_id: str, admin: db.Admin = Depends(deps.require_admin)):
        entry = deps.peek_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
        result, _ = entry
        return templates.TemplateResponse(
            request,
            "bulk_result.html",
            {"admin": admin, "batch_id": batch_id, "result": result},
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
    def batch_bundle(batch_id: str, admin: db.Admin = Depends(deps.require_admin)):
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
