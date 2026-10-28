"""Bulk onboarding through the real Employee/Device/Certificate chain —
Employees CSV first, then a Devices CSV that issues real, VLAN-eligible
certs. See app/bulk_network_service.py for why this is a separate path
from the older app/bulk_service.py (free-text, no subsidiary_id/
network_role_id, can never match a VLAN binding).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app import bulk_network_service as bns
from app import crl_health, db


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["bulk-network"])

    @router.get("/bulk/employees")
    def employees_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request, "bulk_employees.html", {"admin": admin, **crl_health.banner_context(session)}
        )

    @router.get("/bulk/employees/template.csv")
    def employees_template(admin: db.Admin = Depends(deps.require_admin)):
        sample = (
            "subsidiary_code,department_code,display_name,employee_number\r\n"
            "topline,ops,Juan Dela Cruz,EMP-001\r\n"
            "topline,ops,Maria Santos,EMP-002\r\n"
        )
        return Response(
            content=sample, media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="bulk-employees-template.csv"'},
        )

    @router.post("/bulk/employees/preview")
    async def employees_preview(
        request: Request, csv_file: UploadFile = None,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session = deps.get_db_session()
        if csv_file is None or not csv_file.filename:
            return templates.TemplateResponse(
                request, "bulk_employees.html",
                {"admin": admin, "error": "Choose a CSV file first.", **crl_health.banner_context(session)},
                status_code=400,
            )
        input_rows = bns.parse_employee_csv(await csv_file.read())
        try:
            rows = bns.classify_employees(session, input_rows)
        except bns.BatchTooLargeError as e:
            return templates.TemplateResponse(
                request, "bulk_employees.html",
                {"admin": admin, "error": str(e), **crl_health.banner_context(session)},
                status_code=400,
            )

        batch_token = str(uuid.uuid4())
        deps.store_pending_preview(batch_token, input_rows)
        return templates.TemplateResponse(
            request, "bulk_employees_preview.html",
            {
                "admin": admin, "rows": rows, "batch_token": batch_token,
                "valid_count": sum(1 for r in rows if r.classification == "valid"),
                "total_count": len(rows),
                **crl_health.banner_context(session),
            },
        )

    @router.post("/bulk/employees/confirm")
    def employees_confirm(
        request: Request, batch_token: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        all_rows = deps.take_pending_preview(batch_token)
        if all_rows is None:
            raise HTTPException(status.HTTP_410_GONE, "preview expired or already confirmed")

        session = deps.get_db_session()
        classified = bns.classify_employees(session, all_rows)
        valid_rows = [r.row for r in classified if r.classification == "valid"]

        batch_id = str(uuid.uuid4())
        result = bns.confirm_employees(admin, session, valid_rows, batch_id)
        return templates.TemplateResponse(
            request, "bulk_network_result.html",
            {"admin": admin, "kind": "employees", "result": result, **crl_health.banner_context(session)},
        )

    @router.get("/bulk/devices")
    def devices_form(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request, "bulk_devices.html", {"admin": admin, **crl_health.banner_context(session)}
        )

    @router.get("/bulk/devices/template.csv")
    def devices_template(admin: db.Admin = Depends(deps.require_admin)):
        sample = (
            "subsidiary_code,employee_number,role_code,device_type,device_model,mac_address,serial_number\r\n"
            "topline,EMP-001,staff,Laptop,HP EliteBook 840,aa:bb:cc:dd:ee:ff,C02XG2JMQ6L9\r\n"
        )
        return Response(
            content=sample, media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="bulk-devices-template.csv"'},
        )

    @router.post("/bulk/devices/preview")
    async def devices_preview(
        request: Request, csv_file: UploadFile = None,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session = deps.get_db_session()
        if csv_file is None or not csv_file.filename:
            return templates.TemplateResponse(
                request, "bulk_devices.html",
                {"admin": admin, "error": "Choose a CSV file first.", **crl_health.banner_context(session)},
                status_code=400,
            )
        input_rows = bns.parse_device_csv(await csv_file.read())
        try:
            rows = bns.classify_devices(session, input_rows)
        except bns.BatchTooLargeError as e:
            return templates.TemplateResponse(
                request, "bulk_devices.html",
                {"admin": admin, "error": str(e), **crl_health.banner_context(session)},
                status_code=400,
            )

        batch_token = str(uuid.uuid4())
        deps.store_pending_preview(batch_token, input_rows)
        return templates.TemplateResponse(
            request, "bulk_devices_preview.html",
            {
                "admin": admin, "rows": rows, "batch_token": batch_token,
                "valid_count": sum(1 for r in rows if r.classification == "valid"),
                "total_count": len(rows),
                **crl_health.banner_context(session),
            },
        )

    @router.post("/bulk/devices/confirm")
    def devices_confirm(
        request: Request, batch_token: str = Form(...), export_password: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        all_rows = deps.take_pending_preview(batch_token)
        if all_rows is None:
            raise HTTPException(status.HTTP_410_GONE, "preview expired or already confirmed")

        session = deps.get_db_session()
        classified = bns.classify_devices(session, all_rows)
        valid_rows = [r.row for r in classified if r.classification == "valid"]

        batch_id = str(uuid.uuid4())
        result, zip_bytes = bns.confirm_devices(
            admin, session, deps.pki_path, deps.inter_cert, deps.inter_key,
            valid_rows, batch_id, export_password, deps.client_cert_days,
        )
        deps.store_pending_batch(batch_id, result, zip_bytes)
        deps.regenerate_and_push_crl()
        return RedirectResponse(f"/bulk/devices/{batch_id}", status_code=303)

    @router.get("/bulk/devices/{batch_id}")
    def devices_result(request: Request, batch_id: str, admin: db.Admin = Depends(deps.require_admin)):
        entry = deps.peek_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "batch not found")
        result, _ = entry
        session = deps.get_db_session()
        return templates.TemplateResponse(
            request, "bulk_network_result.html",
            {"admin": admin, "kind": "devices", "batch_id": batch_id, "result": result, **crl_health.banner_context(session)},
        )

    @router.get("/bulk/devices/{batch_id}/bundle")
    def devices_bundle(batch_id: str, admin: db.Admin = Depends(deps.require_write)):
        entry = deps.take_pending_batch(batch_id)
        if entry is None:
            raise HTTPException(status.HTTP_410_GONE, "batch bundle already consumed or not found")
        _, zip_bytes = entry
        return Response(
            content=zip_bytes, media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{batch_id}.zip"'},
        )

    return router
