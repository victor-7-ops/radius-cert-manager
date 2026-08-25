"""Certificate endpoints — handoff §6b. Role checks live in the
dependency (app.main wires require_admin/require_super_admin), never in
handler bodies, so §10's direct-API test is meaningful."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select

from app import cert_service, db

router = APIRouter(prefix="/api/certs", tags=["certs"])


class IssueRequest(BaseModel):
    cn: str
    note: str | None = None
    request_id: str
    export_password: str | None = None


class StatusChangeRequest(BaseModel):
    reason: str


def get_router(deps) -> APIRouter:
    """deps carries app-specific providers (db session, pki material,
    settings, require_admin/require_super_admin) so this module has no
    hidden global state."""

    @router.get("")
    def list_certs(
        q: str | None = None,
        status_filter: str | None = None,
        page: int = 1,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        stmt = select(db.Certificate)
        if q:
            stmt = stmt.where(db.Certificate.cn.contains(q))
        if status_filter:
            stmt = stmt.where(db.Certificate.status == status_filter)
        page_size = 50
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        rows = session.scalars(stmt).all()
        return {"items": [_serialize(r) for r in rows], "page": page}

    @router.get("/{serial}")
    def get_cert(serial: str, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return _serialize(cert)

    @router.post("", status_code=status.HTTP_201_CREATED)
    def issue(body: IssueRequest, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        try:
            result = cert_service.issue_certificate(
                session,
                deps.pki_path,
                deps.inter_cert,
                deps.inter_key,
                cn=body.cn,
                note=body.note,
                request_id=body.request_id,
                export_password=body.export_password,
                issued_by=admin.username,
                days=deps.client_cert_days,
            )
        except cert_service.CNConflictError as e:
            raise HTTPException(status.HTTP_409_CONFLICT, str(e))
        deps.store_pending_bundle(result.certificate.serial, result.bundle)
        return _serialize(result.certificate)

    @router.get("/{serial}/bundle")
    def get_bundle(serial: str, admin: db.Admin = Depends(deps.require_admin)):
        bundle = deps.take_pending_bundle(serial)
        if bundle is None:
            raise HTTPException(status.HTTP_410_GONE, "bundle already consumed or not found")
        from fastapi import Response

        return Response(content=bundle.data, media_type="application/x-pkcs12")

    @router.post("/{serial}/suspend")
    def suspend(
        serial: str, body: StatusChangeRequest, admin: db.Admin = Depends(deps.require_admin)
    ):
        session = deps.get_db_session()
        try:
            cert = cert_service.suspend(session, deps.pki_path, serial, body.reason, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return _serialize(cert)

    @router.post("/{serial}/unsuspend")
    def unsuspend(serial: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        try:
            cert = cert_service.unsuspend(session, deps.pki_path, serial, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return _serialize(cert)

    @router.post("/{serial}/revoke")
    def revoke(
        serial: str, body: StatusChangeRequest, admin: db.Admin = Depends(deps.require_super_admin)
    ):
        session = deps.get_db_session()
        try:
            cert = cert_service.revoke(session, deps.pki_path, serial, body.reason, admin.username)
        except KeyError:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        deps.regenerate_and_push_crl()
        return _serialize(cert)

    return router


def _serialize(cert: db.Certificate) -> dict:
    return {
        "id": cert.id,
        "cn": cert.cn,
        "serial": cert.serial,
        "status": cert.status.value if hasattr(cert.status, "value") else cert.status,
        "issued_at": cert.issued_at.isoformat() if cert.issued_at else None,
        "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
        "issued_by": cert.issued_by,
        "supersedes_id": cert.supersedes_id,
    }
