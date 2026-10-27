"""REST API router for employees, devices, and reliable multi-certificate offboarding.

Implements B10 and B11 specifications:
- Tenant-scoped employee and device inventory
- Query-time distinct counts (registered vs active vs usable vs active certs vs attention)
- Device status transitions and credential revocations
- Durable employee offboarding operations
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import db, device_service, employee_service, network_policy as np

logger = logging.getLogger(__name__)


class CreateEmployeeRequest(BaseModel):
    subsidiary_id: str
    display_name: str
    department_id: str
    employee_number: str | None = None


class UpdateEmployeeRequest(BaseModel):
    display_name: str | None = None
    department_id: str | None = None
    employee_number: str | None = None


class RegisterDeviceRequest(BaseModel):
    display_name: str
    department_id: str
    network_role_id: str
    device_type: str | None = None
    device_model: str | None = None
    asset_tag: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None


class UpdateDeviceRequest(BaseModel):
    display_name: str | None = None
    department_id: str | None = None
    network_role_id: str | None = None
    device_type: str | None = None
    device_model: str | None = None
    asset_tag: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None


class DeviceStatusRequest(BaseModel):
    status: str
    reason: str


class RevokeDeviceCredentialsRequest(BaseModel):
    reason: str


class OffboardEmployeeRequest(BaseModel):
    confirm_name: str
    reason: str


def _handle_domain_error(e: Exception):
    if isinstance(e, np.PolicyValidationError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    elif isinstance(e, np.ForbiddenError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    elif isinstance(e, np.ResourceNotFoundError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    elif isinstance(e, np.ConcurrencyError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    raise e


def get_router(deps) -> APIRouter:
    router = APIRouter(prefix="/api", tags=["employees-and-devices"])

    @router.get("/employees")
    def list_employees(
        subsidiary_id: str | None = None,
        department_id: str | None = None,
        search: str | None = None,
        status_filter: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            results, total = employee_service.list_employees(
                actor=admin,
                session=session,
                subsidiary_id=subsidiary_id,
                department_id=department_id,
                search=search,
                status_filter=status_filter,
                limit=limit,
                offset=offset,
            )
            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "employees": results,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/employees", status_code=status.HTTP_201_CREATED, dependencies=[Depends(deps.require_write)])
    def create_employee(
        payload: CreateEmployeeRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.create_employee(
                actor=admin,
                subsidiary_id=payload.subsidiary_id,
                display_name=payload.display_name,
                department_id=payload.department_id,
                employee_number=payload.employee_number,
                session=session,
            )
            session.commit()
            return {
                "id": emp.id,
                "subsidiary_id": emp.subsidiary_id,
                "display_name": emp.display_name,
                "department_id": emp.department_id,
                "employee_number": emp.employee_number,
                "status": emp.status,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/employees/{employee_id}")
    def get_employee(
        employee_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
            metrics = employee_service.compute_employee_metrics(emp.id, session)
            sub = session.get(db.Subsidiary, emp.subsidiary_id)
            dept = session.get(db.Department, emp.department_id)
            return {
                "id": emp.id,
                "display_name": emp.display_name,
                "subsidiary_id": emp.subsidiary_id,
                "subsidiary_name": sub.display_name if sub else "",
                "department_id": emp.department_id,
                "department_name": dept.display_name if dept else "",
                "employee_number": emp.employee_number,
                "status": emp.status,
                "created_at": emp.created_at.isoformat() if emp.created_at else None,
                "updated_at": emp.updated_at.isoformat() if emp.updated_at else None,
                **metrics,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.patch("/employees/{employee_id}", dependencies=[Depends(deps.require_write)])
    def update_employee(
        employee_id: str,
        payload: UpdateEmployeeRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.update_employee(
                actor=admin,
                employee_id=employee_id,
                display_name=payload.display_name,
                department_id=payload.department_id,
                employee_number=payload.employee_number,
                session=session,
            )
            session.commit()
            return {
                "id": emp.id,
                "display_name": emp.display_name,
                "department_id": emp.department_id,
                "employee_number": emp.employee_number,
                "status": emp.status,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/employees/{employee_id}/devices")
    def list_employee_devices(
        employee_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
            devices, total = device_service.list_devices(
                actor=admin,
                session=session,
                employee_id=emp.id,
            )
            return {"total": total, "devices": devices}
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/employees/{employee_id}/devices", status_code=status.HTTP_201_CREATED, dependencies=[Depends(deps.require_write)])
    def register_employee_device(
        employee_id: str,
        payload: RegisterDeviceRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.register_device(
                actor=admin,
                employee_id=employee_id,
                display_name=payload.display_name,
                department_id=payload.department_id,
                network_role_id=payload.network_role_id,
                session=session,
                device_type=payload.device_type,
                device_model=payload.device_model,
                asset_tag=payload.asset_tag,
                serial_number=payload.serial_number,
                mac_address=payload.mac_address,
            )
            session.commit()
            return {
                "id": dev.id,
                "employee_id": dev.employee_id,
                "display_name": dev.display_name,
                "subsidiary_id": dev.subsidiary_id,
                "department_id": dev.department_id,
                "network_role_id": dev.network_role_id,
                "status": dev.status,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/devices/{device_id}")
    def get_device(
        device_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.get_device(admin, device_id, session)
            emp = session.get(db.Employee, dev.employee_id)
            dept = session.get(db.Department, dev.department_id)
            role = session.get(db.NetworkRole, dev.network_role_id)
            sub = session.get(db.Subsidiary, dev.subsidiary_id)
            return {
                "id": dev.id,
                "display_name": dev.display_name,
                "subsidiary_id": dev.subsidiary_id,
                "subsidiary_name": sub.display_name if sub else "",
                "employee_id": dev.employee_id,
                "employee_name": emp.display_name if emp else "",
                "employee_number": emp.employee_number if emp else "",
                "department_id": dev.department_id,
                "department_name": dept.display_name if dept else "",
                "network_role_id": dev.network_role_id,
                "network_role_name": role.display_name if role else "",
                "device_type": dev.device_type,
                "device_model": dev.device_model,
                "asset_tag": dev.asset_tag,
                "serial_number": dev.serial_number,
                "mac_address": dev.mac_address,
                "status": dev.status,
                "created_at": dev.created_at.isoformat() if dev.created_at else None,
                "updated_at": dev.updated_at.isoformat() if dev.updated_at else None,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.patch("/devices/{device_id}", dependencies=[Depends(deps.require_write)])
    def update_device(
        device_id: str,
        payload: UpdateDeviceRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.update_device(
                actor=admin,
                device_id=device_id,
                session=session,
                display_name=payload.display_name,
                department_id=payload.department_id,
                network_role_id=payload.network_role_id,
                device_type=payload.device_type,
                device_model=payload.device_model,
                asset_tag=payload.asset_tag,
                serial_number=payload.serial_number,
                mac_address=payload.mac_address,
            )
            session.commit()
            return {
                "id": dev.id,
                "display_name": dev.display_name,
                "department_id": dev.department_id,
                "network_role_id": dev.network_role_id,
                "status": dev.status,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/devices/{device_id}/certificates")
    def get_device_certificates(
        device_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.get_device(admin, device_id, session)
            certs = session.scalars(
                select(db.Certificate)
                .where(db.Certificate.device_id == dev.id, db.Certificate.cert_type == "client")
                .order_by(db.Certificate.issued_at.desc())
            ).all()
            return {
                "device_id": dev.id,
                "certificates": [
                    {
                        "serial": c.serial,
                        "cn": c.cn,
                        "status": c.status.value if hasattr(c.status, "value") else str(c.status),
                        "issued_at": c.issued_at.isoformat() if c.issued_at else None,
                        "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                        "network_role_id": c.network_role_id,
                        "is_active_and_valid": c.status == db.CertStatus.active and not c.is_expired(),
                    }
                    for c in certs
                ],
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/devices/{device_id}/status", dependencies=[Depends(deps.require_write)])
    def set_device_status(
        device_id: str,
        payload: DeviceStatusRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.set_device_status(
                actor=admin,
                device_id=device_id,
                status=payload.status,
                reason=payload.reason,
                session=session,
            )
            session.commit()
            return {
                "id": dev.id,
                "status": dev.status,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/devices/{device_id}/revoke-credentials", dependencies=[Depends(deps.require_write)])
    def revoke_device_credentials(
        device_id: str,
        payload: RevokeDeviceCredentialsRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            revoked = device_service.revoke_device_credentials(
                actor=admin,
                device_id=device_id,
                reason=payload.reason,
                session=session,
                pki_path=deps.pki_path,
                inter_cert=deps.inter_cert,
                inter_key=deps.inter_key,
                regenerate_crl_fn=deps.regenerate_and_push_crl,
            )
            session.commit()
            return {
                "device_id": device_id,
                "revoked_serials": revoked,
                "revoked_count": len(revoked),
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.post("/employees/{employee_id}/offboard", dependencies=[Depends(deps.require_write)])
    def offboard_employee(
        employee_id: str,
        payload: OffboardEmployeeRequest,
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
            if payload.confirm_name.strip() != emp.display_name.strip():
                raise np.PolicyValidationError(
                    f"Confirmation name '{payload.confirm_name}' does not match '{emp.display_name}'"
                )

            op = employee_service.offboard_employee(
                actor=admin,
                employee_id=employee_id,
                reason=payload.reason,
                session=session,
                pki_path=deps.pki_path,
                inter_cert=deps.inter_cert,
                inter_key=deps.inter_key,
                regenerate_crl_fn=deps.regenerate_and_push_crl,
            )
            return {
                "operation_id": op.id,
                "employee_id": op.employee_id,
                "status": op.status,
                "revoked_serials": json.loads(op.revoked_serials_json),
                "crl_published_at": op.crl_published_at.isoformat() if op.crl_published_at else None,
            }
        except Exception as e:
            _handle_domain_error(e)

    @router.get("/employees/{employee_id}/offboarding-operations/{operation_id}")
    def get_offboarding_operation(
        employee_id: str,
        operation_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
            op = session.get(db.OffboardingOperation, operation_id)
            if not op or op.employee_id != emp.id:
                raise np.ResourceNotFoundError("Operation not found")

            return {
                "id": op.id,
                "employee_id": op.employee_id,
                "requested_by": op.requested_by,
                "reason": op.reason,
                "status": op.status,
                "target_serials": json.loads(op.target_serials_json),
                "revoked_serials": json.loads(op.revoked_serials_json),
                "crl_published_at": op.crl_published_at.isoformat() if op.crl_published_at else None,
                "created_at": op.created_at.isoformat() if op.created_at else None,
                "error_detail": op.error_detail,
            }
        except Exception as e:
            _handle_domain_error(e)

    return router
