"""Employee inventory, directory, computed distinct metrics, and offboarding engine.

Implements B09, B10, and B11 specifications:
- Stable UUID employee identity
- Distinct device counts vs active certificate counts computed at query time in UTC
- Subsidiary-scoped filtering and permission enforcement
- Multi-certificate employee offboarding with CRL publication
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import cert_service, db
from app.network_policy import (
    ForbiddenError,
    PolicyValidationError,
    ResourceNotFoundError,
    assert_can_manage_subsidiary,
    is_admin_in_scope,
    resolve_admin_subsidiary_id,
)

logger = logging.getLogger(__name__)


def _as_utc(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def compute_employee_metrics(employee_id: str, session: Session) -> dict[str, int]:
    """Computes exact inventory metrics for a specific employee at query time in UTC.
    
    Definitions (EMPLOYEE-DEVICE-BUILD.md §28-39):
    - registered_devices: distinct linked device IDs
    - active_devices: distinct devices with status='active'
    - devices_with_usable_credentials: distinct active devices having at least one active,
      unexpired client certificate whose signed assignment matches the device
    - active_certificates: active, unexpired client certificates owned by this employee
    - needs_attention: devices with lost status, missing credentials, or expiring credentials (<30d)
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    soon = now + datetime.timedelta(days=30)

    devices = session.scalars(
        select(db.Device).where(db.Device.employee_id == employee_id)
    ).all()

    registered_devices = len(devices)
    active_devices = sum(1 for d in devices if d.status == "active")

    # Fetch all certificates linked to this employee
    certs = session.scalars(
        select(db.Certificate).where(
            db.Certificate.employee_id == employee_id,
            db.Certificate.cert_type == "client",
        )
    ).all()

    active_certs = [
        c for c in certs
        if c.status == db.CertStatus.active and not c.is_expired(now)
    ]
    active_certificate_count = len(active_certs)

    # Compute devices with usable credentials & needs attention
    usable_device_ids = set()
    attention_count = 0

    for d in devices:
        if d.status == "lost":
            attention_count += 1
            continue
        if d.status == "retired":
            continue

        # Device is active: look for active, unexpired certificate linked to it
        dev_certs = [
            c for c in active_certs
            if c.device_id == d.id
        ]
        if not dev_certs:
            # Active device with no active credentials -> needs attention
            attention_count += 1
            continue

        # Check if credential matches current assignment
        has_matching = any(
            c.network_role_id == d.network_role_id
            for c in dev_certs
        )
        if has_matching:
            usable_device_ids.add(d.id)
        else:
            attention_count += 1

        # Check for expiring credentials
        if any(_as_utc(c.expires_at) <= soon for c in dev_certs):
            attention_count += 1

    return {
        "registered_devices": registered_devices,
        "active_devices": active_devices,
        "devices_with_usable_credentials": len(usable_device_ids),
        "active_certificates": active_certificate_count,
        "needs_attention": attention_count,
    }


def list_employees(
    actor: db.Admin,
    session: Session,
    subsidiary_id: str | None = None,
    department_id: str | None = None,
    search: str | None = None,
    status_filter: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Lists employees with tenant scoping and computed metrics."""
    stmt = select(db.Employee)

    # Apply tenant scoping
    if actor.role == db.AdminRole.subsidiary_super_admin:
        actor_sub = resolve_admin_subsidiary_id(actor, session)
        if not actor_sub:
            return [], 0
        stmt = stmt.where(db.Employee.subsidiary_id == actor_sub)
    elif actor.subsidiary_scope:
        actor_sub = resolve_admin_subsidiary_id(actor, session)
        if actor_sub:
            stmt = stmt.where(db.Employee.subsidiary_id == actor_sub)
        else:
            return [], 0
    elif subsidiary_id:
        stmt = stmt.where(db.Employee.subsidiary_id == subsidiary_id)

    if department_id:
        stmt = stmt.where(db.Employee.department_id == department_id)

    if status_filter:
        stmt = stmt.where(db.Employee.status == status_filter)

    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(
            (db.Employee.display_name.ilike(term)) | (db.Employee.employee_number.ilike(term))
        )

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    employees = session.scalars(
        stmt.order_by(db.Employee.display_name.asc()).limit(limit).offset(offset)
    ).all()

    results = []
    for emp in employees:
        metrics = compute_employee_metrics(emp.id, session)
        dept = session.get(db.Department, emp.department_id)
        sub = session.get(db.Subsidiary, emp.subsidiary_id)
        results.append({
            "id": emp.id,
            "employee_number": emp.employee_number,
            "display_name": emp.display_name,
            "subsidiary_id": emp.subsidiary_id,
            "subsidiary_name": sub.display_name if sub else "",
            "department_id": emp.department_id,
            "department_name": dept.display_name if dept else "",
            "status": emp.status,
            "created_at": emp.created_at,
            **metrics,
        })

    return results, total


def get_employee(actor: db.Admin, employee_id: str, session: Session) -> db.Employee:
    emp = session.get(db.Employee, employee_id)
    if not emp:
        raise ResourceNotFoundError("Employee not found")

    if not is_admin_in_scope(actor, emp.subsidiary_id, session):
        raise ResourceNotFoundError("Employee not found")

    return emp


def create_employee(
    actor: db.Admin,
    subsidiary_id: str,
    display_name: str,
    department_id: str,
    employee_number: str | None,
    session: Session,
) -> db.Employee:
    assert_can_manage_subsidiary(actor, subsidiary_id, session)

    name = display_name.strip()
    if not name:
        raise PolicyValidationError("Employee display name cannot be blank")

    dept = session.get(db.Department, department_id)
    if not dept or dept.subsidiary_id != subsidiary_id or not dept.is_active:
        raise PolicyValidationError("Department does not belong to this subsidiary or is inactive")

    emp_num = employee_number.strip() if employee_number else None
    if emp_num:
        existing = session.scalar(
            select(db.Employee).where(
                db.Employee.subsidiary_id == subsidiary_id,
                db.Employee.employee_number == emp_num,
            )
        )
        if existing:
            raise PolicyValidationError(f"Employee number '{emp_num}' already exists in this subsidiary")

    emp = db.Employee(
        subsidiary_id=subsidiary_id,
        employee_number=emp_num,
        display_name=name,
        department_id=department_id,
        status="active",
    )
    session.add(emp)
    session.flush()

    sub = session.get(db.Subsidiary, subsidiary_id)
    db.audit(
        session,
        actor=actor.username,
        action="employee.create",
        target=emp.display_name,
        detail=f"Created employee {emp.display_name} ({emp.id}) dept={dept.code}",
        subsidiary=sub.display_name if sub else None,
    )
    return emp


def update_employee(
    actor: db.Admin,
    employee_id: str,
    display_name: str | None,
    department_id: str | None,
    employee_number: str | None,
    session: Session,
) -> db.Employee:
    emp = get_employee(actor, employee_id, session)
    assert_can_manage_subsidiary(actor, emp.subsidiary_id, session)

    if display_name is not None:
        name = display_name.strip()
        if not name:
            raise PolicyValidationError("Display name cannot be empty")
        emp.display_name = name

    if department_id is not None:
        dept = session.get(db.Department, department_id)
        if not dept or dept.subsidiary_id != emp.subsidiary_id or not dept.is_active:
            raise PolicyValidationError("Department does not belong to this subsidiary or is inactive")
        emp.department_id = department_id

    if employee_number is not None:
        num = employee_number.strip() or None
        if num and num != emp.employee_number:
            existing = session.scalar(
                select(db.Employee).where(
                    db.Employee.subsidiary_id == emp.subsidiary_id,
                    db.Employee.employee_number == num,
                    db.Employee.id != emp.id,
                )
            )
            if existing:
                raise PolicyValidationError(f"Employee number '{num}' already exists in this subsidiary")
        emp.employee_number = num

    session.flush()
    sub = session.get(db.Subsidiary, emp.subsidiary_id)
    db.audit(
        session,
        actor=actor.username,
        action="employee.update",
        target=emp.display_name,
        detail=f"Updated employee {emp.id}",
        subsidiary=sub.display_name if sub else None,
    )
    return emp


def offboard_employee(
    actor: db.Admin,
    employee_id: str,
    reason: str,
    session: Session,
    pki_path: Path,
    inter_cert,
    inter_key,
    regenerate_crl_fn=None,
) -> db.OffboardingOperation:
    """Executes reliable multi-certificate employee offboarding.
    
    1. Scope check: platform superadmin or subsidiary superadmin for this tenant.
    2. Marks employee status='offboarding'.
    3. Finds all usable client certificates owned by this employee (including historical overlaps).
    4. Revokes all target certificates.
    5. Publishes CRL.
    6. On CRL success, marks operation 'completed' and employee 'offboarded'.
    """
    emp = get_employee(actor, employee_id, session)
    assert_can_manage_subsidiary(actor, emp.subsidiary_id, session)

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for offboarding")

    now = datetime.datetime.now(datetime.timezone.utc)
    emp.status = "offboarding"

    # Identify all active or suspended non-expired client certificates owned by this employee
    certs = session.scalars(
        select(db.Certificate).where(
            db.Certificate.employee_id == emp.id,
            db.Certificate.cert_type == "client",
            db.Certificate.status.in_([db.CertStatus.active, db.CertStatus.suspended]),
        )
    ).all()
    usable_certs = [c for c in certs if not c.is_expired(now)]
    target_serials = [c.serial for c in usable_certs]

    op = db.OffboardingOperation(
        subsidiary_id=emp.subsidiary_id,
        employee_id=emp.id,
        requested_by=actor.username,
        reason=reason.strip(),
        status="in_progress",
        target_serials_json=json.dumps(target_serials),
        revoked_serials_json="[]",
    )
    session.add(op)
    session.commit()

    revoked = []
    try:
        for cert in usable_certs:
            cert_service.revoke(
                session,
                pki_path,
                cert.serial,
                reason=f"Employee offboarding: {reason.strip()}",
                actor=actor.username,
            )
            revoked.append(cert.serial)

        op.revoked_serials_json = json.dumps(revoked)
        session.commit()

        # Publish CRL
        if regenerate_crl_fn:
            regenerate_crl_fn(background=False)
        elif inter_cert and inter_key:
            cert_service.regenerate_crl(
                session,
                pki_path,
                inter_cert,
                inter_key,
                validity_days=30,
            )

        op.crl_published_at = datetime.datetime.now(datetime.timezone.utc)
        op.status = "completed"
        emp.status = "offboarded"

        sub = session.get(db.Subsidiary, emp.subsidiary_id)
        db.audit(
            session,
            actor=actor.username,
            action="employee.offboard",
            target=emp.display_name,
            detail=f"Offboarded employee {emp.id}, revoked {len(revoked)} certificates",
            subsidiary=sub.display_name if sub else None,
        )
        session.commit()
    except Exception as e:
        logger.exception("Offboarding failed mid-operation for employee %s", emp.id)
        op.status = "failed"
        op.error_detail = str(e)
        session.commit()
        raise

    return op
