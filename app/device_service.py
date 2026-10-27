"""Device inventory, registration, status management, and credential revocation service.

Implements B09, B10, and B11 specifications:
- Distinct physical devices linked to stable employee UUIDs
- Scoped permissions (platform superadmin, subsidiary superadmin, or ordinary admin with role grant)
- Department and network-role pairing validation per subsidiary
- Device lifecycle states: active, lost, retired
- Per-device credential revocation with CRL regeneration
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import cert_service, db, pki
from app.network_policy import (
    ForbiddenError,
    PolicyValidationError,
    ResourceNotFoundError,
    assert_can_manage_subsidiary,
    is_admin_in_scope,
    resolve_admin_subsidiary_id,
)

logger = logging.getLogger(__name__)


def get_device(actor: db.Admin, device_id: str, session: Session) -> db.Device:
    """Retrieves a device ensuring tenant isolation."""
    device = session.get(db.Device, device_id)
    if not device:
        raise ResourceNotFoundError("Device not found")

    if not is_admin_in_scope(actor, device.subsidiary_id, session):
        raise ResourceNotFoundError("Device not found")

    return device


def list_devices(
    actor: db.Admin,
    session: Session,
    subsidiary_id: str | None = None,
    employee_id: str | None = None,
    department_id: str | None = None,
    network_role_id: str | None = None,
    status_filter: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Lists devices matching filters within actor's subsidiary scope."""
    stmt = select(db.Device)

    # Scoping
    if actor.role == db.AdminRole.subsidiary_super_admin:
        actor_sub = resolve_admin_subsidiary_id(actor, session)
        if not actor_sub:
            return [], 0
        stmt = stmt.where(db.Device.subsidiary_id == actor_sub)
    elif actor.subsidiary_scope:
        actor_sub = resolve_admin_subsidiary_id(actor, session)
        if actor_sub:
            stmt = stmt.where(db.Device.subsidiary_id == actor_sub)
        else:
            return [], 0
    elif subsidiary_id:
        stmt = stmt.where(db.Device.subsidiary_id == subsidiary_id)

    if employee_id:
        stmt = stmt.where(db.Device.employee_id == employee_id)

    if department_id:
        stmt = stmt.where(db.Device.department_id == department_id)

    if network_role_id:
        stmt = stmt.where(db.Device.network_role_id == network_role_id)

    if status_filter:
        stmt = stmt.where(db.Device.status == status_filter)

    if search:
        term = f"%{search.strip()}%"
        stmt = stmt.where(
            (db.Device.display_name.ilike(term))
            | (db.Device.asset_tag.ilike(term))
            | (db.Device.serial_number.ilike(term))
            | (db.Device.mac_address.ilike(term))
        )

    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    devices = session.scalars(
        stmt.order_by(db.Device.display_name.asc()).limit(limit).offset(offset)
    ).all()

    now = datetime.datetime.now(datetime.timezone.utc)
    results = []
    for d in devices:
        emp = session.get(db.Employee, d.employee_id)
        dept = session.get(db.Department, d.department_id)
        role = session.get(db.NetworkRole, d.network_role_id)
        sub = session.get(db.Subsidiary, d.subsidiary_id)

        # Get active certs for this device
        certs = session.scalars(
            select(db.Certificate).where(
                db.Certificate.device_id == d.id,
                db.Certificate.cert_type == "client",
                db.Certificate.status == db.CertStatus.active,
            )
        ).all()
        usable_certs = [c for c in certs if not c.is_expired(now)]

        results.append({
            "id": d.id,
            "display_name": d.display_name,
            "subsidiary_id": d.subsidiary_id,
            "subsidiary_name": sub.display_name if sub else "",
            "employee_id": d.employee_id,
            "employee_name": emp.display_name if emp else "",
            "employee_number": emp.employee_number if emp else "",
            "department_id": d.department_id,
            "department_name": dept.display_name if dept else "",
            "network_role_id": d.network_role_id,
            "network_role_name": role.display_name if role else "",
            "device_type": d.device_type,
            "device_model": d.device_model,
            "asset_tag": d.asset_tag,
            "serial_number": d.serial_number,
            "mac_address": d.mac_address,
            "status": d.status,
            "created_at": d.created_at,
            "active_cert_count": len(usable_certs),
            "has_usable_credentials": len(usable_certs) > 0 and any(c.network_role_id == d.network_role_id for c in usable_certs),
        })

    return results, total


def register_device(
    actor: db.Admin,
    employee_id: str,
    display_name: str,
    department_id: str,
    network_role_id: str,
    session: Session,
    device_type: str | None = None,
    device_model: str | None = None,
    asset_tag: str | None = None,
    serial_number: str | None = None,
    mac_address: str | None = None,
) -> db.Device:
    """Registers a new device attached to an employee.
    
    Validates tenant scope, employee state, department/role validity, and department-role pairing.
    """
    emp = session.get(db.Employee, employee_id)
    if not emp:
        raise ResourceNotFoundError("Employee not found")

    if not is_admin_in_scope(actor, emp.subsidiary_id, session):
        raise ResourceNotFoundError("Employee not found")

    if emp.status == "offboarded":
        raise PolicyValidationError("Cannot add device to an offboarded employee")

    # Permission check:
    if actor.role == db.AdminRole.admin:
        # Ordinary admin must have grant for network_role_id
        grant = session.scalar(
            select(db.AdminRoleGrant).where(
                db.AdminRoleGrant.admin_id == actor.id,
                db.AdminRoleGrant.network_role_id == network_role_id,
            )
        )
        if not grant:
            raise ForbiddenError("Admin lacks issuance grant for this network role")
    else:
        assert_can_manage_subsidiary(actor, emp.subsidiary_id, session)

    name = display_name.strip()
    if not name:
        raise PolicyValidationError("Device display name cannot be blank")

    # Validate department
    dept = session.get(db.Department, department_id)
    if not dept or dept.subsidiary_id != emp.subsidiary_id or not dept.is_active:
        raise PolicyValidationError("Department does not belong to employee's subsidiary or is inactive")

    # Validate role
    role = session.get(db.NetworkRole, network_role_id)
    if not role or role.subsidiary_id != emp.subsidiary_id or not role.is_active:
        raise PolicyValidationError("Network role does not belong to employee's subsidiary or is inactive")

    # Validate pairing
    pairing = session.scalar(
        select(db.DepartmentRole).where(
            db.DepartmentRole.department_id == department_id,
            db.DepartmentRole.network_role_id == network_role_id,
        )
    )
    if not pairing:
        raise PolicyValidationError(
            f"Department '{dept.display_name}' is not paired with network role '{role.display_name}'"
        )

    # Check asset tag uniqueness within subsidiary if supplied
    clean_tag = asset_tag.strip() if asset_tag else None
    if clean_tag:
        existing = session.scalar(
            select(db.Device).where(
                db.Device.subsidiary_id == emp.subsidiary_id,
                db.Device.asset_tag == clean_tag,
            )
        )
        if existing:
            raise PolicyValidationError(f"Asset tag '{clean_tag}' is already registered in this subsidiary")

    device = db.Device(
        subsidiary_id=emp.subsidiary_id,
        employee_id=emp.id,
        display_name=name,
        device_type=device_type.strip() if device_type else None,
        device_model=device_model.strip() if device_model else None,
        asset_tag=clean_tag,
        serial_number=serial_number.strip() if serial_number else None,
        mac_address=mac_address.strip() if mac_address else None,
        department_id=department_id,
        network_role_id=network_role_id,
        status="active",
    )
    session.add(device)
    session.flush()

    sub = session.get(db.Subsidiary, emp.subsidiary_id)
    db.audit(
        session,
        actor=actor.username,
        action="device.register",
        target=device.display_name,
        detail=f"Registered device {device.display_name} ({device.id}) for employee {emp.display_name}",
        subsidiary=sub.display_name if sub else None,
    )
    return device


def update_device(
    actor: db.Admin,
    device_id: str,
    session: Session,
    display_name: str | None = None,
    department_id: str | None = None,
    network_role_id: str | None = None,
    device_type: str | None = None,
    device_model: str | None = None,
    asset_tag: str | None = None,
    serial_number: str | None = None,
    mac_address: str | None = None,
) -> db.Device:
    """Updates device metadata and/or assigned department/role."""
    device = get_device(actor, device_id, session)

    if actor.role == db.AdminRole.admin:
        # Check grant on existing and new role if changed
        target_role = network_role_id or device.network_role_id
        grant = session.scalar(
            select(db.AdminRoleGrant).where(
                db.AdminRoleGrant.admin_id == actor.id,
                db.AdminRoleGrant.network_role_id == target_role,
            )
        )
        if not grant:
            raise ForbiddenError("Admin lacks grant for network role")
    else:
        assert_can_manage_subsidiary(actor, device.subsidiary_id, session)

    if display_name is not None:
        name = display_name.strip()
        if not name:
            raise PolicyValidationError("Display name cannot be empty")
        device.display_name = name

    target_dept_id = department_id or device.department_id
    target_role_id = network_role_id or device.network_role_id

    if department_id is not None or network_role_id is not None:
        dept = session.get(db.Department, target_dept_id)
        if not dept or dept.subsidiary_id != device.subsidiary_id or not dept.is_active:
            raise PolicyValidationError("Department does not belong to subsidiary or is inactive")

        role = session.get(db.NetworkRole, target_role_id)
        if not role or role.subsidiary_id != device.subsidiary_id or not role.is_active:
            raise PolicyValidationError("Network role does not belong to subsidiary or is inactive")

        pairing = session.scalar(
            select(db.DepartmentRole).where(
                db.DepartmentRole.department_id == target_dept_id,
                db.DepartmentRole.network_role_id == target_role_id,
            )
        )
        if not pairing:
            raise PolicyValidationError(
                f"Department '{dept.display_name}' is not paired with network role '{role.display_name}'"
            )

        device.department_id = target_dept_id
        device.network_role_id = target_role_id

    if device_type is not None:
        device.device_type = device_type.strip() or None
    if device_model is not None:
        device.device_model = device_model.strip() or None
    if serial_number is not None:
        device.serial_number = serial_number.strip() or None
    if mac_address is not None:
        device.mac_address = mac_address.strip() or None

    if asset_tag is not None:
        tag = asset_tag.strip() or None
        if tag and tag != device.asset_tag:
            existing = session.scalar(
                select(db.Device).where(
                    db.Device.subsidiary_id == device.subsidiary_id,
                    db.Device.asset_tag == tag,
                    db.Device.id != device.id,
                )
            )
            if existing:
                raise PolicyValidationError(f"Asset tag '{tag}' is already registered in this subsidiary")
        device.asset_tag = tag

    session.flush()
    sub = session.get(db.Subsidiary, device.subsidiary_id)
    db.audit(
        session,
        actor=actor.username,
        action="device.update",
        target=device.display_name,
        detail=f"Updated device {device.id}",
        subsidiary=sub.display_name if sub else None,
    )
    return device


def set_device_status(
    actor: db.Admin,
    device_id: str,
    status: str,
    reason: str,
    session: Session,
) -> db.Device:
    """Sets device lifecycle status ('active', 'lost', 'retired')."""
    device = get_device(actor, device_id, session)
    assert_can_manage_subsidiary(actor, device.subsidiary_id, session)

    clean_status = status.strip().lower()
    if clean_status not in ("active", "lost", "retired"):
        raise PolicyValidationError("Status must be 'active', 'lost', or 'retired'")

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for status change")

    old_status = device.status
    device.status = clean_status
    session.flush()

    sub = session.get(db.Subsidiary, device.subsidiary_id)
    db.audit(
        session,
        actor=actor.username,
        action="device.status_change",
        target=device.display_name,
        detail=f"Status changed from {old_status} to {clean_status}: {reason.strip()}",
        subsidiary=sub.display_name if sub else None,
    )
    return device


def revoke_device_credentials(
    actor: db.Admin,
    device_id: str,
    reason: str,
    session: Session,
    pki_path: Path,
    inter_cert=None,
    inter_key=None,
    regenerate_crl_fn=None,
) -> list[str]:
    """Revokes all usable client certificates linked to this device and updates CRL."""
    device = get_device(actor, device_id, session)
    assert_can_manage_subsidiary(actor, device.subsidiary_id, session)

    if not reason or not reason.strip():
        raise PolicyValidationError("Reason is required for credential revocation")

    now = datetime.datetime.now(datetime.timezone.utc)
    certs = session.scalars(
        select(db.Certificate).where(
            db.Certificate.device_id == device.id,
            db.Certificate.cert_type == "client",
            db.Certificate.status.in_([db.CertStatus.active, db.CertStatus.suspended]),
        )
    ).all()
    usable = [c for c in certs if not c.is_expired(now)]

    revoked_serials = []
    for c in usable:
        cert_service.revoke(
            session,
            pki_path,
            c.serial,
            reason=f"Device credential revocation: {reason.strip()}",
            actor=actor.username,
        )
        revoked_serials.append(c.serial)

    if revoked_serials:
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

        sub = session.get(db.Subsidiary, device.subsidiary_id)
        db.audit(
            session,
            actor=actor.username,
            action="device.revoke_credentials",
            target=device.display_name,
            detail=f"Revoked {len(revoked_serials)} credentials on device {device.id}: {reason.strip()}",
            subsidiary=sub.display_name if sub else None,
        )

    return revoked_serials
