"""HTML Web routes for employees, devices, and reliable multi-certificate offboarding.

Implements B10 and B11 specifications:
- Main navigation directory at /employees
- Detailed views at /people/{employee_id} and /devices/{device_id}
- Add device and status change actions
- Reliable multi-certificate offboarding confirmation and execution
- Backward compatibility with legacy /employees/{employee_key} paths
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, crl_health, db, device_service, employee_service, network_policy as np
from app.routes import web_helpers as h
from app.validation import normalize_employee_key

logger = logging.getLogger(__name__)
_REVOCABLE_STATUSES = (db.CertStatus.active, db.CertStatus.suspended)
DEFAULT_OFFBOARD_REASON = "employee offboarding"


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-employees"])
    _crl_banner_context = crl_health.banner_context

    @router.get("/employees")
    def employee_directory(
        request: Request,
        subsidiary_id: str | None = None,
        department_id: str | None = None,
        q: str | None = None,
        status: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        is_plat_super = admin.role == db.AdminRole.super_admin
        actor_sub_id = np.resolve_admin_subsidiary_id(admin, session)

        # Build list of accessible subsidiaries
        if is_plat_super:
            subs = session.scalars(
                select(db.Subsidiary).where(db.Subsidiary.is_active.is_(True)).order_by(db.Subsidiary.display_name.asc())
            ).all()
        elif actor_sub_id:
            sub = session.get(db.Subsidiary, actor_sub_id)
            subs = [sub] if sub and sub.is_active else []
        else:
            subs = []

        # Effective subsidiary filter
        eff_sub_id = actor_sub_id if not is_plat_super else subsidiary_id

        # Departments for filtering and modal
        dept_stmt = select(db.Department).where(db.Department.is_active.is_(True))
        if eff_sub_id:
            dept_stmt = dept_stmt.where(db.Department.subsidiary_id == eff_sub_id)
        departments = session.scalars(dept_stmt.order_by(db.Department.display_name.asc())).all()

        employees, total = employee_service.list_employees(
            actor=admin,
            session=session,
            subsidiary_id=eff_sub_id,
            department_id=department_id,
            search=q,
            status_filter=status,
            limit=limit,
            offset=offset,
        )

        can_manage = is_plat_super or admin.role == db.AdminRole.subsidiary_super_admin

        return templates.TemplateResponse(
            request,
            "employees_list.html",
            {
                "admin": admin,
                "is_platform_superadmin": is_plat_super,
                "can_manage": can_manage,
                "actor_subsidiary_id": actor_sub_id,
                "subsidiaries": subs,
                "departments": departments,
                "modal_departments": departments,
                "selected_subsidiary_id": eff_sub_id,
                "selected_department_id": department_id,
                "selected_status": status,
                "search_query": q,
                "employees": employees,
                "total": total,
                "limit": limit,
                "offset": offset,
                **_crl_banner_context(session),
            },
        )

    @router.post("/people/new", dependencies=[Depends(deps.require_write)])
    def create_person(
        request: Request,
        display_name: str = Form(...),
        subsidiary_id: str = Form(...),
        department_id: str = Form(...),
        employee_number: str | None = Form(None),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.create_employee(
                actor=admin,
                subsidiary_id=subsidiary_id,
                display_name=display_name,
                department_id=department_id,
                employee_number=employee_number,
                session=session,
            )
            session.commit()
            return RedirectResponse(
                h.flash(f"/people/{emp.id}", f"Employee '{emp.display_name}' created successfully.", "success"),
                status_code=303,
            )
        except Exception as e:
            return RedirectResponse(
                h.flash("/employees", f"Error creating employee: {e}", "danger"),
                status_code=303,
            )

    @router.get("/people/{employee_id}")
    def person_detail(
        request: Request,
        employee_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
        except Exception:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee not found")

        metrics = employee_service.compute_employee_metrics(emp.id, session)
        sub = session.get(db.Subsidiary, emp.subsidiary_id)
        dept = session.get(db.Department, emp.department_id)

        devices, _ = device_service.list_devices(actor=admin, session=session, employee_id=emp.id)

        # Available roles paired with employee's department
        paired_role_ids = session.scalars(
            select(db.DepartmentRole.network_role_id).where(db.DepartmentRole.department_id == emp.department_id)
        ).all()
        roles = session.scalars(
            select(db.NetworkRole).where(
                db.NetworkRole.id.in_(paired_role_ids),
                db.NetworkRole.is_active.is_(True),
            )
        ).all()

        depts = session.scalars(
            select(db.Department).where(
                db.Department.subsidiary_id == emp.subsidiary_id,
                db.Department.is_active.is_(True),
            )
        ).all()

        can_manage = admin.role in (db.AdminRole.super_admin, db.AdminRole.subsidiary_super_admin)

        return templates.TemplateResponse(
            request,
            "person_detail.html",
            {
                "admin": admin,
                "can_manage": can_manage,
                "employee": emp,
                "subsidiary": sub,
                "department": dept,
                "departments": depts,
                "available_roles": roles,
                "metrics": metrics,
                "devices": devices,
                **_crl_banner_context(session),
            },
        )

    @router.post("/people/{employee_id}/devices/new", dependencies=[Depends(deps.require_write)])
    def register_device(
        request: Request,
        employee_id: str,
        display_name: str = Form(...),
        department_id: str = Form(...),
        network_role_id: str = Form(...),
        device_type: str | None = Form(None),
        device_model: str | None = Form(None),
        asset_tag: str | None = Form(None),
        serial_number: str | None = Form(None),
        mac_address: str | None = Form(None),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.register_device(
                actor=admin,
                employee_id=employee_id,
                display_name=display_name,
                department_id=department_id,
                network_role_id=network_role_id,
                session=session,
                device_type=device_type,
                device_model=device_model,
                asset_tag=asset_tag,
                serial_number=serial_number,
                mac_address=mac_address,
            )
            session.commit()
            return RedirectResponse(
                h.flash(f"/devices/{dev.id}", f"Device '{dev.display_name}' registered successfully.", "success"),
                status_code=303,
            )
        except Exception as e:
            return RedirectResponse(
                h.flash(f"/people/{employee_id}", f"Error registering device: {e}", "danger"),
                status_code=303,
            )

    @router.get("/people/{employee_id}/offboard")
    def person_offboard_confirm(
        request: Request,
        employee_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
        except Exception:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee not found")

        # Check permissions: platform superadmin or subsidiary superadmin for this tenant
        if not (admin.role == db.AdminRole.super_admin or (
            admin.role == db.AdminRole.subsidiary_super_admin and np.is_admin_in_scope(admin, emp.subsidiary_id, session)
        )):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only superadmins can offboard employees")

        sub = session.get(db.Subsidiary, emp.subsidiary_id)
        devices = session.scalars(select(db.Device).where(db.Device.employee_id == emp.id)).all()

        certs = session.scalars(
            select(db.Certificate).where(
                db.Certificate.employee_id == emp.id,
                db.Certificate.cert_type == "client",
                db.Certificate.status.in_(_REVOCABLE_STATUSES),
            )
        ).all()
        target_certs = [c for c in certs if not c.is_expired()]

        return templates.TemplateResponse(
            request,
            "person_offboard_confirm.html",
            {
                "admin": admin,
                "employee": emp,
                "subsidiary": sub,
                "devices": devices,
                "target_certs": target_certs,
                **_crl_banner_context(session),
            },
        )

    @router.post("/people/{employee_id}/offboard", dependencies=[Depends(deps.require_write)])
    def person_offboard_submit(
        request: Request,
        employee_id: str,
        confirm_name: str = Form(...),
        reason: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            emp = employee_service.get_employee(admin, employee_id, session)
        except Exception:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Employee not found")

        if confirm_name.strip() != emp.display_name.strip():
            sub = session.get(db.Subsidiary, emp.subsidiary_id)
            devices = session.scalars(select(db.Device).where(db.Device.employee_id == emp.id)).all()
            certs = session.scalars(
                select(db.Certificate).where(
                    db.Certificate.employee_id == emp.id,
                    db.Certificate.cert_type == "client",
                    db.Certificate.status.in_(_REVOCABLE_STATUSES),
                )
            ).all()
            target_certs = [c for c in certs if not c.is_expired()]

            return templates.TemplateResponse(
                request,
                "person_offboard_confirm.html",
                {
                    "admin": admin,
                    "employee": emp,
                    "subsidiary": sub,
                    "devices": devices,
                    "target_certs": target_certs,
                    "error": f"Typed name '{confirm_name}' did not match '{emp.display_name}'.",
                    **_crl_banner_context(session),
                },
                status_code=400,
            )

        try:
            op = employee_service.offboard_employee(
                actor=admin,
                employee_id=employee_id,
                reason=reason,
                session=session,
                pki_path=deps.pki_path,
                inter_cert=deps.inter_cert,
                inter_key=deps.inter_key,
                regenerate_crl_fn=deps.regenerate_and_push_crl,
            )
            import json
            revoked_count = len(json.loads(op.revoked_serials_json))
            return RedirectResponse(
                h.flash(
                    f"/people/{emp.id}",
                    f"Employee '{emp.display_name}' offboarded. {revoked_count} certificate(s) revoked and CRL published.",
                    "danger",
                ),
                status_code=303,
            )
        except Exception as e:
            return RedirectResponse(
                h.flash(f"/people/{employee_id}", f"Offboarding error: {e}", "danger"),
                status_code=303,
            )

    @router.get("/devices/{device_id}")
    def device_detail(
        request: Request,
        device_id: str,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.get_device(admin, device_id, session)
        except Exception:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Device not found")

        emp = session.get(db.Employee, dev.employee_id)
        sub = session.get(db.Subsidiary, dev.subsidiary_id)
        dept = session.get(db.Department, dev.department_id)
        role = session.get(db.NetworkRole, dev.network_role_id)

        # Site policies for this role
        bindings = session.scalars(
            select(db.SiteRoleBinding).where(
                db.SiteRoleBinding.subsidiary_id == dev.subsidiary_id,
                db.SiteRoleBinding.network_role_id == dev.network_role_id,
            )
        ).all()

        site_policies = []
        for b in bindings:
            site = session.get(db.Site, b.site_id)
            latest_pub = session.scalar(
                select(db.SitePolicyRevision)
                .where(db.SitePolicyRevision.site_id == b.site_id)
                .order_by(db.SitePolicyRevision.revision.desc())
                .limit(1)
            )
            latest_ack = session.scalar(
                select(db.SitePolicyAck)
                .where(db.SitePolicyAck.site_id == b.site_id)
                .order_by(db.SitePolicyAck.installed_at.desc())
                .limit(1)
            )
            is_installed = (
                latest_pub is not None
                and latest_ack is not None
                and latest_ack.revision == latest_pub.revision
                and latest_ack.success
            )
            site_policies.append({
                "site_id": b.site_id,
                "site_name": site.name if site else b.site_id,
                "vlan_id": b.vlan_id,
                "fallback_vlan_id": b.fallback_vlan_id,
                "tenant_enabled": b.tenant_enabled,
                "platform_enabled": b.platform_enabled,
                "distribution_status": "installed" if is_installed else "pending_distribution",
            })

        certs = session.scalars(
            select(db.Certificate)
            .where(db.Certificate.device_id == dev.id, db.Certificate.cert_type == "client")
            .order_by(db.Certificate.issued_at.desc())
        ).all()

        can_manage = admin.role in (db.AdminRole.super_admin, db.AdminRole.subsidiary_super_admin)

        return templates.TemplateResponse(
            request,
            "device_detail.html",
            {
                "admin": admin,
                "can_manage": can_manage,
                "device": dev,
                "employee": emp,
                "subsidiary": sub,
                "department": dept,
                "network_role": role,
                "site_policies": site_policies,
                "certificates": certs,
                **_crl_banner_context(session),
            },
        )

    @router.post("/devices/{device_id}/revoke", dependencies=[Depends(deps.require_write)])
    def revoke_device_credentials(
        request: Request,
        device_id: str,
        reason: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            revoked = device_service.revoke_device_credentials(
                actor=admin,
                device_id=device_id,
                reason=reason,
                session=session,
                pki_path=deps.pki_path,
                inter_cert=deps.inter_cert,
                inter_key=deps.inter_key,
                regenerate_crl_fn=deps.regenerate_and_push_crl,
            )
            session.commit()
            return RedirectResponse(
                h.flash(
                    f"/devices/{device_id}",
                    f"Revoked {len(revoked)} certificate(s) for this device and updated CRL.",
                    "danger",
                ),
                status_code=303,
            )
        except Exception as e:
            return RedirectResponse(
                h.flash(f"/devices/{device_id}", f"Revocation error: {e}", "danger"),
                status_code=303,
            )

    @router.post("/devices/{device_id}/status", dependencies=[Depends(deps.require_write)])
    def update_device_status(
        request: Request,
        device_id: str,
        status: str = Form(...),
        reason: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session: Session = deps.get_db_session()
        try:
            dev = device_service.set_device_status(
                actor=admin,
                device_id=device_id,
                status=status,
                reason=reason,
                session=session,
            )
            session.commit()
            return RedirectResponse(
                h.flash(f"/devices/{device_id}", f"Device status updated to '{dev.status}'.", "success"),
                status_code=303,
            )
        except Exception as e:
            return RedirectResponse(
                h.flash(f"/devices/{device_id}", f"Status update error: {e}", "danger"),
                status_code=303,
            )

    # -------------------------------------------------------------------------
    # Legacy routes preservation: /employees/{employee_key}
    # -------------------------------------------------------------------------
    def _load_legacy_employee_certs_or_404(session, admin: db.Admin, employee_key: str) -> list[db.Certificate]:
        stmt = select(db.Certificate).where(
            db.Certificate.employee_key == employee_key, db.Certificate.cert_type == "client"
        )
        if admin.subsidiary_scope:
            stmt = stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        certs = session.scalars(stmt.order_by(db.Certificate.status, db.Certificate.expires_at)).all()
        if not certs:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return certs

    def _canonical_name(certs: list[db.Certificate]) -> str:
        return max(certs, key=lambda c: c.issued_at).employee_name

    @router.get("/employees/{employee_key}")
    def legacy_employee_detail(request: Request, employee_key: str, admin: db.Admin = Depends(deps.require_admin)):
        session: Session = deps.get_db_session()
        # Check if this maps to a unique employee record
        actor_sub_id = np.resolve_admin_subsidiary_id(admin, session)
        emp_stmt = select(db.Employee)
        if actor_sub_id:
            emp_stmt = emp_stmt.where(db.Employee.subsidiary_id == actor_sub_id)

        def _clean_key(val: str | None) -> str:
            if not val:
                return ""
            import re
            return re.sub(r"[\s_-]+", " ", val.strip()).casefold()

        matching_emps = session.scalars(emp_stmt).all()
        target_key = _clean_key(employee_key)
        normalized_matches = [
            e for e in matching_emps
            if _clean_key(e.display_name) == target_key
            or (e.employee_number and _clean_key(e.employee_number) == target_key)
        ]
        if len(normalized_matches) == 1:
            # Unambiguous resolution -> redirect to stable UUID path
            return RedirectResponse(f"/people/{normalized_matches[0].id}", status_code=302)

        certs = _load_legacy_employee_certs_or_404(session, admin, employee_key)
        revocable = [c for c in certs if c.status in _REVOCABLE_STATUSES]
        return templates.TemplateResponse(
            request,
            "employee_detail.html",
            {
                "admin": admin,
                "employee_key": employee_key,
                "employee_name": _canonical_name(certs),
                "certs": certs,
                "revocable_count": len(revocable),
                **_crl_banner_context(session),
            },
        )

    @router.get("/employees/{employee_key}/offboard")
    def legacy_offboard_confirm(request: Request, employee_key: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session: Session = deps.get_db_session()
        certs = _load_legacy_employee_certs_or_404(session, admin, employee_key)
        revocable = [c for c in certs if c.status in _REVOCABLE_STATUSES]
        if not revocable:
            return RedirectResponse(
                h.flash(f"/employees/{employee_key}", "No active or suspended certificates to revoke.", "warn"),
                status_code=303,
            )
        return templates.TemplateResponse(
            request,
            "employee_offboard_confirm.html",
            {
                "admin": admin,
                "employee_key": employee_key,
                "employee_name": _canonical_name(certs),
                "revocable": revocable,
                "default_reason": DEFAULT_OFFBOARD_REASON,
                **_crl_banner_context(session),
            },
        )

    @router.post("/employees/{employee_key}/offboard")
    def legacy_offboard_submit(
        request: Request,
        employee_key: str,
        confirm_name: str = Form(...),
        reason: str = Form(DEFAULT_OFFBOARD_REASON),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session: Session = deps.get_db_session()
        certs = _load_legacy_employee_certs_or_404(session, admin, employee_key)
        revocable = [c for c in certs if c.status in _REVOCABLE_STATUSES]
        employee_name = _canonical_name(certs)

        if not revocable:
            return RedirectResponse(
                h.flash(f"/employees/{employee_key}", "No active or suspended certificates to revoke.", "warn"),
                status_code=303,
            )

        if normalize_employee_key(confirm_name) != employee_key:
            return templates.TemplateResponse(
                request,
                "employee_offboard_confirm.html",
                {
                    "admin": admin,
                    "employee_key": employee_key,
                    "employee_name": employee_name,
                    "revocable": revocable,
                    "default_reason": reason or DEFAULT_OFFBOARD_REASON,
                    "error": "Typed name didn't match — nothing was revoked.",
                    **_crl_banner_context(session),
                },
                status_code=400,
            )

        reason = reason.strip() or DEFAULT_OFFBOARD_REASON
        serials = []
        for cert in revocable:
            cert_service.revoke(session, deps.pki_path, cert.serial, reason, admin.username)
            serials.append(cert.serial)

        deps.regenerate_and_push_crl()

        db.audit(
            session,
            actor=admin.username,
            action="employee_offboard",
            target=employee_name,
            detail=f"revoked {len(serials)} certificate(s): {', '.join(serials)} (reason: {reason})",
        )
        session.commit()

        return RedirectResponse(
            h.flash(
                f"/employees/{employee_key}",
                f"{len(serials)} certificate(s) revoked for {employee_name}.",
                "danger",
            ),
            status_code=303,
        )

    return router
