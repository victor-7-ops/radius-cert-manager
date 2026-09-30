"""Employee offboarding (HANDOFF-LIFECYCLE.md §1.2). Every certificate a
departed employee holds — laptop, phone, tablet — must be revoked
together, keyed on employee_key (§1.1) so display-spelling drift can't
make revoke-all miss a device."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import cert_service, crl_health, db
from app.routes import web_helpers as h
from app.validation import normalize_employee_key

_REVOCABLE_STATUSES = (db.CertStatus.active, db.CertStatus.suspended)
DEFAULT_OFFBOARD_REASON = "employee offboarding"


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-employees"])

    _crl_banner_context = crl_health.banner_context

    def _load_employee_certs_or_404(session, admin: db.Admin, employee_key: str) -> list[db.Certificate]:
        stmt = select(db.Certificate).where(
            db.Certificate.employee_key == employee_key, db.Certificate.cert_type == "client"
        )
        if admin.subsidiary_scope:
            # A scoped admin must never see or act on an employee outside
            # their subsidiary — treating "exists but out of scope" and
            # "doesn't exist" identically (404 either way) rather than a
            # 403 avoids confirming an out-of-scope employee even exists.
            stmt = stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        certs = session.scalars(stmt.order_by(db.Certificate.status, db.Certificate.expires_at)).all()
        if not certs:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        return certs

    def _canonical_name(certs: list[db.Certificate]) -> str:
        # The most recently issued cert's spelling — the most likely to
        # be current if the display spelling has drifted over time.
        return max(certs, key=lambda c: c.issued_at).employee_name

    @router.get("/employees/{employee_key}")
    def employee_detail(request: Request, employee_key: str, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        certs = _load_employee_certs_or_404(session, admin, employee_key)
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
    def offboard_confirm(request: Request, employee_key: str, admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        certs = _load_employee_certs_or_404(session, admin, employee_key)
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
    def offboard_submit(
        request: Request,
        employee_key: str,
        confirm_name: str = Form(...),
        reason: str = Form(DEFAULT_OFFBOARD_REASON),
        admin: db.Admin = Depends(deps.require_super_admin),
    ):
        session = deps.get_db_session()
        certs = _load_employee_certs_or_404(session, admin, employee_key)
        revocable = [c for c in certs if c.status in _REVOCABLE_STATUSES]
        employee_name = _canonical_name(certs)

        if not revocable:
            return RedirectResponse(
                h.flash(f"/employees/{employee_key}", "No active or suspended certificates to revoke.", "warn"),
                status_code=303,
            )

        if normalize_employee_key(confirm_name) != employee_key:
            # The confirmation itself must be posted correctly — a typed
            # mismatch can't be bypassed by resubmitting with a stale or
            # guessed value, unlike the duplicate-warning confirm flow
            # elsewhere, which is deliberately a single hidden flag.
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

        # One CRL regen for the whole batch, not one per certificate
        # (reuses the same pattern as /certs/bulk-action).
        deps.regenerate_and_push_crl()

        # One summary audit row naming the employee and listing every
        # serial, on top of the per-certificate rows cert_service.revoke()
        # already writes — an auditor asking "what happened when X left"
        # finds one entry, not fifteen.
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
