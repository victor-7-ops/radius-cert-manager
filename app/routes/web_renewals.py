"""The renewal campaign work queue (HANDOFF-LIFECYCLE.md §2) — what has
to be re-enrolled, and what's already done. Client certs are 365 days
with no automated re-enrolment, so this is run by hand once a year.
"""

from __future__ import annotations

import csv
import datetime
import io

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app import cert_service, crl_health, db, rate_limit, renewal
from app.routes import web_helpers as h

WINDOW_CHOICES = {"30": 30, "60": 60, "90": 90, "expired": None}


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web-renewals"])

    _crl_banner_context = crl_health.banner_context

    def _cohort_rows(session, admin: db.Admin, window_days: int | None, now: datetime.datetime) -> list[renewal.CohortRow]:
        stmt = select(db.Certificate).where(
            db.Certificate.cert_type == "client", db.Certificate.status == db.CertStatus.active
        )
        if admin.subsidiary_scope:
            stmt = stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        candidates = session.scalars(stmt).all()

        rows = []
        for cert in candidates:
            if not renewal.in_cohort(cert, window_days, now):
                continue
            successor = session.scalar(
                select(db.Certificate).where(db.Certificate.supersedes_id == cert.id)
            )
            progress = renewal.progress_for(cert, successor, window_days, now)
            days_remaining = (renewal.aware(cert.expires_at) - now).total_seconds() / 86400
            rows.append(renewal.CohortRow(certificate=cert, successor=successor, progress=progress, days_remaining=days_remaining))
        rows.sort(key=lambda r: r.days_remaining)
        return rows

    def _parse_window(window: str) -> int | None:
        if window not in WINDOW_CHOICES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid window")
        return WINDOW_CHOICES[window]

    @router.get("/renewals")
    def renewals_cohort(
        request: Request,
        window: str = "30",
        subsidiary: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        session = deps.get_db_session()
        window_days = _parse_window(window)
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = _cohort_rows(session, admin, window_days, now)

        by_subsidiary: dict[str, dict[str, int]] = {}
        for r in rows:
            key = r.certificate.subsidiary or "Unassigned"
            bucket = by_subsidiary.setdefault(key, {"outstanding": 0, "done": 0, "total": 0})
            bucket["total"] += 1
            if r.progress == renewal.RenewalProgress.done:
                bucket["done"] += 1
            else:
                bucket["outstanding"] += 1

        if subsidiary:
            rows = [r for r in rows if (r.certificate.subsidiary or "Unassigned") == subsidiary]

        return templates.TemplateResponse(
            request,
            "renewals.html",
            {
                "admin": admin,
                "window": window,
                "subsidiary_filter": subsidiary,
                "rows": rows,
                "by_subsidiary": sorted(by_subsidiary.items()),
                "total_count": sum(b["total"] for b in by_subsidiary.values()),
                "outstanding_count": sum(b["outstanding"] for b in by_subsidiary.values()),
                "done_count": sum(b["done"] for b in by_subsidiary.values()),
                **_crl_banner_context(session),
            },
        )

    @router.get("/renewals/export.csv")
    def renewals_export(
        window: str = "30",
        subsidiary: str | None = None,
        admin: db.Admin = Depends(deps.require_write),
    ):
        if rate_limit.is_rate_limited(f"export:{admin.id}", max_requests=10, window_seconds=300):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many exports — wait a few minutes and try again.")
        session = deps.get_db_session()
        window_days = _parse_window(window)
        now = datetime.datetime.now(datetime.timezone.utc)
        rows = _cohort_rows(session, admin, window_days, now)
        if subsidiary:
            rows = [r for r in rows if (r.certificate.subsidiary or "Unassigned") == subsidiary]

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["cn", "employee_name", "subsidiary", "device_type", "device_model", "expires_at", "days_remaining", "progress"])
        for r in rows:
            c = r.certificate
            writer.writerow([
                c.cn, c.employee_name or "", c.subsidiary or "", c.device_type or "", c.device_model or "",
                c.expires_at.date().isoformat(), round(r.days_remaining), r.progress.value,
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="renewal-cohort.csv"'},
        )

    @router.post("/certs/{serial}/retire")
    def retire_cert(
        request: Request,
        serial: str,
        reason: str = Form(...),
        admin: db.Admin = Depends(deps.require_write),
    ):
        session = deps.get_db_session()
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == serial))
        if cert is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
        h.require_cert_scope(admin, cert)

        cert.retired_at = datetime.datetime.now(datetime.timezone.utc)
        db.audit(
            session, actor=admin.username, action="cert_retire", target=cert.cn,
            detail=f"serial={cert.serial} reason={reason}", subsidiary=cert.subsidiary,
        )
        session.commit()

        dest = request.headers.get("referer", "/renewals")
        return RedirectResponse(h.flash(dest, f"{cert.cn} marked as not renewing.", "warn"), status_code=303)

    return router
