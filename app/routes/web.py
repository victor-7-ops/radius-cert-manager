"""Server-rendered UI routes (Jinja2 + HTMX) — handoff §6: dashboard,
system health, activity log, login page, and the root redirect.

Certificate routes live in app/routes/web_certs.py, self-service
account routes in app/routes/web_account.py, and admin management in
app/routes/web_admins.py — split out of this module since it used to
carry all of them (see app/routes/web_helpers.py for the shared
formatting/scope helpers used across all four).
"""

from __future__ import annotations

import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from app import crl_health, db, fleet_health, reconcile
from app.routes import web_helpers as h


def get_router(deps, templates: Jinja2Templates) -> APIRouter:
    router = APIRouter(tags=["web"])

    _crl_banner_context = crl_health.banner_context

    @router.get("/login")
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html", {})

    @router.get("/dashboard")
    def dashboard(request: Request, admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        now = datetime.datetime.now(datetime.timezone.utc)
        thirty_days = now + datetime.timedelta(days=30)

        cert_stmt = select(db.Certificate).where(db.Certificate.cert_type == "client")
        if admin.subsidiary_scope:
            cert_stmt = cert_stmt.where(db.Certificate.subsidiary == admin.subsidiary_scope)
        rows = session.scalars(cert_stmt).all()
        counts = {"active": 0, "expiring_soon": 0, "suspended": 0, "revoked": 0, "expired": 0}
        expiring = []
        for c in rows:
            eff = h.effective_status(c)
            if eff == "active":
                counts["active"] += 1
                exp = c.expires_at.replace(tzinfo=datetime.timezone.utc) if c.expires_at.tzinfo is None else c.expires_at
                if exp <= thirty_days:
                    counts["expiring_soon"] += 1
                    expiring.append(c)
            elif eff == "expired":
                counts["expired"] += 1
            elif c.status == db.CertStatus.suspended:
                counts["suspended"] += 1
            elif c.status == db.CertStatus.revoked:
                counts["revoked"] += 1

        # Donut chart segments (handoff has no chart requirement — this is
        # a glance-value add). Mutually exclusive buckets only; expiring_soon
        # is a subset of active, shown separately in "Attention needed".
        donut_buckets = [
            ("active", counts["active"], "#16a34a"),
            ("suspended", counts["suspended"], "#d97706"),
            ("revoked", counts["revoked"], "#dc2626"),
            ("expired", counts["expired"], "#94a3b8"),
        ]
        donut_total = sum(n for _, n, _ in donut_buckets)
        donut_segments = []
        cursor = 0.0
        if donut_total:
            for label, n, color in donut_buckets:
                if n == 0:
                    continue
                start = cursor
                cursor += 360 * n / donut_total
                donut_segments.append({"label": label, "count": n, "color": color, "start": round(start, 1), "end": round(cursor, 1)})

        # By-company breakdown (handoff has no requirement for this — a
        # glance-value add for tracking subsidiaries). Every cert counts
        # once here regardless of status, since this answers "how many
        # devices does each company have on file", not "how many are
        # currently valid" — that's what the status donut above is for.
        company_totals: dict[str, int] = {}
        for c in rows:
            key = c.subsidiary or "Unassigned"
            company_totals[key] = company_totals.get(key, 0) + 1
        company_breakdown = [
            {
                "name": name,
                "count": n,
                "color": db.subsidiary_color(None if name == "Unassigned" else name),
                "pct": round(100 * n / len(rows), 1) if rows else 0,
            }
            for name, n in sorted(company_totals.items(), key=lambda kv: kv[1], reverse=True)
        ]

        # Same breakdown, as conic-gradient segments for the inner ring of
        # the fleet-status donut — otherwise an all-one-status fleet (the
        # common case early on) renders as a flat, boring single-color ring.
        company_segments = []
        cursor = 0.0
        for c in company_breakdown:
            start = cursor
            cursor += 360 * c["count"] / len(rows) if rows else 0
            company_segments.append({**c, "start": round(start, 1), "end": round(cursor, 1)})

        # Issuance-over-time: last 6 calendar months, oldest first. Built
        # from the same `rows` fetch above rather than a second query —
        # this dashboard is already all-certs-in-memory, no need to hit
        # the DB again for one more aggregate over the same data.
        month_counts: dict[str, int] = {}
        month_labels: list[tuple[str, str]] = []
        cursor_month = now.replace(day=1)
        for _ in range(6):
            key = cursor_month.strftime("%Y-%m")
            month_labels.append((key, cursor_month.strftime("%b")))
            month_counts[key] = 0
            cursor_month = (cursor_month - datetime.timedelta(days=1)).replace(day=1)
        month_labels.reverse()
        for c in rows:
            issued_at = c.issued_at.replace(tzinfo=datetime.timezone.utc) if c.issued_at.tzinfo is None else c.issued_at
            key = issued_at.strftime("%Y-%m")
            if key in month_counts:
                month_counts[key] += 1
        issuance_max = max(month_counts.values()) if month_counts else 0
        issuance_trend = [
            {
                "label": label,
                "count": month_counts[key],
                "pct": round(100 * month_counts[key] / issuance_max) if issuance_max else 0,
            }
            for key, label in month_labels
        ]

        orphans = reconcile.reconcile_issued_dir(session, deps.pki_path / "issued") if not admin.subsidiary_scope else []

        if admin.subsidiary_scope:
            # AuditLog has no subsidiary column, so filter by matching
            # target against this admin's own certs — that also drops
            # admin-management entries (their target is a username, which
            # won't match any cn), which a scoped admin shouldn't see anyway.
            own_cns = {c.cn for c in rows}
            recent = [
                a for a in session.scalars(
                    select(db.AuditLog).order_by(db.AuditLog.timestamp.desc()).limit(200)
                ).all()
                if a.target in own_cns
            ][:10]
        else:
            recent = session.scalars(
                select(db.AuditLog).order_by(db.AuditLog.timestamp.desc()).limit(10)
            ).all()

        health = crl_health.get_health(session)
        ca_warnings = h.ca_expiry_warnings(deps, now)

        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "admin": admin,
                "counts": counts,
                "donut_segments": donut_segments,
                "donut_total": donut_total,
                "company_breakdown": company_breakdown,
                "company_segments": company_segments,
                "company_total": len(rows),
                "issuance_trend": issuance_trend,
                "expiring": [{"cn": c.cn, "serial": c.serial, "expires_at": c.expires_at.date()} for c in expiring],
                "orphans": orphans,
                "recent_activity": [
                    {"actor": a.actor, "action": a.action, "target": a.target, "timestamp": a.timestamp}
                    for a in recent
                ],
                "crl_health": {
                    "last_generated_at": health.last_generated_at,
                    "last_pushed_at": health.last_pushed_at,
                    "last_push_ok": health.last_push_ok,
                    "next_update": health.next_update,
                },
                "ca_expiry_warnings": ca_warnings,
                **_crl_banner_context(session),
            },
        )

    # --- System health (Super Admin only) ---

    @router.get("/health")
    def health_page(request: Request, admin: db.Admin = Depends(deps.require_super_admin)):
        import shutil

        session = deps.get_db_session()
        now = datetime.datetime.now(datetime.timezone.utc)
        crl = crl_health.get_health(session)

        status_counts = {"active": 0, "suspended": 0, "revoked": 0, "expired": 0}
        client_certs_stmt = select(db.Certificate).where(db.Certificate.cert_type == "client")
        for c in session.scalars(client_certs_stmt).all():
            status_counts[h.effective_status(c)] = status_counts.get(h.effective_status(c), 0) + 1

        db_size = deps.db_path.stat().st_size if deps.db_path.exists() else 0
        pki_size = h.dir_size_bytes(deps.pki_path)
        disk = shutil.disk_usage(deps.pki_path if deps.pki_path.exists() else deps.pki_path.parent)

        active_sessions = session.scalar(
            select(func.count()).select_from(db.AdminSession).where(db.AdminSession.revoked_at.is_(None))
        )
        active_admins = session.scalar(
            select(func.count()).select_from(db.Admin).where(db.Admin.is_active == True)  # noqa: E712
        )

        orphans = reconcile.reconcile_issued_dir(session, deps.pki_path / "issued")

        # Opportunistic, not scheduled — see app/expiry_alerts.py. Only
        # ever alerts about certs that just crossed the window since the
        # last time this page loaded, so reloading doesn't re-spam.
        newly_alerted = deps.check_expiry_alerts()

        # Scheduled separately (scripts/fleet_watch.py) for the alerting
        # side — this is just the read for the page (handoff §5.1: a
        # SILENT site must be caught even if nobody opens this page).
        fleet = fleet_health.evaluate_fleet(session, now)

        return templates.TemplateResponse(
            request,
            "health.html",
            {
                "admin": admin,
                "crl": crl,
                "status_counts": status_counts,
                "cert_total": sum(status_counts.values()),
                "db_size": h.human_bytes(db_size),
                "pki_size": h.human_bytes(pki_size),
                "disk_free": h.human_bytes(disk.free),
                "disk_total": h.human_bytes(disk.total),
                "disk_used_pct": round(100 * (disk.total - disk.free) / disk.total, 1) if disk.total else 0,
                "ca_warnings": h.ca_expiry_warnings(deps, now),
                "active_sessions": active_sessions,
                "active_admins": active_admins,
                "orphans": orphans,
                "newly_alerted": [{"cn": c.cn, "expires_at": c.expires_at.date()} for c in newly_alerted],
                "fleet": fleet,
                "expiry_alert_days": deps.expiry_alert_days,
                "slack_configured": bool(deps.alert_webhook_url),
                **_crl_banner_context(session),
            },
        )

    @router.get("/activity")
    def activity(
        request: Request,
        actor: str | None = None,
        action: str | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
        admin: db.Admin = Depends(deps.require_admin),
    ):
        # AuditLog has no subsidiary column, so there's no clean way to
        # scope this view — keep it unscoped-admin only rather than
        # showing a scoped admin other subsidiaries' activity.
        h.require_unscoped(admin, "activity log isn't available to a subsidiary-scoped admin")
        session = deps.get_db_session()
        LIMIT = 200
        stmt = select(db.AuditLog).order_by(db.AuditLog.timestamp.desc())
        if actor:
            stmt = stmt.where(db.AuditLog.actor.contains(actor))
        if action:
            stmt = stmt.where(db.AuditLog.action == action)
        if date_from:
            try:
                stmt = stmt.where(db.AuditLog.timestamp >= datetime.datetime.fromisoformat(date_from))
            except ValueError:
                date_from = None
        if date_to:
            try:
                stmt = stmt.where(
                    db.AuditLog.timestamp < datetime.datetime.fromisoformat(date_to) + datetime.timedelta(days=1)
                )
            except ValueError:
                date_to = None
        rows = session.scalars(stmt.limit(LIMIT + 1)).all()
        truncated = len(rows) > LIMIT
        rows = rows[:LIMIT]
        known_actions = sorted(a for (a,) in session.execute(select(db.AuditLog.action).distinct()))
        return templates.TemplateResponse(
            request,
            "activity_log.html",
            {
                "admin": admin,
                "entries": [
                    {"timestamp": e.timestamp, "actor": e.actor, "action": e.action, "target": e.target, "detail": e.detail}
                    for e in rows
                ],
                "actor": actor,
                "action_filter": action,
                "date_from": date_from,
                "date_to": date_to,
                "known_actions": known_actions,
                "truncated": truncated,
                "result_limit": LIMIT,
                **_crl_banner_context(session),
            },
        )

    @router.get("/")
    def root():
        return RedirectResponse("/dashboard", status_code=303)

    return router
