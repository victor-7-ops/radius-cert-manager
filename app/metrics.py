"""Prometheus metrics collector and exporter.

Produces OpenMetrics / Prometheus text exposition format (0.0.4) for
operational monitoring and alerting in Grafana/Prometheus.
"""

from __future__ import annotations

import datetime
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import crl_health, db, fleet_health


def format_prometheus_line(name: str, value: float | int, labels: dict[str, str] | None = None) -> str:
    if labels:
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}} {value}"
    return f"{name} {value}"


def collect_metrics(session: Session, now: datetime.datetime | None = None) -> str:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    lines: list[str] = [
        "# HELP radius_up Whether the RADIUS certificate manager service and database are reachable.",
        "# TYPE radius_up gauge",
        "radius_up 1",
    ]

    # 1. Certificate counts by status and cert_type
    lines.append("# HELP radius_certificates_count Current number of certificates grouped by status and type.")
    lines.append("# TYPE radius_certificates_count gauge")

    cert_status_query = (
        select(db.Certificate.cert_type, db.Certificate.status, func.count(db.Certificate.id))
        .group_by(db.Certificate.cert_type, db.Certificate.status)
    )
    for cert_type, status, count in session.execute(cert_status_query).all():
        lines.append(
            format_prometheus_line(
                "radius_certificates_count",
                count,
                {"type": cert_type or "client", "status": status.value if hasattr(status, "value") else str(status)},
            )
        )

    # 2. Active certificates by subsidiary
    lines.append("# HELP radius_certificates_subsidiary_count Active certificate counts grouped by subsidiary.")
    lines.append("# TYPE radius_certificates_subsidiary_count gauge")
    sub_query = (
        select(db.Certificate.subsidiary, func.count(db.Certificate.id))
        .where(db.Certificate.status == db.CertStatus.active)
        .group_by(db.Certificate.subsidiary)
    )
    for subsidiary, count in session.execute(sub_query).all():
        lines.append(
            format_prometheus_line(
                "radius_certificates_subsidiary_count",
                count,
                {"subsidiary": subsidiary or "unassigned"},
            )
        )

    # 3. Certificates expiring soon
    lines.append("# HELP radius_certificates_expiring_soon Active client certificates expiring within the given window.")
    lines.append("# TYPE radius_certificates_expiring_soon gauge")
    for days in (7, 14, 30):
        threshold = now + datetime.timedelta(days=days)
        expiring_count = session.scalar(
            select(func.count(db.Certificate.id)).where(
                db.Certificate.status == db.CertStatus.active,
                db.Certificate.cert_type == "client",
                db.Certificate.expires_at <= threshold,
                db.Certificate.expires_at > now,
            )
        ) or 0
        lines.append(
            format_prometheus_line(
                "radius_certificates_expiring_soon",
                expiring_count,
                {"window": f"{days}d"},
            )
        )

    # 4. CRL Freshness & Health
    lines.append("# HELP radius_crl_hours_remaining Hours remaining until the active CRL expires.")
    lines.append("# TYPE radius_crl_hours_remaining gauge")
    health = crl_health.get_health(session)
    if health.hours_remaining is not None:
        lines.append(f"radius_crl_hours_remaining {health.hours_remaining:.2f}")

    lines.append("# HELP radius_crl_is_critical Whether CRL is in critical state (expired or under 48h remaining).")
    lines.append("# TYPE radius_crl_is_critical gauge")
    lines.append(f"radius_crl_is_critical {1 if health.is_critical else 0}")

    lines.append("# HELP radius_crl_is_stale Whether CRL is already expired.")
    lines.append("# TYPE radius_crl_is_stale gauge")
    lines.append(f"radius_crl_is_stale {1 if health.is_stale else 0}")

    lines.append("# HELP radius_crl_last_push_ok Status of the last CRL push to RADIUS host (1=ok, 0=failed).")
    lines.append("# TYPE radius_crl_last_push_ok gauge")
    push_val = 1 if health.last_push_ok is True else 0
    lines.append(f"radius_crl_last_push_ok {push_val}")

    crl_entries_count = session.scalar(
        select(func.count(db.Certificate.id)).where(
            db.Certificate.status.in_([db.CertStatus.revoked, db.CertStatus.suspended])
        )
    ) or 0
    lines.append("# HELP radius_crl_revoked_entries_count Total revoked and suspended certificates on the CRL.")
    lines.append("# TYPE radius_crl_revoked_entries_count gauge")
    lines.append(f"radius_crl_revoked_entries_count {crl_entries_count}")

    # 5. Remote Site Fleet Health
    lines.append("# HELP radius_sites_count Remote RADIUS site status counts.")
    lines.append("# TYPE radius_sites_count gauge")
    try:
        site_evals = fleet_health.evaluate_fleet(session, now)
        status_counts = {"OK": 0, "WARN": 0, "CRITICAL": 0, "SILENT": 0}
        for s in site_evals:
            status_counts[s.status.value] = status_counts.get(s.status.value, 0) + 1
        for st, c in status_counts.items():
            lines.append(format_prometheus_line("radius_sites_count", c, {"status": st}))
    except Exception:
        pass

    return "\n".join(lines) + "\n"
