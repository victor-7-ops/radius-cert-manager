from __future__ import annotations

from fastapi import APIRouter, Depends

from app import crl_health, db, fleet_health


def get_router(deps) -> APIRouter:
    router = APIRouter(prefix="/api/health", tags=["health"])

    @router.get("/crl")
    def crl_status(admin: db.Admin = Depends(deps.require_admin)):
        session = deps.get_db_session()
        health = crl_health.get_health(session)
        return {
            "last_generated_at": health.last_generated_at.isoformat()
            if health.last_generated_at
            else None,
            "last_pushed_at": health.last_pushed_at.isoformat() if health.last_pushed_at else None,
            "last_push_ok": health.last_push_ok,
            "next_update": health.next_update.isoformat() if health.next_update else None,
            "hours_remaining": health.hours_remaining,
            "is_critical": health.is_critical,
            "is_stale": health.is_stale,
        }

    @router.get("/fleet")
    def fleet_status(admin: db.Admin = Depends(deps.require_super_admin)):
        session = deps.get_db_session()
        results = fleet_health.evaluate_fleet(session)
        return [
            {
                "site_id": h.site_id,
                "name": h.name,
                "radius_cn": h.radius_cn,
                "subsidiary": h.subsidiary,
                "status": h.status.value,
                "last_seen_at": h.last_seen_at.isoformat() if h.last_seen_at else None,
                "minutes_since_checkin": h.minutes_since_checkin,
                "crl_hours_remaining": h.crl_hours_remaining,
                "server_cert_days_remaining": h.server_cert_days_remaining,
                "freeradius_ok": h.freeradius_ok,
                "agent_version": h.agent_version,
            }
            for h in results
        ]

    return router
