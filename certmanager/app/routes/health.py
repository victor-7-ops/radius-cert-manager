from __future__ import annotations

from fastapi import APIRouter, Depends

from app import crl_health, db


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

    return router
