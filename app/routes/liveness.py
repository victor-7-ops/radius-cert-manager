"""Unauthenticated liveness probe (HANDOFF-FLEET.md §8.2). Deliberately
outside require_admin/require_site — an external monitor (CloudWatch
Synthetics, healthchecks.io) can't hold either kind of session, and if
the hub is unreachable that's exactly the state this route exists to
surface. Gated by a token in the path rather than a bare /healthz so it
isn't just another guessable public endpoint; unset token disables the
route outright rather than defaulting to something guessable."""

from __future__ import annotations

import datetime

from fastapi import APIRouter, HTTPException, status


def get_router(deps) -> APIRouter:
    router = APIRouter(tags=["liveness"])

    @router.get("/api/live/{token}")
    def live(token: str):
        if not deps.liveness_token or token != deps.liveness_token:
            # Same 404 whether the feature is disabled or the token is
            # wrong — don't let the response shape confirm the route exists.
            raise HTTPException(status.HTTP_404_NOT_FOUND)
        return {"ok": True, "time": datetime.datetime.now(datetime.timezone.utc).isoformat()}

    return router
