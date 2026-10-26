"""Prometheus metrics endpoint (/metrics).

Exposes Prometheus text format metrics for scrape ingestion.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from app import metrics


def get_router(deps) -> APIRouter:
    router = APIRouter(tags=["metrics"])

    @router.get("/metrics")
    def prometheus_metrics():
        session = deps.get_db_session()
        content = metrics.collect_metrics(session)
        return Response(
            content=content,
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    return router
