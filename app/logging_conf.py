"""Structured logging configuration for RADIUS PKI Manager.

Supports:
- Human-readable text logging (standard console development)
- Machine-readable structured JSON logging for SIEM ingestion (Splunk, Elastic, Datadog)
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects conforming to SIEM ingestion standards."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        for attr in ("correlation_id", "audit_action", "admin_user", "client_ip"):
            val = getattr(record, attr, None)
            if val is not None:
                log_entry[attr] = val
        return json.dumps(log_entry, default=str)


def setup_logging(log_format: str = "text", level: int = logging.INFO) -> None:
    """Configure root and certmanager logging with either text or JSON format."""
    root_logger = logging.getLogger()
    # Remove existing handlers to prevent duplicate logging
    for h in list(root_logger.handlers):
        root_logger.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    if log_format.lower() == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )

    root_logger.setLevel(level)
    root_logger.addHandler(handler)
