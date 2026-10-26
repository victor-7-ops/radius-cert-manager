"""Tests for structured JSON and text logging configuration."""

from __future__ import annotations

import json
import logging
import pytest

from app.config import Settings
from app.logging_conf import JSONFormatter, setup_logging


def test_json_formatter_standard_fields():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=42,
        msg="Certificate %s issued for %s",
        args=("12345", "alice.smith"),
        exc_info=None,
    )
    formatted = formatter.format(record)
    parsed = json.loads(formatted)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test.logger"
    assert parsed["message"] == "Certificate 12345 issued for alice.smith"
    assert "timestamp" in parsed
    assert "T" in parsed["timestamp"]  # ISO-8601 format


def test_json_formatter_with_exception_and_extra_attributes():
    formatter = JSONFormatter()
    try:
        raise ValueError("Simulated cryptographic failure")
    except ValueError:
        import sys
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="certmanager.pki",
        level=logging.ERROR,
        pathname="pki.py",
        lineno=100,
        msg="Key generation error",
        args=(),
        exc_info=exc_info,
    )
    record.correlation_id = "req-uuid-999"
    record.admin_user = "sec-admin"
    record.audit_action = "CERT_REVOKE"

    formatted = formatter.format(record)
    parsed = json.loads(formatted)

    assert parsed["level"] == "ERROR"
    assert parsed["logger"] == "certmanager.pki"
    assert parsed["message"] == "Key generation error"
    assert "Simulated cryptographic failure" in parsed["exception"]
    assert parsed["correlation_id"] == "req-uuid-999"
    assert parsed["admin_user"] == "sec-admin"
    assert parsed["audit_action"] == "CERT_REVOKE"


def test_setup_logging_switch_format(capsys):
    setup_logging(log_format="json", level=logging.INFO)
    logger = logging.getLogger("siem.test")
    logger.info("JSON SIEM audit event test")

    captured = capsys.readouterr()
    assert captured.out.strip() != ""
    parsed = json.loads(captured.out.strip())
    assert parsed["message"] == "JSON SIEM audit event test"
    assert parsed["level"] == "INFO"

    # Switch back to text
    setup_logging(log_format="text", level=logging.INFO)
    logger.info("Plain text log test")
    captured_text = capsys.readouterr()
    assert "Plain text log test" in captured_text.out
    assert not captured_text.out.strip().startswith("{")


def test_settings_log_format_validation(tmp_path):
    # Valid "json"
    s = Settings(
        secret_key="x" * 40,
        pki_path=tmp_path,
        db_path=tmp_path / "db.sqlite",
        bind_host="127.0.0.1",
        radius_host="127.0.0.1",
        radius_ssh_key=tmp_path / "key",
        log_format="json",
    )
    assert s.log_format == "json"

    # Case-insensitive
    s_upper = Settings(
        secret_key="x" * 40,
        pki_path=tmp_path,
        db_path=tmp_path / "db.sqlite",
        bind_host="127.0.0.1",
        radius_host="127.0.0.1",
        radius_ssh_key=tmp_path / "key",
        log_format="JSON",
    )
    assert s_upper.log_format == "json"

    # Invalid
    with pytest.raises(ValueError, match="log_format must be 'text' or 'json'"):
        Settings(
            secret_key="x" * 40,
            pki_path=tmp_path,
            db_path=tmp_path / "db.sqlite",
            bind_host="127.0.0.1",
            radius_host="127.0.0.1",
            radius_ssh_key=tmp_path / "key",
            log_format="yaml",
        )
