"""Tests for app/retention.py (HANDOFF-COMPLIANCE.md §1)."""

import datetime

import pytest
from sqlalchemy import select

from app import db, retention
from app.config import Settings


def _settings(tmp_path, **overrides):
    base = dict(
        secret_key="x" * 40,
        pki_path=tmp_path / "pki",
        db_path=tmp_path / "certmanager.db",
        bind_host="127.0.0.1",
        bind_port=8443,
        radius_host="127.0.0.1",
        radius_ssh_key=tmp_path / "ssh_key",
        radius_ssh_user="crlpush",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def session(tmp_path):
    engine = db.make_engine(str(tmp_path / "certmanager.db"))
    db.init_db(engine)
    factory = db.make_session_factory(engine)
    s = factory()
    yield s
    s.close()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _make_cert(session, **overrides):
    now = _now()
    defaults = dict(
        cn="device-1.example",
        serial=str(overrides.pop("serial_int", 1)),
        issued_at=now - datetime.timedelta(days=400),
        expires_at=now - datetime.timedelta(days=40),
        status=db.CertStatus.revoked,
        status_changed_at=now - datetime.timedelta(days=40),
        issued_by="admin",
        request_id=f"req-{overrides.get('cn', 'device-1.example')}-{now.timestamp()}",
        employee_name="Jane Doe",
        device_mac="AA:BB:CC:DD:EE:FF",
        device_serial="SN123",
        device_model="ThinkPad",
        cert_type="client",
    )
    defaults.update(overrides)
    cert = db.Certificate(**defaults)
    session.add(cert)
    session.commit()
    return cert


def test_unset_config_is_noop(session, tmp_path):
    _make_cert(session)
    settings = _settings(tmp_path)  # all retention fields default None
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.cert_count == 0
    assert report.audit_count == 0
    assert report.session_count == 0
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name == "Jane Doe"
    assert cert.minimised_at is None


def test_active_cert_never_minimised(session, tmp_path):
    _make_cert(
        session,
        status=db.CertStatus.active,
        status_changed_at=None,
        expires_at=_now() - datetime.timedelta(days=400),  # expired-but-active
    )
    settings = _settings(tmp_path, cert_retention_days=1)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.cert_count == 0
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name == "Jane Doe"


def test_revoked_unexpired_kept(session, tmp_path):
    now = _now()
    _make_cert(
        session,
        status=db.CertStatus.revoked,
        status_changed_at=now - datetime.timedelta(days=400),
        expires_at=now + datetime.timedelta(days=30),  # still valid
    )
    settings = _settings(tmp_path, cert_retention_days=1)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.cert_count == 0
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name == "Jane Doe"
    assert cert.minimised_at is None


def test_revoked_and_expired_past_retention_is_minimised(session, tmp_path):
    _make_cert(session)  # expired 40d ago, revoked 40d ago
    settings = _settings(tmp_path, cert_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.cert_count == 1
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name is None
    assert cert.device_mac is None
    assert cert.device_serial is None
    assert cert.device_model is None
    assert cert.minimised_at is not None
    # kept
    assert cert.serial == "1"
    assert cert.cn == "device-1.example"
    assert cert.status == db.CertStatus.revoked


def test_dry_run_changes_nothing(session, tmp_path):
    _make_cert(session)
    settings = _settings(tmp_path, cert_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=True)
    assert report.cert_count == 1
    assert report.applied is False
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name == "Jane Doe"
    assert cert.minimised_at is None


def test_deletion_audit_row_survives_same_run(session, tmp_path):
    _make_cert(session)
    settings = _settings(tmp_path, cert_retention_days=30)
    retention.run_retention(session, settings, dry_run=False)
    rows = session.scalars(select(db.AuditLog)).all()
    matches = [r for r in rows if r.action == "retention.certs_minimised"]
    assert len(matches) == 1
    assert matches[0].minimised_at is None


def test_rerun_is_idempotent(session, tmp_path):
    _make_cert(session)
    settings = _settings(tmp_path, cert_retention_days=30)
    first = retention.run_retention(session, settings, dry_run=False)
    second = retention.run_retention(session, settings, dry_run=False)
    assert first.cert_count == 1
    assert second.cert_count == 0


def test_audit_retention_minimises_detail_only(session, tmp_path):
    old = _now() - datetime.timedelta(days=400)
    session.add(db.AuditLog(actor="admin", action="cert.issue", target="device-1", detail="Jane Doe's laptop", timestamp=old))
    session.commit()
    settings = _settings(tmp_path, audit_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.audit_count == 1
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "cert.issue"))
    assert row.detail is None
    assert row.minimised_at is not None
    assert row.actor == "admin"
    assert row.target == "device-1"


def test_session_retention_deletes_old_rows(session, tmp_path):
    old = _now() - datetime.timedelta(days=100)
    session.add(db.AdminSession(admin_id="admin-1", created_at=old, last_seen_at=old))
    session.commit()
    settings = _settings(tmp_path, session_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.session_count == 1
    assert session.scalar(select(db.AdminSession)) is None


def test_recent_session_kept(session, tmp_path):
    session.add(db.AdminSession(admin_id="admin-1"))
    session.commit()
    settings = _settings(tmp_path, session_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.session_count == 0
    assert session.scalar(select(db.AdminSession)) is not None
