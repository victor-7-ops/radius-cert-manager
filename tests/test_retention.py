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


def test_expired_never_revoked_cert_becomes_eligible(session, tmp_path):
    """HANDOFF-LIFECYCLE.md §0 defect fix: most certs expire rather than
    get revoked, and eligibility must key on expiry, not on status ==
    revoked — an expired cert that was simply never revoked must not
    keep its personal fields forever."""
    _make_cert(
        session,
        status=db.CertStatus.active,
        status_changed_at=None,
        expires_at=_now() - datetime.timedelta(days=40),
    )
    settings = _settings(tmp_path, cert_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.cert_count == 1
    cert = session.scalar(select(db.Certificate))
    assert cert.employee_name is None
    assert cert.minimised_at is not None
    assert cert.status == db.CertStatus.active  # status itself is untouched


def test_active_unexpired_cert_never_minimised(session, tmp_path):
    _make_cert(
        session,
        status=db.CertStatus.active,
        status_changed_at=None,
        expires_at=_now() + datetime.timedelta(days=300),  # still valid
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


def test_audit_retention_redacts_detail_only(session, tmp_path):
    """HANDOFF-LIFECYCLE.md §0: this is 'detail redaction', not
    'anonymisation' — actor, action, target, timestamp all survive, and
    calling it anonymised would overstate it to a DPO."""
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

    redaction_row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "retention.audit_detail_redacted"))
    assert redaction_row is not None


def test_session_retention_deletes_old_rows(session, tmp_path):
    old = _now() - datetime.timedelta(days=100)
    session.add(db.AdminSession(admin_id="admin-1", created_at=old, last_seen_at=old))
    session.commit()
    settings = _settings(tmp_path, session_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.session_count == 1
    assert session.scalar(select(db.AdminSession)) is None


def test_find_eligible_certs_orders_by_expires_at_so_large_tables_make_progress(session, tmp_path, monkeypatch):
    """HANDOFF-LIFECYCLE.md §0: without an ORDER BY, an arbitrary slice of
    a table above BATCH_SIZE*4 unminimised rows could come back and never
    surface the actually-eligible ones — progress stalls silently. Shrink
    BATCH_SIZE so a handful of rows exercises the same code path."""
    monkeypatch.setattr(retention, "BATCH_SIZE", 2)
    now = _now()
    for i, days_expired in enumerate([10, 90, 50, 200, 30]):
        _make_cert(
            session,
            serial_int=i + 1,
            cn=f"device-{i}.example",
            status=db.CertStatus.active,
            status_changed_at=None,
            expires_at=now - datetime.timedelta(days=days_expired),
            request_id=f"req-order-{i}",
        )

    eligible = retention.find_eligible_certs(session, retention_days=1, now=now)
    assert [c.cn for c in eligible] == ["device-3.example", "device-1.example"]  # 200d, 90d first


def test_recent_session_kept(session, tmp_path):
    session.add(db.AdminSession(admin_id="admin-1"))
    session.commit()
    settings = _settings(tmp_path, session_retention_days=30)
    report = retention.run_retention(session, settings, dry_run=False)
    assert report.session_count == 0
    assert session.scalar(select(db.AdminSession)) is not None
