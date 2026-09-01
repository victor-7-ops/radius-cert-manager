"""audit_log gains subsidiary/site_id (HANDOFF-FLEET.md §8.3): populated
on write where the caller already knows it, and backfilled once at
startup for older rows by joining a cert-related action's target CN
back to certificates.subsidiary."""

import uuid

from sqlalchemy import select

from app import cert_service, db, site_service


def _session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)(), engine


def test_issue_populates_subsidiary_on_audit_row(tmp_path, throwaway_pki):
    session, engine = _session(tmp_path)
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-1", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365, device=cert_service.DeviceInfo(subsidiary="Lezzgo Boracay"),
    )
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "issue"))
    assert row.subsidiary == "Lezzgo Boracay"


def test_revoke_populates_subsidiary_and_site_id_from_cert(tmp_path, throwaway_pki):
    session, engine = _session(tmp_path)
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-2", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365, device=cert_service.DeviceInfo(subsidiary="Bay Mall"),
    )
    cert_service.revoke(session, tmp_path, result.certificate.serial, "lost", "alice")

    row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "revoked"))
    assert row.subsidiary == "Bay Mall"


def test_site_create_populates_site_id_on_audit_row(tmp_path):
    session, engine = _session(tmp_path)
    result = site_service.create_site(
        session, name="Boracay", radius_cn="radius-boracay.internal", actor="alice",
        subsidiary="Lezzgo Boracay",
    )
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "site_create"))
    assert row.site_id == result.site.id
    assert row.subsidiary == "Lezzgo Boracay"


def test_admin_management_audit_rows_leave_subsidiary_null(tmp_path):
    """No subsidiary dimension applies to admin-management actions — must
    stay NULL, not get some fabricated default."""
    session, engine = _session(tmp_path)
    db.audit(session, actor="alice", action="create_admin", target="bob")
    session.commit()
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.action == "create_admin"))
    assert row.subsidiary is None
    assert row.site_id is None


def test_backfill_derives_subsidiary_for_pre_existing_rows(tmp_path):
    """Simulates the historical case: audit_log rows written before the
    subsidiary column existed (or by code that didn't pass it), and a
    certificate row that DOES carry the subsidiary — the backfill should
    join target (CN) -> certificates.subsidiary."""
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="legacy-device", serial="999", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()), subsidiary="Commercial Fuel Trade",
    ))
    session.add(db.AuditLog(actor="alice", action="issue", target="legacy-device", subsidiary=None))
    session.commit()

    updated = db.backfill_audit_log_subsidiary(engine)
    assert updated == 1

    row = session.scalar(select(db.AuditLog).where(db.AuditLog.target == "legacy-device"))
    assert row.subsidiary == "Commercial Fuel Trade"


def test_backfill_is_idempotent(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(db.Certificate(
        id=str(uuid.uuid4()), cn="legacy-device-2", serial="998", issued_at=now,
        expires_at=now + datetime.timedelta(days=365), status=db.CertStatus.active,
        issued_by="alice", request_id=str(uuid.uuid4()), subsidiary="BMEAD",
    ))
    session.add(db.AuditLog(actor="alice", action="issue", target="legacy-device-2", subsidiary=None))
    session.commit()

    first = db.backfill_audit_log_subsidiary(engine)
    second = db.backfill_audit_log_subsidiary(engine)
    assert first == 1
    assert second == 0  # already backfilled, nothing left to touch


def test_backfill_leaves_unmatched_targets_null(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    session.add(db.AuditLog(actor="alice", action="create_admin", target="no-such-cert", subsidiary=None))
    session.commit()

    db.backfill_audit_log_subsidiary(engine)
    row = session.scalar(select(db.AuditLog).where(db.AuditLog.target == "no-such-cert"))
    assert row.subsidiary is None
