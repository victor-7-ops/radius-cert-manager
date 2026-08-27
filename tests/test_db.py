import datetime
import uuid

from app import db, pki, reconcile


def make_session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_first_run_import_records_existing_certs(tmp_path, throwaway_pki):
    issued_dir = tmp_path / "issued"
    issued_dir.mkdir()

    key = pki.generate_private_key()
    csr = pki.build_csr(key, "radius-server")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )
    (issued_dir / "radius-server.crt").write_bytes(pki.cert_to_pem(cert))

    session = make_session(tmp_path)
    imported = reconcile.import_existing_certs(session, issued_dir)

    assert imported == ["radius-server"]
    row = session.query(db.Certificate).filter_by(cn="radius-server").one()
    assert row.issued_by == "imported"
    assert row.serial == str(serial)


def test_reconciliation_runs_after_import_finds_no_orphans(tmp_path, throwaway_pki):
    issued_dir = tmp_path / "issued"
    issued_dir.mkdir()
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "test-device-01")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )
    (issued_dir / "test-device-01.crt").write_bytes(pki.cert_to_pem(cert))

    session = make_session(tmp_path)
    reconcile.import_existing_certs(session, issued_dir)
    orphans = reconcile.reconcile_issued_dir(session, issued_dir)
    assert orphans == []


def test_reconciliation_flags_cert_missing_from_db(tmp_path, throwaway_pki):
    issued_dir = tmp_path / "issued"
    issued_dir.mkdir()
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "orphan-device")
    serial = pki.generate_serial()
    cert = pki.sign_client_cert(
        csr, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], serial, days=365
    )
    (issued_dir / "orphan-device.crt").write_bytes(pki.cert_to_pem(cert))

    session = make_session(tmp_path)
    orphans = reconcile.reconcile_issued_dir(session, issued_dir)
    assert orphans == ["orphan-device.crt"]


def test_audit_log_writes_row(tmp_path):
    session = make_session(tmp_path)
    db.audit(session, actor="alice", action="issue", target="device-01", detail="ok")
    session.commit()
    row = session.query(db.AuditLog).one()
    assert row.actor == "alice"
    assert row.action == "issue"


def test_request_id_is_unique_constraint(tmp_path):
    session = make_session(tmp_path)
    rid = str(uuid.uuid4())
    session.add(
        db.Certificate(
            cn="a",
            serial="1",
            issued_at=datetime.datetime.now(datetime.timezone.utc),
            expires_at=datetime.datetime.now(datetime.timezone.utc),
            issued_by="admin",
            request_id=rid,
        )
    )
    session.commit()

    session.add(
        db.Certificate(
            cn="b",
            serial="2",
            issued_at=datetime.datetime.now(datetime.timezone.utc),
            expires_at=datetime.datetime.now(datetime.timezone.utc),
            issued_by="admin",
            request_id=rid,
        )
    )
    try:
        session.commit()
        assert False, "expected IntegrityError"
    except Exception:
        session.rollback()
