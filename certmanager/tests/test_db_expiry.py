import datetime

from app import cert_service, db


def test_is_expired_handles_sqlite_naive_roundtrip(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    import uuid

    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="expiry-check", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    reloaded = session.query(db.Certificate).filter_by(cn="expiry-check").one()
    # SQLite strips tzinfo on round-trip — this must not raise.
    assert reloaded.is_expired() is False
    assert reloaded.is_expired(now=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=400)) is True
