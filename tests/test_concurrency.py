import uuid
from concurrent.futures import ThreadPoolExecutor

from app import cert_service, db


def test_twenty_parallel_issues_produce_twenty_distinct_certs(tmp_path, throwaway_pki):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    session_factory = db.make_session_factory(engine)

    def issue_one(i: int):
        session = session_factory()
        result = cert_service.issue_certificate(
            session,
            tmp_path,
            throwaway_pki["inter_cert"],
            throwaway_pki["inter_key"],
            cn=f"device-{i}",
            note=None,
            request_id=str(uuid.uuid4()),
            export_password=None,
            issued_by="alice",
            days=365,
        )
        session.close()
        return result.certificate.serial

    with ThreadPoolExecutor(max_workers=20) as pool:
        serials = list(pool.map(issue_one, range(20)))

    assert len(serials) == 20
    assert len(set(serials)) == 20

    verify_session = session_factory()
    assert verify_session.query(db.Certificate).count() == 20
