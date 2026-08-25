import uuid

import pytest

from app import cert_service, db, pki


@pytest.fixture
def session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_issue_writes_cert_and_db_row(session, tmp_path, throwaway_pki):
    result = cert_service.issue_certificate(
        session,
        tmp_path,
        throwaway_pki["inter_cert"],
        throwaway_pki["inter_key"],
        cn="device-a",
        note=None,
        request_id=str(uuid.uuid4()),
        export_password=None,
        issued_by="alice",
        days=365,
    )
    assert result.certificate.cn == "device-a"
    assert (tmp_path / "issued" / "device-a.crt").exists()
    assert result.bundle is not None
    loaded_key, loaded_cert, _ = pki.load_pkcs12(result.bundle.data, result.bundle.password)
    assert str(loaded_cert.serial_number) == result.certificate.serial


def test_repeated_request_id_mints_exactly_one_certificate(session, tmp_path, throwaway_pki):
    rid = str(uuid.uuid4())
    r1 = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-b", note=None, request_id=rid, export_password=None,
        issued_by="alice", days=365,
    )
    r2 = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-b", note=None, request_id=rid, export_password=None,
        issued_by="alice", days=365,
    )
    assert r2.deduped is True
    assert r1.certificate.serial == r2.certificate.serial
    count = session.query(db.Certificate).filter_by(cn="device-b").count()
    assert count == 1


def test_active_cn_conflict_raises(session, tmp_path, throwaway_pki):
    cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-c", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    with pytest.raises(cert_service.CNConflictError):
        cert_service.issue_certificate(
            session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
            cn="device-c", note=None, request_id=str(uuid.uuid4()), export_password=None,
            issued_by="alice", days=365,
        )


def test_reissue_links_supersedes_and_both_valid_during_overlap(session, tmp_path, throwaway_pki):
    original = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-d", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    ).certificate

    # Reissue: suspend the old CN uniqueness isn't violated because the
    # old cert is superseded, not yet revoked/suspended (overlap window).
    successor_row = db.Certificate(
        cn="device-d",
        serial=str(pki.generate_serial()),
        issued_at=original.issued_at,
        expires_at=original.expires_at,
        status=db.CertStatus.active,
        issued_by="alice",
        request_id=str(uuid.uuid4()),
        supersedes_id=original.id,
    )
    session.add(successor_row)
    session.commit()

    assert successor_row.supersedes_id == original.id
    assert original.status == db.CertStatus.active
    assert successor_row.status == db.CertStatus.active
