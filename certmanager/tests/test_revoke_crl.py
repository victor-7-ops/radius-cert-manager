import uuid
from unittest.mock import MagicMock

from app import cert_service, crl_push, db, pki


def make_session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_revoke_updates_status_and_regenerates_crl_containing_serial(tmp_path, throwaway_pki):
    session = make_session(tmp_path)
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-revoke", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    serial = result.certificate.serial

    revoked = cert_service.revoke(session, tmp_path, serial, reason="lost laptop", actor="root-admin")
    assert revoked.status == db.CertStatus.revoked

    pem = cert_service.regenerate_crl(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], validity_days=7
    )
    from cryptography import x509

    crl = x509.load_pem_x509_crl(pem)
    assert crl.get_revoked_certificate_by_serial_number(int(serial)) is not None
    assert (tmp_path / "crl.pem").exists()


def test_suspended_cert_also_appears_on_crl(tmp_path, throwaway_pki):
    session = make_session(tmp_path)
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-suspend", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    serial = result.certificate.serial
    cert_service.suspend(session, tmp_path, serial, reason="lost phone", actor="admin")

    pem = cert_service.regenerate_crl(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], validity_days=7
    )
    from cryptography import x509

    crl = x509.load_pem_x509_crl(pem)
    assert crl.get_revoked_certificate_by_serial_number(int(serial)) is not None


def test_unsuspend_removes_from_next_crl(tmp_path, throwaway_pki):
    session = make_session(tmp_path)
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="device-unsuspend", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    serial = result.certificate.serial
    cert_service.suspend(session, tmp_path, serial, reason="x", actor="admin")
    cert_service.unsuspend(session, tmp_path, serial, actor="root-admin")

    pem = cert_service.regenerate_crl(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], validity_days=7
    )
    from cryptography import x509

    crl = x509.load_pem_x509_crl(pem)
    assert crl.get_revoked_certificate_by_serial_number(int(serial)) is None


def test_crl_push_calls_ssh_with_correct_args_and_never_connects(tmp_path):
    crl_path = tmp_path / "crl.pem"
    crl_path.write_bytes(b"fake-crl-bytes")

    import hashlib

    local_hash = hashlib.sha256(crl_path.read_bytes()).hexdigest()

    mock_run = MagicMock()
    mock_run.side_effect = [
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=0, stdout=f"{local_hash}  crl.pem".encode()),
    ]

    result = crl_push.push_crl(
        crl_path, "192.168.200.19", "crlpush", tmp_path / "ssh_key", run=mock_run
    )

    assert result.ok is True
    assert mock_run.call_count == 3
    scp_call_args = mock_run.call_args_list[0][0][0]
    assert "scp" in scp_call_args
    assert "crlpush@192.168.200.19:crl.pem" in scp_call_args


def test_crl_push_reports_failure_on_hash_mismatch(tmp_path):
    crl_path = tmp_path / "crl.pem"
    crl_path.write_bytes(b"fake-crl-bytes")

    mock_run = MagicMock()
    mock_run.side_effect = [
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=0, stderr=b""),
        MagicMock(returncode=0, stdout=b"deadbeef  crl.pem"),
    ]

    result = crl_push.push_crl(
        crl_path, "192.168.200.19", "crlpush", tmp_path / "ssh_key", run=mock_run
    )
    assert result.ok is False
    assert "mismatch" in result.detail
