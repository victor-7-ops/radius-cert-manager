"""RADIUS server-certificate lifecycle (HANDOFF-FLEET.md §3): issuance
from a site-supplied CSR, renewal-due policy, per-site stagger offset,
and exclusion of server certs from client cert lists/counts/bulk ops."""

import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app import cert_service, db, pki


def _csr_pem(cn: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = pki.generate_private_key()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def test_issue_server_cert_signs_when_csr_cn_matches_site(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    csr_pem = _csr_pem("radius-boracay.internal")

    result = cert_service.issue_server_cert(
        session, tmp_path,
        throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        csr_pem=csr_pem,
        site_id="site-1",
        site_cn="radius-boracay.internal",
        request_id=str(uuid.uuid4()),
        days=365,
        issued_by="alice",
    )

    assert result.certificate.cert_type == "server"
    assert result.certificate.cn == "radius-boracay.internal"
    assert result.certificate.status == db.CertStatus.active


def test_issue_server_cert_rejects_cn_mismatch(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    csr_pem = _csr_pem("radius-other-site.internal")

    try:
        cert_service.issue_server_cert(
            session, tmp_path,
            throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
            csr_pem=csr_pem,
            site_id="site-1",
            site_cn="radius-boracay.internal",
            request_id=str(uuid.uuid4()),
            days=365,
            issued_by="alice",
        )
        assert False, "expected CSRCNMismatchError"
    except cert_service.CSRCNMismatchError:
        pass

    assert session.query(db.Certificate).count() == 0


def test_issue_server_cert_dedupes_on_request_id(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    csr_pem = _csr_pem("radius-boracay.internal")
    request_id = str(uuid.uuid4())

    first = cert_service.issue_server_cert(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        csr_pem=csr_pem, site_id="site-1", site_cn="radius-boracay.internal",
        request_id=request_id, days=365, issued_by="alice",
    )
    second = cert_service.issue_server_cert(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        csr_pem=csr_pem, site_id="site-1", site_cn="radius-boracay.internal",
        request_id=request_id, days=365, issued_by="alice",
    )

    assert second.deduped is True
    assert second.certificate.id == first.certificate.id
    assert session.query(db.Certificate).count() == 1


def test_default_cert_type_is_client(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="laptop-1", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    assert result.certificate.cert_type == "client"


def _cert(now, issued_days_ago, total_days):
    issued_at = now - datetime.timedelta(days=issued_days_ago)
    expires_at = issued_at + datetime.timedelta(days=total_days)
    return db.Certificate(
        cn="x", serial="1", issued_at=issued_at, expires_at=expires_at,
        issued_by="alice", request_id=str(uuid.uuid4()), cert_type="server",
    )


def test_renewal_due_false_with_full_lifetime_remaining():
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _cert(now, issued_days_ago=0, total_days=90)
    assert cert_service.renewal_due(cert, now) is False


def test_renewal_due_false_just_before_two_thirds_elapsed():
    now = datetime.datetime.now(datetime.timezone.utc)
    # 59 of 90 days elapsed: still just over one third remaining.
    cert = _cert(now, issued_days_ago=59, total_days=90)
    assert cert_service.renewal_due(cert, now) is False


def test_renewal_due_true_at_two_thirds_elapsed():
    now = datetime.datetime.now(datetime.timezone.utc)
    # Exactly 60 of 90 days elapsed: one third of lifetime remains — due.
    cert = _cert(now, issued_days_ago=60, total_days=90)
    assert cert_service.renewal_due(cert, now) is True


def test_renewal_due_true_past_expiry():
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = _cert(now, issued_days_ago=100, total_days=90)
    assert cert_service.renewal_due(cert, now) is True


def test_renewal_offset_is_deterministic():
    a = cert_service.renewal_offset("site-1", 30)
    b = cert_service.renewal_offset("site-1", 30)
    assert a == b
    assert 0 <= a < 30


def test_renewal_offset_spreads_across_window():
    # Not a proof of uniform distribution — just that different sites
    # don't all collapse onto the same offset, which is the failure mode
    # the stagger exists to prevent.
    offsets = {cert_service.renewal_offset(f"site-{i}", 30) for i in range(20)}
    assert len(offsets) > 1


def _seed(session, **kwargs):
    defaults = dict(
        cn="x", serial=str(uuid.uuid4().int % (2**63)),
        issued_at=datetime.datetime.now(datetime.timezone.utc),
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365),
        status=db.CertStatus.active, issued_by="alice", request_id=str(uuid.uuid4()),
    )
    defaults.update(kwargs)
    row = db.Certificate(**defaults)
    session.add(row)
    session.commit()
    return row


def test_client_cn_conflict_check_ignores_server_certs(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    _seed(session, cn="shared-cn", cert_type="server")

    # A client cert with the same CN as an existing *server* cert must be
    # issuable — the conflict check is scoped to cert_type="client".
    result = cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn="shared-cn", note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=365,
    )
    assert result.certificate.cert_type == "client"


def test_crl_regeneration_includes_revoked_server_certs(tmp_path, throwaway_pki):
    """The CRL query must NOT filter by cert_type — a revoked server cert
    has to appear on the CRL just like a revoked client cert."""
    session = _session(tmp_path)
    _seed(
        session, cn="radius-x", cert_type="server", status=db.CertStatus.revoked,
        status_changed_at=datetime.datetime.now(datetime.timezone.utc),
        serial="424242",
    )
    pem = cert_service.regenerate_crl(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"], validity_days=7,
    )
    crl = x509.load_pem_x509_crl(pem)
    assert crl.get_revoked_certificate_by_serial_number(424242) is not None


def test_dashboard_counts_exclude_server_certs(tmp_path, monkeypatch, throwaway_pki):
    from fastapi.testclient import TestClient

    from app import auth
    from app.main import create_app
    from tests.conftest import login_as

    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    (pki_dir / "issued").mkdir(parents=True)
    (pki_dir / "intermediate.crt").write_bytes(pki.cert_to_pem(throwaway_pki["inter_cert"]))
    (pki_dir / "private" / "intermediate.key").write_bytes(
        pki.private_key_to_pem(throwaway_pki["inter_key"])
    )
    env = {
        "SECRET_KEY": "x" * 40, "PKI_PATH": str(pki_dir), "DB_PATH": str(tmp_path / "cm.db"),
        "BIND_HOST": "127.0.0.1", "BIND_PORT": "8443", "RADIUS_HOST": "127.0.0.1",
        "RADIUS_SSH_KEY": str(tmp_path / "ssh_key"), "RADIUS_SSH_USER": "crlpush",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    (tmp_path / "ssh_key").write_text("fake")
    from app.config import load_settings
    app_settings = load_settings()

    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    admin = db.Admin(username="alice", password_hash=auth.hash_password("correcthorse123"), role=db.AdminRole.super_admin)
    session.add(admin)
    session.commit()
    session.refresh(admin)

    _seed(session, cn="server-1", cert_type="server")
    _seed(session, cn="client-1", cert_type="client")

    app = create_app(app_settings)
    client = TestClient(app, base_url="https://testserver")
    login_as(client, app_settings, admin)

    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "server-1" not in resp.text
