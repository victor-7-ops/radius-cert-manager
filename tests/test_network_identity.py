"""Unit tests for B03 certificate signing, signed O/OU identity, snapshots, and lifecycle.

Verifies:
- Schema 2 certificate has signed O=subsidiary UUID and OU=network-role UUID
- Schema 1 legacy certificate has CN only
- extract_certificate_identity: handles schema 1, schema 2, and rejects malformed/duplicate attributes
- Idempotency fingerprinting: dedupes identical request_id, rejects reused request_id with changed assignment
- Reissue preserves network assignment and links supersedes_id
- Reconciliation imports signed identity fields
"""

import json
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db, pki
from app.cert_service import NetworkAssignment


@pytest.fixture
def ca_material(throwaway_pki, tmp_path):
    pki_path = tmp_path / "pki"
    pki_path.mkdir(exist_ok=True)
    (pki_path / "issued").mkdir(exist_ok=True)
    return throwaway_pki["inter_cert"], throwaway_pki["inter_key"], pki_path


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_identity.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)
    return engine


def test_schema_2_signed_identity_and_snapshot(ca_material, test_db):
    inter_cert, inter_key, pki_path = ca_material
    with Session(test_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        dept = db.Department(subsidiary_id=sub.id, code="acct", display_name="Accounting")
        role = db.NetworkRole(subsidiary_id=sub.id, code="fin", display_name="Finance Access")
        session.add_all([dept, role])
        session.commit()

        assignment = NetworkAssignment(
            subsidiary_id=sub.id,
            department_id=dept.id,
            network_role_id=role.id,
            employee_id="emp-uuid-1",
            device_id="dev-uuid-1",
        )

        res = cert_service.issue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            cn="alice-laptop.internal",
            note="Test note",
            request_id="req-001",
            export_password="test-password",
            issued_by="admin_alice",
            days=30,
            assignment=assignment,
        )

        assert res.certificate.identity_schema_version == 2
        assert res.certificate.subsidiary_id == sub.id
        assert res.certificate.department_id == dept.id
        assert res.certificate.network_role_id == role.id
        assert res.certificate.employee_id == "emp-uuid-1"
        assert res.certificate.device_id == "dev-uuid-1"
        assert res.certificate.request_fingerprint is not None

        # Verify snapshot JSON
        snapshot = json.loads(res.certificate.issuance_policy_snapshot)
        assert snapshot["subsidiary_id"] == sub.id
        assert snapshot["network_role_id"] == role.id
        assert snapshot["issued_by"] == "admin_alice"

        # Verify certificate on disk has signed O and OU
        cert_file = pki_path / "issued" / f"alice-laptop.internal.{res.certificate.serial}.crt"
        assert cert_file.exists()
        disk_cert = pki.load_cert_pem(cert_file)

        cn, extracted_sub, extracted_role = pki.extract_certificate_identity(disk_cert)
        assert cn == "alice-laptop.internal"
        assert extracted_sub == sub.id
        assert extracted_role == role.id


def test_schema_1_legacy_issuance_preserved(ca_material, test_db):
    inter_cert, inter_key, pki_path = ca_material
    with Session(test_db) as session:
        res = cert_service.issue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            cn="legacy-printer.internal",
            note=None,
            request_id="req-legacy-001",
            export_password=None,
            issued_by="system",
            days=30,
            assignment=None,
        )

        assert res.certificate.identity_schema_version == 1
        assert res.certificate.subsidiary_id is None
        assert res.certificate.network_role_id is None

        cert_file = pki_path / "issued" / f"legacy-printer.internal.{res.certificate.serial}.crt"
        disk_cert = pki.load_cert_pem(cert_file)

        cn, sub_id, role_id = pki.extract_certificate_identity(disk_cert)
        assert cn == "legacy-printer.internal"
        assert sub_id is None
        assert role_id is None


def test_extract_identity_attribute_validation(ca_material):
    inter_cert, inter_key, _ = ca_material

    key = pki.generate_private_key()
    builder = (
        x509.CertificateBuilder()
        .issuer_name(inter_cert.subject)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(inter_cert.not_valid_before_utc)
        .not_valid_after(inter_cert.not_valid_after_utc)
    )

    # 1. Duplicate O attributes -> rejected
    builder_dup = builder.subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "dup.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sub-1"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sub-2"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "role-1"),
        ])
    )
    cert_dup = builder_dup.sign(inter_key, hashes.SHA256())
    with pytest.raises(ValueError, match="duplicate"):
        pki.extract_certificate_identity(cert_dup)

    # 2. Incomplete attributes (O without OU) -> rejected
    builder_inc = builder.subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "inc.test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "sub-1"),
        ])
    )
    cert_inc = builder_inc.sign(inter_key, hashes.SHA256())
    with pytest.raises(ValueError, match="incomplete"):
        pki.extract_certificate_identity(cert_inc)


def test_reused_request_id_with_changed_assignment_rejected(ca_material, test_db):
    inter_cert, inter_key, pki_path = ca_material
    with Session(test_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        dept = db.Department(subsidiary_id=sub.id, code="acct", display_name="Accounting")
        role1 = db.NetworkRole(subsidiary_id=sub.id, code="fin", display_name="Finance Access")
        role2 = db.NetworkRole(subsidiary_id=sub.id, code="eng", display_name="Engineering Access")
        session.add_all([dept, role1, role2])
        session.commit()

        assign1 = NetworkAssignment(
            subsidiary_id=sub.id,
            department_id=dept.id,
            network_role_id=role1.id,
        )
        res1 = cert_service.issue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            cn="device1.internal",
            note=None,
            request_id="req-dedup-1",
            export_password=None,
            issued_by="admin",
            days=30,
            assignment=assign1,
        )
        assert res1.deduped is False

        # Repeating same request_id with same assignment -> returns deduped
        res_dedup = cert_service.issue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            cn="device1.internal",
            note=None,
            request_id="req-dedup-1",
            export_password=None,
            issued_by="admin",
            days=30,
            assignment=assign1,
        )
        assert res_dedup.deduped is True

        # Reusing request_id with different assignment (role2 instead of role1) -> raises error
        assign2 = NetworkAssignment(
            subsidiary_id=sub.id,
            department_id=dept.id,
            network_role_id=role2.id,
        )
        with pytest.raises(ValueError, match="differing assignment"):
            cert_service.issue_certificate(
                session=session,
                pki_path=pki_path,
                inter_cert=inter_cert,
                inter_key=inter_key,
                cn="device1.internal",
                note=None,
                request_id="req-dedup-1",
                export_password=None,
                issued_by="admin",
                days=30,
                assignment=assign2,
            )


def test_reissue_inherits_assignment(ca_material, test_db):
    inter_cert, inter_key, pki_path = ca_material
    with Session(test_db) as session:
        sub = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "topline"))
        dept = db.Department(subsidiary_id=sub.id, code="acct", display_name="Accounting")
        role = db.NetworkRole(subsidiary_id=sub.id, code="fin", display_name="Finance Access")
        session.add_all([dept, role])
        session.commit()

        assign = NetworkAssignment(
            subsidiary_id=sub.id,
            department_id=dept.id,
            network_role_id=role.id,
        )
        original = cert_service.issue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            cn="laptop.internal",
            note="Original",
            request_id="req-reissue-orig",
            export_password=None,
            issued_by="admin",
            days=30,
            assignment=assign,
        )

        reissue_res = cert_service.reissue_certificate(
            session=session,
            pki_path=pki_path,
            inter_cert=inter_cert,
            inter_key=inter_key,
            old_serial=original.certificate.serial,
            request_id="req-reissue-new",
            export_password=None,
            issued_by="admin",
            days=30,
        )

        assert reissue_res.certificate.supersedes_id == original.certificate.id
        assert reissue_res.certificate.identity_schema_version == 2
        assert reissue_res.certificate.subsidiary_id == sub.id
        assert reissue_res.certificate.network_role_id == role.id


def test_reconciliation_import_extracts_schema_2(ca_material, test_db):
    inter_cert, inter_key, pki_path = ca_material
    from app import reconcile

    # Manually issue a certificate directly to disk
    key = pki.generate_private_key()
    csr = pki.build_csr(key, "imported-srv.internal")
    cert = pki.sign_client_cert(
        csr, inter_cert, inter_key, serial=998877, days=30,
        subsidiary_id="sub-uuid-abc", network_role_id="role-uuid-xyz",
    )
    (pki_path / "issued" / "imported-srv.internal.998877.crt").write_bytes(pki.cert_to_pem(cert))

    with Session(test_db) as session:
        imported = reconcile.import_existing_certs(session, pki_path / "issued")
        assert "imported-srv.internal" in imported

        imported_row = session.scalar(select(db.Certificate).where(db.Certificate.serial == "998877"))
        assert imported_row is not None
        assert imported_row.identity_schema_version == 2
        assert imported_row.subsidiary_id == "sub-uuid-abc"
        assert imported_row.network_role_id == "role-uuid-xyz"
