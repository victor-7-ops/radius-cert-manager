"""Tests for employee and device inventory, metrics calculation, and offboarding.

Implements test coverage for B09, B10, B11, and B12 specifications:
- Scoped tenant isolation for employees and devices
- Query-time UTC distinct counts (registered vs active vs usable devices vs active certs vs attention)
- Separation of server certificates and expired certificates
- Device registration, update, status transitions, and credential revocation
- Multi-certificate employee offboarding and CRL publishing
"""

import datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import cert_service, db, device_service, employee_service, network_migrations, pki
from app.network_policy import ForbiddenError, PolicyValidationError, ResourceNotFoundError


@pytest.fixture
def test_db_session(tmp_path: Path):
    db_file = tmp_path / "test_emp_dev.db"
    engine = db.make_engine(str(db_file))
    db.init_db(engine)
    session = Session(engine)
    yield session
    session.close()


@pytest.fixture
def baseline_setup(test_db_session: Session):
    session = test_db_session
    # Get seeded tenants
    sub_a = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_boracay"))
    sub_b = session.scalar(select(db.Subsidiary).where(db.Subsidiary.code == "lezzgo_cebu"))
    assert sub_a and sub_b

    # Create departments and roles for sub_a
    dept_a = db.Department(subsidiary_id=sub_a.id, code="ops", display_name="Operations")
    role_a1 = db.NetworkRole(subsidiary_id=sub_a.id, code="staff", display_name="Staff WiFi")
    role_a2 = db.NetworkRole(subsidiary_id=sub_a.id, code="pos", display_name="POS Terminal")
    session.add_all([dept_a, role_a1, role_a2])
    session.flush()

    # Link dept_a to role_a1 and role_a2
    pair_a1 = db.DepartmentRole(department_id=dept_a.id, network_role_id=role_a1.id)
    pair_a2 = db.DepartmentRole(department_id=dept_a.id, network_role_id=role_a2.id)
    session.add_all([pair_a1, pair_a2])

    # Create department and role for sub_b
    dept_b = db.Department(subsidiary_id=sub_b.id, code="ops", display_name="Operations Cebu")
    role_b = db.NetworkRole(subsidiary_id=sub_b.id, code="staff", display_name="Staff Cebu")
    session.add_all([dept_b, role_b])
    session.flush()
    pair_b = db.DepartmentRole(department_id=dept_b.id, network_role_id=role_b.id)
    session.add(pair_b)

    # Admins
    admin_plat = db.Admin(
        username="plat_admin",
        password_hash="fake",
        role=db.AdminRole.super_admin,
    )
    admin_sub_a = db.Admin(
        username="sub_admin_a",
        password_hash="fake",
        role=db.AdminRole.subsidiary_super_admin,
        subsidiary_scope=sub_a.id,
    )
    admin_sub_b = db.Admin(
        username="sub_admin_b",
        password_hash="fake",
        role=db.AdminRole.subsidiary_super_admin,
        subsidiary_scope=sub_b.id,
    )
    session.add_all([admin_plat, admin_sub_a, admin_sub_b])
    session.commit()

    return {
        "sub_a": sub_a,
        "sub_b": sub_b,
        "dept_a": dept_a,
        "role_a1": role_a1,
        "role_a2": role_a2,
        "dept_b": dept_b,
        "role_b": role_b,
        "admin_plat": admin_plat,
        "admin_sub_a": admin_sub_a,
        "admin_sub_b": admin_sub_b,
    }


def test_employee_and_device_registration(test_db_session: Session, baseline_setup: dict):
    session = test_db_session
    setup = baseline_setup

    # Register employee in sub_a
    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Juan dela Cruz",
        department_id=setup["dept_a"].id,
        employee_number="EMP-001",
        session=session,
    )
    session.commit()
    assert emp.id
    assert emp.display_name == "Juan dela Cruz"
    assert emp.status == "active"

    # Register device 1
    dev1 = device_service.register_device(
        actor=setup["admin_sub_a"],
        employee_id=emp.id,
        display_name="Juan's Laptop",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        session=session,
        asset_tag="LAPTOP-01",
    )
    session.commit()
    assert dev1.id
    assert dev1.status == "active"
    assert dev1.employee_id == emp.id

    # Create an unpaired role in sub_a
    role_unpaired = db.NetworkRole(subsidiary_id=setup["sub_a"].id, code="guest_temp", display_name="Guest Temp")
    session.add(role_unpaired)
    session.flush()

    # Unpaired department/role fails
    with pytest.raises(PolicyValidationError, match="not paired"):
        device_service.register_device(
            actor=setup["admin_sub_a"],
            employee_id=emp.id,
            display_name="Juan's Phone",
            department_id=setup["dept_a"].id,
            network_role_id=role_unpaired.id,
            session=session,
        )

    # Role from different subsidiary fails
    with pytest.raises(PolicyValidationError, match="Network role does not belong"):
        device_service.register_device(
            actor=setup["admin_sub_a"],
            employee_id=emp.id,
            display_name="Juan's Phone",
            department_id=setup["dept_a"].id,
            network_role_id=setup["role_b"].id,  # From sub_b
            session=session,
        )

    # Cross-tenant registration rejected
    with pytest.raises(ResourceNotFoundError):
        device_service.register_device(
            actor=setup["admin_sub_b"],  # sub_b superadmin targeting sub_a employee
            employee_id=emp.id,
            display_name="Hacked Device",
            department_id=setup["dept_b"].id,
            network_role_id=setup["role_b"].id,
            session=session,
        )


def test_distinct_counts_and_metrics_calculation(test_db_session: Session, baseline_setup: dict):
    """B12 requirement: Two devices with three overlapping active certs show exactly 2 devices and 3 certs."""
    session = test_db_session
    setup = baseline_setup
    now = datetime.datetime.now(datetime.timezone.utc)

    emp = employee_service.create_employee(
        actor=setup["admin_plat"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Maria Santos",
        department_id=setup["dept_a"].id,
        employee_number="EMP-002",
        session=session,
    )
    session.commit()

    dev1 = device_service.register_device(
        actor=setup["admin_plat"],
        employee_id=emp.id,
        display_name="Maria Laptop",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        session=session,
    )
    dev2 = device_service.register_device(
        actor=setup["admin_plat"],
        employee_id=emp.id,
        display_name="Maria Tablet",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a2"].id,
        session=session,
    )
    session.commit()

    # Create certificates for dev1: 2 overlapping active client certs
    c1 = db.Certificate(
        serial="1001",
        cn="maria-laptop-old",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-1001",
        cert_type="client",
        issued_at=now - datetime.timedelta(days=100),
        expires_at=now + datetime.timedelta(days=265),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        employee_id=emp.id,
        device_id=dev1.id,
    )
    c2 = db.Certificate(
        serial="1002",
        cn="maria-laptop-new",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-1002",
        cert_type="client",
        issued_at=now - datetime.timedelta(days=10),
        expires_at=now + datetime.timedelta(days=355),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        employee_id=emp.id,
        device_id=dev1.id,
    )
    # dev2 has 1 active client cert
    c3 = db.Certificate(
        serial="1003",
        cn="maria-tablet",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-1003",
        cert_type="client",
        issued_at=now - datetime.timedelta(days=5),
        expires_at=now + datetime.timedelta(days=360),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a2"].id,
        employee_id=emp.id,
        device_id=dev2.id,
    )
    # dev2 also has 1 EXPIRED cert (should not count as active)
    c_expired = db.Certificate(
        serial="1004",
        cn="maria-tablet-expired",
        status=db.CertStatus.active,  # DB says active but expires_at is past
        issued_by="admin",
        request_id="req-1004",
        cert_type="client",
        issued_at=now - datetime.timedelta(days=400),
        expires_at=now - datetime.timedelta(days=35),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a2"].id,
        employee_id=emp.id,
        device_id=dev2.id,
    )
    # dev2 also has 1 SERVER cert (must be excluded from employee client certs)
    c_server = db.Certificate(
        serial="1005",
        cn="radius-server-cert",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-1005",
        cert_type="server",
        issued_at=now - datetime.timedelta(days=10),
        expires_at=now + datetime.timedelta(days=355),
        subsidiary_id=setup["sub_a"].id,
        employee_id=emp.id,
        device_id=dev2.id,
    )
    session.add_all([c1, c2, c3, c_expired, c_server])
    session.commit()

    metrics = employee_service.compute_employee_metrics(emp.id, session)

    # Invariants verification:
    # 2 registered devices
    assert metrics["registered_devices"] == 2
    # 2 active devices
    assert metrics["active_devices"] == 2
    # 2 devices with usable credentials (both have unexpired cert matching role)
    assert metrics["devices_with_usable_credentials"] == 2
    # 3 active certificates (c1, c2, c3). c_expired is past expiry; c_server is server type.
    assert metrics["active_certificates"] == 3


def test_device_credential_revocation_and_status(
    test_db_session: Session,
    baseline_setup: dict,
    throwaway_pki: dict,
    tmp_path: Path,
):
    session = test_db_session
    setup = baseline_setup
    now = datetime.datetime.now(datetime.timezone.utc)

    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Carlos Garcia",
        department_id=setup["dept_a"].id,
        employee_number="EMP-003",
        session=session,
    )
    session.commit()

    dev = device_service.register_device(
        actor=setup["admin_sub_a"],
        employee_id=emp.id,
        display_name="Carlos Phone",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        session=session,
    )
    session.commit()

    c = db.Certificate(
        serial="2001",
        cn="carlos-phone",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-2001",
        cert_type="client",
        issued_at=now,
        expires_at=now + datetime.timedelta(days=365),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        employee_id=emp.id,
        device_id=dev.id,
    )
    session.add(c)
    session.commit()

    # Revoke credentials on device
    revoked = device_service.revoke_device_credentials(
        actor=setup["admin_sub_a"],
        device_id=dev.id,
        reason="Device lost by user",
        session=session,
        pki_path=throwaway_pki["tmp_path"],
        inter_cert=throwaway_pki["inter_cert"],
        inter_key=throwaway_pki["inter_key"],
    )
    session.commit()

    assert revoked == ["2001"]
    cert_row = session.scalar(select(db.Certificate).where(db.Certificate.serial == "2001"))
    assert cert_row.status == db.CertStatus.revoked

    # Update device status to 'lost'
    dev = device_service.set_device_status(
        actor=setup["admin_sub_a"],
        device_id=dev.id,
        status="lost",
        reason="Reported stolen in taxi",
        session=session,
    )
    session.commit()
    assert dev.status == "lost"

    metrics = employee_service.compute_employee_metrics(emp.id, session)
    assert metrics["devices_with_usable_credentials"] == 0
    assert metrics["active_certificates"] == 0
    assert metrics["needs_attention"] == 1  # Lost device


def test_reliable_multi_certificate_offboarding(
    test_db_session: Session,
    baseline_setup: dict,
    throwaway_pki: dict,
):
    session = test_db_session
    setup = baseline_setup
    now = datetime.datetime.now(datetime.timezone.utc)

    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Departing Employee",
        department_id=setup["dept_a"].id,
        employee_number="EMP-004",
        session=session,
    )
    session.commit()

    # Register 2 devices
    dev1 = device_service.register_device(
        actor=setup["admin_sub_a"],
        employee_id=emp.id,
        display_name="Departing Laptop",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        session=session,
    )
    dev2 = device_service.register_device(
        actor=setup["admin_sub_a"],
        employee_id=emp.id,
        display_name="Departing Tablet",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a2"].id,
        session=session,
    )
    session.commit()

    # 3 active certs
    c1 = db.Certificate(
        serial="3001",
        cn="dep-laptop-1",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-3001",
        cert_type="client",
        issued_at=now,
        expires_at=now + datetime.timedelta(days=365),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        employee_id=emp.id,
        device_id=dev1.id,
    )
    c2 = db.Certificate(
        serial="3002",
        cn="dep-laptop-2",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-3002",
        cert_type="client",
        issued_at=now,
        expires_at=now + datetime.timedelta(days=365),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        employee_id=emp.id,
        device_id=dev1.id,
    )
    c3 = db.Certificate(
        serial="3003",
        cn="dep-tablet-1",
        status=db.CertStatus.active,
        issued_by="admin",
        request_id="req-3003",
        cert_type="client",
        issued_at=now,
        expires_at=now + datetime.timedelta(days=365),
        subsidiary_id=setup["sub_a"].id,
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a2"].id,
        employee_id=emp.id,
        device_id=dev2.id,
    )
    session.add_all([c1, c2, c3])
    session.commit()

    from cryptography import x509

    # Offboard employee
    op = employee_service.offboard_employee(
        actor=setup["admin_sub_a"],
        employee_id=emp.id,
        reason="Resignation effective today",
        session=session,
        pki_path=throwaway_pki["tmp_path"],
        inter_cert=throwaway_pki["inter_cert"],
        inter_key=throwaway_pki["inter_key"],
    )

    assert op.status == "completed"
    assert op.crl_published_at is not None
    assert set(json_loads(op.target_serials_json)) == {"3001", "3002", "3003"}
    assert set(json_loads(op.revoked_serials_json)) == {"3001", "3002", "3003"}

    # Employee status is offboarded
    emp_refreshed = session.get(db.Employee, emp.id)
    assert emp_refreshed.status == "offboarded"

    # All certificates revoked
    for s in ["3001", "3002", "3003"]:
        cert = session.scalar(select(db.Certificate).where(db.Certificate.serial == s))
        assert cert.status == db.CertStatus.revoked

    # CRL file exists and can be parsed
    crl_path = throwaway_pki["tmp_path"] / "crl.pem"
    assert crl_path.exists()
    crl_obj = x509.load_pem_x509_crl(crl_path.read_bytes())
    revoked_crl_serials = {str(r.serial_number) for r in crl_obj}
    assert {"3001", "3002", "3003"}.issubset(revoked_crl_serials)


def test_same_name_employees_across_subsidiaries_remain_separate(test_db_session: Session, baseline_setup: dict):
    """B12 requirement: Same-name employees in separate subsidiaries remain strictly separate."""
    session = test_db_session
    setup = baseline_setup

    emp_a = employee_service.create_employee(
        actor=setup["admin_plat"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Maria Santos",
        department_id=setup["dept_a"].id,
        employee_number="A-001",
        session=session,
    )
    emp_b = employee_service.create_employee(
        actor=setup["admin_plat"],
        subsidiary_id=setup["sub_b"].id,
        display_name="Maria Santos",
        department_id=setup["dept_b"].id,
        employee_number="B-001",
        session=session,
    )
    session.commit()

    assert emp_a.id != emp_b.id
    assert emp_a.subsidiary_id == setup["sub_a"].id
    assert emp_b.subsidiary_id == setup["sub_b"].id

    # List employees as sub_a superadmin: must only see emp_a
    list_a, total_a = employee_service.list_employees(actor=setup["admin_sub_a"], session=session)
    emp_a_ids = [e["id"] for e in list_a]
    assert emp_a.id in emp_a_ids
    assert emp_b.id not in emp_a_ids

    # List employees as sub_b superadmin: must only see emp_b
    list_b, total_b = employee_service.list_employees(actor=setup["admin_sub_b"], session=session)
    emp_b_ids = [e["id"] for e in list_b]
    assert emp_b.id in emp_b_ids
    assert emp_a.id not in emp_b_ids


def test_tenant_scoping_and_cross_tenant_denials(test_db_session: Session, baseline_setup: dict):
    """B12 requirement: Tenant filtering and mutation denial on foreign resources."""
    session = test_db_session
    setup = baseline_setup

    emp_a = employee_service.create_employee(
        actor=setup["admin_sub_a"],
        subsidiary_id=setup["sub_a"].id,
        display_name="Isolated Employee",
        department_id=setup["dept_a"].id,
        employee_number="ISO-100",
        session=session,
    )
    dev_a = device_service.register_device(
        actor=setup["admin_sub_a"],
        employee_id=emp_a.id,
        display_name="Isolated Laptop",
        department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id,
        session=session,
    )
    session.commit()

    # sub_b superadmin cannot get, update, or retire sub_a's employee or device
    with pytest.raises(ResourceNotFoundError):
        employee_service.get_employee(setup["admin_sub_b"], emp_a.id, session)

    with pytest.raises(ResourceNotFoundError):
        device_service.get_device(setup["admin_sub_b"], dev_a.id, session)

    with pytest.raises(ResourceNotFoundError):
        device_service.set_device_status(setup["admin_sub_b"], dev_a.id, "lost", "compromised", session)

    # Unscoped subsidiary superadmin denied all mutations
    unscoped_admin = db.Admin(
        username="unscoped_sub_admin",
        password_hash="fake",
        role=db.AdminRole.subsidiary_super_admin,
        subsidiary_scope=None,
    )
    session.add(unscoped_admin)
    session.commit()

    with pytest.raises(ForbiddenError):
        employee_service.create_employee(
            actor=unscoped_admin,
            subsidiary_id=setup["sub_a"].id,
            display_name="Blocked Emp",
            department_id=setup["dept_a"].id,
            employee_number="BLK-1",
            session=session,
        )


def test_delete_employee_refuses_without_force_when_certs_exist(test_db_session: Session, baseline_setup: dict):
    session = test_db_session
    setup = baseline_setup
    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"], subsidiary_id=setup["sub_a"].id,
        display_name="Has History", department_id=setup["dept_a"].id,
        employee_number="HIST-1", session=session,
    )
    session.commit()
    dev = device_service.register_device(
        actor=setup["admin_sub_a"], employee_id=emp.id,
        display_name="Laptop", department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id, session=session,
    )
    session.commit()

    with pytest.raises(PolicyValidationError, match="0 certificate\\(s\\) and 1 device"):
        employee_service.delete_employee(
            actor=setup["admin_sub_a"], employee_id=emp.id, session=session,
            confirm_name=emp.display_name, force=False,
        )
    # device alone (no certs) still trips the refusal
    session.rollback()


def test_delete_employee_force_removes_everything(test_db_session: Session, baseline_setup: dict):
    session = test_db_session
    setup = baseline_setup
    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"], subsidiary_id=setup["sub_a"].id,
        display_name="Force Delete Me", department_id=setup["dept_a"].id,
        employee_number="FORCE-1", session=session,
    )
    session.commit()
    dev = device_service.register_device(
        actor=setup["admin_sub_a"], employee_id=emp.id,
        display_name="Laptop", department_id=setup["dept_a"].id,
        network_role_id=setup["role_a1"].id, session=session,
    )
    session.commit()

    # attach a bare Certificate row referencing this employee/device, no
    # real PKI material needed -- delete_employee only touches DB rows
    import uuid
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = db.Certificate(
        id=str(uuid.uuid4()), cn="force-delete-laptop", serial="999999",
        issued_at=now, expires_at=now + datetime.timedelta(days=365),
        status=db.CertStatus.revoked, issued_by="test", request_id=str(uuid.uuid4()),
        employee_id=emp.id, device_id=dev.id,
    )
    session.add(cert)
    session.commit()

    employee_service.delete_employee(
        actor=setup["admin_sub_a"], employee_id=emp.id, session=session,
        confirm_name=emp.display_name, force=True,
    )

    assert session.get(db.Employee, emp.id) is None
    assert session.get(db.Device, dev.id) is None
    assert session.get(db.Certificate, cert.id) is None


def test_delete_employee_requires_exact_name_match(test_db_session: Session, baseline_setup: dict):
    session = test_db_session
    setup = baseline_setup
    emp = employee_service.create_employee(
        actor=setup["admin_sub_a"], subsidiary_id=setup["sub_a"].id,
        display_name="Typo Check", department_id=setup["dept_a"].id,
        employee_number="TYPO-1", session=session,
    )
    session.commit()

    with pytest.raises(PolicyValidationError, match="did not match"):
        employee_service.delete_employee(
            actor=setup["admin_sub_a"], employee_id=emp.id, session=session,
            confirm_name="wrong name", force=True,
        )
    assert session.get(db.Employee, emp.id) is not None


def json_loads(data: str):
    import json
    return json.loads(data)
