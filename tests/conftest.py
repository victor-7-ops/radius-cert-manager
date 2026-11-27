"""Throwaway test PKI, built fresh under tmp_path for every test.

Non-negotiable (handoff §12): tests never touch the live PKI or the live
CM4. If a test could conceivably write to PKI_PATH or SSH to RADIUS_HOST,
it is wrong.
"""

import datetime
import os
import sys
import uuid
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth, db, pki  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _cheap_password_hashing():
    # Production argon2 params are deliberately expensive (~100ms/hash) —
    # fine for real logins, but hundreds of test logins/admin-creations
    # at that cost is most of this suite's wall-clock time. Lowest-cost
    # params here since test security guarantees don't depend on them.
    auth._hasher = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def login_as(client, app_settings, admin):
    """Log a TestClient in as `admin` the same way the real /auth/login
    route does — creates a real AdminSession row and mints a cookie
    carrying its id, rather than hand-building a cookie that skips
    session tracking entirely (require_admin rejects a cookie with no
    "sid" as of the per-session-list feature)."""
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    record = auth.create_admin_session(session, admin, user_agent="pytest-client", ip_address="127.0.0.1")
    cookie = auth._serializer(app_settings.secret_key).dumps({
        "sub": admin.id,
        "tv": admin.token_version,
        "sid": record.id,
        "session_start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    client.cookies.set(auth.SESSION_COOKIE, cookie)


def create_test_device(app_settings, subsidiary_name: str | None = None, employee_name: str = "Test Employee", role_default_cert_days: int | None = None) -> str:
    """Minimal employee+device fixture (handoff J, 20 Nov 2026): /certs/issue
    now requires a device, since a device-less cert has no
    department/network_role and authorize_policy.py always Access-Rejects
    it. db.init_db seeds the real Subsidiary rows on every create_app call;
    Department/NetworkRole aren't seeded, so create throwaway ones here."""
    engine = db.make_engine(str(app_settings.db_path))
    db.init_db(engine)
    session = db.make_session_factory(engine)()
    if subsidiary_name:
        sub = session.scalars(select(db.Subsidiary).where(db.Subsidiary.display_name == subsidiary_name)).one()
    else:
        sub = session.scalars(select(db.Subsidiary).where(db.Subsidiary.is_active.is_(True))).first()
    suffix = uuid.uuid4().hex[:8]
    dept = db.Department(subsidiary_id=sub.id, code=f"test-{suffix}", display_name="Test Dept")
    session.add(dept)
    session.flush()
    role = db.NetworkRole(subsidiary_id=sub.id, code=f"test-{suffix}", display_name="Test Role", default_cert_days=role_default_cert_days)
    session.add(role)
    session.flush()
    emp = db.Employee(subsidiary_id=sub.id, display_name=employee_name, department_id=dept.id)
    session.add(emp)
    session.flush()
    device = db.Device(
        subsidiary_id=sub.id, employee_id=emp.id, display_name=f"{employee_name}'s device",
        department_id=dept.id, network_role_id=role.id,
    )
    session.add(device)
    session.commit()
    session.refresh(device)
    return device.id


@pytest.fixture
def throwaway_pki(tmp_path):
    root_cert, root_key = pki.build_self_signed_ca("Test Root CA", days=15 * 365)
    inter_cert, inter_key = pki.build_intermediate_ca(
        "Test Issuing CA", 5 * 365, root_cert, root_key
    )
    return {
        "root_cert": root_cert,
        "root_key": root_key,
        "inter_cert": inter_cert,
        "inter_key": inter_key,
        "tmp_path": tmp_path,
    }


@pytest.fixture(autouse=True)
def _no_live_env(monkeypatch):
    # Belt-and-suspenders: ensure nothing accidentally points at real paths/hosts.
    monkeypatch.delenv("PKI_PATH", raising=False)
    monkeypatch.delenv("RADIUS_HOST", raising=False)


@pytest.fixture
def app_settings(tmp_path, monkeypatch):
    pki_dir = tmp_path / "pki"
    (pki_dir / "private").mkdir(parents=True)
    (pki_dir / "issued").mkdir(parents=True)
    env = {
        "SECRET_KEY": "x" * 40,
        "PKI_PATH": str(pki_dir),
        "DB_PATH": str(tmp_path / "certmanager.db"),
        "BIND_HOST": "127.0.0.1",
        "BIND_PORT": "8443",
        "RADIUS_HOST": "127.0.0.1",
        "RADIUS_SSH_KEY": str(tmp_path / "ssh_key"),
        "RADIUS_SSH_USER": "crlpush",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    (tmp_path / "ssh_key").write_text("fake")
    from app.config import load_settings

    return load_settings()
