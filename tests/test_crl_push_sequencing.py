"""H1: sequential multi-host CRL push with a health gate between hosts.

main.regenerate_and_push_crl must restart hosts one at a time, confirming
each is healthy before moving to the next, and must never actually spawn
scp/ssh in tests (handoff §12) — crl_push.push_crl and
crl_push.check_host_health are always stubbed.
"""

from app import crl_push, db, site_service
from app.main import create_app

from tests.test_app import _write_throwaway_pki


def _app_with_two_push_hosts(app_settings, throwaway_pki):
    _write_throwaway_pki(app_settings, throwaway_pki)
    app = create_app(app_settings)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    site_service.create_site(
        session, name="freeradius2", radius_cn="freeradius2.topline.local", actor="system",
        crl_push_host="192.168.13.102",
    )
    return app


def test_two_healthy_hosts_push_and_health_check_in_order(app_settings, throwaway_pki, monkeypatch):
    events = []
    monkeypatch.setattr(
        crl_push,
        "push_crl",
        lambda crl_path, host, *a, **k: (events.append(("push", host)), crl_push.PushResult(ok=True, detail="ok"))[1],
    )
    monkeypatch.setattr(
        crl_push,
        "check_host_health",
        lambda host, *a, **k: (events.append(("health", host)), crl_push.PushResult(ok=True, detail="ok"))[1],
    )

    app = _app_with_two_push_hosts(app_settings, throwaway_pki)
    app.state.regenerate_and_push_crl(background=False)

    expected_hosts = sorted({app_settings.radius_host, "192.168.13.102"})
    assert events == [
        ("push", expected_hosts[0]),
        ("health", expected_hosts[0]),
        ("push", expected_hosts[1]),
        ("health", expected_hosts[1]),
    ]


def test_aborts_remaining_hosts_when_first_fails_health_check(app_settings, throwaway_pki, monkeypatch):
    events = []
    monkeypatch.setattr(
        crl_push,
        "push_crl",
        lambda crl_path, host, *a, **k: (events.append(("push", host)), crl_push.PushResult(ok=True, detail="ok"))[1],
    )
    monkeypatch.setattr(
        crl_push,
        "check_host_health",
        lambda host, *a, **k: (events.append(("health", host)), crl_push.PushResult(ok=False, detail="freeradius not active"))[1],
    )

    app = _app_with_two_push_hosts(app_settings, throwaway_pki)
    app.state.regenerate_and_push_crl(background=False)

    expected_hosts = sorted({app_settings.radius_host, "192.168.13.102"})
    # Only the first host was ever touched; the second never got pushed to.
    assert events == [("push", expected_hosts[0]), ("health", expected_hosts[0])]

    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    audit_rows = session.query(db.AuditLog).filter_by(action="crl_push_health_gate_failed").all()
    assert len(audit_rows) == 1
    assert audit_rows[0].target == expected_hosts[0]


def test_pull_only_site_is_never_pushed_to(app_settings, throwaway_pki, monkeypatch):
    pushed_hosts = []
    monkeypatch.setattr(
        crl_push,
        "push_crl",
        lambda crl_path, host, *a, **k: (pushed_hosts.append(host), crl_push.PushResult(ok=True, detail="ok"))[1],
    )
    monkeypatch.setattr(
        crl_push, "check_host_health", lambda *a, **k: crl_push.PushResult(ok=True, detail="ok")
    )

    _write_throwaway_pki(app_settings, throwaway_pki)
    app = create_app(app_settings)
    engine = db.make_engine(str(app_settings.db_path))
    session = db.make_session_factory(engine)()
    site_service.create_site(
        session, name="pull-only-site", radius_cn="pull-only.topline.local", actor="system",
    )

    app.state.regenerate_and_push_crl(background=False)

    assert pushed_hosts == [app_settings.radius_host]
