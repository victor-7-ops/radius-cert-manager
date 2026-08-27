"""Cert-expiry alerting — checked opportunistically (there's no
scheduler), one alert per newly-crossed-threshold cert rather than
re-alerting every check. See app/expiry_alerts.py."""

import datetime
import uuid

from app import cert_service, db, expiry_alerts


def _session(tmp_path):
    engine = db.make_engine(str(tmp_path / "test.db"))
    db.init_db(engine)
    return db.make_session_factory(engine)()


def _issue(session, tmp_path, throwaway_pki, cn, days, employee_name=None):
    return cert_service.issue_certificate(
        session, tmp_path, throwaway_pki["inter_cert"], throwaway_pki["inter_key"],
        cn=cn, note=None, request_id=str(uuid.uuid4()), export_password=None,
        issued_by="alice", days=days,
        device=cert_service.DeviceInfo(employee_name=employee_name) if employee_name else None,
    ).certificate


def test_alerts_on_cert_expiring_within_window(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    _issue(session, tmp_path, throwaway_pki, "soon-device", days=3, employee_name="Jordan Ellis")
    _issue(session, tmp_path, throwaway_pki, "later-device", days=365)

    calls = []
    due = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert [c.cn for c in due] == ["soon-device"]
    assert len(calls) == 1
    assert "soon-device" in calls[0]
    assert "Jordan Ellis" in calls[0]
    assert "later-device" not in calls[0]


def test_does_not_realert_on_second_check(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    _issue(session, tmp_path, throwaway_pki, "once-device", days=3)

    calls = []
    first = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)
    second = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert len(first) == 1
    assert second == []
    assert len(calls) == 1  # not called a second time


def test_batches_multiple_due_certs_into_one_alert_call(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    _issue(session, tmp_path, throwaway_pki, "batch-a", days=1)
    _issue(session, tmp_path, throwaway_pki, "batch-b", days=2)
    _issue(session, tmp_path, throwaway_pki, "batch-c", days=5)

    calls = []
    due = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert len(due) == 3
    assert len(calls) == 1  # one message covering all three, not three separate ones
    for cn in ("batch-a", "batch-b", "batch-c"):
        assert cn in calls[0]


def test_no_alert_call_when_nothing_is_due(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    _issue(session, tmp_path, throwaway_pki, "safe-device", days=365)

    calls = []
    due = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert due == []
    assert calls == []


def test_already_expired_active_cert_is_included(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    cert = _issue(session, tmp_path, throwaway_pki, "expired-device", days=365)
    # Backdate it past expiry without changing status — the "expired"
    # badge is a computed status (handoff §5.2), the stored status stays
    # active until an admin acts on it, and that's exactly the case that
    # most needs an alert.
    cert.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    session.commit()

    calls = []
    due = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert [c.cn for c in due] == ["expired-device"]
    assert "EXPIRED" in calls[0]


def test_suspended_or_revoked_certs_are_not_alerted(tmp_path, throwaway_pki):
    session = _session(tmp_path)
    cert = _issue(session, tmp_path, throwaway_pki, "suspended-device", days=3)
    cert_service.suspend(session, tmp_path, cert.serial, "test", "alice")

    calls = []
    due = expiry_alerts.check_and_alert(session, calls.append, warning_days=7)

    assert due == []
    assert calls == []
