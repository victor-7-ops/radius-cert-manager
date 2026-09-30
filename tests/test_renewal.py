"""Renewal campaign logic (HANDOFF-LIFECYCLE.md §2) — pure functions,
unit-tested like app/fleet_health.py and app/crl_health.py."""

import datetime
import uuid

from app import db, renewal


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _cert(expires_in_days, status=db.CertStatus.active, retired_at=None, cert_type="client"):
    now = _now()
    return db.Certificate(
        cn="x", serial=str(uuid.uuid4()), issued_at=now - datetime.timedelta(days=300),
        expires_at=now + datetime.timedelta(days=expires_in_days),
        status=status, issued_by="alice", request_id=str(uuid.uuid4()),
        retired_at=retired_at, cert_type=cert_type,
    )


def test_in_cohort_within_window():
    assert renewal.in_cohort(_cert(20), 30, _now()) is True


def test_in_cohort_outside_window():
    assert renewal.in_cohort(_cert(45), 30, _now()) is False


def test_in_cohort_already_expired_window():
    assert renewal.in_cohort(_cert(-5), None, _now()) is True
    assert renewal.in_cohort(_cert(5), None, _now()) is False


def test_in_cohort_excludes_non_client():
    assert renewal.in_cohort(_cert(10, cert_type="server"), 30, _now()) is False


def test_in_cohort_excludes_non_active():
    assert renewal.in_cohort(_cert(10, status=db.CertStatus.suspended), 30, _now()) is False
    assert renewal.in_cohort(_cert(10, status=db.CertStatus.revoked), 30, _now()) is False


def test_in_cohort_excludes_retired():
    assert renewal.in_cohort(_cert(10, retired_at=_now()), 30, _now()) is False


def test_progress_outstanding_with_no_successor():
    cert = _cert(10)
    assert renewal.progress_for(cert, None, 30, _now()) == renewal.RenewalProgress.outstanding


def test_progress_done_when_successor_active_and_far_out():
    cert = _cert(10)
    successor = _cert(400)  # far beyond the window
    assert renewal.progress_for(cert, successor, 30, _now()) == renewal.RenewalProgress.done


def test_progress_outstanding_when_successor_itself_due_soon():
    cert = _cert(10)
    successor = _cert(15)  # still within the 30-day window
    assert renewal.progress_for(cert, successor, 30, _now()) == renewal.RenewalProgress.outstanding


def test_progress_outstanding_when_successor_not_active():
    cert = _cert(10)
    successor = _cert(400, status=db.CertStatus.revoked)
    assert renewal.progress_for(cert, successor, 30, _now()) == renewal.RenewalProgress.outstanding


def test_progress_retired_overrides_everything():
    cert = _cert(10, retired_at=_now())
    successor = _cert(400)
    assert renewal.progress_for(cert, successor, 30, _now()) == renewal.RenewalProgress.retired
