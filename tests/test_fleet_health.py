"""Fleet status derivation (HANDOFF-FLEET.md §5) and the edge-triggered
alert dedup in app/fleet_watch.py (§5.1 TRAP: exactly one alert per
transition, not one per scheduler run)."""

import datetime
import uuid

from app import db, fleet_health, fleet_watch


def _site(**overrides):
    defaults = dict(
        id=str(uuid.uuid4()), name="Boracay", radius_cn="radius-boracay.internal",
        subsidiary="Lezzgo Boracay", auth_token_hash="x", crl_validity_days=30,
        checkin_interval_seconds=3600, is_active=True,
    )
    defaults.update(overrides)
    return db.Site(**defaults)


def _cert(days_remaining, **overrides):
    now = datetime.datetime.now(datetime.timezone.utc)
    defaults = dict(
        id=str(uuid.uuid4()), cn="radius-boracay.internal", serial="1",
        issued_at=now - datetime.timedelta(days=1),
        expires_at=now + datetime.timedelta(days=days_remaining),
        status=db.CertStatus.active, issued_by="alice", request_id=str(uuid.uuid4()),
        cert_type="server",
    )
    defaults.update(overrides)
    return db.Certificate(**defaults)


def test_ok_when_everything_fresh():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now - datetime.timedelta(minutes=5))
    cert = _cert(days_remaining=300)
    health = fleet_health.evaluate_site(site, cert, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.ok


def test_silent_when_missed_more_than_three_intervals():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(
        last_seen_at=now - datetime.timedelta(hours=4),  # 4 intervals at 1h each
        checkin_interval_seconds=3600,
    )
    health = fleet_health.evaluate_site(site, None, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.silent


def test_silent_when_never_checked_in():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)
    health = fleet_health.evaluate_site(site, None, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.silent


def test_critical_when_freeradius_down():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, last_reported_freeradius_ok=False)
    health = fleet_health.evaluate_site(site, None, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.critical


def test_critical_when_cert_expiring_within_14_days():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now)
    cert = _cert(days_remaining=10)
    health = fleet_health.evaluate_site(site, cert, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.critical


def test_critical_when_crl_expiring_within_48_hours():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now, crl_validity_days=30)
    old_crl = now - datetime.timedelta(days=29, hours=1)  # ~23h of margin left
    health = fleet_health.evaluate_site(site, None, crl_last_generated_at=old_crl, now=now)
    assert health.status == fleet_health.SiteStatus.critical


def test_warn_when_cert_inside_renewal_window_but_not_critical():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=now)
    # 90-day cert, 25 days remaining: under the 1/3-remaining renewal_due
    # threshold (30 days), but comfortably clear of the 14-day CRITICAL cutoff.
    cert = _cert(
        days_remaining=25,
        issued_at=now - datetime.timedelta(days=65),
    )
    health = fleet_health.evaluate_site(site, cert, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.warn


def test_warn_on_one_missed_checkin():
    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(
        last_seen_at=now - datetime.timedelta(hours=1, minutes=30),
        checkin_interval_seconds=3600,
    )
    health = fleet_health.evaluate_site(site, None, crl_last_generated_at=now, now=now)
    assert health.status == fleet_health.SiteStatus.warn


def test_fleet_watch_fires_once_on_transition_then_stays_quiet(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)  # SILENT from the start
    session.add(site)
    session.commit()

    alerts = []
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1

    # Second run, nothing changed — must NOT alert again.
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1


def test_fleet_watch_alerts_again_on_recovery(tmp_path):
    engine = db.make_engine(str(tmp_path / "t.db"))
    db.init_db(engine)
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    site = _site(last_seen_at=None)
    session.add(site)
    session.commit()

    alerts = []
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 1

    site.last_seen_at = now
    site.last_reported_freeradius_ok = True
    session.commit()
    fleet_watch.check_and_alert(session, alerts.append, now=now)
    assert len(alerts) == 2  # recovery to OK is its own transition
