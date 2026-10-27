#!/usr/bin/env python3
"""Scheduled maintenance script to refresh expiring site network policy leases.

Usage:
    python scripts/refresh_site_policy.py [--threshold-hours 6] [--lease-hours 24]
"""

import argparse
import datetime
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from sqlalchemy import select
from app import config, db, site_policy


def _as_utc(dt: datetime.datetime) -> datetime.datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def main():
    parser = argparse.ArgumentParser(description="Refresh expiring site policy leases.")
    parser.add_argument("--threshold-hours", type=int, default=6, help="Renew policies expiring within this many hours")
    parser.add_argument("--lease-hours", type=int, default=24, help="New policy lease duration in hours")
    args = parser.parse_args()

    settings = config.load_settings()
    engine = db.make_engine(str(settings.db_path))
    session = db.make_session_factory(engine)()

    now = datetime.datetime.now(datetime.timezone.utc)
    threshold = now + datetime.timedelta(hours=args.threshold_hours)

    try:
        sites = session.scalars(select(db.Site).where(db.Site.is_active.is_(True))).all()
        priv_key, _ = site_policy.get_or_create_policy_signing_key(settings.pki_path)

        renewed = 0
        for site in sites:
            latest = session.scalar(
                select(db.SitePolicyRevision)
                .where(db.SitePolicyRevision.site_id == site.id)
                .order_by(db.SitePolicyRevision.revision.desc())
                .limit(1)
            )

            needs_renewal = False
            if latest is None:
                needs_renewal = True
            elif latest.expires_at and _as_utc(latest.expires_at) <= threshold:
                needs_renewal = True

            if needs_renewal:
                rev = site_policy.publish_site_policy(
                    site_id=site.id,
                    actor_username="daemon:policy_refresh",
                    session=session,
                    private_key=priv_key,
                    lease_hours=args.lease_hours,
                )
                session.commit()
                print(f"Refreshed policy for site '{site.name}' ({site.id}) to revision {rev.revision} (expires {rev.expires_at})")
                renewed += 1

        print(f"Policy refresh complete: {renewed} of {len(sites)} active sites refreshed.")
    finally:
        session.close()


if __name__ == "__main__":
    main()
