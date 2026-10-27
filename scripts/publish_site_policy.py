#!/usr/bin/env python3
"""CLI utility to compile and publish a signed network policy revision for a site.

Usage:
    python scripts/publish_site_policy.py --site-id <SITE_ID> [--lease-hours 24]
"""

import argparse
import sys
from pathlib import Path

# Ensure repository root is in sys.path
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from app import config, db, site_policy


def main():
    parser = argparse.ArgumentParser(description="Publish signed network policy for a FreeRADIUS site.")
    parser.add_argument("--site-id", required=True, help="Site identifier to publish policy for")
    parser.add_argument("--lease-hours", type=int, default=24, help="Policy lease duration in hours (default: 24)")
    parser.add_argument("--actor", default="cli:publish_site_policy", help="Audit actor name")
    args = parser.parse_args()

    settings = config.load_settings()
    engine = db.make_engine(str(settings.db_path))
    session = db.make_session_factory(engine)()

    try:
        site = session.get(db.Site, args.site_id)
        if not site:
            print(f"Error: Site '{args.site_id}' not found.", file=sys.stderr)
            sys.exit(1)

        priv_key, pub_key = site_policy.get_or_create_policy_signing_key(settings.pki_path)
        rev_record = site_policy.publish_site_policy(
            site_id=site.id,
            actor_username=args.actor,
            session=session,
            private_key=priv_key,
            lease_hours=args.lease_hours,
        )
        session.commit()

        print(f"Successfully published network policy revision {rev_record.revision} for site '{site.name}' ({site.id})")
        print(f"  Payload SHA256: {rev_record.payload_hash}")
        print(f"  Signing Key ID: {rev_record.signing_key_id}")
        print(f"  Issued: {rev_record.issued_at.isoformat()}")
        print(f"  Expires: {rev_record.expires_at.isoformat()}")
    finally:
        session.close()


if __name__ == "__main__":
    main()
