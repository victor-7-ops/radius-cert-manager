#!/usr/bin/env python3
"""CLI utility to export the hub's policy-signing public key for site provisioning.

Each site pins this file locally via POLICY_PUBLIC_KEY_FILE; site_agent.py
verifies every synced policy's signature against it. Copy the output file to
the site out-of-band (e.g. scp during provisioning) -- this script never
touches the private key file.

Usage:
    python scripts/export_policy_public_key.py [--out policy_signing.pub.pem]
"""

import argparse
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from app import config, site_policy


def main():
    parser = argparse.ArgumentParser(description="Export the hub's Ed25519 policy-signing public key.")
    parser.add_argument("--out", default="policy_signing.pub.pem", help="Output file path (default: policy_signing.pub.pem)")
    args = parser.parse_args()

    settings = config.load_settings()
    _, pub_key = site_policy.get_or_create_policy_signing_key(settings.pki_path)

    out_path = Path(args.out)
    out_path.write_bytes(site_policy.export_public_key_pem(pub_key))

    print(f"Exported policy-signing public key to {out_path}")
    print(f"  Key ID: {site_policy.get_public_key_id(pub_key)}")
    print("Copy this file to the site and point POLICY_PUBLIC_KEY_FILE at it.")


if __name__ == "__main__":
    main()
