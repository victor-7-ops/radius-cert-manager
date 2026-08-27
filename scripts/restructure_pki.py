"""Phase A, §3: build the two-tier PKI (offline root -> online intermediate)
and reissue the RADIUS server cert under the new intermediate.

Run this ONCE, on the CA machine (192.168.200.18), before deploying the
app. It does NOT touch the CM4, does NOT restart FreeRADIUS, and does
NOT delete anything from the old ~/ca layout — deployment (copying the
chain to the CM4, the test-device transition, archiving the old CA) is
a separate manual procedure documented in deploy/RUNBOOK.md, because
those steps require live hardware and an eapol_test checkpoint at each
one (handoff §3 step 5 — getting that order wrong locks you out of your
own test rig).

Usage:
    python -m scripts.restructure_pki --out-root /path/to/removable/media \
        --out-service /opt/certmanager/pki
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import pki


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-root",
        required=True,
        type=Path,
        help="Directory for the OFFLINE root CA material (removable media, not this host's disk)",
    )
    parser.add_argument(
        "--out-service",
        required=True,
        type=Path,
        help="pki/ directory for the service host (PKI_PATH) — intermediate key lives here",
    )
    parser.add_argument("--root-cn", default="Arekushi Root CA")
    parser.add_argument("--intermediate-cn", default="Arekushi Issuing CA")
    parser.add_argument("--root-days", type=int, default=15 * 365)
    parser.add_argument("--intermediate-days", type=int, default=5 * 365)
    parser.add_argument("--radius-server-cn", default="radius-server")
    parser.add_argument("--client-days", type=int, default=365)
    args = parser.parse_args()

    if args.out_root.resolve().is_relative_to(Path(__file__).resolve().parent.parent):
        print(
            "Refusing: --out-root resolves inside this repo. The root key must go on "
            "removable media, physically separate from the service host (handoff §3).",
            file=sys.stderr,
        )
        return 1

    args.out_root.mkdir(parents=True, exist_ok=True)
    (args.out_service / "private").mkdir(parents=True, exist_ok=True)
    (args.out_service / "issued").mkdir(parents=True, exist_ok=True)

    print(f"Building root CA '{args.root_cn}' ({args.root_days} days)...")
    root_password = getpass.getpass("Set a passphrase for the root CA key: ")
    confirm = getpass.getpass("Confirm: ")
    if root_password != confirm:
        print("Passphrases did not match.", file=sys.stderr)
        return 1
    if len(root_password) < 16:
        print("Use at least 16 characters — this key is offline for years at a time.", file=sys.stderr)
        return 1

    root_cert, root_key = pki.build_self_signed_ca(args.root_cn, args.root_days)

    root_key_path = args.out_root / "root.key.pem"
    root_key_path.write_bytes(pki.private_key_to_encrypted_pem(root_key, root_password.encode()))
    (args.out_root / "root.crt.pem").write_bytes(pki.cert_to_pem(root_cert))
    print(f"Root key (encrypted) written to {root_key_path} — move this to removable media now.")

    print(f"Building intermediate CA '{args.intermediate_cn}' ({args.intermediate_days} days)...")
    inter_cert, inter_key = pki.build_intermediate_ca(
        args.intermediate_cn, args.intermediate_days, root_cert, root_key
    )
    (args.out_service / "intermediate.crt").write_bytes(pki.cert_to_pem(inter_cert))
    (args.out_service / "private" / "intermediate.key").write_bytes(pki.private_key_to_pem(inter_key))

    chain_pem = pki.cert_to_pem(root_cert) + pki.cert_to_pem(inter_cert)
    (args.out_service / "ca-chain.pem").write_bytes(chain_pem)

    print(f"Reissuing '{args.radius_server_cn}' under the new intermediate...")
    server_key = pki.generate_private_key()
    server_csr = pki.build_csr(server_key, args.radius_server_cn)
    server_serial = pki.generate_serial()
    server_cert = pki.sign_server_cert(
        server_csr, inter_cert, inter_key, server_serial, args.client_days
    )
    (args.out_service / "issued").mkdir(parents=True, exist_ok=True)
    (args.out_service / "issued" / f"{args.radius_server_cn}.crt").write_bytes(
        pki.cert_to_pem(server_cert)
    )
    server_key_path = args.out_service / f"{args.radius_server_cn}.key.pem"
    server_key_path.write_bytes(pki.private_key_to_pem(server_key))

    print()
    print("Done. Produced:")
    print(f"  {root_key_path}  <- move to removable media, encrypted, keep offline")
    print(f"  {args.out_root / 'root.crt.pem'}  <- public, fine to keep alongside for reference")
    print(f"  {args.out_service / 'intermediate.crt'}")
    print(f"  {args.out_service / 'private' / 'intermediate.key'}  <- 0600, owned by certmgr")
    print(f"  {args.out_service / 'ca-chain.pem'}  <- deploy to CM4 as FreeRADIUS ca_file")
    print(f"  {args.out_service / 'issued' / (args.radius_server_cn + '.crt')}")
    print(f"  {server_key_path}  <- deploy to CM4, then delete the local copy")
    print()
    print("Next: follow deploy/RUNBOOK.md for the CM4 deployment and test-device transition.")
    print("Do NOT delete anything under the old ~/ca layout yet — archive it per §3 step 5e,")
    print("only after the new chain has run cleanly for at least a week.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
