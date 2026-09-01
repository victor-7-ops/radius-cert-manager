"""Back up the DB, pki/issued/, and the intermediate key to one
timestamped, passphrase-encrypted archive (HANDOFF-FLEET.md §8.4).

Usage:
    python -m scripts.backup --output-dir /var/backups/certmanager

Passphrase comes from $BACKUP_PASSPHRASE if set, otherwise prompted
interactively (never taken as a CLI arg — that would land in shell
history and /proc). Never writes plaintext key material: the archive is
built in memory and encrypted before the first byte touches disk.
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.backup import BackupContents, build_archive
from app.config import load_settings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    settings = load_settings()
    passphrase = os.environ.get("BACKUP_PASSPHRASE") or getpass.getpass(
        "Backup encryption passphrase: "
    )
    if not passphrase:
        print("Refusing to back up with an empty passphrase.", file=sys.stderr)
        return 1

    contents = BackupContents(db_path=settings.db_path, pki_path=settings.pki_path)
    archive = build_archive(contents, passphrase)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = args.output_dir / f"certmanager-backup-{timestamp}.cmbk"
    out_path.write_bytes(archive)
    os.chmod(out_path, 0o600)

    print(f"Wrote {out_path} ({len(archive)} bytes, encrypted).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
