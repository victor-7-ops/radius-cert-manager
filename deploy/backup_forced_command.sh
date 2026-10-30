#!/usr/bin/env bash
# Forced command for the certmanager-backup SSH key's authorized_keys
# entry on the CM4. This is the ONLY thing that key is allowed to run --
# it stages an incoming nightly backup tarball, installs it under a
# dated filename, and prunes anything older than KEEP_DAYS. No shell,
# no arbitrary command execution.
#
# app/... (hub-side backup_push.sh) drives this key over two SSH calls:
#   1. `scp backup.tar.gz host:` -> SSH_ORIGINAL_COMMAND starts with "scp"
#      Writes the incoming bytes to a staging file only.
#   2. `ssh host install-backup` -> SSH_ORIGINAL_COMMAND is "install-backup"
#      Moves the staged file to a dated final name, prunes old ones.

set -euo pipefail

BACKUP_DIR="$HOME/certmanager-backups"
STAGING="$BACKUP_DIR/.staging.tar.gz"
KEEP_DAYS=30

mkdir -p "$BACKUP_DIR"

case "${SSH_ORIGINAL_COMMAND:-}" in
    scp*)
        scp -t "$STAGING"
        ;;

    install-backup)
        if [[ ! -s "$STAGING" ]]; then
            echo "No staged backup to install." >&2
            exit 1
        fi
        dest="$BACKUP_DIR/certmanager-$(date +%Y%m%d-%H%M%S).tar.gz"
        mv "$STAGING" "$dest"
        find "$BACKUP_DIR" -name 'certmanager-*.tar.gz' -mtime "+${KEEP_DAYS}" -delete
        echo "Installed $(basename "$dest")."
        ;;

    *)
        echo "This key may only push and install a nightly backup tarball." >&2
        exit 1
        ;;
esac
