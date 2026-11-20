#!/usr/bin/env bash
# Nightly off-array backup: tars the certmanager container's /data (DB +
# full PKI, private keys included) and pushes it to the CM4 over the
# dedicated certmanager-backup key (deploy/backup_forced_command.sh is
# the only thing that key can run on the receiving end).
#
# Exists because Array B on the hub (where /srv/data/certmanager lives)
# is RAID0 -- zero hardware redundancy. This doesn't fix that; it just
# means a dead Array B doesn't also take the only copy of the data with
# it. See deploy/STAGING-READINESS.md blocker #8.

set -euo pipefail

# Two CM4 destinations -- two physical copies. Same backup key and forced
# command on both ends (deploy/backup_forced_command.sh is identical on
# freeradius1 and freeradius2); each push is independent, so one CM4 being
# down doesn't block the other's backup.
BACKUP_HOSTS=(
    "topline-freeradius1:192.168.13.54"
    "certmanager-backup:192.168.13.102"
)
BACKUP_KEY="/srv/data/backup_id_ed25519"
KNOWN_HOSTS="/srv/data/.ssh/known_hosts_backup"
TMP_TAR="/tmp/certmanager-backup-$$.tar.gz"

cleanup() { docker exec certmanager rm -f "/tmp/$(basename "$TMP_TAR")" 2>/dev/null || true; rm -f "$TMP_TAR"; }
trap cleanup EXIT

docker exec certmanager tar czf "/tmp/$(basename "$TMP_TAR")" -C /data \
    --exclude=lost+found .
docker cp "certmanager:/tmp/$(basename "$TMP_TAR")" "$TMP_TAR"

fail=0
for entry in "${BACKUP_HOSTS[@]}"; do
    BACKUP_USER="${entry%%:*}"
    BACKUP_HOST="${entry##*:}"

    if scp -O -i "$BACKUP_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
            "$TMP_TAR" "${BACKUP_USER}@${BACKUP_HOST}:" \
        && ssh -i "$BACKUP_KEY" -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
            "${BACKUP_USER}@${BACKUP_HOST}" "install-backup"; then
        echo "Backup pushed and installed on ${BACKUP_HOST}: $(date -u +%FT%TZ)"
    else
        echo "Backup push to ${BACKUP_HOST} FAILED" >&2
        fail=1
    fi
done

exit "$fail"
