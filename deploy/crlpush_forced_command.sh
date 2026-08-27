#!/usr/bin/env bash
# Forced command for the crlpush SSH key's authorized_keys entry on the CM4
# (handoff §8.4). This is the ONLY thing that key is allowed to run.
#
# app/crl_push.py drives this key over three separate SSH connections —
# don't change one side without the other:
#   1. `scp local crl.pem crlpush@host:crl.pem`  -> SSH_ORIGINAL_COMMAND starts with "scp"
#      Writes the incoming bytes to a staging file only. Does NOT install
#      or reload yet — a partial/interrupted scp must never touch the live CRL.
#   2. `ssh crlpush@host` (no command)            -> SSH_ORIGINAL_COMMAND is empty
#      Validates the staged file (nextUpdate not in the past, `freeradius -XC`
#      passes), installs it as the live CRL, and reloads FreeRADIUS. This is
#      the step that can fail loudly and leave the previous CRL in place.
#   3. `ssh crlpush@host sha256sum-crl`           -> SSH_ORIGINAL_COMMAND is "sha256sum-crl"
#      Reads back the hash of the now-live CRL so the caller can confirm the
#      push actually landed (handoff §8.5 — verify, don't assume).
#
# This key must not be able to read the RADIUS server's private key or
# open a shell — enforced by the authorized_keys restrictions (see
# deploy/RUNBOOK.md), not by this script, but this script must not
# undermine that either: no arbitrary command execution, ever.

set -euo pipefail

CERT_DIR="/etc/freeradius/3.0/certs"
CRL_DEST="${CERT_DIR}/crl.pem"
CRL_STAGING="${CERT_DIR}/.crl.pem.staging"

case "${SSH_ORIGINAL_COMMAND:-}" in
    scp*)
        # Step 1: stage only. `scp -t` is scp's own wire protocol for
        # "receive a file" — invoking it here is how we accept the bytes
        # without granting a shell.
        scp -t "$CRL_STAGING" < /dev/stdin > /dev/null
        ;;

    "")
        # Step 2: validate, install, reload.
        if [[ ! -s "$CRL_STAGING" ]]; then
            echo "No staged CRL to install (did the scp step run first?)." >&2
            exit 1
        fi

        next_update_epoch=$(
            openssl crl -in "$CRL_STAGING" -noout -nextupdate 2>/dev/null \
                | sed 's/nextUpdate=//' \
                | xargs -I{} date -d {} +%s 2>/dev/null
        ) || next_update_epoch=0

        if [[ "$next_update_epoch" -eq 0 ]]; then
            echo "Could not parse nextUpdate from the staged CRL — refusing to install." >&2
            rm -f "$CRL_STAGING"
            exit 1
        fi

        if [[ "$next_update_epoch" -le "$(date +%s)" ]]; then
            echo "Staged CRL's nextUpdate is already in the past — refusing to install." >&2
            rm -f "$CRL_STAGING"
            exit 1
        fi

        cp "$CRL_STAGING" "$CRL_DEST"
        chmod 644 "$CRL_DEST"
        rm -f "$CRL_STAGING"

        if ! freeradius -XC > /tmp/freeradius_check.$$.log 2>&1; then
            echo "freeradius -XC failed after installing new CRL. See /tmp/freeradius_check.$$.log" >&2
            exit 1
        fi
        rm -f /tmp/freeradius_check.$$.log

        systemctl reload freeradius
        echo "CRL installed and FreeRADIUS reloaded. nextUpdate epoch: $next_update_epoch"
        ;;

    sha256sum-crl)
        # Step 3: read back what's actually live.
        if [[ ! -f "$CRL_DEST" ]]; then
            echo "no crl installed" >&2
            exit 1
        fi
        sha256sum "$CRL_DEST" | awk '{print $1, "crl.pem"}'
        ;;

    *)
        echo "This key may only push, install, or read back crl.pem." >&2
        exit 1
        ;;
esac
