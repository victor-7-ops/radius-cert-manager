#!/usr/bin/env bash
# CM4 parity check (V2, PRODUCTION-READINESS.md §5 part A).
#
# freeradius1 and freeradius2 are a failover pair that keeps drifting:
# check_crl was enabled on one box only for weeks, the backup account name
# differs between them, a polkit rule and the deployed site-agent code have
# both been found out of sync. A fix verified on one box is not verified on
# the other. This runs the same read-only commands on both and diffs the
# output -- it changes nothing.
#
# Run from a machine with SSH key access to both boxes' admin accounts
# (never run by the AI assistant itself -- hand the output back for review).
#
# Usage: ./check_cm4_parity.sh <host1-ssh-target> <host2-ssh-target>
# Example:
#   ./check_cm4_parity.sh topline-freeradius1@topline-freeradius1 topline-freeradius2@topline-freeradius2
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "Usage: $0 <host1-ssh-target> <host2-ssh-target>" >&2
  exit 1
fi

HOST1=$1
HOST2=$2

# ponytail: one remote command block run twice beats two hand-maintained
# lists that silently drift from each other -- the exact failure mode this
# script exists to catch.
read -r -d '' REMOTE_SCRIPT <<'EOF' || true
set -uo pipefail
echo "## freeradius version"
freeradius -v 2>&1 | head -1
echo "## check_crl / crl_file / ca_file (mods-available/eap)"
grep -n "check_crl\|crl_file\|ca_file" /etc/freeradius/3.0/mods-available/eap 2>&1
echo "## relevant unit files"
systemctl list-unit-files 'site-agent*' 'certmanager*' 'backup*' 2>&1 | sort
echo "## certs dir ownership/modes"
ls -la /etc/freeradius/3.0/certs 2>&1
echo "## deployed site-agent code hash"
sha256sum /opt/certmanager-agent/site_agent.py 2>&1
echo "## polkit rules present"
ls -la /etc/polkit-1/rules.d/ 2>&1
echo "## certmgr-agent account + groups"
id certmgr-agent 2>&1
echo "## accounts (admin login, backup account)"
getent passwd topline-freeradius1 topline-freeradius2 certmanager-backup 2>&1 | cut -d: -f1,3,4,6
echo "## backup tarball count"
ls ~/certmanager-backups/*.tar.gz 2>/dev/null | wc -l
EOF

OUT1=$(ssh "$HOST1" "$REMOTE_SCRIPT")
OUT2=$(ssh "$HOST2" "$REMOTE_SCRIPT")

if diff -u --label "$HOST1" --label "$HOST2" <(echo "$OUT1") <(echo "$OUT2"); then
  echo "No differences found."
fi
