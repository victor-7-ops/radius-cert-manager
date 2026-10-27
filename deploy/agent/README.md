# Site agent

Runs on each site's FreeRADIUS box (never on the hub). One script,
`site_agent.py`, standard library + `requests`, invoked once per pass by
a systemd timer — not a daemon. Every pass: check in, pull a newer CRL
if the hub reports one, renew the server cert if the hub says it's due,
sync the signed network policy, and sync the signed FreeRADIUS adapter
source (`deploy/radius/authorize_policy.py`) itself.

Install is safe by construction (HANDOFF-FLEET.md §3.4): stage the new
file(s) → `freeradius -XC` → only on success install and reload → verify
`freeradius` is active → on any failure, restore what was there before,
reload again, and let it show up in the next check-in as
`freeradius_ok=False` (the fleet view already treats that as CRITICAL).
An adapter-source change is staged the same way but applies with a real
`systemctl restart` instead of a reload — a SIGHUP doesn't make the
embedded Python interpreter reimport the module.

## Deploying an adapter code change

This is pull-only, same as the policy and CRL: there's no push mechanism
from the hub, by design (`app/db.py`'s `Site` model — a site is never
pushed to). To ship a fix to `deploy/radius/authorize_policy.py`:

1. `git pull` + restart the hub app — that's the only "deploy" step.
2. Every site picks up the new signed bundle on its next poll via
   `GET /api/site/radius-adapter`, verified against the same
   `POLICY_PUBLIC_KEY_FILE` pin already used for policy sync (one key,
   both purposes), then installed via the safety path above.

Set `RADIUS_ADAPTER_PATH` in a site's `.env` only if the module lives
somewhere other than the default `/opt/certmanager/deploy/radius/authorize_policy.py`.

## Install

Despite the "standard library + requests" framing above, policy/adapter
signature verification imports `app.site_policy` (and transitively
`app.db`), so the deploy needs a venv with `cryptography` and
`sqlalchemy>=2.0`, plus copies of those two app files. `NoNewPrivileges=yes`
in the unit also means sudo-based privilege escalation inside the service
doesn't work — file/service access has to come from actual group
membership, not a sudoers rule.

```bash
sudo useradd --system --home /opt/certmanager-agent --shell /usr/sbin/nologin certmgr-agent
sudo mkdir -p /opt/certmanager-agent/app /var/lib/certmanager-agent
sudo cp site_agent.py /opt/certmanager-agent/
sudo cp site-agent.env.example /opt/certmanager-agent/.env   # then edit it
sudo touch /opt/certmanager-agent/app/__init__.py
sudo cp /path/to/repo/app/db.py /path/to/repo/app/site_policy.py /opt/certmanager-agent/app/
sudo chown -R certmgr-agent:certmgr-agent /opt/certmanager-agent /var/lib/certmanager-agent
sudo chmod 600 /opt/certmanager-agent/.env

# Verification deps, pinned to match the hub's own requirements.txt.
sudo python3 -m venv /opt/certmanager-agent/.venv
sudo /opt/certmanager-agent/.venv/bin/pip install --no-cache-dir \
    'sqlalchemy==2.0.52' 'cryptography==44.0.0' 'requests==2.32.3'

# The hub's TLS cert — if self-signed (no real CA yet), export it from
# wherever the hub terminates TLS and copy it here; if it's issued by a
# real intermediate not in this box's system trust store, use the
# intermediate/chain instead. The agent refuses to start without
# HUB_CA_BUNDLE (fails closed: no fallback to system trust, no fallback
# to no verification — see site_agent.py's _require_ca_bundle).
sudo cp ca-chain.pem /opt/certmanager-agent/ca-chain.pem   # or hub's web.crt
sudo chown certmgr-agent:certmgr-agent /opt/certmanager-agent/ca-chain.pem

# POLICY_PUBLIC_KEY_FILE: export with scripts/export_policy_public_key.py
# on the hub, copy the output here, point .env at it.

# certmgr-agent needs real group membership, not sudo (NoNewPrivileges
# blocks escalation inside the unit):
#  - freerad group: read FreeRADIUS config, write policy.json/certs/adapter
#  - ssl-cert group: freeradius -XC reads the snakeoil private key as part
#    of its own config validation, even when the check is only validating
#    an unrelated file -- this install-safety check runs as whatever user
#    the agent runs as, not as the freerad service user.
sudo usermod -aG freerad,ssl-cert certmgr-agent
sudo chmod g+w /etc/freeradius/3.0 /etc/freeradius/3.0/certs
sudo chmod g+w /opt/certmanager/deploy/radius/authorize_policy.py 2>/dev/null || true
# If adapter sync will run (RADIUS_ADAPTER_PATH's parent dir), that whole
# tree needs certmgr-agent as owner, not just group-write -- the install
# path chmod()s what it writes, and chmod requires ownership:
sudo chown -R certmgr-agent:freerad /opt/certmanager/deploy/radius

sudo cp site-agent.service site-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now site-agent.timer
```

## Get a site's token

From the hub, as a Super Admin:

```bash
curl -sX POST https://certmanager.example.internal/api/admin/sites \
  -H "Cookie: <admin session>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Boracay", "radius_cn": "radius-boracay.internal"}'
```

The response's `token` field is shown exactly once — put it straight
into the site's `.env` and discard it. Losing it means rotating
(`POST /api/admin/sites/{id}/rotate-token`), not recovering it.

## Verify

```bash
sudo systemctl start site-agent.service   # run one pass immediately
sudo journalctl -u site-agent.service -n 50
```

A deliberately corrupted renewal (bad CSR, hub down mid-install) must
leave the previous cert/key in place and FreeRADIUS running — that's
the property `_install_with_safety` in `site_agent.py` exists to
guarantee, and it's worth testing on a spare box before trusting it
against a live site.
