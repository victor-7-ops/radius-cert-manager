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

```bash
sudo useradd --system --home /opt/certmanager-agent --shell /usr/sbin/nologin certmgr-agent
sudo mkdir -p /opt/certmanager-agent /var/lib/certmanager-agent
sudo cp site_agent.py /opt/certmanager-agent/
sudo cp site-agent.env.example /opt/certmanager-agent/.env   # then edit it
sudo chown -R certmgr-agent:certmgr-agent /opt/certmanager-agent /var/lib/certmanager-agent
sudo chmod 600 /opt/certmanager-agent/.env

# The hub's TLS cert is issued by the Arekushi intermediate, which isn't
# in this box's system trust store — copy the hub's ca-chain.pem here and
# point HUB_CA_BUNDLE at it in .env. The agent refuses to start without
# it (fails closed: no fallback to system trust, no fallback to no
# verification — see site_agent.py's _require_ca_bundle).
sudo cp ca-chain.pem /opt/certmanager-agent/ca-chain.pem
sudo chown certmgr-agent:certmgr-agent /opt/certmanager-agent/ca-chain.pem

# certmgr-agent needs write access to the FreeRADIUS cert dir and
# permission to run `freeradius -XC` / `systemctl reload freeradius` —
# grant the minimum via sudoers or a group, don't run this as root.

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
