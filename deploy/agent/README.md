# Site agent

Runs on each site's FreeRADIUS box (never on the hub). One script,
`site_agent.py`, standard library + `requests`, invoked once per pass by
a systemd timer — not a daemon. Every pass: check in, pull a newer CRL
if the hub reports one, renew the server cert if the hub says it's due.

Install is safe by construction (HANDOFF-FLEET.md §3.4): stage the new
file(s) → `freeradius -XC` → only on success install and reload → verify
`freeradius` is active → on any failure, restore what was there before,
reload again, and let it show up in the next check-in as
`freeradius_ok=False` (the fleet view already treats that as CRITICAL).

## Install

```bash
sudo useradd --system --home /opt/certmanager-agent --shell /usr/sbin/nologin certmgr-agent
sudo mkdir -p /opt/certmanager-agent /var/lib/certmanager-agent
sudo cp site_agent.py /opt/certmanager-agent/
sudo cp site-agent.env.example /opt/certmanager-agent/.env   # then edit it
sudo chown -R certmgr-agent:certmgr-agent /opt/certmanager-agent /var/lib/certmanager-agent
sudo chmod 600 /opt/certmanager-agent/.env

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
