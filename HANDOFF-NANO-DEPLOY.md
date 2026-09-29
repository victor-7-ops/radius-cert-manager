# Handoff: deploying the cert manager onto a freshly reset CM4 Nano

**Audience:** whoever executes this — Victor at a keyboard, or an agent with shell access.
**Purpose:** take a blank CM4 Nano to a running cert manager on the office LAN, then use it to run
the one test nothing in this project has ever done: **the site agent against a real FreeRADIUS box.**

**Read this first — what this deployment is and is not.**

- This is the **rehearsal rig**, not production. Production target remains an EC2 instance in the VPC
  the AWS VPN terminates into (see `PROJECT-BRIEF-CertManager.md` §2.0). Every step here is the same
  procedure you will repeat there, which is the point of doing it.
- **Use a throwaway PKI.** Do NOT perform the real offline root ceremony yet. That is the one step
  that cannot be redone, and the deployment target should be settled before it happens.
- Success is not "the web UI loads." Success is **§9** — the agent pulling a CRL and rolling back a
  bad certificate against real FreeRADIUS.

---

## 1. Hardware and OS

- EDATEC CM4 Nano, 12V barrel jack (the Pi PoE+ HAT does not fit this carrier board).
- **USB SSD strongly preferred.** The app writes constantly — SQLite, audit log, sessions, logs — and
  the 8GB eMMC is soldered. If you have an SSD, either boot from it or at minimum put
  `/opt/certmanager` on it. If you only have eMMC, proceed but treat this box as disposable and
  expect to reflash it.
- Raspberry Pi OS Lite **64-bit (Bookworm)** via `rpiboot` (mass-storage-gadget64) + Raspberry Pi
  Imager — same procedure already used for `radius-test`.
- Hostname `certmanager`. SSH enabled. Bookworm ships Python 3.11; the app needs 3.10+, so this is fine.

**Gate:** you can SSH in, and `python3 --version` reports 3.11 or newer.

## 2. Static address — do this before anything else

Give it `192.168.200.20`, static or a DHCP reservation. Every later step and every document assumes it.

```bash
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.200.20/24 \
  ipv4.gateway 192.168.200.1 ipv4.dns 192.168.200.1 ipv4.method manual
sudo reboot
```

**Gate:** after the reboot, `.20` answers, and it can reach `192.168.200.19` and `.18`.

## 3. Packages, user, layout

```bash
sudo apt update && sudo apt install -y python3-venv python3-pip git openssl
sudo useradd --system --home /opt/certmanager --shell /usr/sbin/nologin certmgr
sudo mkdir -p /opt/certmanager/pki/private /opt/certmanager/pki/issued
sudo chown -R certmgr:certmgr /opt/certmanager
sudo chmod 700 /opt/certmanager/pki/private
```

If using an SSD, mount it at `/opt/certmanager` **before** creating these directories.

## 4. Code

```bash
cd /opt/certmanager
sudo -u certmgr git clone https://github.com/victor-7-ops/radius-cert-manager.git .
sudo -u certmgr python3 -m venv /opt/certmanager/.venv
sudo -u certmgr /opt/certmanager/.venv/bin/pip install -r requirements.txt
```

**Clone directly into `/opt/certmanager`, not into an `app` subdirectory.** Every systemd unit in
`deploy/` (`certmanager.service`, `retention.service`, `fleet_watch.service`) sets
`WorkingDirectory=/opt/certmanager` and runs a relative path like `scripts/serve.py` — that only
resolves if the repo root (containing `app/`, `scripts/`, `deploy/`) sits directly at
`/opt/certmanager`, not one level down. An `app`-subdirectory clone (as an earlier version of this
doc had it) makes every unit fail to start.

The repo is private — you will need a token or a deploy key. Alternatively `scp` a clone across from
the Windows machine.

## 5. Throwaway two-tier PKI

Mirrors `deploy/RUNBOOK.md` §2, but explicitly disposable. A passphrase on this root is optional
precisely because it is **not** the real root — label the directory so nobody mistakes it later.

```bash
cd /opt/certmanager/pki
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/throwaway-root.key
openssl req -x509 -new -key /tmp/throwaway-root.key -sha256 -days 3650 \
  -subj "/CN=THROWAWAY Arekushi Root CA" -out root.crt

openssl ecparam -name prime256v1 -genkey -noout -out private/intermediate.key
openssl req -new -key private/intermediate.key -subj "/CN=THROWAWAY Arekushi Issuing CA" -out /tmp/int.csr
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n" > /tmp/int.ext
openssl x509 -req -in /tmp/int.csr -CA root.crt -CAkey /tmp/throwaway-root.key -CAcreateserial \
  -days 1825 -sha256 -extfile /tmp/int.ext -out intermediate.crt

cat root.crt intermediate.crt > ca-chain.pem
chmod 600 private/intermediate.key
chown -R certmgr:certmgr /opt/certmanager/pki
```

**Gate:** `openssl verify -CAfile root.crt intermediate.crt` returns OK, and
`grep -r PRIVATE /opt/certmanager/pki/*.pem` finds nothing (only `private/` holds a key).

Move `/tmp/throwaway-root.key` off the box or delete it — rehearse the habit even with a fake root.

## 6. TLS for the web app — **fixed, no longer a manual step**

~~`deploy/certmanager.service` starts uvicorn with no `--ssl-certfile`~~ — as of
`deploy/RUNBOOK.md` §6.1, `certmanager.service` runs `scripts/serve.py`, which picks up
`WEB_SSL_KEYFILE`/`WEB_SSL_CERTFILE` from `.env` when set (`app/config.py`). The underlying
problem is unchanged and still applies here: the session cookie is flagged `Secure`, which
browsers accept over `http://localhost` but **not** over `http://192.168.200.20` — you will
log in and be bounced straight back to the login page with no error explaining why. Do not
work around it by removing the `Secure` flag.

Issue the box a server certificate from the throwaway intermediate:

```bash
cd /opt/certmanager/pki
openssl ecparam -name prime256v1 -genkey -noout -out private/web.key
openssl req -new -key private/web.key -subj "/CN=certmanager" -out /tmp/web.csr
printf "subjectAltName=DNS:certmanager,IP:192.168.200.20\nextendedKeyUsage=serverAuth\n" > /tmp/web.ext
openssl x509 -req -in /tmp/web.csr -CA intermediate.crt -CAkey private/intermediate.key \
  -CAcreateserial -days 825 -sha256 -extfile /tmp/web.ext -out web.crt
chmod 600 private/web.key && chown certmgr:certmgr private/web.key web.crt
```

Then in `.env`:

```
WEB_SSL_KEYFILE=/opt/certmanager/pki/private/web.key
WEB_SSL_CERTFILE=/opt/certmanager/pki/web.crt
```

No `ExecStart` edit needed — restart the service and it picks these up.

Install `ca-chain.pem` in the trusted roots of whatever machine you browse from, so you get a clean
padlock rather than a warning you learn to click through.

## 7. Configuration

`/opt/certmanager/.env`, mode `600`, owned by `certmgr`:

```
SECRET_KEY=<32+ random chars — openssl rand -base64 48>
PKI_PATH=/opt/certmanager/pki
DB_PATH=/opt/certmanager/certmanager.db
BIND_HOST=192.168.200.20
BIND_PORT=8443
CLIENT_CERT_DAYS=365
CRL_VALIDITY_DAYS=7
CRL_REGEN_HOURS=24
RADIUS_HOST=192.168.200.19
RADIUS_SSH_USER=crlpush
RADIUS_SSH_KEY=/opt/certmanager/crlpush_id_ed25519
ALERT_WEBHOOK_URL=
EXPIRY_ALERT_DAYS=7
INITIAL_SUPERADMIN_USER=
```

`BIND_HOST` is `.20`, never `0.0.0.0`. `config.py` fails fast on anything missing or malformed, so a
bad env surfaces immediately rather than at first use.

## 8. Service

```bash
sudo cp /opt/certmanager/deploy/certmanager.service /etc/systemd/system/
# set WEB_SSL_KEYFILE/WEB_SSL_CERTFILE in .env per §6, if needed — no ExecStart edit
sudo systemctl daemon-reload && sudo systemctl enable --now certmanager
systemd-analyze security certmanager.service
```

Bootstrap the first admin, then **create a second Super Admin immediately** — revoke is
Super-Admin-only, and one person unavailable must not mean nobody can kill a stolen device's access.

```bash
sudo -u certmgr /opt/certmanager/.venv/bin/python /opt/certmanager/scripts/bootstrap_superadmin.py
```

**Gates:** the service runs as `certmgr`; `https://192.168.200.20:8443` loads from another machine on
the LAN with no certificate warning once `ca-chain.pem` is trusted; both Super Admins can log in; a
regular Admin calling a super-admin API endpoint directly gets 403.

## 9. The actual point — exercise the agent against real FreeRADIUS

Everything above is setup. This is the part no test has ever covered: `_install_with_safety()` has
only ever run with every subprocess mocked.

1. Create a site in the cert manager for `radius-test` (`POST /api/admin/sites`, Super Admin) and
   capture the token — it is shown once.
2. Install the agent on `192.168.200.19` per `deploy/agent/README.md`, with
   `HUB_URL=https://192.168.200.20:8443` and that token.
3. ~~You will hit the CA-bundle bug immediately~~ — **fixed.** `site_agent.py` now requires
   `HUB_CA_BUNDLE` and fails closed (refuses to start) if it's unset or the file doesn't exist —
   see `deploy/agent/site-agent.env.example`. Point it at `ca-chain.pem` from this rig's throwaway
   intermediate. Do **not** set `verify=False`; that hands anyone on the LAN the CRL feed and the
   CSR exchange.
4. Run the agent once by hand. Confirm: it checks in, the site's `last_seen_at` updates, and the CRL
   pull returns 200 the first time and 304 the second.
5. **Revocation, end to end:** issue a cert through the UI, validate it with `eapol_test`, revoke it,
   run the agent, then re-run `eapol_test` — **it must now FAIL.** Issuance-only testing verifies half
   a system.
6. **Rollback, deliberately:** hand the agent a corrupt server certificate and confirm
   `freeradius -XC` rejects it, the previous cert and key are restored, FreeRADIUS comes back, and the
   failure is reported at the next check-in. This is the single most valuable test in this document.
7. Confirm the site appears in the fleet view, then stop the agent and confirm it turns `SILENT`
   within three intervals and alerts exactly once.

## 10. Report back

Record, in `PROJECT-BRIEF-CertManager.md`:

- which of §9's steps passed on real hardware, with the actual `eapol_test` output;
- every place a document or script was wrong (§6's missing TLS and §9.3's CA bundle are two known
  ones — expect more);
- whether the DB ended up on eMMC or SSD.

## 11. Do not do

- The real offline root ceremony. Throwaway PKI only until the production target is settled.
- Removing the `Secure` cookie flag to work around §6.
- `verify=False` anywhere.
- Deleting `test-device-01`, the current `radius-server` cert, or `crl_push.py`. They are the safety net.
- Pointing this box at anything outside the lab LAN.
