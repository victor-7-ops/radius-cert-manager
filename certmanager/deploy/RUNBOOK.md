# Phase A runbook — static IPs, PKI restructure, host hardening

Everything in this document runs on your real hosts (192.168.200.18 and
192.168.200.19). Nothing here can be run from this environment — it has
no network path to either machine. Follow it in order; each step has a
checkpoint before the next one.

**Do not delete anything under the old `~/ca` layout until step 7 says so.**

---

## 0. Prerequisites

- SSH access to both `192.168.200.18` (CA/admin machine) and
  `192.168.200.19` (`radius-test` user, the CM4).
- The `certmanager/` repo checked out on `192.168.200.18`, with the venv
  built (`README.md` → Setup).
- `eapol_test` available somewhere you can run it against the CM4 —
  this is the only real verification that any of this worked.

## 1. Static IPs (handoff §2)

Both hosts are documented as DHCP-with-reservation-risk. Convert both to
static addresses (or a DHCP reservation with a long lease) before
touching anything else — a changed IP silently breaks the backend bind
address, `clients.conf`, and the CRL push path, and you won't notice
until something fails later for an unrelated-looking reason.

- `192.168.200.18` → static
- `192.168.200.19` → static

Checkpoint: `ping` both from a third machine after a reboot.

## 2. Build the new PKI (handoff §3, steps 1–4)

On `192.168.200.18`, inside the repo:

```bash
cd certmanager
.venv/Scripts/python -m scripts.restructure_pki \
    --out-root /media/<your-removable-drive>/ca-root \
    --out-service /opt/certmanager/pki
```

This builds the offline root CA (prompts for a passphrase — 16+ chars,
write it down somewhere durable, it protects a key you'll touch maybe
once a year), the online intermediate, the `ca-chain.pem`, and a
freshly reissued `radius-server` cert/key under the intermediate.

**Immediately move `root.key.pem` off this host onto the removable
media path you pointed `--out-root` at, if it isn't already there, and
verify it's not staying behind on the CA machine's disk.**

Checkpoint: `openssl verify -CAfile <root.crt.pem> <intermediate.crt>`
should say `OK`.

## 3. Deploy the chain and server cert to the CM4

```bash
scp /opt/certmanager/pki/ca-chain.pem radius-test@192.168.200.19:/tmp/
scp /opt/certmanager/pki/issued/radius-server.crt radius-test@192.168.200.19:/tmp/
scp /opt/certmanager/pki/radius-server.key.pem radius-test@192.168.200.19:/tmp/
```

On the CM4:

```bash
sudo cp /tmp/ca-chain.pem /etc/freeradius/3.0/certs/ca.pem
sudo cp /tmp/radius-server.crt /etc/freeradius/3.0/certs/server.pem
sudo cp /tmp/radius-server.key.pem /etc/freeradius/3.0/certs/server.key
sudo chown freerad:freerad /etc/freeradius/3.0/certs/{ca.pem,server.pem,server.key}
sudo chmod 640 /etc/freeradius/3.0/certs/server.key
rm /tmp/ca-chain.pem /tmp/radius-server.crt /tmp/radius-server.key.pem
```

Update `/etc/freeradius/3.0/mods-available/eap` (or wherever `tls-config
tls-common` lives) to point `ca_file`, `certificate_file`, and
`private_key_file` at the new files if the names changed.

**Do not restart FreeRADIUS yet.** First, add the OLD root CA to the
trust bundle alongside the new chain, per §3 step 5a below — the order
in the next section matters and getting it wrong locks you out of your
own test rig.

## 4. Transition `test-device-01` — exact order (handoff §3 step 5)

**a.** Put BOTH the old root cert and the new `ca.pem` chain in the
CM4's trust bundle (concatenate them, or use a hashed `ca_path` if
that's how the config is set up — whichever the current config expects).

**b.** Restart FreeRADIUS:

```bash
sudo systemctl restart freeradius
```

Run `eapol_test` against `test-device-01` (the OLD cert, still signed by
the old root):

```bash
eapol_test -c test-device-01.conf -s testing123
```

**It must still say `SUCCESS`.** If it doesn't, stop here and fix the
trust bundle before continuing — do not proceed to step c.

**c.** Issue `test-device-01-v2` under the new intermediate. You don't
have the web UI running yet at this point in the sequence, so use the
CLI path — either bring up the app against `/opt/certmanager` now (see
step 6) and issue through the UI, or use `pki.py` directly in a throwaway
script. Validate the new `.p12` with `eapol_test`:

```bash
eapol_test -c test-device-01-v2.conf -s testing123
```

Must say `SUCCESS`.

**d.** Only once (c) passes: remove the OLD root cert from the trust
bundle, restart FreeRADIUS, and re-run `eapol_test` against
`test-device-01-v2`. Must still say `SUCCESS`.

**e.** Archive the old CA material (the old `~/ca` directory) offline.
Do not delete it — archive means moved somewhere safe, not gone. Only
delete it after the new chain has been running cleanly for at least a
week (handoff §3).

Checkpoint (this is the Phase A gate from handoff §0.5): `eapol_test`
returns `SUCCESS` for the transitioned test device.

## 5. Also re-issue `radius-server` itself under the intermediate

Already done in step 2/3 above (`restructure_pki.py` reissues it as
part of the same run) — just confirm `eapol_test` against
`test-device-01-v2` above also exercised the new server cert, which it
did if you deployed step 3 before running step 4's tests.

## 6. Host layout, service user, systemd (handoff §4)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin certmgr
sudo mkdir -p /opt/certmanager
sudo chown -R certmgr:certmgr /opt/certmanager
sudo chmod 700 /opt/certmanager/pki/private
sudo chmod 600 /opt/certmanager/pki/private/intermediate.key
```

Copy the repo to `/opt/certmanager` (or clone directly there), build the
venv as `certmgr`, and write `/opt/certmanager/.env` from `.env.example`
with real values.

```bash
sudo cp deploy/certmanager.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certmanager
```

Also disable `systemd-coredump` for this service and confirm the host
has no swap, or encrypted swap only — the intermediate key is in process
memory during every signing operation (handoff §4):

```bash
# no swap:
sudo swapoff -a && sudo sed -i '/swap/d' /etc/fstab
# or, if swap must stay, make sure it's LUKS-encrypted swap, not plain.
```

## 7. CRL push credential (handoff §8.4)

```bash
# on the CM4:
sudo useradd --system --no-create-home --shell /usr/sbin/nologin crlpush
sudo mkdir -p ~crlpush/.ssh
```

Copy `deploy/crlpush_forced_command.sh` to `/usr/local/bin/` on the CM4,
`chmod 755`, owned by root (not `crlpush` — the forced-command script
itself should not be writable by the account it constrains).

Generate the key pair on the service host and install the public half
per `deploy/authorized_keys.crlpush.example`:

```bash
ssh-keygen -t ed25519 -f /opt/certmanager/crlpush_id_ed25519 -N "" -C "certmanager-crlpush"
```

Grant `crlpush` write access to `/etc/freeradius/3.0/certs/` only (not
read access to `server.key`):

```bash
sudo setfacl -m u:crlpush:rwx /etc/freeradius/3.0/certs
```

Point `RADIUS_SSH_KEY` in `.env` at
`/opt/certmanager/crlpush_id_ed25519` and `RADIUS_SSH_USER=crlpush`.

Checkpoint: from the service host,
`ssh -i /opt/certmanager/crlpush_id_ed25519 crlpush@192.168.200.19` should
run the forced command (not a shell), and `python -m
scripts.regenerate_crl_cron` should succeed and update
`/api/health/crl`.

## 8. Wire the CRL regen cron/timer (handoff §8.3)

```bash
sudo tee /etc/systemd/system/certmanager-crl.timer <<'EOF'
[Unit]
Description=Regenerate and push the certmanager CRL

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

sudo tee /etc/systemd/system/certmanager-crl.service <<'EOF'
[Unit]
Description=certmanager CRL regeneration

[Service]
Type=oneshot
User=certmgr
WorkingDirectory=/opt/certmanager
EnvironmentFile=/opt/certmanager/.env
ExecStart=/opt/certmanager/.venv/bin/python -m scripts.regenerate_crl_cron
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now certmanager-crl.timer
```

`CRL_REGEN_HOURS` in `.env` should stay comfortably shorter than
`CRL_VALIDITY_DAYS` (defaults: daily regen, 7-day validity).

## 9. Final Phase A gate

Both of these must hold before Phase B–I code (already built and
tested against a throwaway PKI) touches the real system:

- [ ] `eapol_test` → `SUCCESS` for `test-device-01-v2` (transitioned)
- [ ] `radius-server` and the original `test-device-01` are otherwise
      untouched and still authenticate through their respective paths
      during the overlap window

Once both hold, the app is safe to point at `/opt/certmanager/pki` and
`/opt/certmanager/certmanager.db` for real. Bootstrap the first Super
Admin (`README.md`) and do the full `§10` walkthrough — including the
two `eapol_test` checks (issue `test-device-02` through the app itself,
then revoke it and confirm auth now fails) — before calling this done.
