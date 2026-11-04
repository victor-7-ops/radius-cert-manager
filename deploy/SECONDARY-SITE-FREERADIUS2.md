# Secondary Site: topline-freeradius2 (CM4 failover RADIUS)

Second physical CM4 appliance set up as a failover RADIUS authenticator alongside
`topline-freeradius1` (192.168.13.54). Mirrors the production appliance exactly —
same OS, same FreeRADIUS/rlm_python3 stack, same site-agent install, same
hub-trust chain. Built 2026-11-04.

## Result

| Item | Value |
|---|---|
| Hostname | topline-freeradius2 |
| IP | (DHCP on 192.168.13.0/24 — check `ip a` on box) |
| Hub Site name | `topline-freeradius2` |
| Hub Site UUID | `1ce8376f-b47d-4aad-bd6d-4e81b05ed03a` |
| Subsidiary | Topline (Main Office) |
| OS | Ubuntu Server 24.04.5 LTS (Noble), arm64 |
| FreeRADIUS | 3.2.5+dfsg-3~ubuntu24.04.1 + freeradius-python3 |
| Status | FreeRADIUS running, config OK, site-agent timer active, **not yet wired into AP/switch** |

Also, as a side task during this build: `topline-freeradius1`'s previously-unset
`subsidiary` field was backfilled to `Topline (Main Office)` via a one-off DB
script (no UI route exists to edit an existing site's subsidiary — only at
creation time, see `app/routes/web_sites.py`).

## 1. Flash the CM4 (Windows, no native rpiboot support)

CM4 eMMC-only variant. On Windows there's no native `rpiboot`/`usbboot`, so the
path is: WSL2 Ubuntu + `usbipd-win` (USB/IP passthrough) to forward the CM4's
raw USB boot-ROM device into WSL, then run `rpiboot` natively in Linux to expose
the eMMC as a block device, then flash from Windows (Raspberry Pi Imager) or `dd`
from WSL.

**Hardware prerequisite**: the CM4 board's **EMMC_DISABLE / nRPIBOOT jumper**
must be physically fitted before power-on. Without it, the eMMC enumerates as a
bogus ~722MiB virtual disk and Raspberry Pi Imager fails with a "possible
counterfeit" write error. This is a different jumper than the general boot-mode
switch used elsewhere on the board.

Steps:
1. Fit the EMMC_DISABLE jumper, connect CM4 via USB to the Windows machine, power on.
2. Install `usbipd-win` (download MSI via browser — CLI downloads of GitHub
   release assets were silently truncated to 9 bytes on this network; always
   use the browser instead of `winget`/`curl`/`Invoke-WebRequest` for these).
3. `usbipd list` → find the `BCM2711 Boot` device's busid.
4. If Windows shows `Status: Unknown` (no driver) for `BCM2711 Boot`
   (`Get-PnpDevice`), bind a WinUSB driver with Zadig:
   - Options → "List All Devices" (required, or Zadig shows 0 devices)
   - **The CM4 must be plugged in while Zadig is already running** — devices
     present before Zadig launch are sometimes missed.
   - Select `BCM2711 Boot`, install/confirm WinUSB driver.
5. `usbipd bind --busid <BUSID>` then `usbipd attach --wsl --busid <BUSID>`
   (elevated PowerShell).
6. In WSL2 Ubuntu: `rpiboot -d mass-storage-gadget64`.
   - If it hangs indefinitely at "Waiting for BCM2835/6/7/2711/2712...", the
     USB re-enumeration after stage-1 boot isn't being forwarded reliably
     through the passthrough tunnel. Fix: Ctrl+C, physically unplug/replug the
     CM4, `usbipd detach --busid <BUSID>` then `usbipd attach --wsl --busid
     <BUSID>` again, re-run `rpiboot`.
   - Success looks like "Second stage boot server done." followed by the eMMC
     appearing as `/dev/sda` in WSL (`lsblk`).
7. Flash **Ubuntu Server 24.04 LTS (arm64)** via Raspberry Pi Imager from
   Windows (not Raspberry Pi OS — verified via `cat /etc/os-release` on the
   existing `topline-freeradius1` that production runs Ubuntu Server, not Pi OS,
   despite an earlier incorrect assumption in `HANDOFF-NANO-DEPLOY.md`).
   Apply Imager's "Edit Settings" (hostname, user/password, SSH enabled) before
   writing.
8. `usbipd detach --busid <BUSID>`, remove the EMMC_DISABLE jumper, boot the CM4
   normally.

If SSH password login is rejected after first boot despite correct Imager
customisation, and the box has a local console/HDMI, logging in directly at
the console is the fastest fix — bypasses whatever SSH/cloud-init edge case is
blocking remote password auth.

## 2. Create the Site record on the hub

Via admin UI (`https://192.168.13.73:8443/admin/sites` → New site): name
`topline-freeradius2`, capture the one-time site token shown at creation. This
token goes into the new box's `.env` (`SITE_TOKEN=`) — **copy it character by
character**, don't eyeball it from a screenshot; a transcription slip (e.g.
`1`/`l`/`I` confusion) causes a silent 401 `Invalid site token` later with no
other symptom.

The site's UUID (needed for `CERTMANAGER_SITE_ID`) isn't shown in the UI —
pull it from the DB:

```python
# run inside the certmanager container: docker cp this to /app/, run from there
# (NOT /tmp — Python's sys.path[0] is always the script's own dir, so a script
# at /tmp/x.py can never `import app` even with `docker exec -w /app`)
from app import db
from app.config import load_settings
settings = load_settings()
session = db.make_session_factory(db.make_engine(str(settings.db_path)))()
s = session.query(db.Site).filter_by(name="topline-freeradius2").first()
print(s.id)
```

## 3. Base OS + FreeRADIUS packages

On the new box, matching `topline-freeradius1`'s exact package set:

```bash
sudo apt update && sudo apt install -y freeradius freeradius-python3 python3-venv git
```

`freeradius-python3` is a separate package from base `freeradius` — it provides
`/usr/lib/freeradius/rlm_python3.so`, not installed by default.

## 4. Site-agent install

Followed `deploy/agent/README.md`. Key points specific to this box:

```bash
git clone <repo> /tmp/radius-server
sudo python3 -m venv /opt/certmanager-agent/.venv
sudo /opt/certmanager-agent/.venv/bin/pip install -r /tmp/radius-server/deploy/agent/requirements.txt
sudo cp /tmp/radius-server/deploy/agent/site_agent.py /opt/certmanager-agent/
sudo cp /tmp/radius-server/app/db.py /tmp/radius-server/app/site_policy.py /opt/certmanager-agent/app/
```

### CA trust (the part that actually bit us)

`deploy/agent/README.md` says `HUB_CA_BUNDLE` can be "the hub's `web.crt`".
**That's stale guidance for this hub's current PKI** — the hub's TLS leaf cert
(`/srv/data/certmanager/web.crt`) is issued by an internal "Topline Issuing CA",
not self-signed, so using the leaf cert as the trust anchor fails with
`SSLCertVerificationError: unable to get issuer certificate`.

The correct file is the **CA chain**, not the leaf:

```bash
scp topline-server@192.168.13.73:/srv/data/certmanager/pki/ca-chain.pem ~/ca-chain.pem
sudo mv ~/ca-chain.pem /opt/certmanager-agent/ca-chain.pem
sudo chown certmgr-agent:certmgr-agent /opt/certmanager-agent/ca-chain.pem
```

Also needed, not mentioned prominently in the README — the **policy signing
public key**, required by `app/site_policy.py` signature verification:

```bash
scp topline-server@192.168.13.73:/srv/data/certmanager/policy_signing.pub.pem ~/policy_signing.pub.pem
sudo mv ~/policy_signing.pub.pem /opt/certmanager-agent/policy_signing.pub.pem
sudo chown certmgr-agent:certmgr-agent /opt/certmanager-agent/policy_signing.pub.pem
```

### `.env`

```ini
HUB_URL=https://192.168.13.73:8443
SITE_TOKEN=<token from site creation — verify carefully>
SITE_CN=topline-freeradius2
SITE_ID=1ce8376f-b47d-4aad-bd6d-4e81b05ed03a
HUB_CA_BUNDLE=/opt/certmanager-agent/ca-chain.pem
POLICY_PUBLIC_KEY_FILE=/opt/certmanager-agent/policy_signing.pub.pem
```

```bash
sudo chmod 600 /opt/certmanager-agent/.env
sudo chown certmgr-agent:certmgr-agent /opt/certmanager-agent/.env
```

### Group membership / permissions

```bash
sudo usermod -aG freerad,ssl-cert certmgr-agent
sudo chmod g+w /etc/freeradius/3.0 /etc/freeradius/3.0/certs
```

### polkit rule (lets certmgr-agent restart/reload freeradius without a password)

site-agent calls `systemctl reload/restart freeradius` directly — without this
rule it fails with `Interactive authentication required` (not a sudoers
problem; this hub's reference install uses polkit, not `/etc/sudoers.d`):

```bash
sudo tee /etc/polkit-1/rules.d/50-certmgr-agent-freeradius.rules > /dev/null <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.user == "certmgr-agent" &&
        action.lookup("unit") == "freeradius.service") {
        return polkit.Result.YES;
    }
});
EOF
sudo systemctl restart polkit
```

## 5. FreeRADIUS python3_policy module

Adapter script lives at `/opt/certmanager/deploy/radius/authorize_policy.py`
(package root `/opt/certmanager`, module path `deploy.radius.authorize_policy`
— matches the generic path in `deploy/radius/README.md`; it does exist, just
needs creating fresh on a new box):

```bash
sudo mkdir -p /opt/certmanager/deploy/radius
sudo cp /tmp/radius-server/deploy/radius/authorize_policy.py /opt/certmanager/deploy/radius/
sudo touch /opt/certmanager/deploy/__init__.py /opt/certmanager/deploy/radius/__init__.py
sudo chown -R certmgr-agent:freerad /opt/certmanager
```

`/etc/freeradius/3.0/mods-available/python3_policy` (symlinked into
`mods-enabled/`):

```
python3 python3_policy {
    module = "deploy.radius.authorize_policy"
    python_path = "/opt/certmanager:/etc/freeradius/3.0"

    mod_post_auth = ${.module}
    func_post_auth = "post_auth"
}
```

Hook in `/etc/freeradius/3.0/sites-available/default`, inside the `post-auth {`
block (same spot as production — right after the opening brace):

```
# Call the Python policy adapter after successful EAP-TLS verification
python3_policy
```

Systemd env vars for the FreeRADIUS service itself (this site's own UUID, not
freeradius1's):

```bash
sudo mkdir -p /etc/systemd/system/freeradius.service.d
sudo tee /etc/systemd/system/freeradius.service.d/override.conf > /dev/null <<'EOF'
[Service]
Environment=CERTMANAGER_SITE_ID=1ce8376f-b47d-4aad-bd6d-4e81b05ed03a
Environment=CERTMANAGER_POLICY_FILE=/etc/freeradius/3.0/policy.json
EOF
sudo systemctl daemon-reload
```

Validate: `sudo freeradius -XC` → "Configuration appears to be OK".

## 6. systemd units, first run

```bash
sudo cp /tmp/radius-server/deploy/agent/site-agent.service /tmp/radius-server/deploy/agent/site-agent.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now site-agent.timer
sudo systemctl start site-agent.service
sudo journalctl -u site-agent.service -n 50 --no-pager
```

Expect: `crl: installed and verified`, `network-policy: installed and
verified`, `radius-adapter: installed and verified`, then `Deactivated
successfully.`

## Outcome

- `freeradius.service`: active, "Processing requests", config OK
- `site-agent.timer`: active, recurring check-in/CRL/policy/cert-renewal cycle
- Not yet done: wiring this box into the AP/switch as a secondary RADIUS
  server IP — blocked on networking hardware (gateway → core switch → AP) not
  yet in place, consistent with `deploy/STAGING-READINESS.md` blocker #5b/#9.
  Once hardware is up, point the AP/switch at this box's IP as the secondary
  RADIUS authenticator and verify with `eapol_test` or a real device auth.

## Troubleshooting notes (SSH to the hub, Windows client)

Unrelated to this build specifically but hit hard during it — SSH/SCP to
`topline-server` (192.168.13.73) from a Windows laptop became extremely
unreliable (hangs, silent empty-output "successes"). Three independent causes,
all on the Windows client side plus one server-side:

1. **Tailscale's advertised route for `192.168.13.0/24` (metric 5) outranked
   the laptop's own direct on-link LAN route (metric 291)** even while
   physically on that LAN, routing SSH through the tunnel unnecessarily.
   Fix (elevated PowerShell): `route delete 192.168.13.0 mask 255.255.255.0
   100.100.100.100`.
2. **Stray/orphaned `ssh.exe` processes** accumulate on Windows from every
   timed-out/backgrounded SSH attempt — background-task cancellation in this
   environment only detaches tracking, it doesn't kill the real process.
   Fix (elevated): `Get-Process ssh | Stop-Process -Force`.
3. **Server-side `sshd` auth backlog** from too many overlapping rapid retries
   exhausting `MaxStartups`/`LoginGraceTime` — handshake stalls right after the
   pubkey offer with no server reply (visible via `ssh -vvv`). Fix: back off
   for a few minutes, or restart `sshd`/reboot the hub.

If SSH to the hub is flaky, check these three before assuming anything is
wrong with the hub's RADIUS/certmanager stack itself.
