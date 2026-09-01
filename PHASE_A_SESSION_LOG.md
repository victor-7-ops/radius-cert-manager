# Phase A — CM4 Cert Manager Deployment Session Log

**Date:** 2026-08-28
**Scope:** First hands-on deployment attempt of the cert manager onto a dedicated CM4 Nano, per `PhaseA-CertManager-Nano-Handoff.md`. Test/dry-run using throwaway PKI, not the real offline root ceremony.

---

## Network layout used

| Host | Address | Notes |
|---|---|---|
| Cert manager Nano | `192.168.200.21` | Doc specified `.20` — that address was already in use by another device on the LAN (MAC `28:00:af:de:a8:1f`, unidentified). Used `.21` instead. |
| RADIUS Nano | `192.168.200.19` | Existing, hostname `raspberrypi`, user `radius-test` |
| Ubuntu CA machine | `192.168.200.18` | User `jed`, holds `~/ca` (existing easy-rsa PKI) |

---

## 1. OS install (Raspberry Pi Imager)

- Device: corrected from default "Raspberry Pi 4" to **Compute Module 4**
- OS: Raspberry Pi OS Lite 64-bit → actually landed on **Debian 13 (Trixie)**
- OS Customisation (gear/dialog after NEXT): hostname `certmanager`, user `admin`, SSH enabled with password auth
- Installed to **eMMC**, not the USB SSD — `lsblk` showed no SSD device at all. Doc's §2.1 SSD requirement (write-endurance) was accepted as skipped since **this is a test box**, not production.

## 2. Networking

- Windows lacks mDNS — `.local` hostnames never resolve there; always used IP directly.
- OS uses **NetworkManager**, not `dhcpcd` (despite `/etc/dhcpcd.conf` file existing as a stale leftover). Static IP set via:
  ```bash
  sudo nmcli connection modify "Wired connection 1" ipv4.addresses 192.168.200.21/24 ipv4.gateway 192.168.200.1 ipv4.dns "192.168.200.1 8.8.8.8" ipv4.method manual
  sudo nmcli connection up "Wired connection 1"
  ```
- Verified static IP survives reboot.
- SSH: `apt install -y git python3-venv python3-pip` needed on fresh OS; git wasn't preinstalled.

**Open issue, unresolved at session end:** cert manager Nano lost all LAN connectivity mid-session (`ARP incomplete` to gateway and to the RADIUS Nano, despite `eth0` showing `LOWER_UP`/`state UP` and zero RX/TX errors). Cable reseat and NetworkManager restart did not fix it. Diagnosed as likely switch-port-level issue; port swap was suggested but not confirmed fixed. Separately discovered the Windows machine itself had drifted onto WiFi (`192.168.13.x`), a different subnet entirely — that alone explained why Windows couldn't reach anything, independent of the Nano's own issue. **Next session: reconnect Windows via ethernet to the same switch, then re-verify the Nano's own link (try a different physical port).**

## 3. Host layout (`/opt/certmanager`)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin certmgr
sudo mkdir -p /opt/certmanager/pki/private /opt/certmanager/pki/issued /opt/certmanager/app
sudo chown -R certmgr:certmgr /opt/certmanager
sudo chmod 700 /opt/certmanager/pki/private
```
Full doc §3 systemd hardening (`ProtectSystem=strict` etc.) **not yet applied** — deferred since this is a test box; app was run manually via `uvicorn`, not as a systemd service.

## 4. App install

- Repo: `https://github.com/victor-7-ops/radius-cert-manager`
- Latest commit at time of deployment had already fixed a real CM4 blocker: `str | None` union syntax breaking under Python <3.10 (fixed with `from __future__ import annotations`). Confirmed CM4's Python 3.13 is fine regardless.
- `demo_launch.py` in repo is Windows-only (hardcoded `C:\cmdemo\...` paths) — not usable on Linux, wrote a manual `.env` instead.
- Dependency install hit a permissions snag: `/opt/certmanager/app` was `certmgr`-owned, `admin` user couldn't write. Fixed by temporarily `chown`-ing to `admin` for setup, then back to `certmgr` before running.

`.env` used (test values):
```
SECRET_KEY=demoDemoDemoDemoDemoDemoDemoDemo12345
PKI_PATH=/opt/certmanager/pki
DB_PATH=/opt/certmanager/certmanager.db
BIND_HOST=0.0.0.0
BIND_PORT=8443
CLIENT_CERT_DAYS=365
CRL_VALIDITY_DAYS=7
CRL_REGEN_HOURS=24
RADIUS_HOST=192.168.200.19
RADIUS_SSH_USER=crlpush
RADIUS_SSH_KEY=/opt/certmanager/pki/private/crlpush_key
```

## 5. Test PKI (throwaway, NOT the real root ceremony)

Generated directly with OpenSSL, single-tier, no passphrase — for boot-testing only:
```bash
openssl genrsa -out private/intermediate.key 4096
openssl req -x509 -new -nodes -key private/intermediate.key -sha256 -days 1825 -out intermediate.crt -subj "/CN=Test-Issuing-CA"
cp intermediate.crt ca-chain.pem
```
Also generated a throwaway server cert for the app's own HTTPS (self-signed by this test intermediate), since the session cookie is `Secure`-flagged and won't set over plain HTTP:
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=192.168.200.21"
openssl x509 -req -in server.csr -CA intermediate.crt -CAkey private/intermediate.key -CAcreateserial -out server.crt -days 365 -sha256
```

## 6. First boot

```bash
sudo -u certmgr bash -c "cd /opt/certmanager/app && source .venv/bin/activate && uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8443 --ssl-keyfile /opt/certmanager/pki/server.key --ssl-certfile /opt/certmanager/pki/server.crt"
```
Must run **as `certmgr`** (owns the DB/PKI paths) — running as `admin` throws `sqlite3.OperationalError: unable to open database file`.

**Finding:** the session cookie in `app/auth.py` is hardcoded `secure=True`. Testing over plain HTTP causes a silent login-redirect-loop (POST succeeds, cookie never sticks, bounces back to `/login` with no error shown) — real HTTPS is mandatory even for local testing, not just production.

Bootstrapped first Super Admin:
```bash
python3 scripts/bootstrap_superadmin.py --username admin
```
(prompts for password interactively, 12+ char minimum). Second Super Admin created via the UI per doc §5.4 (single point of failure otherwise).

**Login confirmed working** — dashboard loads over HTTPS.

## 7. RADIUS transition (§7) — all gates passed on the test PKI

Real file names differ from doc's generic references — RADIUS Nano uses `ca.crt` (not `ca.pem`) as its trust bundle, and `radius-server.crt`/`.key` for its own cert, under `/etc/freeradius/3.0/certs/`.

- **7a** — appended new test chain to `ca.crt` alongside old root, restarted FreeRADIUS.
- **7b** — `eapol_test` with original `test-device-01` → **SUCCESS**, MPPE keys OK: 1, mismatch: 0.
- **7c** — re-issued `radius-server` cert. **Hit a real finding here:** the cert manager app's certificate-issuance flow only sets `Extended Key Usage = TLS Web Client Authentication`. A RADIUS/EAP server certificate needs `serverAuth` too, or `wpa_supplicant`/OpenSSL rejects it with a `TLS 1.2 Alert, fatal unsupported_certificate`. Worked around by signing the server cert manually with OpenSSL against the same intermediate, explicit extensions:
  ```
  basicConstraints=CA:FALSE
  keyUsage=digitalSignature,keyEncipherment
  extendedKeyUsage=serverAuth,clientAuth
  ```
  **This is a product gap worth fixing** if the RADIUS server cert is ever meant to be renewed through the UI rather than manually.
- **7d** — issued `test-device-02` **through the actual app UI** (the real proof-of-concept: cert manager → sign → `.p12` → device auth). `eapol_test` → **SUCCESS**.
- **7e** — removed old root from RADIUS trust bundle entirely, re-tested `test-device-02` → still **SUCCESS**. New chain stands alone.
- **7f/7g** (archive old CA, remove CA from Ubuntu) — **not done**, doesn't apply yet since this was a test PKI, not the real production cutover.

## 8. Tooling notes for next time

- `eapol_test` is not packaged in Debian's `wpasupplicant` — had to build from hostap source:
  ```bash
  sudo apt install -y git build-essential libssl-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev pkg-config
  git clone https://w1.fi/hostap.git
  cd hostap/wpa_supplicant
  cp defconfig .config
  sed -i '/CONFIG_CTRL_IFACE_DBUS/d' .config   # avoids needing libdbus-1-dev
  echo "CONFIG_EAPOL_TEST=y" >> .config
  make eapol_test
  sudo cp eapol_test /usr/local/bin/
  ```
- Original `test-device-01` cert/key lived on the **Ubuntu machine** (`~/ca/pki/issued/test-device-01.crt`, `~/ca/pki/private/test-device-01.key`), not on the RADIUS Nano itself — had to be copied over.
- `.p12` files download to Windows; must `scp` them from a **plain Windows PowerShell window** (not from inside an existing SSH session — Windows paths don't parse in bash).
- When extracting cert/key from a `.p12`: `openssl pkcs12 -in file.p12 -clcerts -nokeys -out cert.crt` and `-nocerts -nodes -out key.pem` (the `-nodes` avoids the doc's warned-about OpenSSL 3.x PKCS8 `bad decrypt` trap with FreeRADIUS).

## 9. What's left

- [ ] **Fix the network/connectivity issue** blocking the cert manager Nano from reaching anything on the LAN (open at session end)
- [ ] Confirm Windows machine back on the correct wired LAN segment
- [ ] Move OS/database to the USB SSD if this box is ever promoted beyond testing (doc §2.1)
- [ ] Apply full systemd hardening (§3) and run as a proper service instead of manual `uvicorn`
- [ ] Real offline root CA ceremony (§4) — passphrase-protected, air-gapped, two custody copies
- [ ] Decide/fix the app's cert-issuance EKU gap for server-type certs (§7c workaround was manual OpenSSL)
- [ ] §9 acceptance tests — especially **revocation** (issue → revoke → confirm CRL push → confirm `eapol_test` now fails), doc flags this as the most commonly skipped, most important test
- [ ] §7f/g, §10 deferred items (rotate `testing123` RADIUS secret, AP over-the-air test, multi-site, spare unit, scheduler) — untouched, for later
