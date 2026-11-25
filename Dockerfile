FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# eapol_test (handoff task O2, synthetic auth canary) -- not packaged by
# Debian; built from the same hostapd/wpa_supplicant source tree that
# ships it, same way everyone else gets this binary. Build deps are
# purged afterward so they don't sit in the final image. NOT YET BUILT OR
# RUN ON THE LIVE HUB -- verify with `docker exec certmanager eapol_test`
# after the next rebuild, before relying on the canary timer.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libnl-3-dev libnl-genl-3-dev pkg-config wget ca-certificates \
    && wget -q https://w1.fi/releases/wpa_supplicant-2.10.tar.gz -O /tmp/wpa_supplicant.tar.gz \
    && tar -xzf /tmp/wpa_supplicant.tar.gz -C /tmp \
    && cd /tmp/wpa_supplicant-2.10/wpa_supplicant \
    && cp defconfig .config \
    && sed -i '/CONFIG_CTRL_IFACE_DBUS/d' .config \
    && echo "CONFIG_EAP_TLS=y" >> .config \
    && make eapol_test \
    && cp eapol_test /usr/local/bin/eapol_test \
    && cd / && rm -rf /tmp/wpa_supplicant.tar.gz /tmp/wpa_supplicant-2.10 \
    && apt-get purge -y build-essential wget && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --system --home /app --shell /usr/sbin/nologin certmgr
USER certmgr

EXPOSE 8443

CMD ["python", "scripts/serve.py"]
