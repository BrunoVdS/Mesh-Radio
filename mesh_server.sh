#!/usr/bin/env bash
# Option B + One-time Captive Portal + Pretty URL for Raspberry Pi OS (Bookworm)
# AP on wlan0, DHCP/DNS via dnsmasq, APK hosting via nginx,
# first-HTTP redirect via nftables with whitelist release,
# friendly URL via dnsmasq host mapping (e.g., apkspot.local)

set -euo pipefail

############################
# --- CONFIG VARIABLES --- #
############################
SSID="APK-Spot"
WPA_PASSPHRASE="change-me-1234"

WLAN_IF="wlan0"
AP_IP="10.0.0.1"
CIDR="/24"

# DHCP pool
DHCP_RANGE_START="10.0.0.50"
DHCP_RANGE_END="10.0.0.150"
DHCP_LEASE="12h"

# Wi-Fi channel
CHANNEL="6"

# Whitelist timeout
WHITELIST_TIMEOUT="8h"

# APK directory
APK_DIR="/srv/apks"

# ******** Pretty URL ********
PORTAL_HOST="apkspot.local"   # <-- verander dit als je wilt
EXTRA_HOSTS=("www.apkspot.local")  # extra namen die ook naar de portal wijzen

#################################
# sanity checks & prerequisites #
#################################
if [[ $EUID -ne 0 ]]; then
  echo "Run me as root. Ja, echt. sudo ./setup_apk_portal.sh"
  exit 1
fi

command -v rfkill >/dev/null 2>&1 && rfkill unblock wifi || true

echo "[1/12] Installing packages… (hostapd, dnsmasq, nginx, nftables, python3-flask, jq, imagemagick)"
apt-get update -y
apt-get install -y hostapd dnsmasq nginx nftables python3-flask jq imagemagick || apt-get install -y hostapd dnsmasq nginx nftables python3-flask jq

#############################################
# Make NetworkManager ignore wlan0 (if any) #
#############################################
echo "[2/12] Making NetworkManager ignore ${WLAN_IF} (if present)…"
mkdir -p /etc/NetworkManager/conf.d
cat >/etc/NetworkManager/conf.d/unmanaged-${WLAN_IF}.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${WLAN_IF}
EOF
systemctl restart NetworkManager 2>/dev/null || true

#############################################
# Static IP for wlan0 via dhcpcd (Bookworm) #
#############################################
echo "[3/12] Configuring static IP ${AP_IP}${CIDR} on ${WLAN_IF} via dhcpcd…"
sed -i '/^# BEGIN APK-PORTAL/,/^# END APK-PORTAL/d' /etc/dhcpcd.conf || true
cat >>/etc/dhcpcd.conf <<EOF
# BEGIN APK-PORTAL
interface ${WLAN_IF}
static ip_address=${AP_IP}${CIDR}
nohook wpa_supplicant
# END APK-PORTAL
EOF
systemctl restart dhcpcd
ip addr flush dev "${WLAN_IF}" || true
ip addr add "${AP_IP}${CIDR}" dev "${WLAN_IF}" || true
ip link set "${WLAN_IF}" up || true

#################
# hostapd (AP)  #
#################
echo "[4/12] Configuring hostapd…"
cat >/etc/hostapd/hostapd.conf <<EOF
interface=${WLAN_IF}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=${CHANNEL}
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=${WPA_PASSPHRASE}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
systemctl enable --now hostapd

#################
# dnsmasq (DHCP/DNS with pretty URL)
#################
echo "[5/12] Configuring dnsmasq (DHCP/DNS + ${PORTAL_HOST})…"
if [[ -f /etc/dnsmasq.conf ]]; then
  mv /etc/dnsmasq.conf /etc/dnsmasq.conf.backup.$(date +%s)
fi

cat >/etc/dnsmasq.conf <<EOF
interface=${WLAN_IF}
bind-interfaces

# DHCP pool
dhcp-range=${DHCP_RANGE_START},${DHCP_RANGE_END},${DHCP_LEASE}
dhcp-option=3,${AP_IP}
dhcp-option=6,${AP_IP}

# Local domain hint (pure cosmetica)
domain=lan

# Map friendly hostnames to the portal IP
address=/${PORTAL_HOST}/${AP_IP}
EOF
# extra hostnames
for H in "${EXTRA_HOSTS[@]}"; do
  echo "address=/${H}/${AP_IP}" >> /etc/dnsmasq.conf
done

# Avoid port 53 conflicts with systemd-resolved
systemctl disable --now systemd-resolved 2>/dev/null || true
systemctl enable --now dnsmasq

#############################
# nftables (one-time redirect)
#############################
echo "[6/12] Configuring nftables one-time HTTP redirect…"
cat >/etc/nftables.conf <<EOF
flush ruleset

define PORTAL_IP = ${AP_IP}

table ip nat {
  set whitelist {
    type ipv4_addr
    flags timeout
    timeout ${WHITELIST_TIMEOUT}
  }

  chain prerouting {
    type nat hook prerouting priority -100;

    # traffic destined to portal itself -> leave it
    ip daddr \$PORTAL_IP return

    # already whitelisted source -> leave it
    ip saddr @whitelist return

    # only capture HTTP (80); HTTPS stays private
    tcp dport 80 dnat to \$PORTAL_IP:80
  }

  chain postrouting {
    type nat hook postrouting priority 100;
    # uncomment if you share internet via eth0:
    # oifname "eth0" masquerade
  }
}
EOF
systemctl enable --now nftables

#########################################
# tiny Flask API to "free" client IPs   #
#########################################
echo "[7/12] Installing tiny whitelist API…"
cat >/opt/captive_free.py <<'PY'
from flask import Flask, request, jsonify
import subprocess, ipaddress, os

app = Flask(__name__)

SET_NAME = "whitelist"
TABLE_FAMILY = "ip"
TABLE_NAME = "nat"
TIMEOUT = os.environ.get("WHITELIST_TIMEOUT", "8h")

def add_to_whitelist(ip):
    ipaddress.IPv4Address(ip)  # sanity
    cmd = ["nft", "add", "element", TABLE_FAMILY, TABLE_NAME, SET_NAME, f"{{ {ip} timeout {TIMEOUT} }}"]
    subprocess.run(cmd, check=True)

@app.get("/free")
def free():
    ip = request.headers.get("X-Real-IP") or request.remote_addr
    try:
        add_to_whitelist(ip)
        return jsonify({"ok": True, "ip": ip})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
PY

cat >/etc/systemd/system/captive-free.service <<EOF
[Unit]
Description=Captive Portal Whitelist API
After=network-online.target
Wants=network-online.target

[Service]
Environment=WHITELIST_TIMEOUT=${WHITELIST_TIMEOUT}
ExecStart=/usr/bin/python3 /opt/captive_free.py
Restart=always
User=www-data
Group=www-data
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now captive-free.service

#################
# nginx (portal)
#################
echo "[8/12] Configuring nginx site…"
mkdir -p "${APK_DIR}/icons"

# PWA manifest
cat >"${APK_DIR}/manifest.webmanifest" <<'JSON'
{
  "name": "APK Downloads",
  "short_name": "APK Spot",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#ffffff",
  "icons": [
    { "src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
JSON

# Basic icons (vervang met iets minder lelijk als je tijd hebt)
convert -size 192x192 xc:white "${APK_DIR}/icons/icon-192.png" 2>/dev/null || true
convert -size 512x512 xc:white "${APK_DIR}/icons/icon-512.png" 2>/dev/null || true

# Portal index
cat >"${APK_DIR}/index.html" <<'HTML'
<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="manifest" href="/manifest.webmanifest">
<title>Local APK Downloads</title>
<style>
body{font-family:system-ui,Arial;max-width:720px;margin:40px auto;padding:0 16px}
a{display:inline-block;margin:6px 0}
.btn{display:inline-block;padding:10px 14px;border:1px solid #ddd;border-radius:8px;text-decoration:none}
.note{background:#fff3cd;border:1px solid #ffeeba;padding:10px;border-radius:8px}
#list a{display:block;margin:8px 0}
</style>
</head><body>
<h1>Local APK Downloads</h1>

<p class="note">
<strong>Bookmark?</strong> Open het browsermenu en kies <em>Toevoegen aan bladwijzers</em> of <em>Toevoegen aan startscherm</em>.
Zie je een “Installeren/Add to Home screen” prompt? Klik die. Magie zonder toestemming bestaat niet, helaas.
</p>

<div id="list"></div>

<p><a id="continue" class="btn" href="#">Verder naar internet</a></p>

<script>
async function loadList(){
  try{
    const r = await fetch('./_list.json', {cache:'no-store'});
    const files = await r.json();
    document.getElementById('list').innerHTML =
      files.map(f=>`<a href="${f}">${f}</a>`).join('') || '<em>Geen APKs gevonden.</em>';
  }catch(e){
    document.getElementById('list').textContent = 'Kan lijst niet laden.';
  }
}
loadList();

let deferredPrompt;
window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  deferredPrompt = e;
  const installBtn = document.createElement('a');
  installBtn.textContent = 'Installeren (Add to Home screen)';
  installBtn.href = '#';
  installBtn.className = 'btn';
  installBtn.onclick = async (ev) => {
    ev.preventDefault();
    if(deferredPrompt){
      deferredPrompt.prompt();
      await deferredPrompt.userChoice;
      deferredPrompt = null;
    }
  };
  document.body.insertBefore(installBtn, document.getElementById('list'));
});

document.getElementById('continue').addEventListener('click', async (e)=>{
  e.preventDefault();
  try{ await fetch('/free', {cache:'no-store'}); }catch(e){}
  const fallback = 'http://' + (location.host || 'apkspot.local') + '/';
  location.href = document.referrer && !document.referrer.startsWith(location.origin) ? document.referrer : fallback;
});
</script>
</body></html>
HTML

# APK list generator
cat >/usr/local/bin/mk-apk-list <<'SH'
#!/usr/bin/env bash
set -e
cd /srv/apks || exit 1
ls -1 *.apk 2>/dev/null | jq -R -s 'split("\n") | map(select(length>0))' > _list.json
SH
chmod +x /usr/local/bin/mk-apk-list
mkdir -p "${APK_DIR}"
/usr/local/bin/mk-apk-list || true
chown -R www-data:www-data "${APK_DIR}"

# nginx site
cat >/etc/nginx/sites-available/apks <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /srv/apks;
    index index.html;

    types {
        application/vnd.android.package-archive apk;
    }

    # Static + portal
    location / {
        try_files $uri $uri/ /index.html;
    }

    location = /_list.json {
        try_files $uri =404;
        add_header Cache-Control "no-store";
    }

    # Whitelist API
    location /free {
        proxy_pass http://127.0.0.1:5000/free;
        proxy_set_header X-Real-IP $remote_addr;
        add_header Cache-Control "no-store";
    }
}
NGINX

ln -sf /etc/nginx/sites-available/apks /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

##################################
# Bring it all up (again, neatly)
##################################
echo "[9/12] Restarting services…"
systemctl restart dhcpcd
systemctl restart dnsmasq
systemctl restart nftables
systemctl restart captive-free
systemctl restart hostapd
systemctl restart nginx

echo "[10/12] Wi-Fi AP should be up as SSID: ${SSID}"
echo "[11/12] Pretty URL:   http://${PORTAL_HOST}/    (en ook: ${EXTRA_HOSTS[*]:-geen})"
echo "[12/12] Drop APKs in ${APK_DIR} en run: /usr/local/bin/mk-apk-list"

echo
echo "Notes:"
echo "- Eerste HTTP-poging wordt naar de portal gestuurd; na 'Verder' is je IP vrij voor ${WHITELIST_TIMEOUT}."
echo "- HTTPS wordt niet gekaapt (bewust). Maar je mooie URL werkt voor HTTP."
echo "- Internet delen via eth0? Uncomment de 'masquerade' in /etc/nftables.conf en:"
echo "    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-ipforward.conf && sysctl --system"
echo "- Logs (als het uiteraard weer niet werkt):"
echo "    journalctl -fu hostapd  # Wi-Fi"
echo "    journalctl -fu dnsmasq  # DHCP/DNS"
echo "    journalctl -fu nginx    # Portal"
echo "    journalctl -fu nftables # NAT rules"
echo "    journalctl -fu captive-free # Whitelist API"
