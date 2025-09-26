#!/usr/bin/env bash

# Pi 5 APK Hotspot Setup (v3): wlan0 AP + dnsmasq + nginx (static APK downloads only) + nftables
# Optional: captive-portal-like behavior via DNS hijack; nodogsplash can be toggled but is OFF by default.
# Usage: sudo ./setup_apk_ap_v3.sh

set -euo pipefail

### === TWEAKABLES === ###
WLAN_IF="wlan0"
SSID="PiAPK"
PASSPHRASE="SuperSecret123"    # 8..63 chars
AP_IP="192.168.4.1"
SUBNET_CIDR="/24"               # corresponds to 255.255.255.0
DHCP_RANGE="192.168.4.10,192.168.4.200,255.255.255.0,12h"
APK_DIR="/srv/apk"
ENABLE_NODOGSPLASH="0"          # set to 1 if you want to install nodogsplash (best-effort)
ALLOW_SSH_ANYWHERE="1"          # 1 keeps SSH reachable from any iface; set 0 to restrict to wlan0 only

### === DERIVED === ###
SUBNET_PREFIX="${AP_IP%.*}"
SUBNET_CIDR_ONLY="${SUBNET_CIDR#/}"

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Please run as root: sudo $0" >&2
    exit 1
  fi
}

backup_file() {
  local f="$1"
  if [[ -f "$f" && ! -f "$f.bak_pi_apk" ]]; then
    cp -a "$f" "$f.bak_pi_apk"
  fi
}

write_file() {
  local path="$1"; shift
  backup_file "$path"
  install -D -m 0644 /dev/null "$path"
  cat >"$path" <<'EOF'
PLACEHOLDER
EOF
}

write_file_content() {
  local path="$1"; shift
  backup_file "$path"
  cat >"$path" <<EOF
$*
EOF
}

append_once() {
  local path="$1"; shift
  local marker_start="$2"; shift
  local marker_end="$3"; shift
  local content="$*"
  backup_file "$path"
  # Remove previous block if present
  if grep -q "$marker_start" "$path" 2>/dev/null; then
    awk -v s="$marker_start" -v e="$marker_end" 'BEGIN{inblk=0} $0~s{inblk=1;next} $0~e{inblk=0;next} !inblk{print}' "$path" >"$path.tmp" && mv "$path.tmp" "$path"
  fi
  {
    echo "$marker_start"
    echo "$content"
    echo "$marker_end"
  } >>"$path"
}

install_packages() {
  apt-get update
  local pkgs=(hostapd dnsmasq nginx nftables qrencode)
  if [[ "$ENABLE_NODOGSPLASH" == "1" ]]; then
    pkgs+=(nodogsplash)
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

configure_dhcpcd() {
  local conf=/etc/dhcpcd.conf
  local S="# BEGIN apk-ap v3"
  local E="# END apk-ap v3"
  local block="interface ${WLAN_IF}
static ip_address=${AP_IP}${SUBNET_CIDR}
nohook wpa_supplicant"
  touch "$conf"
  append_once "$conf" "$S" "$E" "$block"
  systemctl restart dhcpcd || true
}

configure_hostapd() {
  mkdir -p /etc/hostapd
  write_file_content /etc/hostapd/hostapd.conf "interface=${WLAN_IF}
ssid=${SSID}
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=${PASSPHRASE}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP"
  # Point daemon to config
  if ! grep -q "DAEMON_CONF" /etc/default/hostapd 2>/dev/null; then
    echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' >> /etc/default/hostapd
  else
    sed -i 's|^#\?\s*DAEMON_CONF=.*$|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
  fi
  systemctl unmask hostapd || true
  systemctl enable --now hostapd
}

configure_dnsmasq() {
  local conf=/etc/dnsmasq.conf
  write_file_content "$conf" "interface=${WLAN_IF}
dhcp-range=${DHCP_RANGE}
# Hijack DNS to local IP for captive-like landing
address=/#/${AP_IP}
# Speed tweaks
dhcp-option=option:router,${AP_IP}
log-queries
log-dhcp"
  systemctl enable --now dnsmasq
}

configure_nginx() {
  mkdir -p "$APK_DIR"
  chown -R "$SUDO_USER:${SUDO_USER:-$USER}" "$APK_DIR" 2>/dev/null || true

  # Site config
  local site=/etc/nginx/sites-available/apk
  write_file_content "$site" "server {
    listen ${AP_IP}:80 default_server;
    server_name _;

    # Only allow the hotspot subnet
    allow ${SUBNET_PREFIX}.0/24;
    deny all;

    root ${APK_DIR};
    index index.html;

    types { application/vnd.android.package-archive apk; }

    location / {
        autoindex on; # directory listing; set to off if you provide index.html
        try_files \$uri \$uri/ =404;
        limit_except GET HEAD {
            deny all;
        }
    }

    location ~* \\.apk$ {
        add_header Content-Type \"application/vnd.android.package-archive\";
        add_header Content-Disposition \"attachment\";
        tcp_nopush on;
        aio on;
        sendfile on;
        limit_except GET HEAD {
            deny all;
        }
    }
  }"
  ln -sf "$site" /etc/nginx/sites-enabled/apk
  rm -f /etc/nginx/sites-enabled/default

  # Minimal landing page (optional)
  if [[ ! -f "${APK_DIR}/index.html" ]]; then
    cat >"${APK_DIR}/index.html" <<EOF
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>APK Downloads</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,\n Cantarell,\"Helvetica Neue\",Arial; max-width:720px; margin:2rem auto; padding:0 1rem;}\ncode{background:#f3f3f3;padding:.1rem .3rem;border-radius:4px}</style>
</head><body>
<h1>APK Downloads</h1>
<p>Connected to <strong>${SSID}</strong>? Great. Tap an APK below to download.</p>
<ul>
<!-- NGINX autoindex will list files if you prefer; otherwise add links here. -->
</ul>
<p>SHA256 sums: <a href="/SHA256SUMS.txt">SHA256SUMS.txt</a></p>
</body></html>
EOF
  fi

  # Generate checksums if APKs exist
  (cd "$APK_DIR" && ls *.apk >/dev/null 2>&1 && sha256sum *.apk > SHA256SUMS.txt) || true

  # QR code for convenience
  qrencode -o "${APK_DIR}/apk-qr.png" "http://${AP_IP}/" || true

  nginx -t
  systemctl enable --now nginx
  systemctl restart nginx
}

configure_nftables() {
  local conf=/etc/nftables.conf
  write_file_content "$conf" "flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;
    ct state established,related accept

    # loopback
    iifname \"lo\" accept

    # ICMP (ping) optional but handy
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    # DHCP (dnsmasq)
    iifname \"${WLAN_IF}\" udp dport 67 accept
    iifname \"${WLAN_IF}\" udp sport 67 accept

    # DNS (dnsmasq)
    iifname \"${WLAN_IF}\" tcp dport 53 accept
    iifname \"${WLAN_IF}\" udp dport 53 accept

    # HTTP (nginx)
    iifname \"${WLAN_IF}\" tcp dport 80 accept

    # SSH
    $(
      if [[ "$ALLOW_SSH_ANYWHERE" == "1" ]]; then
        echo "tcp dport 22 accept"
      else
        echo "iifname \"${WLAN_IF}\" tcp dport 22 accept"
      fi
    )

    # default
    counter drop
  }
  chain forward { type filter hook forward priority 0; drop; }
  chain output  { type filter hook output priority 0; accept; }
}"
  systemctl enable --now nftables
}

configure_nodogsplash() {
  if [[ "$ENABLE_NODOGSPLASH" != "1" ]]; then
    return 0
  fi
  # Very minimal config; nodogsplash integrates primarily with iptables. On newer systems it may work with nft shim.
  local conf=/etc/nodogsplash/nodogsplash.conf
  backup_file "$conf"
  sed -i "s/^GatewayInterface.*/GatewayInterface ${WLAN_IF}/" "$conf" || true
  sed -i "s/^GatewayAddress.*/GatewayAddress ${AP_IP}/" "$conf" || true

  # Simple splash page linking to our local index
  local html=/usr/share/nodogsplash/htdocs/splash.html
  backup_file "$html"
  cat >"$html" <<EOF
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui;max-width:680px;margin:2rem auto;padding:0 1rem}</style>
<title>Welcome</title></head>
<body>
<h1>Welcome to ${SSID}</h1>
<p>Tap to continue: <a href=\"http://${AP_IP}/\">APK Downloads</a></p>
</body></html>
EOF
  systemctl enable --now nodogsplash || true
}

post_summary() {
  echo "\n=== Done ==="
  echo "SSID: ${SSID}"
  echo "Passphrase: ${PASSPHRASE}"
  echo "AP IP: ${AP_IP}"
  echo "APK dir: ${APK_DIR}"
  echo "Browse: http://${AP_IP}/"
  echo "Place your .apk files into ${APK_DIR} then run: (cd ${APK_DIR} && sha256sum *.apk > SHA256SUMS.txt)"
}

main() {
  need_root
  install_packages
  configure_dhcpcd
  configure_hostapd
  configure_dnsmasq
  configure_nginx
  configure_nftables
  configure_nodogsplash
  post_summary
}

main "$@"
