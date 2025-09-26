!/usr/bin/env bash

# Pi 5 APK Hotspot Setup (v3): wlan0 AP + dnsmasq + nginx (static APK downloads only) + nftables
# Optional: captive-portal-like behavior via DNS hijack; nodogsplash can be toggled but is OFF by default.
# Usage: sudo ./mesh_server.sh   (or --refresh-index to rebuild the landing page)

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

format_size() {
  local bytes="$1"
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec --suffix=B "$bytes" 2>/dev/null || echo "${bytes} B"
  else
    echo "${bytes} B"
  fi
}

generate_checksums() {
  (cd "$APK_DIR/android" && shopt -s nullglob && files=(*.apk *.aab); if (( ${#files[@]} )); then sha256sum "${files[@]}" > SHA256SUMS.txt; else rm -f SHA256SUMS.txt; fi) || true
  (cd "$APK_DIR/ios" && shopt -s nullglob && files=(*.ipa); if (( ${#files[@]} )); then sha256sum "${files[@]}" > SHA256SUMS.txt; else rm -f SHA256SUMS.txt; fi) || true
}

generate_download_index() {
  local index_path="${APK_DIR}/index.html"
  local continue_path="${APK_DIR}/continue.html"
  shopt -s nullglob
  local -a android_files=("${APK_DIR}/android"/*.apk "${APK_DIR}/android"/*.aab)
  local -a ios_files=("${APK_DIR}/ios"/*.ipa)
  shopt -u nullglob

  {
    cat <<EOF
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${SSID} Downloads</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;max-width:840px;margin:2rem auto;padding:0 1.25rem;background:#f7f7f9;color:#212529}
header{text-align:center;margin-bottom:2rem}
.platform{background:#fff;border-radius:12px;padding:1.25rem;margin-bottom:1.5rem;box-shadow:0 6px 18px rgba(31,35,40,.08)}
.platform h2{margin-top:0;font-size:1.4rem}
.download-list{list-style:none;padding:0;margin:0}
.download-list li{display:flex;justify-content:space-between;align-items:center;padding:.65rem .75rem;border-radius:8px;border:1px solid #e2e3e5;margin-bottom:.65rem;background:#fafafa}
.download-list li a{color:#0d6efd;text-decoration:none;font-weight:600;word-break:break-word}
.download-list li a:hover{text-decoration:underline}
.filesize{font-size:.9rem;color:#6c757d;margin-left:1rem;white-space:nowrap}
.empty{margin:0;color:#6c757d}
.checksums{margin-top:1rem}
.checksums a{color:#495057}
.nodownload{text-align:center}
.nodownload .button{display:inline-block;padding:.75rem 1.5rem;background:#0d6efd;color:#fff;border-radius:999px;text-decoration:none;font-weight:600;margin-top:.5rem}
.nodownload .button:hover{background:#0b5ed7}
footer{margin-top:2.5rem;font-size:.9rem;color:#6c757d;text-align:center}
</style>
</head><body>
<header>
  <h1>Welcome to ${SSID}</h1>
  <p>Select the downloads for your device or skip if you do not need any files.</p>
</header>
<main>
  <section id="android" class="platform">
    <h2>Android builds</h2>
    <p>Installable APK/AAB files for Android phones and tablets.</p>
EOF

    if (( ${#android_files[@]} )); then
      echo "    <ul class=\"download-list\">"
      local fname bytes human
      for path in "${android_files[@]}"; do
        [[ -f "$path" ]] || continue
        fname="${path##*/}"
        bytes=$(stat -c %s "$path" 2>/dev/null || stat -f %z "$path" 2>/dev/null || echo 0)
        human=$(format_size "$bytes")
        printf '      <li><a href="/android/%s" download>%s</a><span class="filesize">%s</span></li>\n' "$fname" "$fname" "$human"
      done
      echo "    </ul>"
      if [[ -f "${APK_DIR}/android/SHA256SUMS.txt" ]]; then
        echo '    <p class="checksums"><a href="/android/SHA256SUMS.txt">Verify checksums</a></p>'
      fi
    else
      echo '    <p class="empty">No Android builds uploaded yet.</p>'
    fi

    cat <<'EOF'
  </section>
  <section id="ios" class="platform">
    <h2>iOS builds</h2>
    <p>IPA files for iPhone and iPad (requires appropriate provisioning).</p>
EOF

    if (( ${#ios_files[@]} )); then
      echo "    <ul class=\"download-list\">"
      local fname bytes human
      for path in "${ios_files[@]}"; do
        [[ -f "$path" ]] || continue
        fname="${path##*/}"
        bytes=$(stat -c %s "$path" 2>/dev/null || stat -f %z "$path" 2>/dev/null || echo 0)
        human=$(format_size "$bytes")
        printf '      <li><a href="/ios/%s" download>%s</a><span class="filesize">%s</span></li>\n' "$fname" "$fname" "$human"
      done
      echo "    </ul>"
      if [[ -f "${APK_DIR}/ios/SHA256SUMS.txt" ]]; then
        echo '    <p class="checksums"><a href="/ios/SHA256SUMS.txt">Verify checksums</a></p>'
      fi
    else
      echo '    <p class="empty">No iOS builds uploaded yet.</p>'
    fi

    cat <<'EOF'
  </section>
  <section class="platform nodownload">
    <h2>Don't need any downloads?</h2>
    <p>You can simply close this page or tap below to confirm you are ready.</p>
    <p><a class="button" href="/continue.html">Continue without download</a></p>
  </section>
</main>
<footer>
  <p>Admins: upload Android files to ${APK_DIR}/android and iOS files to ${APK_DIR}/ios.</p>
</footer>
</body></html>
EOF
  } >"$index_path"
  chmod 0644 "$index_path"

  cat >"$continue_path" <<EOF
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Continue</title>
<style>body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;text-align:center;max-width:640px;margin:20vh auto;padding:0 1.5rem;color:#212529}</style>
</head><body>
<h1>You're all set</h1>
<p>If you don't need to download anything, you can now close this page or open another website/app.</p>
<p><a href="/">Back to downloads</a></p>
</body></html>
EOF
  chmod 0644 "$continue_path"
}

refresh_download_index() {
  generate_checksums
  generate_download_index
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
  mkdir -p "$APK_DIR"{"","/android","/ios"}
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
    types { application/vnd.android.package-archive apk; application/octet-stream ipa; }

    location / {
        try_files /index.html =404;
    }

    location /android/ {
        autoindex on;
        add_header Content-Disposition \"attachment\";
    }

    location /ios/ {
        autoindex on;
        add_header Content-Disposition \"attachment\";
    }

    location = /continue.html {
        try_files /continue.html =404;
    }
  }"
  ln -sf "$site" /etc/nginx/sites-enabled/apk
  rm -f /etc/nginx/sites-enabled/default

  refresh_download_index

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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;max-width:680px;margin:2rem auto;padding:0 1rem;color:#212529}</style>
<title>Welcome</title></head>
<body>
<h1>Welcome to ${SSID}</h1>
<p>You are connected to the local download hotspot. Choose what to do next:</p>
<ul>
  <li><a href=\"http://${AP_IP}/\">Browse available downloads</a></li>
  <li><a href=\"http://${AP_IP}/continue.html\">Continue without downloading</a></li>
</ul>
<p>If you later need files again, return to <a href=\"http://${AP_IP}/\">http://${AP_IP}/</a>.</p>
</body></html>
EOF
  systemctl enable --now nodogsplash || true
}

post_summary() {
  echo "\n=== Done ==="
  echo "SSID: ${SSID}"
  echo "Passphrase: ${PASSPHRASE}"
  echo "AP IP: ${AP_IP}"
  echo "Download root: ${APK_DIR}"
  echo "Browse: http://${AP_IP}/"
  cat <<EOF
Upload instructions:
  • Android files → ${APK_DIR}/android (APK/AAB)
  • iOS files → ${APK_DIR}/ios (IPA)
  • Refresh landing page & checksums after uploading: sudo ./mesh_server.sh --refresh-index
EOF
}

refresh_index_only() {
  need_root
  mkdir -p "$APK_DIR"{"","/android","/ios"}
  chown -R "$SUDO_USER:${SUDO_USER:-$USER}" "$APK_DIR" 2>/dev/null || true
  refresh_download_index
  systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true
  echo "Updated ${APK_DIR}/index.html with current downloads."
}

main() {
  if [[ "${1:-}" == "--refresh-index" ]]; then
    refresh_index_only
    return 0
  fi

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
