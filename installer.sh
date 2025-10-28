#!/bin/bash

    # ==============================================================================

    ###                       NEW NODE INSTALL SCRIPT                            ###

    ###                                                                          ###
    ###          Version 1.0                                                     ###
    ###                                                                          ###

    # ==============================================================================

set -Eeuo pipefail
trap 'echo "[ERROR] Unexpected error on line $LINENO" >&2' ERR

# === Variables ====================================================================

LOGFILE="/var/log/mesh-install.log"
CONFIG_FILE="/etc/default/mesh.conf"
SYSTEMCTL=$(command -v systemctl || true)
UNATTENDED_INSTALL=0
INSTALL_MODE="attended"
INTERACTIVE_MODE=1

# === Logging helpers ==============================================================

  # === Timestamp format

timestamp() {
  date +%F\ %T
}

  # === Defining different log helpers
log() {
  echo "[$(timestamp)] $*" >>"$LOGFILE"
}

info() {
  local message="INFO: $*"
  if [ -e /proc/$$/fd/3 ]; then
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE" >&3
  else
    echo "[$(timestamp)] ${message}"
  fi
}

warn() {
  local message="WARN: $*"
  if [ -e /proc/$$/fd/3 ]; then
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE" >&3
  else
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE"
  fi
}

error() {
  local message="ERROR: $*"
  if [ -e /proc/$$/fd/3 ]; then
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE" >&3
  else
    echo "[$(timestamp)] ${message}" >&2
  fi
}

  # === log installation summary helper
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

  # === Defining attended of unattended install helpers
usage() {
  cat <<'USAGE'
Usage: basic_installer.sh [--attended | --unattended]

By default the installer runs in attended (interactive) mode.
Use --unattended to apply defaults without prompting.
USAGE
}

parse_cli_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --attended)
        INSTALL_MODE="attended"
        UNATTENDED_INSTALL=0
        ;;
      --unattended)
        INSTALL_MODE="unattended"
        UNATTENDED_INSTALL=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
    shift
  done
}

  # === Creating text on the terminal helper
prompt_to_terminal() {
  local text="$1"
  if [ -w /dev/tty ]; then
    printf '%s' "$text" >/dev/tty
  elif [ -e /proc/$$/fd/3 ]; then
    printf '%s' "$text" >&3
  else
    printf '%s' "$text"
  fi
}

  # === Reading input user helper
prompt_read() {
  local -a args=("$@")
  if [ -r /dev/tty ]; then
    IFS= read "${args[@]}" </dev/tty
  else
    IFS= read "${args[@]}"
  fi
}

  # === Ask the user for input helper
ask() {
  local prompt="$1"
  local default_value="${2-}"
  local var_name="${3-}"
  local input prompt_text

  if [ -n "$default_value" ]; then
    prompt_text="$prompt [$default_value]: "
  else
    prompt_text="$prompt: "
  fi

  prompt_to_terminal "$prompt_text"
  prompt_read -r input || return 1
  input="${input:-$default_value}"

  if [ -n "$var_name" ]; then
    printf -v "$var_name" '%s' "$input"
  else
    printf '%s
' "$input"
  fi
}

  # === Ask input of the user but do not show the input on screen helper
ask_hidden() {
  local prompt="$1"
  local default_value="${2-}"
  local var_name="${3-}"
  local input prompt_text

  if [ -n "$default_value" ]; then
    prompt_text="$prompt [$default_value]: "
  else
    prompt_text="$prompt: "
  fi

  prompt_to_terminal "$prompt_text"
  prompt_read -rs input || return 1
  prompt_to_terminal $'
'
  input="${input:-$default_value}"

  if [ -n "$var_name" ]; then
    printf -v "$var_name" '%s' "$input"
  else
    printf '%s
' "$input"
  fi
}

  # === Yes/No input question to user helper
confirm() {
  local prompt="$1"
  local default_answer="${2-}"
  local default_choice suffix reply normalized

  if [ -z "$default_answer" ]; then
    default_choice="y"
    suffix="[Y/n]"
  else
    normalized=$(printf '%s' "$default_answer" | tr '[:upper:]' '[:lower:]')
    case "$normalized" in
      y|yes)
        default_choice="y"
        suffix="[Y/n]"
        ;;
      n|no)
        default_choice="n"
        suffix="[y/N]"
        ;;
      *)
        default_choice=""
        suffix="[y/n]"
        ;;
    esac
  fi

  while :; do
    prompt_to_terminal "$prompt $suffix "
    prompt_read -r reply || return 1
    if [ -n "$default_choice" ] && [ -z "$reply" ]; then
      reply="$default_choice"
    fi
    normalized=$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')
    case "$normalized" in
      y|yes)
        return 0
        ;;
      n|no)
        return 1
        ;;
      *)
        prompt_to_terminal "Please answer with 'y' or 'n'."
        prompt_to_terminal $'
'
        ;;
    esac
  done
}

  # === Error helper
die() {
  error "$*"
  exit 1
}

  # === Validate IP4 helper
validate_ipv4_cidr() {
  local cidr="$1" ip prefix o1 o2 o3 o4 octet

  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] || return 1

  IFS=/ read -r ip prefix <<<"$cidr"
  IFS=. read -r o1 o2 o3 o4 <<<"$ip"

  for octet in "$o1" "$o2" "$o3" "$o4"; do
    if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
      return 1
    fi
  done

  if ! [[ "$prefix" =~ ^[0-9]+$ ]] || [ "$prefix" -lt 0 ] || [ "$prefix" -gt 32 ]; then
    return 1
  fi

  return 0
}

ensure_network_manager_ready() {
  if ! command_exists nmcli; then
    warn "NetworkManager (nmcli) is required for access point setup."
    return 1
  fi

  if [ -n "$SYSTEMCTL" ] && "$SYSTEMCTL" list-unit-files NetworkManager.service >/dev/null 2>&1; then
    "$SYSTEMCTL" enable NetworkManager >/dev/null 2>&1 || true
    if ! "$SYSTEMCTL" is-active NetworkManager >/dev/null 2>&1; then
      "$SYSTEMCTL" start NetworkManager >/dev/null 2>&1 || return 1
    fi
  fi

  return 0
}

wait_for_wlan_network_details() {
  local attempt ip_cidr route_subnet

  WLAN_IP=""
  AP_SUBNET=""

  for attempt in $(seq 1 20); do
    ip_cidr=$(ip -o -4 addr show dev wlan0 | awk '{print $4}' | head -n1)
    if [ -n "$ip_cidr" ]; then
      WLAN_IP="${ip_cidr%%/*}"
      AP_SUBNET="$ip_cidr"
      route_subnet=$(ip -4 route show dev wlan0 | awk '/proto kernel/ {print $1; exit}')
      if [ -n "$route_subnet" ]; then
        AP_SUBNET="$route_subnet"
      fi
      return 0
    fi
    sleep 1
  done

  if [ -z "$AP_SUBNET" ] && [ -n "${AP_IP_CIDR:-}" ]; then
    AP_SUBNET="$AP_IP_CIDR"
  fi

  return 1
}

  # === Check if certain programs are installed helper
log_apt_package_versions() {
  local pkg version status
  for pkg in "$@"; do
    status=$(dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null || true)
    if printf '%s' "$status" | grep -q "install ok installed"; then
      version=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)
      info "Package '$pkg' installed (version ${version:-unknown})."
    else
      warn "Package '$pkg' is not installed."
    fi
  done
}

  # === Check if services are installed, are running, and start at boot/reboot helper
log_service_status() {
  local service active enabled
  if [ -z "$SYSTEMCTL" ]; then
    warn "systemctl not available; skipping service status logging."
    return
  fi

  for service in "$@"; do
    if systemctl list-unit-files "${service}.service" >/dev/null 2>&1; then
      active=$(systemctl is-active "${service}.service" 2>/dev/null || true)
      enabled=$(systemctl is-enabled "${service}.service" 2>/dev/null || true)
      info "Service ${service}.service status: active=$active, enabled=$enabled."
    else
      warn "Service ${service}.service not found."
    fi
  done
}

  # === Determine account that should own runtime services
resolve_service_account() {
  local candidate
  candidate=${1:-${SUDO_USER:-root}}

  if ! getent passwd "$candidate" >/dev/null 2>&1; then
    candidate=root
  fi

  SERVICE_ACCOUNT_USER="$candidate"
  SERVICE_ACCOUNT_GROUP=$(id -gn "$candidate" 2>/dev/null || echo "$candidate")
  SERVICE_ACCOUNT_HOME=$(getent passwd "$candidate" | cut -d: -f6)

  if [ -z "$SERVICE_ACCOUNT_HOME" ] || [ ! -d "$SERVICE_ACCOUNT_HOME" ]; then
    SERVICE_ACCOUNT_HOME="/root"
  fi
}

  # === Summary of the OS
log_installation_summary() {
  local os_name kernel_version
  os_name=${RPI_OS_PRETTY_NAME:-$(. /etc/os-release; echo "$PRETTY_NAME")}
  kernel_version=$(uname -r)

  info "System summary: OS=${os_name}, Kernel=${kernel_version}."

  if declare -p PACKAGES >/dev/null 2>&1; then
    log_apt_package_versions "${PACKAGES[@]}"
  fi

  if command_exists batctl; then
    info "batctl detailed version: $(batctl -v | head -n1)"
  fi

  log_service_status mesh rnsd reticulum-meshchat
}

  # === Check if the logfile exists
ensure_logfile() {
  install -d -m 0755 /var/log
  install -m 0640 -o root -g adm /dev/null "$LOGFILE"
  exec 3>&1
  exec >>"$LOGFILE" 2>&1
}

  # === Gathering all info for the configuration
gather_configuration() {
  local interactive=1

  if [ "$UNATTENDED_INSTALL" -eq 1 ]; then
    interactive=0
  elif [ ! -t 0 ] || [ ! -t 1 ]; then
    if [ "$INSTALL_MODE" = "attended" ]; then
      warn "Attended mode requested but no interactive terminal detected; falling back to unattended defaults."
    fi
    interactive=0
  fi

  if [ -r "$CONFIG_FILE" ]; then
    info "Loading configuration defaults from $CONFIG_FILE"
    # shellcheck disable=SC1091
    . "$CONFIG_FILE"
  fi

  : "${MESH_ID:=MESHNODE}"
  : "${IFACE:=wlan1}"
  : "${BATIF:=bat0}"
  : "${IP_CIDR:=192.168.0.2/24}"
  : "${COUNTRY:=BE}"
  : "${FREQ:=5180}"
  : "${BANDWIDTH:=HT20}"
  : "${MTU:=1532}"
  : "${BSSID:=02:12:34:56:78:9A}"
  : "${AP_SSID:=Node2}"
  : "${AP_PSK:=SuperSecret123}"
  : "${AP_CHANNEL:=6}"
  : "${AP_COUNTRY:=BE}"
  : "${AP_IP_CIDR:=10.42.10.1/24}"

  if [ $interactive -eq 1 ]; then
    info "Gathering mesh configuration."
    ask "Mesh ID" "$MESH_ID" MESH_ID
    ask "Wireless interface" "$IFACE" IFACE
    ask "batman-adv interface (bat)" "$BATIF" BATIF
    ask "Node IP/CIDR on ${BATIF}" "$IP_CIDR" IP_CIDR
    ask "Country code (regdom)" "$COUNTRY" COUNTRY
    ask "Frequency (MHz)" "$FREQ" FREQ
    ask "Bandwidth" "$BANDWIDTH" BANDWIDTH
    ask "MTU for ${BATIF}" "$MTU" MTU
    ask "IBSS fallback BSSID" "$BSSID" BSSID
    info "Gathering access point configuration."
    ask "Access point SSID" "$AP_SSID" AP_SSID
    ask_hidden "Access point WPA2 password" "$AP_PSK" AP_PSK
    ask "Access point channel" "$AP_CHANNEL" AP_CHANNEL
    ask "Access point country code" "$AP_COUNTRY" AP_COUNTRY
    ask "Access point IP/CIDR" "$AP_IP_CIDR" AP_IP_CIDR
  else
    info "Running in unattended mode; using configuration defaults for mesh."
  fi

  if ! validate_ipv4_cidr "$IP_CIDR"; then
    die "Mesh IP/CIDR '$IP_CIDR' is invalid. Update $CONFIG_FILE or rerun interactively."
  fi

  if ! validate_ipv4_cidr "$AP_IP_CIDR"; then
    die "Access point IP/CIDR '$AP_IP_CIDR' is invalid. Update $CONFIG_FILE or rerun interactively."
  fi

  INTERACTIVE_MODE=$interactive

  install -m 0644 -o root -g root /dev/null "$CONFIG_FILE"
  cat >"$CONFIG_FILE" <<EOF
MESH_ID="$MESH_ID"
IFACE="$IFACE"
BATIF="$BATIF"
IP_CIDR="$IP_CIDR"
COUNTRY="$COUNTRY"
FREQ="$FREQ"
BANDWIDTH="$BANDWIDTH"
MTU="$MTU"
BSSID="$BSSID"
AP_SSID="$AP_SSID"
AP_PSK="$AP_PSK"
AP_CHANNEL="$AP_CHANNEL"
AP_COUNTRY="$AP_COUNTRY"
AP_IP_CIDR="$AP_IP_CIDR"
EOF
}

update_system() {
  info "Starting operating system update and upgrade."
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confdef"           -o Dpkg::Options::="--force-confold"           dist-upgrade -y
  info "Operating system update and upgrade complete."
}

  # === Extra packages that need to be installed
install_packages() {
  PACKAGES=(
    nano
    batctl
    python3
    python3-pip
    python3-cryptography
    python3-serial
    git
    curl
    gnupg
    ca-certificates
    network-manager
    nginx
    php-fpm
    php-cli
  )

  info "Starting package installation."
  if apt-get install -y --no-install-recommends "${PACKAGES[@]}"; then
    info "Bulk install/upgrade succeeded."
  else
    warn "Bulk install failed; falling back to per-package handling."
    for pkg in "${PACKAGES[@]}"; do
      info "Processing: $pkg ===="
      if ! apt-cache policy "$pkg" | grep -q "Candidate:"; then
        log "Warning: package '$pkg' not found in apt policy. Skipping."
        continue
      fi
      if dpkg -s "$pkg" >/dev/null 2>&1; then
        log "'$pkg' already installed. Attempting upgrade (if available)..."
        apt-get install --only-upgrade -y "$pkg" ||           warn "Upgrade failed for $pkg (continuing)."
      else
        log "'$pkg' not installed. Installing now..."
        apt-get install -y --no-install-recommends "$pkg" ||           warn "Installation failed for $pkg (continuing)."
      fi
    done
  fi
  info "Package installation complete."
}

install_access_point() {
  info "Installing access point on wlan0 (AP)."

  if [ $INTERACTIVE_MODE -eq 1 ]; then
    echo
    echo "Summary:"
    echo "  SSID        : $AP_SSID"
    echo "  WPA2 PSK    : (hidden for security)"
    echo "  Channel     : $AP_CHANNEL"
    echo "  IPv4/CIDR   : $AP_IP_CIDR"
    echo "  Country code: $AP_COUNTRY"
    echo
  fi

  local clean=true
  if [ $INTERACTIVE_MODE -eq 1 ]; then
    confirm "Remove all existing Wi-Fi profiles before continuing?" || clean=false
    echo
    confirm "Proceed with access point configuration?" || die "Operation cancelled by user."
  fi

  if ! ensure_network_manager_ready; then
    die "Access point setup requires NetworkManager (nmcli). Please install and enable 'network-manager' before rerunning."
  fi

  log "Setting country code to ${AP_COUNTRY}..."
  if command -v raspi-config >/dev/null 2>&1; then
    raspi-config nonint do_wifi_country "${AP_COUNTRY}" || true
  fi
  iw reg set "${AP_COUNTRY}" || true

  if [[ -f /etc/wpa_supplicant/wpa_supplicant.conf ]]; then
    grep -q "^country=${AP_COUNTRY}\\b" /etc/wpa_supplicant/wpa_supplicant.conf 2>/dev/null || \
      sed -i "1i country=${AP_COUNTRY}" /etc/wpa_supplicant/wpa_supplicant.conf || true
  fi

  log "Reloading Broadcom/CFG80211 drivers..."
  modprobe -r brcmfmac brcmutil cfg80211 2>/dev/null || true
  modprobe cfg80211
  modprobe brcmutil 2>/dev/null || true
  modprobe brcmfmac 2>/dev/null || true

  log "Enabling Wi-Fi radio and disabling power save..."
  rfkill unblock all || true
  nmcli radio wifi on
  mkdir -p /etc/NetworkManager/conf.d
  cat >/etc/NetworkManager/conf.d/wifi-powersave-off.conf <<'EOF'
[connection]
wifi.powersave=2
EOF

  log "Restarting NetworkManager..."
  if [ -n "$SYSTEMCTL" ]; then
    "$SYSTEMCTL" restart NetworkManager
  else
    warn "systemctl not available; please restart NetworkManager manually if required."
  fi
  sleep 2

  if $clean; then
    log "Removing existing Wi-Fi profiles..."
    nmcli device disconnect wlan0 || true
    while read -r NAME; do
      [[ -n "$NAME" ]] && nmcli connection delete "$NAME" || true
    done < <(nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="802-11-wireless"{print $1}')
  else
    log "Leaving existing profiles in place; disconnecting wlan0 regardless."
    nmcli device disconnect wlan0 || true
  fi

  log "Creating AP profile: SSID='${AP_SSID}', channel=${AP_CHANNEL}, WPA2..."
  nmcli -t -f NAME connection show | grep -Fxq "$AP_SSID" && nmcli connection delete "$AP_SSID" || true
  nmcli connection add type wifi ifname wlan0 con-name "${AP_SSID}" ssid "${AP_SSID}"

  nmcli connection modify "${AP_SSID}" \
    802-11-wireless.mode ap \
    802-11-wireless.band bg \
    802-11-wireless.channel "${AP_CHANNEL}" \
    802-11-wireless.hidden no \
    ipv4.method shared \
    ipv6.method ignore \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.psk "${AP_PSK}" \
    connection.autoconnect yes \
    wifi.cloned-mac-address permanent

  if [ -n "${AP_IP_CIDR:-}" ]; then
    nmcli connection modify "${AP_SSID}" ipv4.addresses "${AP_IP_CIDR}"
    local ap_ip_addr="${AP_IP_CIDR%%/*}"
    if [ -n "$ap_ip_addr" ]; then
      nmcli connection modify "${AP_SSID}" ipv4.gateway "$ap_ip_addr"
    fi
  fi

  nmcli connection modify "${AP_SSID}" 802-11-wireless.channel-width 20mhz 2>/dev/null || \
  nmcli connection modify "${AP_SSID}" 802-11-wireless.channel-width ht20 2>/dev/null || true

  nmcli connection modify "${AP_SSID}" +wifi-sec.proto rsn       || true
  nmcli connection modify "${AP_SSID}" +wifi-sec.group ccmp      || true
  nmcli connection modify "${AP_SSID}" +wifi-sec.pairwise ccmp   || true
  nmcli connection modify "${AP_SSID}" 802-11-wireless-security.pmf 0 2>/dev/null || \
  nmcli connection modify "${AP_SSID}" wifi-sec.pmf 0 2>/dev/null || true

  start_ap() {
    local ch="$1"
    log "Starting AP on channel ${ch}..."
    nmcli connection modify "${AP_SSID}" 802-11-wireless.channel "${ch}" || true
    nmcli connection up "${AP_SSID}"
  }

  set +e
  start_ap "${AP_CHANNEL}"
  local rc=$?
  if [ $rc -ne 0 ]; then
    log "Start failed. Attempting fallback on channels 1/6/11..."
    for ch in 1 6 11; do
      [[ "$ch" == "$AP_CHANNEL" ]] && continue
      start_ap "$ch"; rc=$?
      [ $rc -eq 0 ] && { AP_CHANNEL="$ch"; break; }
    done
  fi
  set -e

  if ! wait_for_wlan_network_details; then
    die "Unable to detect wlan0 IPv4 details after waiting for NetworkManager. Access point setup cannot continue."
  fi
  AP_SUBNET="${AP_SUBNET:-$AP_IP_CIDR}"

  echo
  nmcli -f DEVICE,TYPE,STATE,CONNECTION device status | sed 's/^/    /'
  echo

  if nmcli -t -f GENERAL.STATE connection show "${AP_SSID}" >/dev/null 2>&1; then
    echo "[OK] Completed. SSID: ${AP_SSID}"
    echo "   WPA2 password: (still hidden for security)"
    echo "   Channel: ${AP_CHANNEL}"
    echo "   Device IP on wlan0: ${WLAN_IP:-(no IPv4 address detected yet)}"
    echo
    echo "Helpful commands:"
    echo "  - Change channel: nmcli con mod \"${AP_SSID}\" 802-11-wireless.channel 1 && nmcli con up \"${AP_SSID}\""
    echo "  - Update SSID   : nmcli con mod \"${AP_SSID}\" 802-11-wireless.ssid \"NewSSID\" && nmcli con up \"${AP_SSID}\""
    echo "  - Update password: nmcli con mod \"${AP_SSID}\" wifi-sec.psk \"NewPassword\" && nmcli con up \"${AP_SSID}\""
  else
    die "Access point is not active. Check logs:\n  - journalctl -u NetworkManager -b --no-pager | tail -n 200\n  - dmesg | grep -i -E 'brcm|wlan0|cfg80211|ieee80211' | tail -n 200"
  fi

  info "Access point installed."
}

install_web_server() {
  info "Installing web server."

  if [ -z "${WLAN_IP:-}" ] || [ -z "${AP_SUBNET:-}" ]; then
    wait_for_wlan_network_details || true
  fi

  log "Detected wlan0 IPv4 address ${WLAN_IP:-unknown} on subnet ${AP_SUBNET:-unknown}."

  local script_dir web_root files_dir site_avail site_enabled default_site owner_user php_fpm_service php_fpm_socket assets_dir

  script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  web_root="/var/www/server"
  files_dir="$web_root/files"
  site_avail="/etc/nginx/sites-available/fileserver"
  site_enabled="/etc/nginx/sites-enabled/fileserver"
  default_site="/etc/nginx/sites-enabled/default"
  owner_user="${SUDO_USER:-pi}"

  if ! getent passwd "$owner_user" >/dev/null 2>&1; then
    owner_user=root
  fi

  log "Installing packages (nginx)..."
  info "nginx installation handled with base package setup."

  log "Creating directories and setting permissions..."
  mkdir -p "$web_root"
  mkdir -p "$files_dir"
  chown -R "$owner_user":www-data "$web_root"
  chmod -R 775 "$files_dir"

  log "Writing Nginx configuration..."

  if [ -n "$SYSTEMCTL" ]; then
    php_fpm_service=$("$SYSTEMCTL" list-unit-files | awk '/php.*-fpm\.service/ {print $1; exit}' || true)
  else
    php_fpm_service=""
  fi

  if [ -n "$php_fpm_service" ]; then
    info "Ensuring $php_fpm_service is enabled."
    "$SYSTEMCTL" enable "$php_fpm_service" >/dev/null 2>&1 || warn "Unable to enable $php_fpm_service."
    "$SYSTEMCTL" restart "$php_fpm_service" >/dev/null 2>&1 || warn "Unable to restart $php_fpm_service."
  else
    warn "No php-fpm service detected; PHP content may not be served until the service is installed."
  fi

  php_fpm_socket=""
  if [ -d /run/php ]; then
    php_fpm_socket=$(find /run/php -maxdepth 1 -type s -name 'php*-fpm.sock' | head -n1 || true)
  fi
  if [ -z "$php_fpm_socket" ]; then
    php_fpm_socket="/run/php/php-fpm.sock"
    warn "Defaulting to PHP-FPM socket path $php_fpm_socket in Nginx configuration."
  else
    info "Using PHP-FPM socket $php_fpm_socket."
  fi

  cat > "$site_avail" <<'NGINXCONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    server_name _;

    root /var/www/server;
    index index.php index.html;

    location /files/ {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass FASTCGI_SOCKET;
    }

    location ~ /\.ht {
        deny all;
    }
}
NGINXCONF

  sed -i "s|FASTCGI_SOCKET|unix:$php_fpm_socket|" "$site_avail"

  assets_dir="$script_dir/web_assets"
  if [ -d "$assets_dir" ]; then
    info "Deploying web assets from $assets_dir to $web_root."
    cp -a "$assets_dir/." "$web_root/"
    chown -R "$owner_user":www-data "$web_root"
    chmod -R 775 "$files_dir"
  else
    warn "Web assets directory $assets_dir not found; default site will be empty."
  fi

  log "Activating site configuration..."
  ln -sf "$site_avail" "$site_enabled"
  [ -e "$default_site" ] && rm -f "$default_site"

  log "Testing configuration and restarting Nginx..."
  nginx -t
  if [ -n "$SYSTEMCTL" ]; then
    "$SYSTEMCTL" enable nginx >/dev/null 2>&1 || warn "Unable to enable nginx service."
    "$SYSTEMCTL" restart nginx || die "Failed to restart nginx after configuration update."
    if [ -n "$php_fpm_service" ]; then
      "$SYSTEMCTL" restart "$php_fpm_service" || warn "Failed to restart $php_fpm_service."
    fi
  else
    warn "systemctl not available; please manage nginx and PHP-FPM services manually."
  fi

  echo
  echo "[OK] Completed. Place your files in: $files_dir"
  echo "   HTTP: http://${WLAN_IP:-<wlan0-IP>}/files/  (once wlan0 has an IP)"
  echo "   AP subnet: ${AP_SUBNET:-unknown} (for reference only)"

  info "Web server installed."
}

install_reticulum_services() {
  info "Applying Reticulum installation and configuration."

  if ! python3 -m pip install --upgrade --break-system-packages rns; then
    die "Failed to install Reticulum (pip install rns)."
  fi

  if ! python3 -m pip show rns >/dev/null 2>&1; then
    die "Reticulum installation could not be verified."
  fi

  local scripts_dir rnsd_exec
  scripts_dir=$(python3 -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>/dev/null || true)
  if [ -n "$scripts_dir" ] && [ -x "$scripts_dir/rnsd" ]; then
    rnsd_exec="$scripts_dir/rnsd"
  else
    rnsd_exec=$(command -v rnsd || true)
  fi

  if [ -z "$rnsd_exec" ]; then
    die "Unable to locate rnsd executable after installation."
  fi

  resolve_service_account
  local service_user="$SERVICE_ACCOUNT_USER"
  local service_group="$SERVICE_ACCOUNT_GROUP"
  local service_home="$SERVICE_ACCOUNT_HOME"
  local config_path="$service_home/.reticulum"

  install -d -m 0750 -o "$service_user" -g "$service_group" "$config_path"

  cat >"$config_path/config" <<EOF
[reticulum]
  enable_transport = Yes
  share_instance = Yes
  shared_instance_port = 37428
  instance_control_port = 37429
  panic_on_interface_error = No

[logging]
  loglevel = 4

[interfaces]

  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = True
    listen_ip = 0.0.0.0
    listen_port = 4242
    mode = gw

EOF

  chown "$service_user":"$service_group" "$config_path/config"
  chmod 0640 "$config_path/config"

  install -m 0644 -o root -g root /dev/null /etc/systemd/system/rnsd.service
  cat >/etc/systemd/system/rnsd.service <<EOF
[Unit]
Description=Reticulum Network Stack Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$service_user
Group=$service_group
ExecStartPre=/bin/sleep 30
ExecStart=$rnsd_exec --service
Restart=always
RestartSec=3
WorkingDirectory=$service_home

[Install]
WantedBy=multi-user.target
EOF

  if [ -n "$SYSTEMCTL" ]; then
    $SYSTEMCTL daemon-reload
    $SYSTEMCTL enable rnsd
    $SYSTEMCTL restart rnsd || warn "Failed to start rnsd.service immediately."
  else
    warn "systemctl not available; enable and start rnsd.service manually."
  fi

  local hostname ip_address
  hostname=$(hostname)
  ip_address=$(hostname -I | awk '{print $1}' || true)

  info "Reticulum is installed and configured. Use 'systemctl status rnsd' to review state."
  info "Reticulum TCP interface reachable at ${hostname} (${ip_address:-unknown}) on port 4242."
}

install_lxmf_services() {
  info "Applying LXMF installation."

  if python3 -m pip install --upgrade --break-system-packages lxmf; then
    if python3 -m pip show lxmf >/dev/null 2>&1; then
      info "LXMF installation complete."
    else
      warn "LXMF installation completed but could not be verified."
    fi
  else
    warn "Failed to install LXMF via pip."
  fi
}

install_nomadnetwork_services() {
  info "Applying Nomad Network installation."

  if python3 -m pip install --upgrade --break-system-packages nomadnet; then
    info "Nomad Network is installed. Use 'nomadnet' to start the program."
  else
    warn "Nomad Network installation failed."
  fi
}

install_meshchat_services() {
  info "Applying MeshChat installation."

  local keyring="/usr/share/keyrings/nodesource.gpg"
  local repo_file="/etc/apt/sources.list.d/nodesource.list"
  local node_major=22

  if [ ! -f "$keyring" ]; then
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o "$keyring"
  fi

  if [ ! -f "$repo_file" ]; then
    echo "deb [signed-by=$keyring] https://deb.nodesource.com/node_${node_major}.x nodistro main" >"$repo_file"
  fi

  apt-get update -y
  apt-get install -y nodejs

  resolve_service_account
  local service_user="$SERVICE_ACCOUNT_USER"
  local service_group="$SERVICE_ACCOUNT_GROUP"
  local service_home="$SERVICE_ACCOUNT_HOME"
  local meshchat_dir="/opt/reticulum-meshchat"

  if [ ! -d "$meshchat_dir/.git" ]; then
    rm -rf "$meshchat_dir"
    if ! git clone https://github.com/liamcottle/reticulum-meshchat "$meshchat_dir"; then
      die "Failed to clone reticulum-meshchat repository."
    fi
  else
    info "Updating existing reticulum-meshchat repository."
    if ! git -C "$meshchat_dir" pull --ff-only; then
      warn "Unable to fast-forward reticulum-meshchat repository; leaving existing checkout."
    fi
  fi

  chown -R "$service_user":"$service_group" "$meshchat_dir"

  local -a meshchat_pip_args=(python3 -m pip install --user --upgrade)
  if python3 -m pip help install 2>/dev/null | grep -q -- '--break-system-packages'; then
    meshchat_pip_args+=(--break-system-packages)
  fi
  meshchat_pip_args+=('aiohttp>=3.12.14' 'cx_freeze>=7.0.0' 'peewee>=3.18.1' 'websockets>=14.2')

  if ! runuser -u "$service_user" -- "${meshchat_pip_args[@]}"; then
    warn "Failed to install MeshChat Python dependencies."
  fi

  if runuser -u "$service_user" -- bash -c "cd '$meshchat_dir' && npm install --omit=dev"; then
    if ! runuser -u "$service_user" -- bash -c "cd '$meshchat_dir' && npm run build-frontend"; then
      warn "MeshChat frontend build failed."
    fi
  else
    warn "npm install for MeshChat failed."
  fi

  install -m 0644 -o root -g root /dev/null /etc/systemd/system/reticulum-meshchat.service
  cat >/etc/systemd/system/reticulum-meshchat.service <<EOF
[Unit]
Description=Reticulum MeshChat
After=network.target rnsd.service
Wants=network.target rnsd.service

[Service]
Type=simple
User=$service_user
Group=$service_group
WorkingDirectory=$meshchat_dir
Environment=PATH=/usr/bin:/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin:$service_home/.local/bin
ExecStart=/usr/bin/env python3 $meshchat_dir/meshchat.py --headless --host 0.0.0.0
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  if [ -n "$SYSTEMCTL" ]; then
    $SYSTEMCTL daemon-reload
    $SYSTEMCTL enable reticulum-meshchat
    $SYSTEMCTL restart reticulum-meshchat || warn "Failed to start reticulum-meshchat.service immediately."
  else
    warn "systemctl not available; enable and start reticulum-meshchat.service manually."
  fi

  info "MeshChat installation complete. Use 'systemctl status reticulum-meshchat.service' to review state."
}

  # === Installation and starts a BATMAN-adv mesh-netwerk
setup_mesh_services() {
  info "Applying B.A.T.M.A.N. Adv insatalleation and configuration."

  if ! modprobe batman-adv 2>/dev/null; then
    warn "Unable to load batman-adv module immediately. Continuing; module will be loaded by meshctl."
  fi

  install -m 0755 -o root -g root /dev/null /usr/local/sbin/meshctl
  cat >/usr/local/sbin/meshctl <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
CMD="${1:-status}"
. /etc/default/mesh.conf

mesh_supported() {
  iw list 2>/dev/null | awk '/Supported interface modes/{p=1} p{print} /Supported commands/{exit}' | grep -qi "mesh point"
}

mesh_up() {
  modprobe batman-adv
  iw reg set "$COUNTRY" || true
  command -v nmcli >/dev/null 2>&1 && nmcli dev set "$IFACE" managed no || true

  ip link set "$IFACE" down || true
  if mesh_supported; then
    iw dev "$IFACE" set type mp
    ip link set "$IFACE" up
    iw dev "$IFACE" mesh join "$MESH_ID" freq "$FREQ" "$BANDWIDTH"
  else
    iw dev "$IFACE" set type ibss
    ip link set "$IFACE" up
    iw dev "$IFACE" ibss join "$MESH_ID" "$FREQ" "$BANDWIDTH" fixed-freq "$BSSID"
  fi

  batctl if add "$IFACE" || true
  ip link set up dev "$IFACE"
  ip link set up dev "$BATIF"
  ip link set dev "$BATIF" mtu "$MTU" || true
  ip addr add "$IP_CIDR" dev "$BATIF" || true
}

mesh_down() {
  ip addr flush dev "$BATIF" || true
  ip link set "$BATIF" down || true
  batctl if del "$IFACE" 2>/dev/null || true
  iw dev "$IFACE" mesh leave 2>/dev/null || true
  ip link set "$IFACE" down || true
}

mesh_status() {
  echo "== Interfaces =="; ip -br link | grep -E "$IFACE|$BATIF" || true
  echo "== batctl if =="; batctl if || true
  echo "== originators =="; batctl -m "$BATIF" o 2>/dev/null || true
  echo "== neighbors =="; batctl n 2>/dev/null || true
  echo "== 802.11s mpath =="; iw dev "$IFACE" mpath dump 2>/dev/null || true
  echo "== stations (IBSS) =="; iw dev "$IFACE" station dump 2>/dev/null || true
}

case "$CMD" in
  up) mesh_up;;
  down) mesh_down;;
  status) mesh_status;;
  *) echo "Usage: meshctl {up|down|status}"; exit 2;;
esac
EOF

  install -m 0644 -o root -g root /dev/null /etc/systemd/system/mesh.service
  cat >/etc/systemd/system/mesh.service <<'EOF'
[Unit]
Description=BATMAN-adv Mesh bring-up
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/meshctl up
ExecStop=/usr/local/sbin/meshctl down
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  if [ -n "$SYSTEMCTL" ]; then
    $SYSTEMCTL daemon-reload
    $SYSTEMCTL enable mesh
    $SYSTEMCTL start mesh || warn "Failed to start mesh.service immediately."
  else
    warn "systemctl not available; enable and start mesh.service manually."
  fi

  info "Mesh setup complete. Use 'meshctl status' to review state."
}

  # === Logrotation setup
configure_log_rotation() {
  info "Configuring log rotation."
  install -m 0644 -o root -g root /dev/null /etc/logrotate.d/mesh-install
  cat >/etc/logrotate.d/mesh-install <<'EOF'
/var/log/mesh-install.log {
  rotate 7
  daily
  missingok
  notifempty
  compress
  delaycompress
  create 0640 root adm
}
EOF
  info "Log rotation configuration complete."
}

  # === Reboot at end of script
prompt_reboot() {
  info "Installation complete."
  if [ "$INTERACTIVE_MODE" -eq 1 ]; then
    if confirm "Do you want to reboot the system?" "y"; then
      info "Initiating reboot."
      /sbin/shutdown -r now
    else
      info "No reboot requested; exiting."
    fi
  else
    info "Unattended mode detected; skipping reboot prompt."
  fi
}


# === Main installation sequence ========================================================
main() {
  parse_cli_args "$@"

  if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root."
    exit 1
  fi

  ensure_logfile

  info "================================================="
  info "===                                           ==="
  info "===    Installation of the Mesh Radio v1.0.   ==="
  info "===                                           ==="
  info "================================================="
  info ""
  info "Installer running in ${INSTALL_MODE} mode."
  info ""
  info "Running as root (user $(id -un))."

  gather_configuration
  update_system
  install_packages
  install_access_point
  install_web_server
  setup_mesh_services
  install_reticulum_services
  install_lxmf_services
  install_nomadnetwork_services
  install_meshchat_services
  configure_log_rotation
  apt-get autoremove -y
  apt-get clean
  log_installation_summary
  prompt_reboot
}

main "$@"
