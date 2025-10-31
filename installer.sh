
#!/bin/bash

    # ============================================================================ #

    ###                       NEW NODE INSTALL SCRIPT                            ###

    ###                                                                          ###
    ###          Version 1.0                                                     ###
    ###                                                                          ###

    # ============================================================================ #

set -Eeuo pipefail
trap 'echo "[ERROR] Unexpected error on line $LINENO" >&2' ERR

# === Variables ====================================================================

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LOGFILE="/var/log/mesh-install.log"
DEFAULT_CONFIG_FILE="$SCRIPT_DIR/mesh.conf"
CONFIG_FILE="${MESH_CONFIG_PATH:-$DEFAULT_CONFIG_FILE}"
CONFIG_FILE_OVERRIDE=0
if [ -n "${MESH_CONFIG_PATH:-}" ]; then
  CONFIG_FILE_OVERRIDE=1
fi
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
  cat <<USAGE
Usage: basic_installer.sh [--attended | --unattended] [--config PATH]

By default the installer runs in attended (interactive) mode.
Use --unattended to apply defaults without prompting.
Use --config PATH to read defaults from PATH (default: $CONFIG_FILE).
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
      --config)
        if [ $# -lt 2 ]; then
          error "Missing value for --config"
          usage
          exit 1
        fi
        CONFIG_FILE="$2"
        if [ -z "$CONFIG_FILE" ]; then
          error "Configuration file path for --config cannot be empty"
          usage
          exit 1
        fi
        CONFIG_FILE_OVERRIDE=1
        shift
        ;;
      --config=*)
        CONFIG_FILE="${1#--config=}"
        if [ -z "$CONFIG_FILE" ]; then
          error "Configuration file path for --config cannot be empty"
          usage
          exit 1
        fi
        CONFIG_FILE_OVERRIDE=1
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

validate_ipv4_address() {
  local ip="$1" o1 o2 o3 o4 octet

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

  IFS=. read -r o1 o2 o3 o4 <<<"$ip"

  for octet in "$o1" "$o2" "$o3" "$o4"; do
    if ! [[ "$octet" =~ ^[0-9]+$ ]] || [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ]; then
      return 1
    fi
  done

  return 0
}

ipv4_to_int() {
  local ip="$1" o1 o2 o3 o4
  IFS=. read -r o1 o2 o3 o4 <<<"$ip"
  printf '%u' $(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
}

cidr_network_int() {
  local cidr="$1" ip prefix mask
  IFS=/ read -r ip prefix <<<"$cidr"
  if [ "$prefix" -eq 0 ]; then
    mask=0
  else
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  fi
  printf '%u' $(( $(ipv4_to_int "$ip") & mask ))
}

cidr_hostmask_int() {
  local cidr="$1" prefix
  IFS=/ read -r _ prefix <<<"$cidr"
  if [ "$prefix" -eq 32 ]; then
    printf '%u' 0
  elif [ "$prefix" -eq 0 ]; then
    printf '%u' $((0xFFFFFFFF))
  else
    printf '%u' $(( (1 << (32 - prefix)) - 1 ))
  fi
}

is_ip_in_cidr() {
  local ip="$1" cidr="$2" ip_int network hostmask min max
  ip_int=$(ipv4_to_int "$ip")
  network=$(cidr_network_int "$cidr")
  hostmask=$(cidr_hostmask_int "$cidr")
  min=$network
  max=$(( network + hostmask ))
  [ "$ip_int" -ge "$min" ] && [ "$ip_int" -le "$max" ]
}

ip_in_range() {
  local ip="$1" start="$2" end="$3"
  local ip_int start_int end_int
  ip_int=$(ipv4_to_int "$ip")
  start_int=$(ipv4_to_int "$start")
  end_int=$(ipv4_to_int "$end")
  [ "$ip_int" -ge "$start_int" ] && [ "$ip_int" -le "$end_int" ]
}

validate_dhcp_range() {
  local cidr="$1" start="$2" end="$3"
  local start_int end_int

  if ! validate_ipv4_address "$start" || ! validate_ipv4_address "$end"; then
    return 1
  fi

  if ! is_ip_in_cidr "$start" "$cidr" || ! is_ip_in_cidr "$end" "$cidr"; then
    return 1
  fi

  start_int=$(ipv4_to_int "$start")
  end_int=$(ipv4_to_int "$end")

  [ "$start_int" -le "$end_int" ]
}

validate_wpa_passphrase() {
  local passphrase="$1" length
  length=${#passphrase}
  [ "$length" -ge 8 ] && [ "$length" -le 63 ]
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
  elif [ "$CONFIG_FILE_OVERRIDE" -eq 1 ]; then
    die "Configuration file '$CONFIG_FILE' does not exist or is not readable. Provide a valid path with --config or set MESH_CONFIG_PATH."
  else
    error "Configuration file '$CONFIG_FILE' does not exist or is not readable. Continuing with built-in defaults."
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
  : "${AP_INTERFACE:=wlan0}"
  : "${AP_SSID:=Node2}"
  : "${AP_PSK:=SuperSecret123}"
  : "${AP_CHANNEL:=6}"
  : "${AP_COUNTRY:=BE}"
  : "${AP_IP_CIDR:=10.0.0.1/24}"
  : "${AP_DHCP_RANGE_START:=10.0.0.100}"
  : "${AP_DHCP_RANGE_END:=10.0.0.200}"
  : "${AP_DHCP_LEASE:=12h}"

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
    ask "Access point interface" "$AP_INTERFACE" AP_INTERFACE
    ask "Access point SSID" "$AP_SSID" AP_SSID
    ask_hidden "Access point WPA2/WPA3 passphrase" "$AP_PSK" AP_PSK
    ask "Access point channel" "$AP_CHANNEL" AP_CHANNEL
    ask "Access point country code" "$AP_COUNTRY" AP_COUNTRY
    ask "Access point IP/CIDR" "$AP_IP_CIDR" AP_IP_CIDR
    ask "Access point DHCP range start" "$AP_DHCP_RANGE_START" AP_DHCP_RANGE_START
    ask "Access point DHCP range end" "$AP_DHCP_RANGE_END" AP_DHCP_RANGE_END
    ask "Access point DHCP lease" "$AP_DHCP_LEASE" AP_DHCP_LEASE
  else
    info "Running in unattended mode; using configuration defaults for mesh."
  fi

  if ! validate_ipv4_cidr "$IP_CIDR"; then
    die "Mesh IP/CIDR '$IP_CIDR' is invalid. Update $CONFIG_FILE or rerun interactively."
  fi

  if [ -z "$AP_INTERFACE" ]; then
    die "Access point interface cannot be empty."
  fi

  if ! [[ "$AP_CHANNEL" =~ ^[0-9]+$ ]]; then
    die "Access point channel '$AP_CHANNEL' must be a numeric value."
  fi

  if ! validate_ipv4_cidr "$AP_IP_CIDR"; then
    die "Access point IP/CIDR '$AP_IP_CIDR' is invalid. Update $CONFIG_FILE or rerun interactively."
  fi

  AP_IP_ADDRESS="${AP_IP_CIDR%%/*}"

  if ! validate_ipv4_address "$AP_IP_ADDRESS"; then
    die "Access point IP '$AP_IP_ADDRESS' is invalid."
  fi

  if ! validate_ipv4_address "$AP_DHCP_RANGE_START"; then
    die "Access point DHCP range start '$AP_DHCP_RANGE_START' is invalid."
  fi

  if ! validate_ipv4_address "$AP_DHCP_RANGE_END"; then
    die "Access point DHCP range end '$AP_DHCP_RANGE_END' is invalid."
  fi

  if ! validate_wpa_passphrase "$AP_PSK"; then
    die "Access point passphrase must be between 8 and 63 characters for WPA2 compatibility."
  fi

  if ! validate_dhcp_range "$AP_IP_CIDR" "$AP_DHCP_RANGE_START" "$AP_DHCP_RANGE_END"; then
    die "DHCP range $AP_DHCP_RANGE_START - $AP_DHCP_RANGE_END is not valid for subnet $AP_IP_CIDR."
  fi

  if ip_in_range "$AP_IP_ADDRESS" "$AP_DHCP_RANGE_START" "$AP_DHCP_RANGE_END"; then
    die "Access point IP '$AP_IP_ADDRESS' overlaps with the DHCP range."
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
AP_INTERFACE="$AP_INTERFACE"
AP_SSID="$AP_SSID"
AP_PSK="$AP_PSK"
AP_CHANNEL="$AP_CHANNEL"
AP_COUNTRY="$AP_COUNTRY"
AP_IP_CIDR="$AP_IP_CIDR"
AP_DHCP_RANGE_START="$AP_DHCP_RANGE_START"
AP_DHCP_RANGE_END="$AP_DHCP_RANGE_END"
AP_DHCP_LEASE="$AP_DHCP_LEASE"
EOF
}

update_system() {
  info "Starting operating system update and upgrade."
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confdef"           -o Dpkg::Options::="--force-confold"           dist-upgrade -y
  info "Operating system update and upgrade complete."
}

configure_access_point() {
  local hw_mode="g" hostapd_conf="/etc/hostapd/hostapd.conf" dnsmasq_conf="/etc/dnsmasq.d/mesh-ap.conf"
  local default_hostapd="/etc/default/hostapd" ip_setup_script="/usr/local/sbin/mesh-ap-setup"
  local ip_service="/etc/systemd/system/mesh-ap-ip.service" ap_ip="$AP_IP_ADDRESS" escaped_config_path

  if [ "$AP_CHANNEL" -gt 14 ]; then
    hw_mode="a"
  fi

  info "Configuring Wi-Fi access point on ${AP_INTERFACE} with static address ${AP_IP_CIDR}."

  install -d -m 0755 /etc/hostapd
  install -d -m 0755 /etc/dnsmasq.d

  install -m 0640 -o root -g root /dev/null "$hostapd_conf"
  cat >"$hostapd_conf" <<EOF
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
interface=$AP_INTERFACE
driver=nl80211
ssid=$AP_SSID
country_code=$AP_COUNTRY
hw_mode=$hw_mode
channel=$AP_CHANNEL
wmm_enabled=1
ieee80211d=1
ieee80211h=1
ieee80211n=1
ieee80211ac=1
ieee80211w=2
sae_require_mfp=1
sae_pwe=1
wpa=2
wpa_key_mgmt=WPA-PSK SAE
rsn_pairwise=CCMP
auth_algs=1
wpa_passphrase=$AP_PSK
sae_password=$AP_PSK
beacon_int=100
ignore_broadcast_ssid=0
EOF

  install -m 0644 -o root -g root /dev/null "$default_hostapd"
  cat >"$default_hostapd" <<EOF
DAEMON_CONF="$hostapd_conf"
EOF

  if [ -z "$ap_ip" ]; then
    ap_ip="${AP_IP_CIDR%%/*}"
  fi

  install -m 0644 -o root -g root /dev/null "$dnsmasq_conf"
  cat >"$dnsmasq_conf" <<EOF
interface=$AP_INTERFACE
bind-interfaces
dhcp-range=$AP_DHCP_RANGE_START,$AP_DHCP_RANGE_END,$AP_DHCP_LEASE
dhcp-option=option:router,$ap_ip
dhcp-option=option:dns-server,$ap_ip
log-dhcp
EOF

  install -m 0755 -o root -g root /dev/null "$ip_setup_script"
  cat >"$ip_setup_script" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${MESH_CONFIG_PATH:-__MESH_CONFIG_PATH__}"

if [ -r "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
else
  echo "Configuration file '$CONFIG_FILE' does not exist or is not readable." >&2
  exit 1
fi

interface="${AP_INTERFACE:-wlan0}"
cidr="${AP_IP_CIDR:-10.0.0.1/24}"

ip_bin="$(command -v ip)"

if [ -z "$ip_bin" ]; then
  echo "ip command not found" >&2
  exit 1
fi

"$ip_bin" link set "$interface" up
"$ip_bin" address replace "$cidr" dev "$interface"
EOF

  escaped_config_path=$(printf '%s\n' "$CONFIG_FILE" | sed 's/[&]/\\&/g')
  sed -i "s|__MESH_CONFIG_PATH__|$escaped_config_path|g" "$ip_setup_script"

  install -m 0644 -o root -g root /dev/null "$ip_service"
  cat >"$ip_service" <<EOF
[Unit]
Description=Configure Mesh access point interface
After=network-pre.target
Before=hostapd.service dnsmasq.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=$ip_setup_script
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  if "$ip_setup_script"; then
    info "Assigned ${AP_IP_CIDR} to ${AP_INTERFACE}."
  else
    warn "Failed to assign ${AP_IP_CIDR} to ${AP_INTERFACE}; check mesh-ap-setup script."
  fi

  if [ -n "$SYSTEMCTL" ]; then
    $SYSTEMCTL daemon-reload
    $SYSTEMCTL unmask hostapd.service >/dev/null 2>&1 || true
    $SYSTEMCTL unmask dnsmasq.service >/dev/null 2>&1 || true
    $SYSTEMCTL enable mesh-ap-ip.service hostapd.service dnsmasq.service
    $SYSTEMCTL restart mesh-ap-ip.service || warn "Failed to trigger mesh-ap-ip.service"
    $SYSTEMCTL restart hostapd.service || warn "Failed to start hostapd.service"
    $SYSTEMCTL restart dnsmasq.service || warn "Failed to start dnsmasq.service"
  else
    warn "systemctl not available; start hostapd and dnsmasq manually."
  fi
}

  # === Installation B.A.T.M.A.N.-adv mesh-netwerk (bat0)
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
CONFIG_FILE="${MESH_CONFIG_PATH:-__MESH_CONFIG_PATH__}"

if [ -r "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
else
  echo "Configuration file '$CONFIG_FILE' does not exist or is not readable." >&2
  exit 1
fi

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

  sed -i "s|__MESH_CONFIG_PATH__|$(printf '%s\n' "$CONFIG_FILE" | sed 's/[&]/\\&/g')|g" /usr/local/sbin/meshctl

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

  # === Installing packages
install_packages() {
  PACKAGES=(
    nano
    batctl
    python3
    python3-pip
    python3-cryptography
    python3-serial
    git
    hostapd
    dnsmasq
    nftables
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
  configure_access_point
  setup_mesh_services
  install_reticulum_services
  configure_log_rotation
  apt-get autoremove -y
  apt-get clean
  log_installation_summary
  prompt_reboot
}

main "$@"
