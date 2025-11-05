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

LOGFILE="/var/log/mesh-install.log"
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
  local ts
  ts=$(timestamp)
  printf '%s\n' "[$ts] $*"
}

info() {
  local ts message formatted
  ts=$(timestamp)
  message="INFO: $*"
  formatted="[$ts] ${message}"
  if [ -e /proc/$$/fd/3 ]; then
    printf '%s\n' "$formatted" >&3
  fi
  printf '%s\n' "$formatted"
}

warn() {
  local ts message formatted
  ts=$(timestamp)
  message="WARN: $*"
  formatted="[$ts] ${message}"
  if [ -e /proc/$$/fd/3 ]; then
    printf '%s\n' "$formatted" >&3
  fi
  printf '%s\n' "$formatted"
}

error() {
  local ts message formatted
  ts=$(timestamp)
  message="ERROR: $*"
  formatted="[$ts] ${message}"
  if [ -e /proc/$$/fd/3 ]; then
    printf '%s\n' "$formatted" >&3
  fi
  printf '%s\n' "$formatted" >&2
}

  # === log installation summary helper
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

  # === Defining attended of unattended install helpers
usage() {
  cat <<USAGE
Usage: installer.sh [--attended | --unattended]

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
  local cidr="$1"
  python3 - "$cidr" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)

if network.version != 4:
    sys.exit(1)
PY
}

validate_ipv4_address() {
  local ip="$1"
  python3 - "$ip" <<'PY'
import ipaddress
import sys

try:
    addr = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)

if addr.version != 4:
    sys.exit(1)
PY
}

ip_in_range() {
  local ip="$1" start="$2" end="$3"
  python3 - "$ip" "$start" "$end" <<'PY'
import ipaddress
import sys

try:
    ip, start, end = (ipaddress.ip_address(arg) for arg in sys.argv[1:4])
except ValueError:
    sys.exit(1)

sys.exit(0 if int(start) <= int(ip) <= int(end) else 1)
PY
}

validate_dhcp_range() {
  local cidr="$1" start="$2" end="$3"
  python3 - "$cidr" "$start" "$end" <<'PY'
import ipaddress
import sys

try:
    network = ipaddress.ip_network(sys.argv[1], strict=False)
    start = ipaddress.ip_address(sys.argv[2])
    end = ipaddress.ip_address(sys.argv[3])
except ValueError:
    sys.exit(1)

if network.version != 4 or start.version != 4 or end.version != 4:
    sys.exit(1)

if start not in network or end not in network:
    sys.exit(1)

if int(start) > int(end):
    sys.exit(1)
PY
}

validate_wpa_passphrase() {
  local passphrase="$1" length
  length=${#passphrase}
  [ "$length" -ge 8 ] && [ "$length" -le 63 ]
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
    if "$SYSTEMCTL" list-unit-files "${service}.service" >/dev/null 2>&1; then
      active=$("$SYSTEMCTL" is-active "${service}.service" 2>/dev/null || true)
      enabled=$("$SYSTEMCTL" is-enabled "${service}.service" 2>/dev/null || true)
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

  log_service_status mesh rnsd
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

  : "${MESH_ID:=MESHNODE}"
  : "${IFACE:=wlan1}"
  : "${BATIF:=bat0}"
  : "${IP_CIDR:=192.168.0.1/24}"
  : "${COUNTRY:=BE}"
  : "${FREQ:=5180}"
  : "${BANDWIDTH:=HT20}"
  : "${MTU:=1532}"
  : "${BSSID:=02:12:34:56:78:9A}"
  : "${AP_INTERFACE:=wlan0}"
  : "${AP_SSID:=Node1}"
  : "${AP_PSK:=SuperSecret123}"
  : "${AP_CHANNEL:=6}"
  : "${AP_COUNTRY:=BE}"
  : "${AP_IP_CIDR:=10.0.0.1/24}"
  : "${AP_DHCP_RANGE_START:=10.0.0.100}"
  : "${AP_DHCP_RANGE_END:=10.0.0.200}"
  : "${AP_DHCP_LEASE:=12h}"
  : "${BAT_WIRED_INTERFACES:=}"
  : "${ENABLE_AP_BRIDGE:=no}"
  : "${BRIDGE_NAME:=br-mesh}"
  : "${BRIDGE_IP_CIDR:=}"
  : "${BRIDGE_STP:=on}"
  : "${AP_ROUTING_MODE:=disabled}"
  : "${AP_ROUTING_PEERS:=bat0}"
  : "${AP_ROUTING_NAT_EGRESS:=}"

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
    ask_hidden "Access point WPA2 passphrase" "$AP_PSK" AP_PSK
    ask "Access point channel" "$AP_CHANNEL" AP_CHANNEL
    ask "Access point country code" "$AP_COUNTRY" AP_COUNTRY
    ask "Access point IP/CIDR" "$AP_IP_CIDR" AP_IP_CIDR
    ask "Access point DHCP range start" "$AP_DHCP_RANGE_START" AP_DHCP_RANGE_START
    ask "Access point DHCP range end" "$AP_DHCP_RANGE_END" AP_DHCP_RANGE_END
    ask "Access point DHCP lease" "$AP_DHCP_LEASE" AP_DHCP_LEASE
    ask "Wired interfaces to join batman (space-separated)" "$BAT_WIRED_INTERFACES" BAT_WIRED_INTERFACES
    ask "Bridge AP onto mesh? (yes/no)" "$ENABLE_AP_BRIDGE" ENABLE_AP_BRIDGE
    ask "Bridge name" "$BRIDGE_NAME" BRIDGE_NAME
    ask "Bridge IP/CIDR (leave empty to reuse mesh IP)" "$BRIDGE_IP_CIDR" BRIDGE_IP_CIDR
    ask "Bridge STP (on/off)" "$BRIDGE_STP" BRIDGE_STP
    ask "AP routing mode (disabled/route/nat)" "$AP_ROUTING_MODE" AP_ROUTING_MODE
    ask "AP routing peers (space-separated)" "$AP_ROUTING_PEERS" AP_ROUTING_PEERS
    ask "AP NAT egress interface" "$AP_ROUTING_NAT_EGRESS" AP_ROUTING_NAT_EGRESS
  else
    info "Running in unattended mode; using configuration defaults for mesh."
  fi

  if ! validate_ipv4_cidr "$IP_CIDR"; then
    die "Mesh IP/CIDR '$IP_CIDR' is invalid. Rerun the installer with a valid value."
  fi

  if [ -z "$AP_INTERFACE" ]; then
    die "Access point interface cannot be empty."
  fi

  if ! [[ "$AP_CHANNEL" =~ ^[0-9]+$ ]]; then
    die "Access point channel '$AP_CHANNEL' must be a numeric value."
  fi

  if ! validate_ipv4_cidr "$AP_IP_CIDR"; then
    die "Access point IP/CIDR '$AP_IP_CIDR' is invalid. Rerun the installer with a valid value."
  fi

  local bridge_enabled="${ENABLE_AP_BRIDGE,,}" routing_mode="${AP_ROUTING_MODE,,}" stp_mode="${BRIDGE_STP,,}" effective_ap_cidr="$AP_IP_CIDR"

  case "$bridge_enabled" in
    yes|no) ;;
    *) die "Bridge toggle must be 'yes' or 'no'.";;
  esac

  if [ -z "$BRIDGE_NAME" ] && [ "$bridge_enabled" = "yes" ]; then
    die "Bridge name cannot be empty when bridging is enabled."
  fi

  if [ -n "$BRIDGE_IP_CIDR" ] && ! validate_ipv4_cidr "$BRIDGE_IP_CIDR"; then
    die "Bridge IP/CIDR '$BRIDGE_IP_CIDR' is invalid."
  fi

  case "$stp_mode" in
    on|off) ;;
    *) die "Bridge STP must be 'on' or 'off'.";;
  esac

  case "$routing_mode" in
    disabled|route|nat) ;;
    *) die "AP routing mode must be one of disabled, route, or nat.";;
  esac

  if [ "$bridge_enabled" = "yes" ] && [ "$routing_mode" != "disabled" ]; then
    die "AP bridging and routing modes are mutually exclusive; disable routing when bridging is enabled."
  fi

  if [ "$routing_mode" = "nat" ] && [ -z "$AP_ROUTING_NAT_EGRESS" ]; then
    die "AP NAT egress interface must be set when routing mode is 'nat'."
  fi

  ENABLE_AP_BRIDGE="$bridge_enabled"
  AP_ROUTING_MODE="$routing_mode"
  BRIDGE_STP="$stp_mode"

  if [ "$bridge_enabled" = "yes" ]; then
    if [ -n "$BRIDGE_IP_CIDR" ]; then
      effective_ap_cidr="$BRIDGE_IP_CIDR"
    else
      effective_ap_cidr="$IP_CIDR"
    fi
  fi

  AP_EFFECTIVE_CIDR="$effective_ap_cidr"
  AP_IP_ADDRESS="${AP_EFFECTIVE_CIDR%%/*}"

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

  if ! validate_dhcp_range "$AP_EFFECTIVE_CIDR" "$AP_DHCP_RANGE_START" "$AP_DHCP_RANGE_END"; then
    die "DHCP range $AP_DHCP_RANGE_START - $AP_DHCP_RANGE_END is not valid for subnet $AP_EFFECTIVE_CIDR."
  fi

  if ip_in_range "$AP_IP_ADDRESS" "$AP_DHCP_RANGE_START" "$AP_DHCP_RANGE_END"; then
    die "Access point IP '$AP_IP_ADDRESS' overlaps with the DHCP range."
  fi

  INTERACTIVE_MODE=$interactive
}

update_system() {
  info "Starting operating system update and upgrade."
  apt-get update -y
  apt-get upgrade -y
  info "Operating system update and upgrade complete."
}

ensure_networkmanager_unmanages_interfaces() {
  if ! command_exists nmcli; then
    return
  fi

  local nm_conf_dir="/etc/NetworkManager/conf.d"
  local unmanaged_file="$nm_conf_dir/mesh-radio-unmanaged.conf"
  local -a interfaces=("$IFACE")
  local unmanaged_devices="" nm_iface interface_label=""

  if [ -n "${AP_INTERFACE:-}" ] && [ "$AP_INTERFACE" != "$IFACE" ]; then
    interfaces+=("$AP_INTERFACE")
  fi

  install -d -m 0755 "$nm_conf_dir"

  for nm_iface in "${interfaces[@]}"; do
    if [ -n "$nm_iface" ]; then
      if [ -n "$unmanaged_devices" ]; then
        unmanaged_devices+=";"
      fi
      unmanaged_devices+="interface-name:${nm_iface}"
    fi
  done

  if [ -n "$unmanaged_devices" ]; then
    cat >"$unmanaged_file" <<EOF
[keyfile]
unmanaged-devices=$unmanaged_devices
EOF

    interface_label="${interfaces[*]}"
    info "Configured NetworkManager to leave the following interfaces unmanaged: ${interface_label}."
  fi

  nmcli general reload || true

  for nm_iface in "${interfaces[@]}"; do
    if [ -n "$nm_iface" ]; then
      nmcli device disconnect "$nm_iface" >/dev/null 2>&1 || true
      nmcli device set "$nm_iface" managed no >/dev/null 2>&1 || true
    fi
  done
}

configure_access_point() {
  local hw_mode="g" hostapd_conf="/etc/hostapd/hostapd.conf" dnsmasq_conf="/etc/dnsmasq.d/mesh-ap.conf"
  local default_hostapd="/etc/default/hostapd" ip_setup_script="/usr/local/sbin/mesh-ap-setup"
  local ip_service="/etc/systemd/system/mesh-ap-ip.service" ap_ip="$AP_IP_ADDRESS"
  local bridge_enabled="${ENABLE_AP_BRIDGE,,}"
  local ip_target="$AP_INTERFACE" dnsmasq_iface="$AP_INTERFACE" ip_cidr_value="$AP_EFFECTIVE_CIDR"

  if [ "$bridge_enabled" = "yes" ]; then
    ip_target="$BRIDGE_NAME"
    dnsmasq_iface="$BRIDGE_NAME"
  fi

  if [ -z "$ap_ip" ]; then
    ap_ip="${ip_cidr_value%%/*}"
  fi

  if [ "$AP_CHANNEL" -gt 14 ]; then
    hw_mode="a"
  fi

  info "Configuring Wi-Fi access point on ${AP_INTERFACE} with management IP ${ip_cidr_value}."

  ensure_networkmanager_unmanages_interfaces

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
# WPA2-only configuration for broad hardware compatibility. Enable SAE manually if supported.
ieee80211w=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
auth_algs=1
wpa_passphrase=$AP_PSK
beacon_int=100
ignore_broadcast_ssid=0
EOF

  if [ "$bridge_enabled" = "yes" ]; then
    cat >>"$hostapd_conf" <<EOF
bridge=$BRIDGE_NAME
EOF
  fi

  install -m 0644 -o root -g root /dev/null "$default_hostapd"
  cat >"$default_hostapd" <<EOF
DAEMON_CONF="$hostapd_conf"
EOF

  install -m 0644 -o root -g root /dev/null "$dnsmasq_conf"
  cat >"$dnsmasq_conf" <<EOF
interface=$dnsmasq_iface
bind-interfaces
dhcp-range=$AP_DHCP_RANGE_START,$AP_DHCP_RANGE_END,$AP_DHCP_LEASE
dhcp-option=option:router,$ap_ip
dhcp-option=option:dns-server,$ap_ip
log-dhcp
EOF

  install -m 0755 -o root -g root /dev/null "$ip_setup_script"
  cat >"$ip_setup_script" <<EOF
#!/usr/bin/env bash
set -euo pipefail

interface="$ip_target"
cidr="$ip_cidr_value"

ip_bin="$(command -v ip)"

if [ -z "\$ip_bin" ]; then
  echo "ip command not found" >&2
  exit 1
fi

"\$ip_bin" link set "\$interface" up
"\$ip_bin" address replace "\$cidr" dev "\$interface"
EOF

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

  if [ "$bridge_enabled" = "yes" ]; then
    info "Access point DHCP and IP configuration will target bridge ${BRIDGE_NAME}."
  fi

  if "$ip_setup_script"; then
    info "Assigned ${ip_cidr_value} to ${ip_target}."
  else
    warn "Failed to assign ${ip_cidr_value} to ${ip_target}; check mesh-ap-setup script."
  fi

  if [ -n "$SYSTEMCTL" ]; then
    $SYSTEMCTL daemon-reload
    $SYSTEMCTL unmask hostapd.service >/dev/null 2>&1 || true
    $SYSTEMCTL unmask dnsmasq.service >/dev/null 2>&1 || true
    if ! $SYSTEMCTL enable mesh-ap-ip.service hostapd.service dnsmasq.service; then
      warn "Failed to enable one or more access point services; verify hostapd/dnsmasq installation."
    fi
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
  cat >/usr/local/sbin/meshctl <<EOF
#!/usr/bin/env bash
set -euo pipefail
CMD="\${1:-status}"

MESH_ID="$MESH_ID"
FREQ="$FREQ"
BANDWIDTH="$BANDWIDTH"
BSSID="$BSSID"
IFACE="$IFACE"
COUNTRY="$COUNTRY"
BATIF="$BATIF"
MTU="$MTU"
IP_CIDR="$IP_CIDR"
AP_INTERFACE="$AP_INTERFACE"
BAT_WIRED_INTERFACES="$BAT_WIRED_INTERFACES"
ENABLE_AP_BRIDGE="$ENABLE_AP_BRIDGE"
BRIDGE_NAME="$BRIDGE_NAME"
BRIDGE_IP_CIDR="$BRIDGE_IP_CIDR"
BRIDGE_STP="$BRIDGE_STP"
AP_ROUTING_MODE="$AP_ROUTING_MODE"
AP_ROUTING_PEERS="$AP_ROUTING_PEERS"
AP_ROUTING_NAT_EGRESS="$AP_ROUTING_NAT_EGRESS"
AP_EFFECTIVE_CIDR="$AP_EFFECTIVE_CIDR"

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

mesh_supported() {
  iw list 2>/dev/null | awk '/Supported interface modes/{p=1} p{print} /Supported commands/{exit}' | grep -qi "mesh point"
}

have_iptables() {
  command -v iptables >/dev/null 2>&1
}

iptables_add() {
  if ! have_iptables; then
    warn "iptables not available; skipping firewall rule addition"
    return 0
  fi
  local table="\$1"; shift
  local chain="\$1"; shift
  local -a rule=("\$@")
  local -a check=(iptables)
  if [ "\$table" != "filter" ]; then
    check+=(-t "\$table")
  fi
  check+=(-C "\$chain")
  check+=("\${rule[@]}")
  if ! "\${check[@]}" >/dev/null 2>&1; then
    local -a add=(iptables)
    if [ "\$table" != "filter" ]; then
      add+=(-t "\$table")
    fi
    add+=(-A "\$chain")
    add+=("\${rule[@]}")
    if ! "\${add[@]}" >/dev/null 2>&1; then
      warn "Failed to add iptables rule to \$chain (\${rule[*]})"
    fi
  fi
}

iptables_delete() {
  have_iptables || return 0
  local table="\$1"; shift
  local chain="\$1"; shift
  local -a rule=("\$@")
  local -a check=(iptables)
  if [ "\$table" != "filter" ]; then
    check+=(-t "\$table")
  fi
  local -a delete=(iptables)
  if [ "\$table" != "filter" ]; then
    delete+=(-t "\$table")
  fi
  delete+=(-D "\$chain")
  delete+=("\${rule[@]}")
  while "\${check[@]}" -C "\$chain" "\${rule[@]}" >/dev/null 2>&1; do
    if ! "\${delete[@]}" >/dev/null 2>&1; then
      break
    fi
  done
}

join_wired_interfaces_up() {
  local dev
  for dev in $BAT_WIRED_INTERFACES; do
    [ -n "\$dev" ] || continue
    ip link set "\$dev" down >/dev/null 2>&1 || true
    batctl if add "\$dev" >/dev/null 2>&1 || true
    ip link set "\$dev" up >/dev/null 2>&1 || true
  done
}

join_wired_interfaces_down() {
  local dev
  for dev in $BAT_WIRED_INTERFACES; do
    [ -n "\$dev" ] || continue
    batctl if del "\$dev" >/dev/null 2>&1 || true
    ip link set "\$dev" down >/dev/null 2>&1 || true
  done
}

configure_bridge_up() {
  if [ "$ENABLE_AP_BRIDGE" != "yes" ]; then
    return 0
  fi

  local br="$BRIDGE_NAME" stp_state=0 cidr="$AP_EFFECTIVE_CIDR"

  ip link show "\$br" >/dev/null 2>&1 || ip link add name "\$br" type bridge

  if [ "$BRIDGE_STP" = "on" ]; then
    stp_state=1
  fi

  ip link set "\$br" type bridge stp_state "\$stp_state" >/dev/null 2>&1 || true
  ip addr flush dev "$BATIF" >/dev/null 2>&1 || true
  ip link set "$BATIF" up >/dev/null 2>&1 || true
  ip link set "$BATIF" master "\$br" >/dev/null 2>&1 || true

  if [ -n "$AP_INTERFACE" ]; then
    ip link set "$AP_INTERFACE" down >/dev/null 2>&1 || true
    ip addr flush dev "$AP_INTERFACE" >/dev/null 2>&1 || true
    ip link set "$AP_INTERFACE" master "\$br" >/dev/null 2>&1 || true
    ip link set "$AP_INTERFACE" up >/dev/null 2>&1 || true
  fi

  ip link set "\$br" up >/dev/null 2>&1 || true

  if [ -n "\$cidr" ]; then
    ip addr replace "\$cidr" dev "\$br" >/dev/null 2>&1 || true
  fi
}

configure_bridge_down() {
  if [ "$ENABLE_AP_BRIDGE" != "yes" ]; then
    return 0
  fi

  local br="$BRIDGE_NAME"

  if [ -n "$AP_INTERFACE" ]; then
    ip link set "$AP_INTERFACE" nomaster >/dev/null 2>&1 || true
  fi

  ip link set "$BATIF" nomaster >/dev/null 2>&1 || true
  ip addr flush dev "\$br" >/dev/null 2>&1 || true
  ip link set "\$br" down >/dev/null 2>&1 || true
  ip link delete "\$br" type bridge >/dev/null 2>&1 || true
}

configure_routing_up() {
  if [ "$AP_ROUTING_MODE" = "disabled" ] || [ -z "$AP_INTERFACE" ]; then
    return 0
  fi

  mkdir -p /run >/dev/null 2>&1 || true

  if [ -w /proc/sys/net/ipv4/ip_forward ]; then
    cat /proc/sys/net/ipv4/ip_forward > /run/meshctl-ip-forward 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || warn "Failed to enable IPv4 forwarding"
  fi

  local peer
  for peer in $AP_ROUTING_PEERS; do
    [ -n "\$peer" ] || continue
    iptables_add filter FORWARD -i "$AP_INTERFACE" -o "\$peer" -j ACCEPT
    iptables_add filter FORWARD -i "\$peer" -o "$AP_INTERFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  if [ "$AP_ROUTING_MODE" = "nat" ] && [ -n "$AP_ROUTING_NAT_EGRESS" ]; then
    iptables_add nat POSTROUTING -o "$AP_ROUTING_NAT_EGRESS" -j MASQUERADE
  fi
}

configure_routing_down() {
  if [ "$AP_ROUTING_MODE" = "disabled" ] || [ -z "$AP_INTERFACE" ]; then
    return 0
  fi

  local peer
  for peer in $AP_ROUTING_PEERS; do
    [ -n "\$peer" ] || continue
    iptables_delete filter FORWARD -i "$AP_INTERFACE" -o "\$peer" -j ACCEPT
    iptables_delete filter FORWARD -i "\$peer" -o "$AP_INTERFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  if [ "$AP_ROUTING_MODE" = "nat" ] && [ -n "$AP_ROUTING_NAT_EGRESS" ]; then
    iptables_delete nat POSTROUTING -o "$AP_ROUTING_NAT_EGRESS" -j MASQUERADE
  fi

  if [ -f /run/meshctl-ip-forward ] && [ -w /proc/sys/net/ipv4/ip_forward ]; then
    local prev
    prev=$(cat /run/meshctl-ip-forward 2>/dev/null || echo 0)
    sysctl -w net.ipv4.ip_forward="\$prev" >/dev/null 2>&1 || true
    rm -f /run/meshctl-ip-forward
  fi
}

mesh_up() {
  modprobe batman-adv
  iw reg set "\$COUNTRY" || true
  command -v nmcli >/dev/null 2>&1 && nmcli dev set "\$IFACE" managed no || true

  ip link set "\$IFACE" down || true
  if mesh_supported; then
    iw dev "\$IFACE" set type mp
    ip link set "\$IFACE" up
    iw dev "\$IFACE" mesh join "\$MESH_ID" freq "\$FREQ" "\$BANDWIDTH"
  else
    iw dev "\$IFACE" set type ibss
    ip link set "\$IFACE" up
    iw dev "\$IFACE" ibss join "\$MESH_ID" "\$FREQ" "\$BANDWIDTH" fixed-freq "\$BSSID"
  fi

  batctl if add "\$IFACE" >/dev/null 2>&1 || true
  ip link set up dev "\$IFACE"
  ip link set up dev "\$BATIF"
  ip link set dev "\$BATIF" mtu "\$MTU" || true

  join_wired_interfaces_up

  if [ "\$ENABLE_AP_BRIDGE" = "yes" ]; then
    configure_bridge_up
  else
    ip addr replace "\$IP_CIDR" dev "\$BATIF" >/dev/null 2>&1 || true
  fi

  configure_routing_up
}

mesh_down() {
  configure_routing_down

  if [ "\$ENABLE_AP_BRIDGE" = "yes" ]; then
    configure_bridge_down
  else
    ip addr flush dev "\$BATIF" >/dev/null 2>&1 || true
  fi

  join_wired_interfaces_down

  batctl if del "\$IFACE" 2>/dev/null || true
  ip link set "\$BATIF" down || true
  iw dev "\$IFACE" mesh leave 2>/dev/null || true
  ip link set "\$IFACE" down || true
}

mesh_status() {
  echo "== Interfaces =="; ip -br link | grep -E "\$IFACE|\$BATIF" || true
  if [ "\$ENABLE_AP_BRIDGE" = "yes" ]; then
    echo "== Bridge ${BRIDGE_NAME} =="; ip -br addr show "\$BRIDGE_NAME" 2>/dev/null || true
  fi
  if [ -n "\$BAT_WIRED_INTERFACES" ]; then
    echo "== Wired interfaces =="
    local dev
    for dev in \$BAT_WIRED_INTERFACES; do
      ip -br link show "\$dev" 2>/dev/null || true
    done
  fi
  echo "== batctl if =="; batctl if || true
  echo "== originators =="; batctl -m "\$BATIF" o 2>/dev/null || true
  echo "== neighbors =="; batctl n 2>/dev/null || true
  echo "== 802.11s mpath =="; iw dev "\$IFACE" mpath dump 2>/dev/null || true
  echo "== stations (IBSS) =="; iw dev "\$IFACE" station dump 2>/dev/null || true
}

case "\$CMD" in
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
