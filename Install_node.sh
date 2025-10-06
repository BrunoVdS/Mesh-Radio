#!/bin/bash

    # ==============================================================================

    ###                       NEW NODE INSTALL SCRIPT                            ###

    ###          Version 1.0                                                     ###

    # ==============================================================================


# === Config =======================================================================

  # === Exit on errors, unset vars, or failed pipes; show an error with line number if any command fails
set -Eeuo pipefail
trap 'error "Unexpected error on line $LINENO"; exit 1' ERR

  # === Forcing apt/dpkg to run without prompting for user input, letting the script perform package operations unattended
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

  # === LOGFILE - variables
    # Log file location
LOGFILE="/var/log/mesh-install.log"

    # Create timestamp variable
timestamp() { date +%F\ %T; }

    # Log helpers (log, info, warn and error)
log()   { echo "[$(timestamp)] $*" >>"$LOGFILE"; }

info()  {
  local message="INFO: $*"
  if [ -e /proc/$$/fd/3 ]; then
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE" >&3
  else
    echo "[$(timestamp)] ${message}"
  fi
}

warn()  {
  local message="WARN: $*"
  if [ -e /proc/$$/fd/3 ]; then
    echo "[$(timestamp)] ${message}" | tee -a "$LOGFILE" >&3
  else
    echo "[$(timestamp)] ${message}"
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

  # === Define a function to check if a command exists; store path to systemctl if found, else empty
command_exists() { command -v "$1" >/dev/null ; }
SYSTEMCTL=$(command -v systemctl || true)

  # === OS validation
require_raspberry_pi_os() {
  if [ ! -r /etc/os-release ]; then
    echo "Unable to detect operating system (missing /etc/os-release)."
    exit 1  
  fi

  . /etc/os-release
  RPI_OS_PRETTY_NAME=${PRETTY_NAME:-unknown}

  if [[ ${ID:-} != "raspbian" ]] && [[ ${NAME:-} != *"Raspberry Pi"* ]] && [[ ${PRETTY_NAME:-} != *"Raspberry Pi"* ]]; then
    echo "Unsupported operating system: ${RPI_OS_PRETTY_NAME}. This installer only supports Raspberry Pi OS."
    exit 1
  fi
}

echo "Raspberry OS has been detected (/etc/os-release)."


# === Root only
if [[ $EUID -ne 0 ]]; then
  error "This installer must be run as root."
  exit 1
fi

info "Running as root (user $(id -un))."


# === Logging
  # Creating the log file
echo "Creating log file."

install -m 0640 -o root -g adm /dev/null "$LOGFILE"
exec 3>&1
exec >>"$LOGFILE" 2>&1


  # First logs added
info ""
info "================================================="
info "===                                           ==="
info "===    Installation of the Mesh Radio v1.0.   ==="
info "===                                           ==="
info "================================================="
info ""
info ""

  # Add system info
info "Summary: OS=${RPI_OS_PRETTY_NAME:-$(. /etc/os-release; echo $PRETTY_NAME)}, Kernel=$(uname -r))"

  #add some info that before did not got logged,
info "Log file is created."
info "location: /var/log/mesh-install.log"

info "Detected operating system: ${RPI_OS_PRETTY_NAME:-unknown}."

  # Add we are root
info "Confirmed running as root."


# === Housekeeping
info "Housekeeping starting."

  # Perform a small cleanup in the user’s home directory
TARGET_USER=${SUDO_USER:-$USER}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
TARGET_GROUP=$(id -gn "$TARGET_USER" 2>/dev/null || echo "$TARGET_USER")
if [ -z "$TARGET_HOME" ]; then
  TARGET_HOME=/root
fi
HOME_DIR=${TARGET_HOME:-/root}
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME/linux" ] && rm -rf "$TARGET_HOME/linux" || true

info "Housekeeping is complete."


# === System update
info "Upgrade and Update of the operatingsystem starting."

apt-get update -y
apt-get -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        dist-upgrade -y

info "Update and Upgrade of the operatingsystem is complete."

sleep 10


# === Prerequisites - install needed packages ===================================
  # === Pakages list
PACKAGES=(
  nano
  python3
  python3-pip
  python3-cryptography
  python3-serial
  aircrack-ng
  iperf3
  ufw
  net-tools
  build-essential
  libssl-dev
  libnl-3-dev
  libnl-genl-3-dev
  pkg-config
  git
  gnupg
)

info "Package install starting."

  # === Automate install (faster)
if apt-get install -y --no-install-recommends "${PACKAGES[@]}"; then
  info "Bulk install/upgrade succeeded."
else
  info "Bulk install failed; falling back to per-package handling."

  # === Fallback: per-packages processing
for pkg in "${PACKAGES[@]}"; do
    info "Processing: $pkg ===="
    if ! apt-cache policy "$pkg" | grep -q "Candidate:"; then
      log "Warning: package '$pkg' not found in apt policy. Skipping."
      continue
    fi
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      log "'$pkg' already installed. Attempting upgrade (if available)..."
      apt-get install --only-upgrade -y "$pkg" || \
         error "Upgrade failed for $pkg (continuing)."
    else
      log "'$pkg' not installed. Installing now..."
      apt-get install -y --no-install-recommends "$pkg" || \
        error "Installation failed for $pkg (continuing)."
    fi
  done
fi

  # === Update the system with the install of all new packages
apt-get update -y

info "Installation of all packages is complete."

sleep 10


  # === Create PIP_INSTALL for Reticulum and Flask
info "Create PIP_INSTALL variable"

PIP_INSTALL=(python3 -m pip install --upgrade)
if python3 -m pip install --help 2>&1 | grep -q -- '--break-system-packages'; then
  PIP_INSTALL+=(--break-system-packages)
fi

info "PIP_INSTALL variable created and ready to use"


# === Install B.A.T.M.A.N.-adv ===================================================
info "Installing B.A.T.M.A.N.-Adv."

  # === Fast detection: is the module available without the need of installing it?
if modprobe -n batman-adv 2>/dev/null; then
  log "B.A.T.M.A.N.-Adv kernelmodule is available (dry-run ok) — skip installation proces."
else
  log "B.A.T.M.A.N.-Adv module not available. Create and install the B.A.T.M.A.N.-Adv module."

  # === Building the B.A.T.M.A.N.-Adv module
    # Raspberry Pi OS (Raspbian/Debian voor Pi)
  apt-get install -y raspberrypi-kernel-headers || true

    # DKMS-build of B.A.T.M.A.N.-Adv
  apt-get install -y batman-adv-dkms || true
  dpkg-reconfigure -fnoninteractive batman-adv-dkms || true
fi

  # === Load the B.A.T.M.A.N.-Adv module
if ! modprobe batman-adv 2>/dev/null; then
  if [ -d "/sys/module/batman_adv" ]; then
    log "B.A.T.M.A.N.-Adv is build in as module; modprobe not nessesary."
  elif grep -qE '(^|/| )batman-adv(\.ko(\.(xz|gz|zst))?)?($| )' "/lib/modules/$(uname -r)/modules.dep" 2>/dev/null; then
    info "B.A.T.M.A.N.-Adv modulebestand is present nut loading faled; continue."
  else
    error "Can't load or find B.A.T.M.A.N.-Adv . Check kernel/modules/headers."
    exit 1
  fi
fi

  # === Setting up loading at start
printf "%s\n" "batman-adv" > /etc/modules-load.d/batman-adv.conf

  # === Update the system withe the install of all new packages
apt-get update -y

  # === Install complete
info "Installation of B.A.T.M.A.N.-Adv complete."

sleep 10


# === Install Batctl =============================================================
info "Installing Batctl."

  # === Install via APT.
  if apt-cache policy batctl 2>/dev/null | grep -q "Candidate:"; then
    apt-get install -y --no-install-recommends batctl
  else
    log "Batctl not found in APT; falling back to latest source build."

  # === Fall back to latest source build
  CURRENT_DIR=$(pwd)
    install -d -m 0755 /usr/local/src
    cd /usr/local/src

    if [[ -d batctl ]]; then
      cd batctl
      git pull --ff-only
    else
      git clone https://git.open-mesh.org/batctl.git
      cd batctl
    fi

    make && make install
    cd "$CURRENT_DIR"
  fi

  # === Verify installation
  if ! batctl -v >/dev/null 2>&1; then
    error "Batctl not available after install."
    exit 1
  fi
  log "Batctl Installed: $(batctl -v | head -n1)."

  # === Update the system withe the install of all new packages
apt-get update -y

  # === Install complete
info "Installation of Batctl complete."

sleep 10


# === Install Hostapd ============================================================
info "Installing Hostpad"

  # === Settings
SERVICE_FILE="/etc/systemd/system/hostapd.service"
HOSTAPD_BIN=$(command -v hostapd || echo "/usr/local/bin/hostapd")

  # === Clone or update the official repo
install -d -m 0755 /usr/local/src
HOSTAPD_SRC_DIR=/usr/local/src/hostap
if [ -d "$HOSTAPD_SRC_DIR" ]; then
  info "Updating existing hostap source in $HOSTAPD_SRC_DIR."
  git -C "$HOSTAPD_SRC_DIR" pull --ff-only
else
  info "Cloning hostap sources into $HOSTAPD_SRC_DIR."
  git clone git://w1.fi/hostap.git "$HOSTAPD_SRC_DIR"
fi

pushd "$HOSTAPD_SRC_DIR/hostapd" >/dev/null
cp defconfig .config

  # === Build & install
HOSTAPD_BUILD_JOBS=1
if command -v nproc >/dev/null 2>&1; then
  HOSTAPD_BUILD_JOBS=$(nproc)
fi
make -j"$HOSTAPD_BUILD_JOBS"
make install
popd >/dev/null

  # === Refresh Hostapd binary path
HOSTAPD_BIN=$(command -v hostapd || echo "/usr/local/bin/hostapd")
info "Hostapd binary found at: $HOSTAPD_BIN"

  # === Collect hostapd configuration from user
HOSTAPD_CONFIG_DIR=/etc/hostapd
HOSTAPD_CONFIG_FILE="$HOSTAPD_CONFIG_DIR/hostapd.conf"
DEFAULT_SSID="takNode1"
DEFAULT_CHANNEL="1"

if [ -t 0 ]; then
  printf "Enter SSID [%s]: " "$DEFAULT_SSID" >&3
  read -r HOSTAPD_SSID <&0 || HOSTAPD_SSID=""
  HOSTAPD_SSID=${HOSTAPD_SSID:-$DEFAULT_SSID}

  while :; do
    printf "Enter channel [%s]: " "$DEFAULT_CHANNEL" >&3
    read -r HOSTAPD_CHANNEL <&0 || HOSTAPD_CHANNEL=""
    HOSTAPD_CHANNEL=${HOSTAPD_CHANNEL:-$DEFAULT_CHANNEL}
    if [[ "$HOSTAPD_CHANNEL" =~ ^[0-9]+$ ]]; then
      break
    fi
    printf "Invalid channel. Please provide a numeric value.\n" >&3
  done

  while :; do
    printf "Enter WPA2 passphrase (8-63 characters): " >&3
    read -rs HOSTAPD_PASSPHRASE <&0 || HOSTAPD_PASSPHRASE=""
    printf "\n" >&3
    if (( ${#HOSTAPD_PASSPHRASE} >= 8 && ${#HOSTAPD_PASSPHRASE} <= 63 )); then
      break
    fi
    printf "Passphrase must be between 8 and 63 characters.\n" >&3
  done
else
  HOSTAPD_SSID=$DEFAULT_SSID
  HOSTAPD_CHANNEL=$DEFAULT_CHANNEL
  HOSTAPD_PASSPHRASE="52235223"
  info "Non-interactive environment detected; using default hostapd settings."
fi

install -d -m 0755 "$HOSTAPD_CONFIG_DIR"
cat >"$HOSTAPD_CONFIG_FILE" <<EOF
interface=wlan0
ssid=$HOSTAPD_SSID
hw_mode=g
channel=$HOSTAPD_CHANNEL
auth_algs=1
wmm_enabled=1
wpa=2
wpa_passphrase=$HOSTAPD_PASSPHRASE
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF
chmod 0640 "$HOSTAPD_CONFIG_FILE"
chown root:root "$HOSTAPD_CONFIG_FILE"

info "hostapd configuration written to $HOSTAPD_CONFIG_FILE (SSID: $HOSTAPD_SSID, channel: $HOSTAPD_CHANNEL)"

# === Hostapd systemd service setup
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Hostapd IEEE 802.11 Access Point
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$HOSTAPD_BIN -P /run/hostapd.pid /etc/hostapd/hostapd.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target
EOF

info "Service file created: $SERVICE_FILE"

# === Manage hostapd
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable hostapd.service
  $SYSTEMCTL restart hostapd.service
  if $SYSTEMCTL is-active --quiet hostapd.service; then
    info "hostapd service is active."
  else
    error "hostapd service failed to start. Check journalctl -u hostapd."
    exit 1
  fi
  if $SYSTEMCTL is-enabled --quiet hostapd.service; then
    info "hostapd service enabled to start on boot."
  else
    warn "hostapd service is not enabled to start on boot."
  fi
else
  warn "systemctl not available; enable hostapd manually."
fi

  # === Update the system withe the install of all new packages
apt-get update -y

  # === Install complete
info "Hostpad installed"

sleep 10


#=== Install Flask ===============================================================

FLASK_APP_DIR="/opt/mesh-flask"
FLASK_APP_FILE="$FLASK_APP_DIR/app.py"
FLASK_ENV_DIR="/etc/mesh"
FLASK_ENV_FILE="$FLASK_ENV_DIR/flask.env"
FLASK_SERVICE_FILE="/etc/systemd/system/mesh-flask.service"

if [ -z "${TARGET_USER:-}" ] || [ "${TARGET_USER}" = "root" ]; then
  FLASK_USER_DIRECTIVE="User=root"
  FLASK_GROUP_DIRECTIVE="Group=root"
else
  FLASK_USER_DIRECTIVE="User=$TARGET_USER"
  FLASK_GROUP_DIRECTIVE="Group=$TARGET_USER"
fi

info "Installing Flask"

if python3 -m pip show flask >/dev/null 2>&1; then
  FLASK_OLD_VERSION=$(python3 -m pip show flask 2>/dev/null | awk '/Version:/ {print $2}')
  info "Flask already present (version ${FLASK_OLD_VERSION:-unknown}); ensuring it is up to date."
else
  info "Flask not detected; installing now."
fi

if "${PIP_INSTALL[@]}" flask; then
  FLASK_NEW_VERSION=$(python3 -m pip show flask 2>/dev/null | awk '/Version:/ {print $2}')
  log "Flask installed successfully: version ${FLASK_NEW_VERSION:-unknown}."
else
  error "Failed to install or upgrade Flask."
  exit 1
fi

# === Flast systemd service setup
info "Configuring Flask systemd service."

cat >"$FLASK_SERVICE_FILE" <<EOF
[Unit]
Description=Mesh Flask Application Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-$FLASK_ENV_FILE
WorkingDirectory=$FLASK_APP_DIR
ExecStart=/usr/bin/python3 -m flask run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
$FLASK_USER_DIRECTIVE
$FLASK_GROUP_DIRECTIVE

[Install]
WantedBy=multi-user.target
EOF

  # === Manage Flask
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable mesh-flask.service
  if ! $SYSTEMCTL restart mesh-flask.service; then
    warn "mesh-flask.service failed to start; check journalctl -u mesh-flask.service for details."
  fi
  $SYSTEMCTL --no-pager --full status mesh-flask.service || true
else
  warn "systemctl not available; enable mesh-flask.service manually."
fi

  # === Update the system with the install of all new packages
apt-get update -y

  # === Install complete
info "Flask installation and service configuration complete."

sleep 10


# === Install Reticulum =========================================================
info "Installing Reticulum (RNS)."

  # === Install RNS
if "${PIP_INSTALL[@]}" rns; then
  log "Reticulum installed successfully: $(python3 -m pip show rns 2>/dev/null | grep Version || echo 'unknown version')"
else
  error "Reticulum installation failed."
  exit 1
fi

  # === Check if RNS is installed
RNSD_PATH=$(command -v rnsd || true)
if [ -z "$RNSD_PATH" ]; then
  error "Unable to locate rnsd in PATH after installation."
  exit 1
fi

  # === Create Reticulum systemd service
info "Creating Reticulum systemd service."

cat >/etc/systemd/system/rnsd.service <<EOF
[Unit]
Description=Reticulum Network Stack Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$RNSD_PATH
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=rnsd

[Install]
WantedBy=multi-user.target
EOF

  # === Enable and start service
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable rnsd.service
  $SYSTEMCTL restart rnsd.service
else
  warn "systemctl not available; please enable rnsd manually."
fi

info "Reticulum systemd service is set up."

info "==> Version check:"
if "$RNSD_PATH" --version; then
  info "rnsd version OK."
else
  warn "rnsd version check failed; inspect logs if the service does not start."
fi

if command_exists rnstatus; then
  rnstatus --version || true
  info "Ready. Reticulum runs."
  info "Configs: $HOME_DIR/.config/reticulum"
  rnstatus || true
else
  warn "rnstatus command not found. Reticulum may need manual verification."
fi

if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL --no-pager --full status rnsd || true
fi

  # === Update the system withe the install of all new packages
apt-get update -y

  # === Install complete
info "Reticulum (RNS) is installed."

sleep 10


# === NomadNet ===============================================================
info "Installing NomadNet"

  # === Install NomadNet via pip (with fallback to source)
if "${PIP_INSTALL[@]}" nomadnet; then
  log "NomadNet installed successfully: $(python3 -m pip show nomadnet 2>/dev/null | grep Version || echo 'unknown version')"
else
  error "NomadNet installation failed."
  exit 1
fi

  # === Locate the NomadNet executable
NOMADNET_BIN=$(command -v nomadnet || true)
if [ -z "$NOMADNET_BIN" ]; then
  error "Unable to locate nomadnet in PATH after installation."
  exit 1
fi

  # === Prepare runtime directories for the target user
install -d -m 0755 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.local/share/nomadnet" || true
install -d -m 0755 -o "$TARGET_USER" -g "$TARGET_GROUP" "$TARGET_HOME/.config/nomadnet" || true

  # === Create NomadNet systemd service so it starts on boot
NOMADNET_SERVICE="/etc/systemd/system/nomadnet.service"
info "Creating NomadNet systemd service at $NOMADNET_SERVICE."

cat >"$NOMADNET_SERVICE" <<EOF
[Unit]
Description=NomadNet Service
After=network-online.target rnsd.service
Wants=network-online.target rnsd.service

[Service]
Type=simple
User=$TARGET_USER
Group=$TARGET_GROUP
Environment=HOME=$TARGET_HOME
WorkingDirectory=$TARGET_HOME
ExecStart=$NOMADNET_BIN --serve
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  # === Enable and start NomadNet service
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable nomadnet.service
  $SYSTEMCTL restart nomadnet.service
else
  warn "systemctl not available; please enable nomadnet manually."
fi

info "NomadNet systemd service configured."

if "$NOMADNET_BIN" --version >/dev/null 2>&1; then
  info "NomadNet version: $($NOMADNET_BIN --version 2>/dev/null | head -n1)"
else
  warn "Unable to determine NomadNet version."
fi

  # === Update the system withe the install of all new packages
apt-get update -y

sleep 10


# === Install TAK Server =========================================================
info "Installing TAK server - Single server setup"

  # === Edit Raspberry OS: Increase JVM threads
info "Changes in Raspberry OS: Increase JVM threads"

LIMITS_SOFT="*      soft      nofile      32768"
LIMITS_HARD="*      hard      nofile      32768"
if ! grep -Fxq "$LIMITS_SOFT" /etc/security/limits.conf || ! grep -Fxq "$LIMITS_HARD" /etc/security/limits.conf; then
  cat <<'EOF' >>/etc/security/limits.conf
*      soft      nofile      32768
*      hard      nofile      32768
EOF
  info "JVM thread limits appended to /etc/security/limits.conf."
else
  info "JVM thread limits already configured."
fi

info "Changes in Increase JVM threads are done"


  # === Install Java 17 openjdk
info "Verifying OpenJDK 17 installation"

REQUIRED_JAVA_MAJOR=17
JAVA_PACKAGE="openjdk-17-jre"

    # Check current Java version (if any)
if command -v java >/dev/null 2>&1; then
  java_version_raw=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
  java_major_version=${java_version_raw%%.*}
  info "Current Java version detected: ${java_version_raw:-unknown}"
else
  warn "Java runtime not found in PATH."
  java_major_version=0
fi

    # Install OpenJDK 17 if not already present or wrong version
if [ "$java_major_version" -ne "$REQUIRED_JAVA_MAJOR" ] || ! dpkg -s "$JAVA_PACKAGE" >/dev/null 2>&1; then
  log "Installing ${JAVA_PACKAGE}..."
  apt-get install -y "$JAVA_PACKAGE"
else
  info "OpenJDK 17 is already installed."
fi

    # Update the system withe the install of all new packages
apt-get update -y

    # Install complete
info "Java 17 OpenJDK step is complete"


  # === Install PostgreSQL 15 and PostGIS
info "Installing PostgreSQL 15 and PostGIS"

POSTGRES_VERSION=15
POSTGRES_PACKAGES=(
  "postgresql-${POSTGRES_VERSION}"
  "postgresql-client-${POSTGRES_VERSION}"
)
POSTGIS_PACKAGES=(
  "postgresql-${POSTGRES_VERSION}-postgis-3"
  "postgresql-${POSTGRES_VERSION}-postgis-3-scripts"
)

missing_packages=()
for pkg in "${POSTGRES_PACKAGES[@]}" "${POSTGIS_PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    missing_packages+=("$pkg")
  fi
done

if [ ${#missing_packages[@]} -eq 0 ]; then
  info "PostgreSQL $POSTGRES_VERSION and PostGIS already installed."
else
  info "The following PostgreSQL/PostGIS packages are missing: ${missing_packages[*]}"

  if command -v lsb_release >/dev/null 2>&1; then
    pg_codename=$(lsb_release -cs)
  else
    pg_codename=$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}" )
  fi

  if [ -z "${pg_codename:-}" ]; then
    error "Unable to determine distribution codename for PostgreSQL repository."
    exit 1
  fi

  pg_repo_line="deb https://apt.postgresql.org/pub/repos/apt ${pg_codename}-pgdg main"
  pg_sources_file="/etc/apt/sources.list.d/pgdg.list"

  if [ ! -f "$pg_sources_file" ] || ! grep -Fxq "$pg_repo_line" "$pg_sources_file"; then
    info "Adding PostgreSQL APT repository ($pg_repo_line)."
    printf '%s\n' "$pg_repo_line" >>"$pg_sources_file"
  else
    info "PostgreSQL APT repository already configured."
  fi

  pg_keyring="/etc/apt/trusted.gpg.d/postgresql.org.gpg"
  if [ ! -s "$pg_keyring" ]; then
    info "Importing PostgreSQL signing key."
    wget -qO- https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | tee "$pg_keyring" >/dev/null
  else
    info "PostgreSQL signing key already present."
  fi

  apt-get update
  apt-get install -y "${missing_packages[@]}"
fi

if command -v psql >/dev/null 2>&1; then
  installed_psql_version=$(psql --version | awk '{print $3}')
  installed_psql_major=${installed_psql_version%%.*}
  if [ "$installed_psql_major" = "$POSTGRES_VERSION" ]; then
    info "psql version detected: ${installed_psql_version:-unknown}"
  else
    warn "psql version ${installed_psql_version:-unknown} detected; expected major version $POSTGRES_VERSION."
  fi
else
  warn "psql command not found after installation attempt."
fi

if dpkg -s "postgresql-${POSTGRES_VERSION}-postgis-3" >/dev/null 2>&1; then
  info "PostGIS extension package is installed."
else
  warn "PostGIS extension package is not installed."
fi

    # Update the system withe the install of all new packages
apt-get update -y

    # Install complete
info "PostgreSQL installation step complete."


  # === Install TAK server
info "Installing TAK Server"

apt-get install -y ./takserver_5.0-RELEASE29_all.deb

info "TAK server is installed"
info "For configuration follow the guide at https://mytecknet.com/lets-build-a-tak-server/."

    # Update the system withe the install of all new packages
apt-get update -y

    # Install complete
echo "TAK server fully installed"

sleep 10


#=== Install MediaMTX ============================================================
info "Installing MediaMTX."

  # === Create directory for MediaMTX
install -d -m 0755 /opt/mediamtx
cd /opt/mediamtx

  # === Determine archive matching architecture
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  armhf)
    MEDIAMTX_ARCHIVE=mediamtx_linux_armv7.tar.gz
    ;;
  arm64)
    MEDIAMTX_ARCHIVE=mediamtx_linux_arm64v8.tar.gz
    ;;
  *)
    error "Unsupported architecture '$ARCH'. MediaMTX installation requires Raspberry Pi OS on armhf or arm64. Please rerun this installer on Raspberry Pi OS running on Raspberry Pi hardware."
    exit 1
    ;;
esac

MEDIAMTX_URL="https://github.com/bluenviron/mediamtx/releases/latest/download/${MEDIAMTX_ARCHIVE}"

  # === Download latest release from GitHub
if command_exists curl; then
  curl -fsSL -o mediamtx.tar.gz "$MEDIAMTX_URL"
elif command_exists wget; then
  wget -O mediamtx.tar.gz "$MEDIAMTX_URL"
else
  error "Neither curl nor wget is available to download MediaMTX."
  exit 1
fi

  # === Extract and install
tar -xzf mediamtx.tar.gz --strip-components=1
rm -f mediamtx.tar.gz

  # === Verify installation
if [ ! -x /opt/mediamtx/mediamtx ]; then
  error "MediaMTX binary not found after extraction."
  exit 1
fi
log "MediaMTX Installed: $(/opt/mediamtx/mediamtx --version 2>/dev/null || echo 'version check failed')"

if [ ! -f /opt/mediamtx/mediamtx.yml ]; then
  warn "MediaMTX configuration file (mediamtx.yml) not found; using built-in defaults."
fi

  # === Systemd service for MediaMTX
info "Creating MediaMTX systemd service."

cat >/etc/systemd/system/mediamtx.service <<'EOF'
[Unit]
Description=MediaMTX Service
After=network.target

[Service]
ExecStart=/opt/mediamtx/mediamtx /opt/mediamtx/mediamtx.yml
WorkingDirectory=/opt/mediamtx
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mediamtx

[Install]
WantedBy=multi-user.target
EOF

  # === Enable and start the service
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable mediamtx.service
  $SYSTEMCTL restart mediamtx.service
else
  warn "systemctl not available; please enable mediamtx manually."
fi

# === Update the system withe the install of all new packages
apt-get update -y

info "MediaMTX installation and service setup complete."

sleep 10


# === UFW firewall install ================================================================
info "Installing and setting up UFW (all connections open for now)"

  # === Ensure latest package lists and install/upgrade UFW
apt-get install -y --no-install-recommends ufw
apt-get install -y --only-upgrade ufw || true  # if already latest, this no-ops

info "UFW version: $(ufw --version | head -n1 || echo 'unknown')"

  # === Optional: enable IPv6 (so rules apply to v6 too when we harden later)
if grep -q '^IPV6=no' /etc/default/ufw 2>/dev/null; then
  sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw
  info "Enabled IPv6 in /etc/default/ufw"
fi

  # === Start from a clean state
ufw --force reset

  # === Open everything (yes, really)
ufw default allow incoming
ufw default allow outgoing

  # === Keep logs quiet while it's wide open
ufw logging off

  # === Enable UFW (with allow-all defaults, this is effectively no firewalling)
ufw --force enable

  # === Update the system withe the install of all new packages
apt-get update -y

info "UFW is enabled with ALL traffic allowed (incoming & outgoing)."
info "We'll lock this down later per-app to create a safe environment."

sleep 10


# === Logrotate config ============================================================
info "Logrotate config."

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

info "Logrotate config done."


# === Clean up after installation is complete ====================================
info "Clean up before end of script."

apt-get autoremove -y
apt-get clean

info "Clean up finished."

sleep 5

# === Log status of all installed software ===============================================================
info "Summary: OS=$(. /etc/os-release; echo $PRETTY_NAME), Kernel=$(uname -r), batctl=$(batctl -v | head -n1 || echo n/a)"

info "Installation complete."

sleep 5

# === Reboot prompt ==============================================================
info "Reboot or not"

read -r -p "Do you want to reboot the system? [Y/n]: " REPLY || REPLY=""
REPLY="${REPLY:-Y}"
if [[ "$REPLY" =~ ^[Yy]$ ]]; then
  info "Initiating reboot."
  /sbin/shutdown -r now
else
  info "we will exit the script now."
fi

exit
