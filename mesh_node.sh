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

# === LOGFILE - mesh-install.log
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

  # Define a function to check if a command exists; store path to systemctl if found, else empty
command_exists() { command -v "$1" >/dev/null ; }
SYSTEMCTL=$(command -v systemctl || true)

# ===Set Batctl version if you want a spcecific version. If needed uncomment.
#BATCTL_VERSION=

# === version if you want a spcecific version. If Bridge-Utils is not needen comment out by adding # in fornt of the line
WANT_BRCTL=1

# === Root only =================================================================
echo "Check for ROOT."

if [[ $EUID -ne 0 ]]; then
  echo "This script needs elevated privileges; attempting to re-run with sudo."
  if command -v sudo >/dev/null 2>&1; then
    exec sudo --preserve-env=DEBIAN_FRONTEND,BATCTL_VERSION,LOGFILE bash "$0" "$@"
  else
    echo "sudo is not available. Please run this script as root." >&2
    exit 1
  fi
fi

echo "Root check complete, (running as $(id -un))."


# === Logging ===================================================================
  # Creating the log file
echo "Creating log file."

install -m 0640 -o root -g adm /dev/null "$LOGFILE"
exec 3>&1
exec >>"$LOGFILE" 2>&1


  #First logs added
info ""
info "================================================="
info "===                                           ==="
info "===    Installation of the Mesh Radio v1.0.   ==="
info "===                                           ==="
info "================================================="
info ""
info ""

  # Add system info
info "Summary: OS=$(. /etc/os-release; echo $PRETTY_NAME), Kernel=$(uname -r), batctl=$(batctl -v | head -n1 || echo n/a)"

  #add some info that before did not got logged,
info "Log file is created."
info "location: /var/log/mesh-install.log"

  # Add we are root
info "Run as root (sudo)."

# === Housekeeping ==============================================================
info "Housekeeping starting."

  # Perform a small cleanup in the user’s home directory
TARGET_USER=${SUDO_USER:-$USER}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
HOME_DIR=${TARGET_HOME:-/root}
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME/linux" ] && rm -rf "$TARGET_HOME/linux" || true

info "Housekeeping is complete."


# === System update =============================================================
info "Upgrade and Update of the operatingsystem starting."

apt-get update -y
apt-get -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        dist-upgrade -y

info "Update and Upgrade of the operatingsystem is complete."

sleep 10


# === Prerequisites - install needed packages ===================================
    # Pakages list
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

  # Automate install (faster)
if apt-get install -y --no-install-recommends "${PACKAGES[@]}"; then
  info "Bulk install/upgrade succeeded."
else
  info "Bulk install failed; falling back to per-package handling."

  # Fallback: per-packages processing
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

info "Installation of all packages is complete."

sleep 10


#=== Install B.A.T.M.A.N.-adv ===================================================
info "Installing B.A.T.M.A.N.-Adv."

# 1) Fast detection: is the module available without the need of installing it?
if modprobe -n batman-adv 2>/dev/null; then
  log "B.A.T.M.A.N.-Adv kernelmodule is available (dry-run ok) — skip installation proces."
else
  log "B.A.T.M.A.N.-Adv module not available; attempt to create and install the B.A.T.M.A.N.-Adv module."

  # Raspberry Pi OS (Raspbian/Debian voor Pi)
  apt-get install -y raspberrypi-kernel-headers || true

  # If there are still problems, fallback to DKMS-build of B.A.T.M.A.N.-Adv
  apt-get install -y batman-adv-dkms || true
  dpkg-reconfigure -fnoninteractive batman-adv-dkms || true
fi

# 2) Load the B.A.T.M.A.N.-Adv module
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

# 3) Setting up loading at start
printf "%s\n" "batman-adv" > /etc/modules-load.d/batman-adv.conf

info "Installation of B.A.T.M.A.N.-Adv complete."

sleep 10


#=== Install Batctl =============================================================
info "Installing Batctl."

  # 1) First attempt, load the module.
  if apt-cache policy batctl 2>/dev/null | grep -q "Candidate:"; then
    apt-get install -y --no-install-recommends batctl
  else
    log "Batctl nnot found in APT ; fall back to source code build."

    install -d -m 0755 /usr/local/src
    cd /usr/local/src

  # 2) If you want to install a specific version: export BATCTL_VERSION=2025.0 (of wat je wilt)
    if [ -n "${BATCTL_VERSION:-}" ]; then
      log "Build batctl verion: ${BATCTL_VERSION}"
      # First try the release-tarball. Fallback to git.
      if command -v curl >/dev/null 2>&1; then
        TAR="batctl-${BATCTL_VERSION}.tar.gz"
        URL="https://downloads.open-mesh.org/batman/releases/${TAR}"
        if curl -fsSLO "$URL"; then
          tar xf "$TAR"
          cd "batctl-${BATCTL_VERSION}"
          make && make install
        else
          log "Release-tarball nor found, fall back to git tag."
          if [ -d batctl ]; then
            cd batctl && git fetch --tags && git checkout "v${BATCTL_VERSION}" && git pull --ff-only
          else
            git clone https://git.open-mesh.org/batctl.git
            cd batctl && git fetch --tags && git checkout "v${BATCTL_VERSION}"
          fi
          make && make install
        fi
      else
        # No curl? Continu over git tag.
        if [ -d batctl ]; then
          cd batctl && git fetch --tags && git checkout "v${BATCTL_VERSION}" && git pull --ff-only
        else
          git clone https://git.open-mesh.org/batctl.git
          cd batctl && git fetch --tags && git checkout "v${BATCTL_VERSION}"
        fi
        make && make install
      fi
    else
    # 3) No version set: build HEAD (fastest fallback)
      if [[ -d batctl ]]; then
        cd batctl
        git pull --ff-only
      else
        git clone https://git.open-mesh.org/batctl.git
        cd batctl
      fi
      make && make install
    fi
  fi

  # 4) Verify installation
  if ! batctl -v >/dev/null 2>&1; then
    error "Batctl not available after install."
    exit 1
  fi
  log "Batctl Installed: $(batctl -v | head -n1)."

info "Installation of Batctl complete."

sleep 10


#=== Bridge-Utils ================================================================
if [ "$WANT_BRCTL" = "1" ]; then
  info "Installing Bridge-Utils (legacy Brctl."

  if apt-cache policy bridge-utils | grep -q "Candidate:"; then
    apt-get install -y --no-install-recommends bridge-utils \
      && info "Installation of Bridge-Utils complete."\
      || error "Installation failed for bridge-utils (continuing)."
  else
    error "Warning: bridge-utils not found in APT (skipping)."
  fi
fi

sleep 10

# === Install Reticulum =========================================================
info "Installing Reticulum (RNS)."

# Install Reticulum into system Python
PIP_INSTALL=(python3 -m pip install --upgrade)
if python3 -m pip install --help 2>&1 | grep -q -- '--break-system-packages'; then
  PIP_INSTALL+=(--break-system-packages)
fi

if "${PIP_INSTALL[@]}" rns; then
  log "Reticulum installed successfully: $(python3 -m pip show rns 2>/dev/null | grep Version || echo 'unknown version')"
else
  error "Reticulum installation failed."
  exit 1
fi

RNSD_PATH=$(command -v rnsd || true)
if [ -z "$RNSD_PATH" ]; then
  error "Unable to locate rnsd in PATH after installation."
  exit 1
fi

# Create Reticulum systemd service
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

# Enable and start service
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

info "Reticulum (RNS) is installed."

sleep 10


# === Install Hostapd (last version) =============================================
info "Installing Hostpad"

    # Settings
SERVICE_FILE="/etc/systemd/system/hostapd.service"
HOSTAPD_BIN=$(command -v hostapd || echo "/usr/local/bin/hostapd")

    # Clone the official repo
git clone git://w1.fi/hostap.git
cd hostapd/hostapd
cp defconfig .config

    # Build & install 
make -j4
sudo make install

    # Create systemd service file
echo "Hostapd binary gevonden op: $HOSTAPD_BIN"

sudo bash -c "cat > $SERVICE_FILE" <<EOF
[Unit]
Description=Hostapd IEEE 802.11 Access Point
After=network.target

[Service]
ExecStart=$HOSTAPD_BIN -P /run/hostapd.pid /etc/hostapd/hostapd.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target
EOF

echo "Service bestand aangemaakt: $SERVICE_FILE"

    # Manage hostapd
sudo systemctl daemon-reload
sudo systemctl enable hostapd
sudo systemctl start hostapd

info "Hostpad installed"


#=== Install Flask system-wide for systemd services=============================
info "Installing Flask"

PIP_CMD=(python3 -m pip install --upgrade)
if python3 -m pip install --help 2>&1 | grep -q -- '--break-system-packages'; then
  PIP_CMD+=(--break-system-packages)
fi

if python3 -m pip show flask >/dev/null 2>&1; then
  FLASK_OLD_VERSION=$(python3 -m pip show flask 2>/dev/null | awk '/Version:/ {print $2}')
  info "Flask already present (version ${FLASK_OLD_VERSION:-unknown}); ensuring it is up to date."
else
  info "Flask not detected; installing now."
fi

if "${PIP_CMD[@]}" flask; then
  FLASK_NEW_VERSION=$(python3 -m pip show flask 2>/dev/null | awk '/Version:/ {print $2}')
  log "Flask installed successfully: version ${FLASK_NEW_VERSION:-unknown}."
else
  error "Failed to install or upgrade Flask."
  exit 1
fi

FLASK_APP_DIR="/opt/mesh-flask"
FLASK_APP_FILE="$FLASK_APP_DIR/app.py"
FLASK_ENV_DIR="/etc/mesh"
FLASK_ENV_FILE="$FLASK_ENV_DIR/flask.env"
FLASK_SERVICE_FILE="/etc/systemd/system/mesh-flask.service"

install -d -m 0755 "$FLASK_APP_DIR"
if [ ! -f "$FLASK_APP_FILE" ]; then
  info "Deploying default Flask application stub at $FLASK_APP_FILE."
  cat >"$FLASK_APP_FILE" <<'EOF'
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "Mesh Flask service is running."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
EOF
  chmod 0644 "$FLASK_APP_FILE"
fi

install -d -m 0755 "$FLASK_ENV_DIR"
if [ ! -f "$FLASK_ENV_FILE" ]; then
  info "Creating Flask environment configuration at $FLASK_ENV_FILE."
  cat >"$FLASK_ENV_FILE" <<'EOF'
# Environment configuration for the Mesh Flask service
FLASK_APP=/opt/mesh-flask/app.py
FLASK_RUN_HOST=0.0.0.0
FLASK_RUN_PORT=5000
EOF
  chmod 0644 "$FLASK_ENV_FILE"
fi

FLASK_SERVICE_USER=${TARGET_USER:-root}
if [ -z "$FLASK_SERVICE_USER" ] || [ "$FLASK_SERVICE_USER" = "root" ]; then
  FLASK_USER_DIRECTIVE="User=root"
  FLASK_GROUP_DIRECTIVE="Group=root"
else
  FLASK_USER_DIRECTIVE="User=$FLASK_SERVICE_USER"
  FLASK_GROUP_DIRECTIVE="Group=$FLASK_SERVICE_USER"
fi

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

info "Flask installation and service configuration complete."

sleep 10


# === Install TAK Server =========================================================
info "Installing TAK server - Single server setup"

# === Edit Raspberry OS: Increase JVM threads
info "Changes in Raspberry OS: Increase JVM threads"

echo -e "*      soft      nofile      32768\n*      hard      nofile      32768\n" | sudo tee --append /etc/security/limits.conf

info "Changes in Raspberry OS are done"


# === Install Java 17
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
    echo "$pg_repo_line" | sudo tee "$pg_sources_file" >/dev/null
  else
    info "PostgreSQL APT repository already configured."
  fi

  pg_keyring="/etc/apt/trusted.gpg.d/postgresql.org.gpg"
  if [ ! -s "$pg_keyring" ]; then
    info "Importing PostgreSQL signing key."
    wget -qO- https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | sudo tee "$pg_keyring" >/dev/null
  else
    info "PostgreSQL signing key already present."
  fi

  sudo apt-get update -y
  sudo apt-get install -y "${missing_packages[@]}"
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

info "PostgreSQL installation step complete."

sleep 10


# === Install TAK server
info "Installing TAK Server"

sudo apt install ./takserver_5.0-RELEASE29_all.deb -y

info "TAK server is installed"


# === firewall install and setting up rules
info "Installing and setting up firewall"

# ===  Install UFW
if ! command -v ufw &> /dev/null; then
    info "UFW is not installed. Installing..."
    sudo apt update && sudo apt install -y ufw
else
    info "UFW is already installed."
fi

# === Setting up UFW for TAK server



info "Firewall is installed and set up for TAK server"

info "TAK server is fully installed,"
info "for configuration follow the guide at https://mytecknet.com/lets-build-a-tak-server/."

sleep 10

#=== Install MediaMTX ============================================================
info "Installing MediaMTX."

# Create directory for MediaMTX
install -d -m 0755 /opt/mediamtx
cd /opt/mediamtx

# Determine archive matching architecture
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  armhf)
    MEDIAMTX_ARCHIVE=mediamtx_linux_armv7.tar.gz
    ;;
  arm64)
    MEDIAMTX_ARCHIVE=mediamtx_linux_arm64v8.tar.gz
    ;;
  amd64)
    MEDIAMTX_ARCHIVE=mediamtx_linux_amd64.tar.gz
    ;;
  *)
    warn "Unsupported architecture '$ARCH'; defaulting to amd64 build."
    MEDIAMTX_ARCHIVE=mediamtx_linux_amd64.tar.gz
    ;;
esac

MEDIAMTX_URL="https://github.com/bluenviron/mediamtx/releases/latest/download/${MEDIAMTX_ARCHIVE}"

# Download latest release from GitHub
if command_exists curl; then
  curl -fsSL -o mediamtx.tar.gz "$MEDIAMTX_URL"
elif command_exists wget; then
  wget -O mediamtx.tar.gz "$MEDIAMTX_URL"
else
  error "Neither curl nor wget is available to download MediaMTX."
  exit 1
fi

# Extract and install
tar -xzf mediamtx.tar.gz --strip-components=1
rm -f mediamtx.tar.gz

# Verify installation
if [ ! -x /opt/mediamtx/mediamtx ]; then
  error "MediaMTX binary not found after extraction."
  exit 1
fi
log "MediaMTX Installed: $(/opt/mediamtx/mediamtx --version 2>/dev/null || echo 'version check failed')"

if [ ! -f /opt/mediamtx/mediamtx.yml ]; then
  warn "MediaMTX configuration file (mediamtx.yml) not found; using built-in defaults."
fi

# Systemd service for MediaMTX
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

# Enable and start the service
if [ -n "$SYSTEMCTL" ]; then
  $SYSTEMCTL daemon-reload
  $SYSTEMCTL enable mediamtx.service
  $SYSTEMCTL restart mediamtx.service
else
  warn "systemctl not available; please enable mediamtx manually."
fi

info "MediaMTX installation and service setup complete."

sleep 10


#=== Logrotate config ============================================================
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


#=== Clean up after installation is complete ====================================
info "Clean up before end of script."

apt-get autoremove -y
apt-get clean

info "Clean up finished."


#=== End of script ===============================================================
info "Summary: OS=$(. /etc/os-release; echo $PRETTY_NAME), Kernel=$(uname -r), batctl=$(batctl -v | head -n1 || echo n/a)"

info "Installation complete."


#=== Reboot prompt ==============================================================
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
