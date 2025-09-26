#!/bin/bash


set -Eeuo pipefail
trap 'error "Unexpected error on line $LINENO"; exit 1' ERR


# ==============================================================================

###                       FRESH NODE SETUP SCRIPT                            ###

# ==============================================================================


#=== Config ====================================================================
LOGFILE="/var/log/mesh-install.log"

DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

  # Log helpers
log()   { echo "[$(date +%F %T)] $*" >>"$LOGFILE"; }
info()  { if [ -e /proc/$$/fd/3 ]; then echo "[$(date +%F %T)] INFO: $*" | tee -a "$LOGFILE" >&3; else echo "INFO: $*"; fi; }
error() { if [ -e /proc/$$/fd/3 ]; then echo "[$(date +%F %T)] ERROR: $*" | tee -a "$LOGFILE" >&3; else echo "ERROR: $*" >&2; fi; }

#Set Batctl version if you want a spcecific version. If needed uncomment.
#BATCTL_VERSION=

# version if you want a spcecific version. If Bridge-Utils is not needen comment out by adding # in fornt of the line.
WANT_BRCTL=1

#=== Root only =================================================================
echo "Check for ROOT."

if [[ $EUID -ne 0 ]]; then
  log "Run as root (sudo) — exiting."
  info "Please make sure you are running the script while being root - Cancelling the script."
  exit 1
fi

echo "Root check complete."


#=== Logging ===================================================================
echo "Creating log file."

install -m 0640 -o root -g adm /dev/null "$LOGFILE"
exec 3>&1
exec >>"$LOGFILE" 2>&1

info "Log file is created."



info "================================================="
info "===                                           ==="
info "===    Installation of the Mesh Radio v1.0.   ==="
info "===                                           ==="
info "================================================="



info "Summary: OS=$(. /etc/os-release; echo $PRETTY_NAME), Kernel=$(uname -r), batctl=$(batctl -v | head -n1 || echo n/a)"


#=== Housekeeping ==============================================================
info "Housekeeping starting."

TARGET_USER=${SUDO_USER:-$USER}
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME/linux" ] && rm -rf "$TARGET_HOME/linux" || true

info "Housekeeping is complete."


#=== System update =============================================================
info "Upgrade and Update of the operatingsystem starting."

apt-get update -y
apt-get -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        dist-upgrade -y

info "Update and Upgrade of the operatingsystem is complete."


#=== Base packages==============================================================
  #=== Prerequisites - install needed packages
 
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


#=== Install B.A.T.M.A.N.-adv ===================================================
info "Installing B.A.T.M.A.N.-Adv."

# Define current OS
. /etc/os-release 2>/dev/null || true
OS_ID="${ID:-unknown}"

# 1) Fast detection: is the module available without the need of installing it?
if modprobe -n batman-adv 2>/dev/null; then
  log "B.A.T.M.A.N.-Adv kernelmodule is available (dry-run ok) — skip installation proces."
else
  log "B.A.T.M.A.N.-Adv module not available; attempt to create and install the B.A.T.M.A.N.-Adv module."

  if echo "$OS_ID" | grep -qi 'ubuntu'; then
    # Ubuntu on Raspberry Pi: Install extra modules specific to the current setup.'
    apt-get install -y "linux-modules-extra-$(uname -r)" || true
    # Headers  / DKMS
    apt-get install -y "linux-headers-$(uname -r)" || true
  else
    # Raspberry Pi OS (Raspbian/Debian voor Pi)
    apt-get install -y raspberrypi-kernel-headers || true
  fi

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


# === Install Reticulum =========================================================
info "Installing Reticulum (RNS)."

# Ensure Python and pip are available (already handled in base packages, but safe check)
if ! command -v python3 >/dev/null 2>&1; then
  error "Python3 not found. Cannot install Reticulum."
  exit 1
fi

# Install Reticulum into system Python
if pip3 install --upgrade rns; then
  log "Reticulum installed successfully: $(pip3 show rns 2>/dev/null | grep Version || echo 'unknown version')"
else
  error "Reticulum installation failed."
  exit 1
fi

# Create Reticulum systemd service
info "Creating Reticulum systemd service."

cat >/etc/systemd/system/rnsd.service <<'EOF'
[Unit]
Description=Reticulum Network Stack Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/rnsd
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=rnsd

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reexec
systemctl enable rnsd.service
systemctl start rnsd.service

info "Reticulum systemd service is set up."

info "==> Version check:"
if $RNSD_PATH --version; then
  info "rnsd version OK."
else
  echo "!! rnsd --failed. Check logs."
fi

if need_cmd rnstatus; then
  rnstatus --version || true
fi

  # Check service staus
sudo systemctl --no-pager --full status rnsd || true

echo "Ready. Reticulum runs."
echo "Configs: $HOME_DIR/.config/reticulum"

rnstatus

info "Reticulum (RNS) is installed."


#=== Install MediaMTX ============================================================
info "Installing MediaMTX."

# Create directory for MediaMTX
install -d -m 0755 /opt/mediamtx
cd /opt/mediamtx

# Download latest release from GitHub
if command -v curl >/dev/null 2>&1; then
  curl -L -o mediamtx.tar.gz https://github.com/bluenviron/mediamtx/releases/latest/download/mediamtx_linux_amd64.tar.gz
else
  wget -O mediamtx.tar.gz https://github.com/bluenviron/mediamtx/releases/latest/download/mediamtx_linux_amd64.tar.gz
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
systemctl daemon-reexec
systemctl enable mediamtx.service
systemctl start mediamtx.service

info "MediaMTX installation and service setup complete."


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
  info "Initiating reboot. 👋"
  /sbin/shutdown -r now
else
  info "we will exit the script now."
fi


exit
