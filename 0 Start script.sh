
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

#state version if you want a spcecific version
#BATCTL_VERSION=

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

