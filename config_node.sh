#!/bin/bash

    # ==============================================================================

    ###                       NEW NODE CONFIG SCRIPT                            ###

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
LOGFILE="/var/log/mesh-config.log"

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
info "===    Configuration of the Mesh Radio v1.0.   ==="
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






exit
