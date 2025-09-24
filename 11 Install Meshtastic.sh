#=== Install Meshtastic (meshtasticd) ===========================================
info "Installing Meshtastic (meshtasticd)."

# Detect OS
. /etc/os-release 2>/dev/null || true
OS_ID="${ID:-unknown}"
OS_CODENAME="${VERSION_CODENAME:-unknown}"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"

# Add repo & install meshtasticd based on distro
case "$OS_ID" in
  debian)
    info "Detected Debian ($OS_CODENAME). Adding Meshtastic OpenSUSE repo."
    case "$OS_CODENAME" in
      bookworm)
        echo 'deb http://download.opensuse.org/repositories/network:/Meshtastic:/beta/Debian_12/ /' \
          > /etc/apt/sources.list.d/network:Meshtastic:beta.list
        curl -fsSL https://download.opensuse.org/repositories/network:Meshtastic:beta/Debian_12/Release.key \
          | gpg --dearmor > /etc/apt/trusted.gpg.d/network_Meshtastic_beta.gpg
        ;;
      trixie)
        echo 'deb http://download.opensuse.org/repositories/network:/Meshtastic:/beta/Debian_13/ /' \
          > /etc/apt/sources.list.d/network:Meshtastic:beta.list
        curl -fsSL https://download.opensuse.org/repositories/network:Meshtastic:beta/Debian_13/Release.key \
          | gpg --dearmor > /etc/apt/trusted.gpg.d/network_Meshtastic_beta.gpg
        ;;
      *)
        log "Unsupported/untested Debian codename '$OS_CODENAME'; attempting Debian_12 repo as best effort."
        echo 'deb http://download.opensuse.org/repositories/network:/Meshtastic:/beta/Debian_12/ /' \
          > /etc/apt/sources.list.d/network:Meshtastic:beta.list
        curl -fsSL https://download.opensuse.org/repositories/network:Meshtastic:beta/Debian_12/Release.key \
          | gpg --dearmor > /etc/apt/trusted.gpg.d/network_Meshtastic_beta.gpg
        ;;
    esac
    apt-get update -y
    if apt-get install -y meshtasticd; then
      log "Meshtastic installed (Debian)."
    else
      error "Meshtastic install failed on Debian."
      exit 1
    fi
    ;;
  raspbian)
    info "Detected Raspbian ($OS_CODENAME, $ARCH). Adding Meshtastic OpenSUSE repo."
    # Official note: OpenSUSE Raspbian builds are for 32-bit armhf; 64-bit should use Debian repos.
    if [[ "$ARCH" = "armhf" && "$OS_CODENAME" = "bookworm" ]]; then
      echo 'deb http://download.opensuse.org/repositories/network:/Meshtastic:/beta/Raspbian_12/ /' \
        > /etc/apt/sources.list.d/network:Meshtastic:beta.list
      curl -fsSL https://download.opensuse.org/repositories/network:Meshtastic:beta/Raspbian_12/Release.key \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/network_Meshtastic_beta.gpg
    else
      log "Using Debian repo path for RPi ($OS_CODENAME/$ARCH)."
      echo 'deb http://download.opensuse.org/repositories/network:/Meshtastic:/beta/Debian_12/ /' \
        > /etc/apt/sources.list.d/network:Meshtastic:beta.list
      curl -fsSL https://download.opensuse.org/repositories/network:Meshtastic:beta/Debian_12/Release.key \
        | gpg --dearmor > /etc/apt/trusted.gpg.d/network_Meshtastic_beta.gpg
    fi
    apt-get update -y
    if apt-get install -y meshtasticd; then
      log "Meshtastic installed (Raspbian)."
    else
      error "Meshtastic install failed on Raspbian."
      exit 1
    fi
    ;;
  ubuntu)
    info "Detected Ubuntu ($OS_CODENAME). Adding Meshtastic PPA."
    apt-get install -y --no-install-recommends software-properties-common
    add-apt-repository -y ppa:meshtastic/beta
    apt-get update -y
    if apt-get install -y meshtasticd; then
      log "Meshtastic installed (Ubuntu)."
    else
      error "Meshtastic install failed on Ubuntu."
      exit 1
    fi
    ;;
  *)
    error "Unsupported distribution '$OS_ID'. Please install meshtasticd manually."
    exit 1
    ;;
esac

# Verify binary and service
if ! command -v meshtasticd >/dev/null 2>&1; then
  error "meshtasticd not found in PATH after installation."
  exit 1
fi
log "Meshtasticd path: $(command -v meshtasticd)"

# The package provides a systemd unit; ensure autostart on boot
info "Enabling Meshtastic service (autostart on reboot)."
systemctl daemon-reexec
systemctl enable --now meshtasticd.service || {
  error "Failed to enable/start meshtasticd.service."
  exit 1
}

# Minimal smoke check (no configuration performed)
sleep 1
if systemctl is-active --quiet meshtasticd.service; then
  info "Meshtastic installation and service setup complete."
else
  error "meshtasticd service is not active (configuration will be done later)."
fi

echo "Meshtasic is installed"