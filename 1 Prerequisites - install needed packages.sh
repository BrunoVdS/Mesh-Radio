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

