#=== Install B.A.T.M.A.N.-adv =========================================================
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


#=== Bridge-Utils =====================================================================
info "Installing Bridge-Utils."

if [ "$WANT_BRCTL" = "1" ]; then
  log "Installing bridge-utils (legacy brctl)"
  if apt-cache policy bridge-utils | grep -q "Candidate:"; then
    apt-get install -y --no-install-recommends bridge-utils \
      && log "Installed: bridge-utils." \
      || error "Installation failed for bridge-utils (continuing)."
  else
    error "Warning: bridge-utils not found in APT (skipping)."
  fi
fi

info "Installation of Bridge-Utils complete."

