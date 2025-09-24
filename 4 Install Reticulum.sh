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

