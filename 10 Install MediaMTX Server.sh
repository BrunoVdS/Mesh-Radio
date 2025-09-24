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





#This section does the following:
#Downloads and installs the latest MediaMTX release.
#Validates installation with your existing log and error helpers.
#Creates a systemd unit file so the service starts automatically on reboot.
#Immediately enables and starts the service.
#Would you like me to also adapt the logging inside the MediaMTX systemd service (e.g., redirect logs into your existing $LOGFILE) so it fully integrates with your current script’s log, info, and error handlers?



