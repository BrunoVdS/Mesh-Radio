#!/bin/bash

set -Eeuo pipefail

info() {
  echo "[INFO] $*"
}

warn() {
  echo "[WARN] $*" >&2
}

error() {
  echo "[ERROR] $*" >&2
}

if [[ $EUID -ne 0 ]]; then
  error "This script must be run as root."
  exit 1
fi

SYSTEMCTL=$(command -v systemctl || true)
TARGET_USER=${SUDO_USER:-$USER}

FLASK_APP_DIR="/opt/mesh-flask"
FLASK_APP_FILE="$FLASK_APP_DIR/app.py"
FLASK_ENV_DIR="/etc/mesh"
FLASK_ENV_FILE="$FLASK_ENV_DIR/flask.env"
FLASK_SERVICE_FILE="/etc/systemd/system/mesh-flask.service"

install -d -m 0755 "$FLASK_APP_DIR"
if [ ! -f "$FLASK_APP_FILE" ]; then
  info "Deploying default Flask application stub at $FLASK_APP_FILE."
  cat >"$FLASK_APP_FILE" <<'APP_EOF'
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "Mesh Flask service is running."


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
APP_EOF
  chmod 0644 "$FLASK_APP_FILE"
else
  info "Existing Flask application detected at $FLASK_APP_FILE; leaving in place."
fi

install -d -m 0755 "$FLASK_ENV_DIR"
if [ ! -f "$FLASK_ENV_FILE" ]; then
  info "Creating Flask environment configuration at $FLASK_ENV_FILE."
  cat >"$FLASK_ENV_FILE" <<'ENV_EOF'
# Environment configuration for the Mesh Flask service
FLASK_APP=/opt/mesh-flask/app.py
FLASK_RUN_HOST=0.0.0.0
FLASK_RUN_PORT=5000
ENV_EOF
  chmod 0644 "$FLASK_ENV_FILE"
else
  info "Flask environment file already exists at $FLASK_ENV_FILE; leaving in place."
fi

if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  FLASK_USER_DIRECTIVE="User=root"
  FLASK_GROUP_DIRECTIVE="Group=root"
else
  FLASK_USER_DIRECTIVE="User=$TARGET_USER"
  FLASK_GROUP_DIRECTIVE="Group=$TARGET_USER"
fi

info "Configuring Flask systemd service."
cat >"$FLASK_SERVICE_FILE" <<SERVICE_EOF
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
SERVICE_EOF

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

apt-get update -y

info "Flask service configuration complete."

sleep 10
