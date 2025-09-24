# === Install Hostapd (last version) =============================================
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