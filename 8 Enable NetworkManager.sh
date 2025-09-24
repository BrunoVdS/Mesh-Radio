# === Enable NetworkManager ====================================================

echo "[*] Checking if wpa_supplicant is running on wlan1..."

    # Check if wpa_supplicant has wlan1 in its command line
if pgrep -a wpa_supplicant | grep -q "wlan1"; then
    echo "[!] wpa_supplicant is running on wlan1. Disabling it..."
    sudo systemctl stop wpa_supplicant
    sudo systemctl disable wpa_supplicant
    sudo systemctl mask wpa_supplicant
else
    echo "[!] No wpa_supplicant process bound to wlan1. Skipping disable."
fi

    # Enable Networkmanager
echo "[*] Making sure NetworkManager is enabled..."
sudo systemctl unmask NetworkManager
sudo systemctl enable NetworkManager
sudo systemctl start NetworkManager

    # Enable Hostapd
echo "[*] Making sure hostapd is enabled..."
sudo systemctl unmask hostapd
sudo systemctl enable hostapd
sudo systemctl start hostapd

echo " Done. NetworkManager is running, hostapd is ready, and wpa_supplicant for wlan1 is disabled."