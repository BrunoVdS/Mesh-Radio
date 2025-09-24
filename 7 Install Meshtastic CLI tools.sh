#=== Install Meshtastic CLI tools ==============================================
sudo pip3 install --upgrade pytap2 --break-system-packages
sudo pip3 install --upgrade "meshtastic[cli]" --break-system-packages

sleep 5


#=== Add ~/.local/bin to PATH for pip-installed scripts ========================
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
