#!/bin/sh
# FastDNS macOS installer
set -e

INSTALL_DIR="/usr/local/bin"
PLIST_SRC="scripts/macos/com.fastdns.daemon.plist"
PLIST_DST="/Library/LaunchDaemons/com.fastdns.daemon.plist"

echo "Installing FastDNS..."

# Copy binary
sudo cp target/release/fastdns "$INSTALL_DIR/fastdns"
sudo chmod +x "$INSTALL_DIR/fastdns"

# Copy plist
sudo cp "$PLIST_SRC" "$PLIST_DST"
sudo chmod 644 "$PLIST_DST"
sudo chown root:wheel "$PLIST_DST"

# Bootstrap
sudo launchctl bootout system "$PLIST_DST" 2>/dev/null || true
sudo launchctl bootstrap system "$PLIST_DST"

echo "FastDNS installed and started."
