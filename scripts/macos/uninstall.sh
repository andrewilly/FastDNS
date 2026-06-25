#!/bin/bash
#
# FastDNS macOS Daemon Uninstaller
#
# Removes the FastDNS binary and launchd daemon registration.
#
# Usage:
#   sudo ./uninstall.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_NAME="fastdns"
PLIST_NAME="com.fastdns.daemon.plist"
HEALTHCHECK_PLIST_NAME="com.fastdns.healthcheck.plist"
INSTALL_DIR="/usr/local/bin"
PLIST_DIR="/Library/LaunchDaemons"

# Check for root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root (sudo)."
    echo "   Usage: sudo $0"
    exit 1
fi

echo "╔══════════════════════════════════════════╗"
echo "║   🚀 FastDNS macOS Daemon Uninstaller    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Step 1: Unload the health checker
if [[ -f "$PLIST_DIR/$HEALTHCHECK_PLIST_NAME" ]]; then
    echo "🛑 Stopping FastDNS health checker..."
    launchctl unload "$PLIST_DIR/$HEALTHCHECK_PLIST_NAME" 2>/dev/null || true
    echo "   ✅ Health checker stopped"
fi

# Step 2: Unload the daemon
if [[ -f "$PLIST_DIR/$PLIST_NAME" ]]; then
    echo "🛑 Stopping FastDNS daemon..."
    launchctl unload "$PLIST_DIR/$PLIST_NAME" 2>/dev/null || true
    echo "   ✅ Daemon stopped"
else
    echo "   ℹ️  No plist found at $PLIST_DIR/$PLIST_NAME"
fi

# Step 3: Remove the plists
if [[ -f "$PLIST_DIR/$PLIST_NAME" ]]; then
    echo "📋 Removing launchd plist..."
    rm "$PLIST_DIR/$PLIST_NAME"
    echo "   ✅ Plist removed"
fi
if [[ -f "$PLIST_DIR/$HEALTHCHECK_PLIST_NAME" ]]; then
    echo "📋 Removing health check plist..."
    rm "$PLIST_DIR/$HEALTHCHECK_PLIST_NAME"
    echo "   ✅ Health check plist removed"
fi

# Step 3: Remove the binary
if [[ -f "$INSTALL_DIR/$BINARY_NAME" ]]; then
    echo "📋 Removing binary..."
    rm "$INSTALL_DIR/$BINARY_NAME"
    echo "   ✅ Binary removed: $INSTALL_DIR/$BINARY_NAME"
fi

# Step 4: Optionally remove log files
if [[ -f /var/log/fastdns.log ]] || [[ -f /var/log/fastdns.error.log ]]; then
    echo ""
    echo "📋 Log files remain at /var/log/fastdns.log and /var/log/fastdns.error.log"
    echo "   To remove them: sudo rm /var/log/fastdns.log /var/log/fastdns.error.log"
fi

echo ""
echo "✅ FastDNS has been uninstalled."
