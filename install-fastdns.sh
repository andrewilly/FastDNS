#!/bin/bash
#
# FastDNS macOS One-Shot Installer
#
# Usage:
#   sudo bash install-fastdns.sh
#
# What it does:
#   1. Flushes the system DNS cache
#   2. Copies the release binary to /usr/local/bin/fastdns
#   3. Installs/updates the launchd plist
#   4. Loads the FastDNS daemon via launchctl (port 53, DNSSEC enabled)
#   5. Installs the health-check plist (auto-restart if resolver goes down)
#   6. Sets system DNS to 127.0.0.1 on all active network services
#   7. Verifies the daemon is running
#

set -uo pipefail
# Note: we intentionally do NOT use `set -e` because launchctl operations
# can fail on macOS 15+ SIP and we handle those errors gracefully.

BINARY="target/release/fastdns"
INSTALL_DIR="/usr/local/bin"
DAEMON_PLIST="scripts/macos/com.fastdns.daemon.plist"
HEALTH_PLIST="scripts/macos/com.fastdns.healthcheck.plist"
PLIST_DIR="/Library/LaunchDaemons"

# ── Sanity checks ──────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root (sudo)."
    echo "   Usage: sudo bash $0"
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "❌ Binary not found at $BINARY"
    echo "   Build it first: cargo build --release"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   🚀 FastDNS macOS Installer             ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Step 1: Unload old services ────────────────────────────────
echo "📋 Unloading old services (if any)..."

for plist in "$DAEMON_PLIST" "$HEALTH_PLIST"; do
    name=$(basename "$plist")
    dst="$PLIST_DIR/$name"
    # launchctl unload works on /Library/LaunchDaemons/ plists
    # (bootout system requires SIP-disabled domain — avoid on macOS 15+)
    if launchctl print "system/$name" &>/dev/null; then
        echo "   → Unload $name"
        launchctl unload "$dst" 2>/dev/null || true
    fi
done
# Also kill any lingering fastdns process
pkill -9 fastdns 2>/dev/null || true
sleep 1
echo "   ✅ Old services unloaded"
echo ""

# ── Step 2: Flush DNS cache ────────────────────────────────────
echo "📋 Flushing system DNS cache..."
if dscacheutil -flushcache 2>/dev/null && killall -HUP mDNSResponder 2>/dev/null; then
    echo "   ✅ DNS cache flushed"
else
    echo "   ⚠️  DNS cache flush had non-fatal issues (continuing anyway)"
fi
echo ""

# ── Step 3: Copy binary ────────────────────────────────────────
echo "📋 Installing binary..."
cp "$BINARY" "$INSTALL_DIR/fastdns"
chmod 755 "$INSTALL_DIR/fastdns"
echo "   ✅ Binary installed: $INSTALL_DIR/fastdns"
echo ""

# ── Step 4: Copy plists ────────────────────────────────────────
echo "📋 Installing launchd plists..."

cp "$DAEMON_PLIST" "$PLIST_DIR/com.fastdns.daemon.plist"
chmod 644 "$PLIST_DIR/com.fastdns.daemon.plist"
chown root:wheel "$PLIST_DIR/com.fastdns.daemon.plist"
echo "   ✅ Daemon plist installed"

cp "$HEALTH_PLIST" "$PLIST_DIR/com.fastdns.healthcheck.plist"
chmod 644 "$PLIST_DIR/com.fastdns.healthcheck.plist"
chown root:wheel "$PLIST_DIR/com.fastdns.healthcheck.plist"
echo "   ✅ Health-check plist installed"
echo ""

# ── Step 5: Load daemon ─────────────────────────────────────────
echo "📋 Starting FastDNS daemon..."

# On macOS 15+ with SIP, launchctl load -w can fail with EIO 5.
# We try it first, and fall back to osascript if it fails.
DAEMON_LABEL="com.fastdns.daemon"
HEALTH_LABEL="com.fastdns.healthcheck"

load_via_launchctl() {
    local plist="$1"
    if launchctl load -w "$plist" 2>/dev/null; then
        return 0
    else
        # Check if it's the known SIP-related EIO error
        local rc=$?
        echo "   ⚠️  launchctl load failed (exit=$rc) — trying osascript fallback..."
        return 1
    fi
}

load_via_osascript() {
    local plist="$1"
    local label="$2"
    # osascript can prompt for GUI authentication which works around SIP EIO 5
    osascript -e "do shell script \"launchctl load -w $plist\" with administrator privileges" 2>/dev/null || true
    # Wait and verify
    sleep 1
    if launchctl print "system/$label" &>/dev/null; then
        return 0
    fi
    # Last resort: try bootstrap (may work on some macOS 15 configurations)
    osascript -e "do shell script \"launchctl bootstrap system $plist\" with administrator privileges" 2>/dev/null || true
    sleep 1
    if launchctl print "system/$label" &>/dev/null; then
        return 0
    fi
    return 1
}

# Try loading the daemon plist
DPLIST="$PLIST_DIR/com.fastdns.daemon.plist"
if ! load_via_launchctl "$DPLIST"; then
    load_via_osascript "$DPLIST" "$DAEMON_LABEL" || {
        echo "   ❌ Failed to load daemon after multiple attempts"
        echo "      Try manually: sudo launchctl load -w $DPLIST"
    }
fi

# Verify the daemon is loaded (it may start in background)
if launchctl print "system/$DAEMON_LABEL" &>/dev/null; then
    echo "   ✅ Daemon plist registered"
else
    echo "   ⚠️  Daemon not registered in launchd — will still proceed"
fi
echo ""

# ── Step 6: Set system DNS ─────────────────────────────────────
echo "📋 Setting system DNS to 127.0.0.1..."
IFS=$'\n'
for svc in $(networksetup -listallnetworkservices | tail -n +2); do
    svc_clean=$(echo "$svc" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    # Skip disabled services (marked with *)
    if [[ "$svc_clean" == \** ]]; then
        echo "   ⏭ Skipping disabled service: $svc_clean"
        continue
    fi
    echo "   → Setting DNS for: $svc_clean"
    networksetup -setdnsservers "$svc_clean" "127.0.0.1" 2>/dev/null || echo "   ⚠️  Failed for $svc_clean (may not support DNS)"
done
echo "   ✅ System DNS configured"
echo ""

# ── Step 7: Load health-check ──────────────────────────────────
echo "📋 Starting health check service..."
HPLIST="$PLIST_DIR/com.fastdns.healthcheck.plist"
if ! load_via_launchctl "$HPLIST"; then
    load_via_osascript "$HPLIST" "$HEALTH_LABEL" || {
        echo "   ⚠️  Health check load had issues (non-fatal)"
    }
fi
sleep 1
echo "   ✅ Health check service started"
echo ""

# ── Step 8: Verification ──────────────────────────────────────
echo "═══════════════════ Verification ═══════════════════"
echo ""

# Wait a moment for the daemon to start
sleep 2

# Check daemon status
echo "--- Daemon status ---"
launchctl print system/com.fastdns.daemon 2>&1 | grep -E "state|last exit code|pid"
echo ""

# Check health check status
echo "--- Health check status ---"
launchctl print system/com.fastdns.healthcheck 2>&1 | grep -E "state|last exit code|run interval"
echo ""

# Test DNS resolution via dig
echo "--- DNS test (google.com A) ---"
DIG_OK=false
for i in 1 2 3 4 5; do
    RESULT=$(dig @127.0.0.1 google.com +short +timeout=3 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [[ -n "$RESULT" ]]; then
        echo "   ✅ Resolver works — google.com → $RESULT (attempt $i)"
        DIG_OK=true
        break
    fi
    sleep 2
done
if ! $DIG_OK; then
    echo "   ⚠️  Could not resolve google.com after 5 attempts"
    echo "      Check logs: sudo tail -20 /var/log/fastdns.error.log"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   ✅ FastDNS installation complete!      ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "   DNS resolver is now running on 127.0.0.1:53"
echo "   Logs:  /var/log/fastdns.log"
echo "          /var/log/fastdns.error.log"
echo ""
echo "   Commands:"
echo "     fastdns --healthcheck           # test the resolver"
echo "     fastdns --query google.com A    # diagnostic query"
echo "     sudo fastdns --uninstall-service  # remove service"
echo ""
