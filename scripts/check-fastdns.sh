#!/bin/bash
# Quick status check for a running FastDNS daemon (macOS / Linux).
# Usage: bash scripts/check-fastdns.sh [resolver_ip]   (default 127.0.0.1)
R="${1:-127.0.0.1}"
ok=1

echo "== FastDNS status =="

# 1. Process
if pgrep -x fastdns >/dev/null 2>&1; then
    echo "✅ process running (PID: $(pgrep -x fastdns | tr '\n' ' '))"
else
    echo "❌ process NOT running"
    ok=0
fi

# 2. Built-in healthcheck (prints its own ✅/❌ line, exit 0/1)
if command -v fastdns >/dev/null 2>&1; then
    fastdns --healthcheck || ok=0
else
    echo "ℹ️  'fastdns' not in PATH (skipping --healthcheck)"
fi

# 3. Resolve a real domain through the daemon
if command -v dig >/dev/null 2>&1; then
    ip=$(dig @"$R" google.com A +short +time=3 +tries=1 2>/dev/null | head -1)
    if [ -n "$ip" ]; then
        echo "✅ resolves google.com → $ip"
    else
        echo "❌ cannot resolve google.com via $R"
        ok=0
    fi

    # 4. Negative caching sanity (a bogus name must return NXDOMAIN)
    st=$(dig @"$R" doesnotexist-abc.invalid A +time=3 +tries=1 2>/dev/null \
         | sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)
    if [ "$st" = "NXDOMAIN" ]; then
        echo "✅ NXDOMAIN works"
    else
        echo "⚠️  NXDOMAIN check inconclusive (status: ${st:-none})"
    fi
else
    echo "ℹ️  dig not installed (skipping resolution tests)"
fi

echo
if [ "$ok" = 1 ]; then
    echo "RESULT: FastDNS is working ✅"
    exit 0
else
    echo "RESULT: FastDNS has problems ❌"
    exit 1
fi
