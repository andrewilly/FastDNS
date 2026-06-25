#!/bin/bash
#
# FastDNS Benchmark Suite
#
# Compares FastDNS (cold start) vs Google DNS (8.8.8.8) vs Cloudflare (1.1.1.1)
#
# Usage:
#   ./scripts/benchmark.sh            # Run all benchmarks
#   ./scripts/benchmark.sh --warm     # Include warm-cache benchmark (requires running daemon)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DOMAINS=(
    "google.com"
    "cloudflare.com"
    "github.com"
    "amazon.com"
    "facebook.com"
    "youtube.com"
    "netflix.com"
    "microsoft.com"
    "apple.com"
    "wikipedia.org"
)

ITERATIONS=3
WARM_MODE=false

if [[ "${1:-}" == "--warm" ]]; then
    WARM_MODE=true
fi

header() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  $1"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
}

bench_cold() {
    local label="$1"
    local cmd="$2"
    shift 2

    echo "📊 $label (cold start)"
    echo "   Running $ITERATIONS iterations per domain..."
    echo ""

    local total_time=0
    local count=0
    local fastest=999999
    local slowest=0

    for domain in "${DOMAINS[@]}"; do
        local domain_time=0
        for ((i=0; i<ITERATIONS; i++)); do
            local start="$(( $(date +%s%N) / 1000000 ))"
            eval "$cmd '$domain' > /dev/null 2>&1"
            local end="$(( $(date +%s%N) / 1000000 ))"
            local elapsed=$(( end - start ))

            domain_time=$(( domain_time + elapsed ))
            total_time=$(( total_time + elapsed ))
            count=$(( count + 1 ))

            if (( elapsed < fastest )); then fastest=$elapsed; fi
            if (( elapsed > slowest )); then slowest=$elapsed; fi
        done
        local avg_domain=$(( domain_time / ITERATIONS ))
        printf "   %-20s %4d ms\n" "$domain" "$avg_domain"
    done

    local overall_avg=$(( total_time / count ))
    echo ""
    echo "   ─────────────────────────────────────────────"
    printf "   %-20s %4d ms\n" "Fastest" "$fastest"
    printf "   %-20s %4d ms\n" "Slowest" "$slowest"
    printf "   %-20s %4d ms\n" "Average" "$overall_avg"
    echo ""
}

bench_warm() {
    local resolver_ip="$1"
    local label="$2"

    echo "📊 $label (warm cache)"
    echo ""

    local total_time=0
    local count=0
    local fastest=999999
    local slowest=0

    for domain in "${DOMAINS[@]}"; do
        local domain_time=0
        for ((i=0; i<ITERATIONS; i++)); do
            local start="$(( $(date +%s%N) / 1000000 ))"
            dig @"$resolver_ip" "$domain" +short +tries=1 +timeout=2 > /dev/null 2>&1
            local end="$(( $(date +%s%N) / 1000000 ))"
            local elapsed=$(( end - start ))

            domain_time=$(( domain_time + elapsed ))
            total_time=$(( total_time + elapsed ))
            count=$(( count + 1 ))

            if (( elapsed < fastest )); then fastest=$elapsed; fi
            if (( elapsed > slowest )); then slowest=$elapsed; fi
        done
        local avg_domain=$(( domain_time / ITERATIONS ))
        printf "   %-20s %4d ms\n" "$domain" "$avg_domain"
    done

    local overall_avg=$(( total_time / count ))
    echo ""
    echo "   ─────────────────────────────────────────────"
    printf "   %-20s %4d ms\n" "Fastest" "$fastest"
    printf "   %-20s %4d ms\n" "Slowest" "$slowest"
    printf "   %-20s %4d ms\n" "Average" "$overall_avg"
    echo ""
}

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           🚀 FastDNS Benchmark Suite                        ║"
echo "║           $(date)              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Testing ${#DOMAINS[@]} domains × $ITERATIONS iterations"
echo ""

# == Cold Start Benchmarks ==

header "1. FastDNS (cold start, recursive from root hints)"
cd "$PROJECT_DIR"
bench_cold "FastDNS cold" "cargo run --release --quiet -- --query"

header "2. dig @8.8.8.8 (Google DNS, warm cache)"
bench_cold "Google DNS" "dig @8.8.8.8 +short +tries=1 +timeout=2"

header "3. dig @1.1.1.1 (Cloudflare DNS, warm cache)"
bench_cold "Cloudflare DNS" "dig @1.1.1.1 +short +tries=1 +timeout=2"

# == Warm Cache Benchmarks ==

if $WARM_MODE; then
    header "4. FastDNS local daemon (warm cache)"
    if pgrep -x fastdns > /dev/null 2>&1; then
        bench_warm "127.0.0.1" "FastDNS (warm)"
    else
        echo "⚠️  FastDNS daemon is not running."
        echo "   Start it first: sudo cargo run --release &"
        echo "   Then re-run: ./scripts/benchmark.sh --warm"
    fi
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ Benchmark complete!                                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
