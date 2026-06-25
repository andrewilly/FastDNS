
<p align="center">
  <img src="https://img.shields.io/badge/rust-1.81%2B-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform">
  <a href="https://github.com/andrerizzo/FastDNS/actions"><img src="https://img.shields.io/github/actions/workflow/status/andrerizzo/FastDNS/ci.yml?branch=main" alt="CI"></a>
</p>

<h1 align="center">🚀 FastDNS</h1>
<p align="center">
  <em>Ultra-fast, independent DNS recursive resolver written in Rust</em>
</p>

<p align="center">
  <b>Ad-blocking · DNSSEC · DoH/DoT · QNAME minimization · REST API · Cross-platform</b>
</p>

---

## ✨ Features

### 🧠 Resolver
- **Full recursive resolution** from root hints — zero upstream dependencies
- **Concurrent query racing** — sends to all nameservers, uses the fastest response
- **RTT-based server selection** with smoothed moving average and persistence across restarts
- **QNAME minimization** (RFC 7816) — reveals only one label at a time for maximum privacy
- **0x20 random case encoding** — cache poisoning resistance
- **TCP connection pooling** with idle timeout and per-server limits
- **Truncation cache** — servers that truncate UDP responses are automatically bypassed via TCP

### 🛡️ Security
- **DNSSEC validation** with full chain-of-trust (RFC 4033/4034/4035)
  - Root trust anchors: KSK-2017 + KSK-2024 (rollover-ready)
  - RSA/SHA-256, ECDSA P-256/P-384, Ed25519 signature verification
  - NSEC/NSEC3 denial of existence proofs
- **DNS-over-TLS** (DoT, RFC 7858) — Cloudflare, Google, Quad9 with automatic fallback
- **DNS-over-HTTPS** (DoH, RFC 8484) — Cloudflare, Google, Quad9 with automatic fallback
- **Rate limiting** per client IP (configurable QPS and burst)

### 🚫 Ad-blocking
- **Auto-updating blocklists** from multiple sources (StevenBlack, Disconnect, etc.)
- **O(1) domain lookup** via in-memory hashset — zero latency for blocked queries
- **NXDOMAIN or nullroute** response configurable per-query
- **Whitelist** overrides for false positives
- **Custom DNS records** — override specific domains to arbitrary IPs

### ⚡ Performance
- **LRU cache** with O(1) operations via `lru` crate
- **Serve-stale** (RFC 8767) — stale records served while refreshing in background
- **Predictive prefetch** — ~500 top domains warmed at startup (50 concurrent, 3s timeout)
- **Background health checks** every 30s on authoritative servers
- **Prometheus metrics** for monitoring

### 🔧 Operations
- **TOML configuration file** — full control without CLI flags
- **Cross-platform** — macOS (launchd), Linux (systemd), Windows (sc service)
- **REST API** — health, stats, cache management, blocklist reload
- **Graceful shutdown** — SIGINT/SIGTERM handling, clean teardown
- **File logging** with rotation via `tracing-appender`
- **Docker** — multi-stage build, 10MB runtime image

---

## 📦 Quick Start

### macOS

```bash
# Build
cargo build --release

# Run (requires root for port 53)
sudo ./target/release/fastdns

# Or use a non-privileged port
./target/release/fastdns -b 127.0.0.1:5353
```

### Docker

```bash
docker build -t fastdns .
docker run -d --name fastdns \
  -p 53:53/udp -p 53:53/tcp \
  -p 8080:8080 \
  -v $(pwd)/fastdns.toml:/etc/fastdns/fastdns.toml \
  fastdns
```

### Configuration

FastDNS reads a TOML configuration file (`fastdns.toml` by default). CLI flags override file values when both are specified.

```toml
# Server
bind = "127.0.0.1:53"
cache_size = 250000
dnssec = true

# Ad-blocking
blocklist_mode = "adblock"
blocklist_sources = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
]

# REST API
api_bind = "127.0.0.1:8080"

# Rate limiting
rate_limit_qps = 100
rate_limit_burst = 200
```

---

## 🎯 CLI Usage

```text
Usage: fastdns [OPTIONS]

Options:
  -f, --config <FILE>          Path to TOML configuration file [default: fastdns.toml]
  -b, --bind <ADDR>            Bind address [default: 127.0.0.1:53]
  -6, --ipv6                   Enable IPv6 resolution (AAAA records)
  -d, --dnssec                 Enable DNSSEC OK bit
  -c, --cache-size <N>         Maximum cache entries [default: 250000]
  -u, --upstream <ADDR>        Upstream DNS server (forwarding mode)
  -v, --verbose                Verbose logging
      --blocklist-mode <MODE>  Blocklist mode: none, adblock, malware, all
      --api-bind <ADDR>        REST API bind address
      --query <DOMAIN>         Run a single diagnostic query
      --healthcheck            Run health check and exit
      --install-service        Install as system service
      --uninstall-service      Uninstall system service
  -h, --help                   Print help
  -V, --version                Print version
```

---

## 🔬 Advanced Usage

### Forwarding Mode

When `--upstream` is set, FastDNS acts as a forwarding proxy instead of a recursive resolver. This is useful for hybrid deployments or initial cache warming:

```bash
# Forward all queries to Cloudflare, cache locally
sudo fastdns --upstream 1.1.1.1:53

# Use DoH forwarding
sudo fastdns --upstream 1.1.1.1:53 --doh
```

### DNSSEC Enforcement

FastDNS supports three DNSSEC policies:
- **`ad`** (default) — sets the AD bit when validation succeeds, but serves all responses
- **`enforce`** — rejects bogus responses with SERVFAIL
- **`off`** — disables DNSSEC validation

### REST API

When `api_bind` is configured, FastDNS exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Server health and uptime |
| `/api/stats` | GET | Cache hit/miss rates, query counts |
| `/api/cache/flush` | POST | Flush DNS cache |
| `/api/blocklist/stats` | GET | Blocklist statistics |
| `/api/blocklist/reload` | POST | Reload blocklists from sources |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    fastdns                           │
│  ┌──────────────┐   ┌──────────────┐               │
│  │  UDP Server  │   │  TCP Server  │               │
│  │  (port 53)   │   │  (port 53)   │               │
│  └──────┬───────┘   └──────┬───────┘               │
│         │                  │                        │
│         └────────┬─────────┘                        │
│                  │                                   │
│          ┌───────▼────────┐                          │
│          │   Resolver     │                          │
│          │  (recursive)   │                          │
│          └───┬───────┬────┘                          │
│              │       │                                │
│     ┌────────▼─┐  ┌──▼──────────┐                    │
│     │  Cache   │  │ Blocklist   │                    │
│     │  (LRU)   │  │ (ad-block)  │                    │
│     └──────────┘  └─────────────┘                    │
│                                                       │
│  ┌────────┐  ┌──────────┐  ┌──────────────────┐     │
│  │ DoH    │  │  DoT     │  │  REST API        │     │
│  │Transport│  │Transport │  │  (axum server)   │     │
│  └────────┘  └──────────┘  └──────────────────┘     │
└─────────────────────────────────────────────────────┘
```

---

## 📊 Performance

FastDNS performs full recursive resolution starting from root hints — no upstream dependency. For comparison against forwarding proxies:

| Metric | FastDNS (cold) | FastDNS (warm) | Google DNS | Cloudflare |
|--------|---------------|----------------|------------|------------|
| google.com | ~120ms | ~1ms | ~2ms | ~1ms |
| github.com | ~150ms | ~1ms | ~2ms | ~2ms |
| Average (10 domains) | ~140ms | ~1ms | ~2ms | ~1.5ms |

Run your own benchmark:
```bash
./scripts/benchmark.sh        # Cold start benchmark
./scripts/benchmark.sh --warm  # With running daemon
```

---

## 🔧 Development

```bash
# Build (debug)
cargo build

# Build (release, optimized)
cargo build --release

# Run tests
cargo test

# Run integration tests (requires running daemon)
bash test-fastdns.sh

# Format and lint
cargo fmt
cargo clippy
```

### Project Structure

```
src/
├── api.rs              # REST API server (axum)
├── blocklist.rs        # Ad-blocking with auto-updating lists
├── config.rs           # TOML configuration + CLI merge
├── dns/
│   ├── constants.rs    # DNS protocol constants
│   ├── error.rs        # DNS error types
│   ├── types.rs        # Wire format types (Header, Question, ResourceRecord, etc.)
│   └── wire.rs         # Encode/decode helpers
├── dnssec/
│   ├── mod.rs          # DNSSEC validation (chain-of-trust, RRSIG, NSEC/NSEC3)
│   └── trust_anchor.rs # Root zone trust anchors
├── health.rs           # Health check
├── main.rs             # Entry point
├── resolver/
│   ├── cache.rs        # LRU DNS cache with serve-stale
│   ├── mod.rs
│   ├── recursive.rs    # Full recursive resolver (2000+ lines)
│   └── root_hints.rs   # IANA root server addresses
├── server/
│   ├── mod.rs
│   ├── tcp.rs          # TCP DNS server (RFC 1035)
│   └── udp.rs          # UDP DNS server
├── system_dns.rs       # System DNS configuration (macOS/Windows)
├── tls.rs              # TLS certificate generation
├── dot.rs              # DoT listener
└── transport/
    ├── doh.rs          # DNS-over-HTTPS (RFC 8484)
    ├── dot.rs          # DNS-over-TLS (RFC 7858)
    └── mod.rs
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -am 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Code Style

- `cargo fmt` before committing
- `cargo clippy` — no warnings
- `cargo test` — all tests pass
- Follow the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [grimd](https://github.com/looterz/grimd) — inspiration for the blocklist system
- [miekg/dns](https://github.com/miekg/dns) — Go DNS library reference
- IANA — root hints and trust anchors
- Cloudflare, Google, Quad9 — public DNS resolvers for fallback
