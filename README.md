<p align="center">
  <img src="https://img.shields.io/badge/rust-1.81%2B-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform">
  <a href="https://github.com/andrewilly/FastDNS/actions"><img src="https://img.shields.io/github/actions/workflow/status/andrewilly/FastDNS/ci.yml?branch=main" alt="CI"></a>
</p>

<h1 align="center">🚀 FastDNS</h1>
<p align="center">
  <em>Ultra-fast, independent DNS recursive resolver written in Rust</em>
</p>

<p align="center">
  <b>Recursive resolver · Ad-blocking · DoH/DoT · QNAME minimization · REST API · Cross-platform</b>
</p>

---

## ✨ Features

### 🧠 Resolver
- **Full recursive resolution** from root hints — zero upstream dependencies
- **Forwarding mode** (`--upstream`) for hybrid deployments
- **Concurrent query racing** — sends to all nameservers, uses the fastest response
- **RTT-based server selection** with smoothed moving average and persistence across restarts
- **QNAME minimization** (RFC 7816) — reveals only one label at a time for privacy
- **0x20 random case encoding** — cache poisoning resistance
- **CNAME chasing** with depth limit
- **Truncation cache** — servers that truncate UDP are bypassed via TCP

### ⚡ Caching
- **Bounded LRU cache** via the `lru` crate (max records-per-key, no unbounded growth)
- **Negative caching** (RFC 2308) — NXDOMAIN/NODATA cached with the SOA TTL
- **Serve-stale** (RFC 8767) — stale records served while refreshing in background
- **Optional persistent cache** (`--persist-cache`) — warm start after restart
- **Predictive prefetch** — top domains warmed at startup (concurrent, rate-limited)
- **Background server health checks** every 30s on authoritative servers

### 🛡️ Security
- **DNS-over-TLS** (DoT, RFC 7858) — Cloudflare, Google, Quad9 with automatic fallback
- **DNS-over-HTTPS** (DoH, RFC 8484) — Cloudflare, Google, Quad9 with automatic fallback
- **Privilege dropping** (`--user`, Unix) — bind privileged ports as root, then drop to an unprivileged user
- **DNSSEC validation** (opt-in with `--dnssec`) — chain-of-trust with root KSK-2017 + KSK-2024.
  ⚠️ *DNSSEC validation is experimental: some valid zones may be falsely rejected in `ad`/`enforce` mode. It is disabled by default and not enabled by the installers.*

### 🚫 Ad-blocking
- **Auto-updating blocklists** from multiple sources (StevenBlack, Disconnect, etc.)
- **O(1) domain lookup** via in-memory hashset — zero latency for blocked queries
- **NXDOMAIN or nullroute** response configurable
- **Whitelist** overrides and **custom DNS records**

### 🔧 Operations
- **TOML configuration file** — full control without CLI flags
- **Cross-platform services** — macOS (launchd), Windows (Windows service), Linux
- **REST API** — health, stats, cache flush, blocklist reload
- **Graceful shutdown** — SIGINT/SIGTERM handling, final cache flush on exit
- **File logging** with rotation (falls back to stderr if unavailable)
- **Docker** — multi-stage build

---

## 📦 Quick Start

### macOS / Linux

```bash
# Build
cargo build --release

# Run (requires root for port 53)
sudo ./target/release/fastdns

# Or use a non-privileged port
./target/release/fastdns -b 127.0.0.1:5353

# Health check (prints the result and exits 0/1)
fastdns --healthcheck
```

### Windows 11 (PowerShell as Administrator)

```powershell
cargo build --release
powershell -ExecutionPolicy Bypass -File .\scripts\windows\install.ps1
```

The installer stops/removes any previous service, installs the new binary, sets the
system DNS to `127.0.0.1`, and verifies resolution. Edit `install.ps1` to add
`--dnssec --persist-cache` if you want those features.

### Docker

```bash
docker build -t fastdns .
docker run -d --name fastdns \
  -p 53:53/udp -p 53:53/tcp -p 8080:8080 \
  -v $(pwd)/fastdns.toml:/etc/fastdns/fastdns.toml \
  fastdns
```

### Configuration

FastDNS reads a TOML file (`fastdns.toml` by default); CLI flags override file values.

```toml
# Server
bind = "127.0.0.1:53"
cache_size = 50000          # entries (each key capped at 16 records)
dnssec = false              # experimental; leave false unless needed

# Optional forwarding
# upstream = "8.8.8.8:53"
# doh = true

# Caching
persist_cache = false       # warm start from disk (~/.fastdns or %APPDATA%)

# Privilege dropping (Unix; start as root, drop to this user after bind)
# user = "_fastdns"

# Ad-blocking
blocklist_mode = "none"     # none | adblock | malware | all
# blocklist_sources = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]

# REST API
# api_bind = "127.0.0.1:8080"

# Logging
log_level = "info"          # empty log_file = stderr
```

---

## 🎯 CLI Usage

```text
Usage: fastdns [OPTIONS]

Options:
  -f, --config <FILE>          TOML configuration file [default: fastdns.toml]
  -b, --bind <ADDR>            Bind address [default: 127.0.0.1:53]
  -6, --ipv6                   Enable IPv6 resolution (AAAA)
  -d, --dnssec                 Enable DNSSEC OK bit (experimental)
  -c, --cache-size <N>         Maximum cache entries [default: 50000]
  -u, --upstream <ADDR>        Upstream DNS server (forwarding mode)
      --doh                    Use DoH for the upstream
      --dot                    Use DoT for the upstream
      --no-prefetch            Disable startup domain prefetch
  -v, --verbose                Verbose (debug) logging to stderr
      --blocklist-mode <MODE>  none | adblock | malware | all
      --log-file <PATH>        Log directory (empty = stderr)
      --log-level <LEVEL>      error | warn | info | debug | trace
      --api-bind <ADDR>        REST API bind address (empty = disabled)
      --metrics                Enable Prometheus metrics on the API
      --user <USER>            Drop privileges to USER after bind (Unix)
      --persist-cache          Persist DNS cache to disk (warm start)
      --query <DOMAIN>         Run a single diagnostic query and exit
      --query-type <TYPE>      Record type for --query [default: A]
      --healthcheck            Query self; prints ✅/❌ and exits 0/1
      --healthcheck-domain <D> Domain for health check [default: google.com]
      --install-service        Install as system service
      --uninstall-service      Uninstall system service
  -h, --help                   Print help
  -V, --version                Print version
```

---

## 🔬 Advanced Usage

### Forwarding Mode
With `--upstream`, FastDNS forwards instead of recursing (optionally over DoH/DoT):

```bash
sudo fastdns --upstream 8.8.8.8:53 --doh
```

### Persistent Cache (warm start)
```bash
sudo fastdns --persist-cache
```
The cache is saved every 5 minutes and on shutdown to `~/.fastdns/dnscache.json`
(macOS/Linux) or `%APPDATA%\FastDNS\dnscache.json` (Windows), and loaded at startup.

### Privilege Dropping (Unix)
```bash
# Start as root (to bind :53), then run as an unprivileged user
sudo fastdns --user _fastdns
```

### Health Check
```bash
fastdns --healthcheck
# ✅ FastDNS OK — 127.0.0.1:53 resolved google.com → 142.250.x.x in 12 ms
# or
# ❌ FastDNS FAIL — timeout after 2000 ms — no response from 127.0.0.1:53
```

### REST API
With `--api-bind 127.0.0.1:8080`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Server health and uptime |
| `/api/stats` | GET | Cache hit/miss rates, query counts |
| `/api/cache/flush` | POST | Flush DNS cache |
| `/api/blocklist/stats` | GET | Blocklist statistics |
| `/api/blocklist/reload` | POST | Reload blocklists |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                     fastdns                          │
│  ┌──────────────┐   ┌──────────────┐                │
│  │  UDP Server  │   │  TCP Server  │  (bind :53)    │
│  └──────┬───────┘   └──────┬───────┘                │
│         └────────┬─────────┘                         │
│          ┌───────▼────────┐                          │
│          │   Resolver     │                          │
│          │  (recursive)   │                          │
│          └───┬───────┬────┘                          │
│     ┌────────▼─┐  ┌──▼──────────┐                    │
│     │  Cache   │  │ Blocklist   │                    │
│     │ (LRU +   │  │ (ad-block)  │                    │
│     │ negative)│  └─────────────┘                    │
│     └──────────┘                                     │
│  ┌────────┐ ┌────────┐ ┌──────────────┐             │
│  │  DoH   │ │  DoT   │ │  REST API    │             │
│  │transport│ │transport│ │ (axum)       │             │
│  └────────┘ └────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────┘
```

---

## 📊 Performance

Full recursive resolution from root hints (no upstream). Repeat queries are served from cache:

| Query | Cold | Warm (cache) |
|-------|------|--------------|
| google.com (A) | ~100–160 ms | ~1 ms |
| NXDOMAIN / NODATA (repeat) | ~100–170 ms | ~0–2 ms (negative cache) |

```bash
./scripts/benchmark.sh          # Cold start benchmark
./scripts/benchmark.sh --warm   # With running daemon
```

---

## 🧪 Development

```bash
cargo build --release     # optimized build
cargo test                # unit tests
cargo clippy -- -D warnings
cargo fmt
bash test-fastdns.sh      # integration tests (requires running daemon)
```

### Project Structure

```
src/
├── api.rs              # REST API (axum)
├── blocklist.rs        # Ad-blocking with auto-updating lists
├── config.rs           # TOML config + CLI merge
├── dns/                # Wire format, types, constants, errors
├── dnssec/             # DNSSEC validation (experimental)
├── health.rs           # Health check (structured result)
├── main.rs             # Entry point, service install, privilege drop
├── resolver/
│   ├── cache.rs        # LRU + negative + serve-stale + snapshot
│   ├── recursive.rs    # Full recursive resolver
│   └── root_hints.rs   # IANA root servers
├── server/             # UDP + TCP servers (bounded, with I/O timeouts)
├── system_dns.rs       # System DNS configuration (macOS/Windows)
├── tls.rs / dot.rs     # TLS / DoT listener
└── transport/          # DoH (RFC 8484), DoT (RFC 7858)
```

---

## 🩺 Stability Notes

Recent hardening (v0.2.x → v0.3.0):
- **TCP read/write timeouts** (5s) — no more hung connections accumulating memory
- **Negative caching** (RFC 2308) — NXDOMAIN/NODATA no longer re-resolve every time
- **Bounded caches** — per-key record cap, no unbounded growth over hours
- **Smaller default cache** (50k) — stable resident memory
- **Privilege dropping** and **persistent cache** are opt-in (no behavior change by default)

## ⚠️ Known Limitations / Roadmap

- **Rate limiting**: `rate_limit_qps`/`rate_limit_burst` exist in config but are **not yet enforced**.
- **DNSSEC**: validation is incomplete (may falsely reject some valid zones); keep `--dnssec` off unless you need it.
- **Cache sharding**: the cache uses a single lock; sharding for very high QPS is planned.
- **Control CLI**: use the REST API for now (no dedicated `fastdns ctl` yet).

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [grimd](https://github.com/looterz/grimd) — inspiration for the blocklist system
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns) and [rDNS](https://github.com/ZerosAndOnesLLC/rDNS) — architectural references
- IANA — root hints and trust anchors
- Cloudflare, Google, Quad9 — public DNS resolvers for fallback
