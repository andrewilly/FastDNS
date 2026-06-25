# FastDNS Dockerfile — multi-stage build
# Build: docker build -t fastdns .
# Run:   docker run -d --name fastdns -p 53:53/udp -p 53:53/tcp -p 8080:8080 fastdns

# ── Stage 1: Build ────────────────────────────────────────────────
FROM rust:1.81-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to build dependencies (improves layer caching)
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    mkdir -p src/dns src/dnssec src/resolver src/server src/transport && \
    for m in dns/mod.rs dns/types.rs dns/wire.rs dns/error.rs dns/constants.rs; do \
        touch "src/$m"; done && \
    for m in dnssec/mod.rs dnssec/trust_anchor.rs; do \
        touch "src/$m"; done && \
    for m in resolver/mod.rs resolver/cache.rs resolver/recursive.rs resolver/root_hints.rs; do \
        touch "src/$m"; done && \
    for m in server/mod.rs server/udp.rs server/tcp.rs; do \
        touch "src/$m"; done && \
    for m in transport/mod.rs transport/doh.rs transport/dot.rs; do \
        touch "src/$m"; done && \
    touch src/config.rs src/api.rs src/blocklist.rs src/main.rs src/health.rs src/system_dns.rs src/tls.rs src/dot.rs && \
    cargo build --release 2>/dev/null || true

# Copy actual source code
COPY src/ src/

# Build release binary
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libc6 libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create fastdns user
RUN groupadd -r fastdns && useradd -r -g fastdns -d /var/lib/fastdns -s /sbin/nologin fastdns

# Create necessary directories
RUN mkdir -p /var/lib/fastdns /var/log/fastdns /etc/fastdns && \
    chown -R fastdns:fastdns /var/lib/fastdns /var/log/fastdns /etc/fastdns

# Copy binary from builder
COPY --from=builder /build/target/release/fastdns /usr/local/bin/fastdns

# Copy default config
COPY fastdns.toml /etc/fastdns/fastdns.toml

# Expose ports
EXPOSE 53/udp 53/tcp 8080/tcp

# Set up healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["fastdns", "--healthcheck"]

# Run as non-root user
USER fastdns

# Default config path
ENV FASTDNS_CONFIG=/etc/fastdns/fastdns.toml

ENTRYPOINT ["fastdns"]
CMD ["-f", "/etc/fastdns/fastdns.toml"]
