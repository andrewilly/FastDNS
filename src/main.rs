//! FastDNS — An ultra-fast, independent, recursive DNS resolver daemon.
//!
//! Features:
//! - Full recursive resolution from root hints (no upstream dependency)
//! - Forwarding mode (--upstream) for hybrid deployment
//! - Async concurrent query racing (fastest response wins)
//! - EDNS0 support (large UDP payloads)
//! - QNAME minimization (RFC 7816) — privacy by default
//! - 0x20 random case encoding — cache poisoning resistance
//! - Intelligent LRU cache with TTL management and serve-stale (RFC 8767)
//! - Predictive prefetch at startup (~500 domains)
//! - DNSSEC validation with chain-of-trust (RFC 4033/4034/4035)
//! - DNS-over-HTTPS (DoH, RFC 8484) and DNS-over-TLS (DoT, RFC 7858)
//! - Ad/tracker/malware blocking with auto-updating blocklists
//! - Rate limiting per client IP
//! - REST API + health check endpoint
//! - Prometheus metrics
//! - Cross-platform (macOS, Windows, Linux) with native service integration
//! - TOML configuration file support
#![cfg_attr(windows, allow(dead_code, unused_variables, unused_imports))]
// Clippy: DNS type names (CNAME, SOA, AAAA, etc.) follow RFC naming, not Rust conventions.
// Type complexity is inherent to DNS resolver internals.
#![allow(
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    clippy::wrong_self_convention
)]

pub mod api;
mod blocklist;
mod config;
mod dns;
mod dnssec;
mod health;
mod resolver;
mod server;
mod system_dns;
mod transport;

use std::net::SocketAddr;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::{CliOverrides, FastDnsConfig};
use crate::server::tcp::run_tcp_server;
use crate::server::udp::run_server;

/// How long to wait for graceful shutdown
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

// Windows service support
#[cfg(windows)]
mod service_handler {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    use crate::server::udp::{run_server, ServerConfig};

    static RUNNING: AtomicBool = AtomicBool::new(true);
    static CONFIG: std::sync::OnceLock<crate::server::udp::ServerConfig> =
        std::sync::OnceLock::new();

    define_windows_service!(ffi_service_main, my_service_main);

    fn my_service_main(_arguments: Vec<OsString>) {
        let status_handle = service_control_handler::register(
            "FastDNS",
            move |control_event| -> ServiceControlHandlerResult {
                match control_event {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        RUNNING.store(false, Ordering::SeqCst);
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            },
        )
        .expect("Failed to register service control handler");

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .expect("Failed to report RUNNING status");

        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        if let Some(config) = CONFIG.get() {
            if config.dnssec_ok {
                tracing::info!("DNSSEC is enabled");
            } else {
                tracing::info!("DNSSEC is disabled (use --dnssec to enable)");
            }
            rt.block_on(async {
                let resolver = Arc::new(
                    crate::resolver::recursive::RecursiveResolver::new(
                        config.enable_ipv6,
                        config.dnssec_ok,
                        config.cache_size,
                    )
                    .await
                    .unwrap(),
                );
                let cancel = Arc::new(AtomicBool::new(false));
                let cancel_clone = cancel.clone();
                // Relay Windows service RUNNING flag to cancel flag
                tokio::spawn(async move {
                    while RUNNING.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    cancel_clone.store(true, Ordering::SeqCst);
                });
                let _ = run_server(config.clone(), cancel, resolver).await;
            });
        }
    }

    pub fn run_as_service(config: ServerConfig) -> Result<bool, Box<dyn std::error::Error>> {
        CONFIG.set(config).ok();
        match service_dispatcher::start("FastDNS", ffi_service_main) {
            Ok(()) => Ok(true),
            Err(_e) => Ok(false),
        }
    }
}

/// Command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "fastdns",
    version,
    about = "🚀 Super-fast independent DNS recursive resolver",
    long_about = "FastDNS is a from-scratch, independent DNS recursive resolver.\n\
                  It performs full iterative resolution starting from root hints,\n\
                  with no dependency on any external resolver or system library.\n\n\
                  Optimized for speed with concurrent query racing, intelligent caching,\n\
                  and QNAME minimization for privacy."
)]
struct Cli {
    /// Path to TOML configuration file
    #[arg(short = 'f', long, default_value = "fastdns.toml")]
    config: String,

    /// Address to bind the DNS server (default: 127.0.0.1:53)
    #[arg(short = 'b', long)]
    bind: Option<String>,

    /// Enable IPv6 resolution (AAAA records)
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Enable DNSSEC OK bit (requests DNSSEC records)
    #[arg(short = 'd', long)]
    dnssec: bool,

    /// Disable startup domain prefetching
    #[arg(long)]
    no_prefetch: bool,

    /// Maximum cache entries (default: 250000)
    #[arg(short = 'c', long)]
    cache_size: Option<usize>,

    /// Verbose logging
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Upstream DNS server for forwarding mode (e.g., "1.1.1.1:53")
    #[arg(short = 'u', long)]
    upstream: Option<String>,

    /// Enable DoH (DNS-over-HTTPS) for transport
    #[arg(long)]
    doh: bool,

    /// Enable DoT (DNS-over-TLS) for transport
    #[arg(long)]
    dot: bool,

    /// Blocklist mode: none, adblock, malware, all
    #[arg(long)]
    blocklist_mode: Option<String>,

    /// Log file path
    #[arg(long)]
    log_file: Option<String>,

    /// Log level: error, warn, info, debug, trace
    #[arg(long)]
    log_level: Option<String>,

    /// REST API bind address (e.g., "127.0.0.1:8080")
    #[arg(long)]
    api_bind: Option<String>,

    /// Enable Prometheus metrics
    #[arg(long)]
    metrics: bool,

    /// Run a single query and exit (diagnostic mode)
    #[arg(long)]
    query: Option<String>,

    /// Record type for diagnostic query (default: A)
    #[arg(long, default_value = "A")]
    query_type: String,

    /// Install as a system service (macOS: launchd, Windows: sc)
    #[arg(long)]
    install_service: bool,

    /// Uninstall the system service
    #[arg(long)]
    uninstall_service: bool,

    /// Health check mode: query self and exit
    #[arg(long)]
    healthcheck: bool,

    /// Domain to resolve for health check (default: google.com)
    #[arg(long, default_value = "google.com")]
    healthcheck_domain: String,
}

fn main() {
    let cli = Cli::parse();

    // Load configuration from TOML file, then merge CLI overrides
    let mut config = FastDnsConfig::from_file(&cli.config);
    config.merge_cli(&CliOverrides {
        bind: cli.bind.clone(),
        ipv6: cli.ipv6,
        dnssec: cli.dnssec,
        no_prefetch: cli.no_prefetch,
        cache_size: cli.cache_size,
        verbose: cli.verbose,
        upstream: cli.upstream.clone(),
        doh: cli.doh,
        dot: cli.dot,
        blocklist_mode: cli.blocklist_mode.clone(),
        log_file: cli.log_file.clone(),
        log_level: cli.log_level.clone(),
        api_bind: cli.api_bind.clone(),
        metrics: cli.metrics,
    });

    // Initialize logging (file + stderr)
    init_logging(&config);

    // Validate configuration
    if let Err(errors) = config.validate() {
        for e in &errors {
            error!("Configuration error: {}", e);
        }
        process::exit(1);
    }

    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Install/uninstall service mode
    if cli.install_service {
        install_service_route(&config);
        return;
    }
    if cli.uninstall_service {
        uninstall_service_route();
        return;
    }

    // Health check mode
    if cli.healthcheck {
        let addr = config.bind.parse::<SocketAddr>().unwrap();
        let domain = cli.healthcheck_domain.clone();
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let ok = rt.block_on(async { health::run_healthcheck(addr, &domain).await });
        process::exit(if ok { 0 } else { 1 });
    }

    // Validate bind address
    check_bind_privileges(&config.bind, cli.healthcheck);

    // Windows: try to register as a system service first
    #[cfg(windows)]
    {
        let svc_config = config.to_server_config();
        match service_handler::run_as_service(svc_config) {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => {
                eprintln!(
                    "Warning: service mode failed ({}), running as normal process.",
                    e
                );
            }
        }
    }

    // Diagnostic query mode
    if let Some(query_name) = cli.query {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        rt.block_on(async {
            if config.doh {
                run_diagnostic_query_doh(&query_name, &cli.query_type, config.ipv6, config.dnssec)
                    .await;
            } else if config.dot {
                run_diagnostic_query_dot(&query_name, &cli.query_type).await;
            } else {
                run_diagnostic_query(&query_name, &cli.query_type, config.ipv6, config.dnssec)
                    .await;
            }
        });
        return;
    }

    // Normal server mode
    let bind = config.bind.clone();
    info!("╔══════════════════════════════════════════╗");
    info!(
        "║         🚀 FastDNS v{}          ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║     Independent Recursive Resolver      ║");
    info!("╚══════════════════════════════════════════╝");
    info!("");
    info!("Listening on   : {}", bind);
    info!(
        "IPv6 support   : {}",
        if config.ipv6 {
            "✅ enabled"
        } else {
            "❌ disabled"
        }
    );
    info!(
        "DNSSEC OK      : {}",
        if config.dnssec {
            "✅ enabled"
        } else {
            "❌ disabled"
        }
    );
    if let Some(ref up) = config.upstream {
        info!(
            "Upstream       : {} ({})",
            up,
            if config.doh {
                "DoH"
            } else if config.dot {
                "DoT"
            } else {
                "UDP"
            }
        );
    }
    info!("Cache size     : {} entries", config.cache_size);
    info!(
        "Prefetch       : {}",
        if config.no_prefetch {
            "❌ disabled"
        } else {
            "✅ enabled"
        }
    );
    info!("Blocklist mode : {}", config.blocklist_mode);
    info!("Blocked domains: {} loaded", 0); // Updated after blocklist load
    if !config.api_bind.is_empty() {
        info!("API server     : {}", config.api_bind);
    }
    info!(
        "Log file       : {}",
        if config.log_file.is_empty() {
            "stderr"
        } else {
            &config.log_file
        }
    );
    info!("");

    let server_config = config.to_server_config();

    // Create tokio runtime
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    rt.block_on(async {
        // Create the resolver
        let resolver = Arc::new(
            crate::resolver::recursive::RecursiveResolver::new(
                server_config.enable_ipv6,
                server_config.dnssec_ok,
                server_config.cache_size,
            )
            .await
            .expect("Failed to create resolver"),
        );

        // Initialize blocklist if enabled
        let blocklist = if server_config.blocklist_mode != "none" {
            let bl = Arc::new(crate::blocklist::Blocklist::new(&server_config));
            // Load blocklists asynchronously
            let bl_clone = bl.clone();
            tokio::spawn(async move {
                bl_clone.load().await;
                let stats = bl_clone.stats().await;
                info!(
                    "Blocklist loaded: {} blocked domains, {} whitelisted, {} custom records",
                    stats.total_blocked, stats.total_whitelisted, stats.total_custom
                );
            });
            Some(bl)
        } else {
            None
        };

        // Start API server if configured
        if let Some(ref api_bind) = server_config.api_bind {
            let api_state = crate::api::AppState {
                start_time: std::time::Instant::now(),
                resolver: resolver.clone(),
                blocklist: blocklist
                    .clone()
                    .map(|b| b as Arc<crate::blocklist::Blocklist>),
                query_count: Arc::new(tokio::sync::RwLock::new(0u64)),
                blocked_count: Arc::new(tokio::sync::RwLock::new(0u64)),
            };
            let api_bind_str = api_bind.clone();
            tokio::spawn(async move {
                info!("Starting API server on {}", api_bind_str);
                crate::api::start_api(api_state, &api_bind_str).await;
            });
        }

        // Create server cancel handle for shutdown
        let cancel_flag = Arc::new(AtomicBool::new(false));

        // Start UDP server
        let udp_resolver = resolver.clone();
        let udp_cancel = cancel_flag.clone();
        let udp_config = server_config.clone();
        let mut udp_handle =
            tokio::spawn(async move { run_server(udp_config, udp_cancel, udp_resolver).await });

        // Start TCP server
        let tcp_resolver = resolver.clone();
        let tcp_addr: SocketAddr = server_config.bind_addr;
        let mut tcp_handle =
            tokio::spawn(async move { run_tcp_server(tcp_addr, tcp_resolver).await });

        // Wait for shutdown signal (Unix: SIGINT/SIGTERM, Windows: Ctrl+C)
        let cancel = cancel_flag.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                    .expect("Failed to install SIGINT handler");
                let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                    .expect("Failed to install SIGTERM handler");

                tokio::select! {
                    _ = sigint.recv() => info!("Received SIGINT"),
                    _ = sigterm.recv() => info!("Received SIGTERM"),
                }
            }
            #[cfg(not(unix))]
            {
                let _ = signal::ctrl_c().await;
                info!("Received Ctrl+C");
            }

            info!("Initiating graceful shutdown...");
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        // Wait for either server to finish (error) or cancel
        tokio::select! {
            result = &mut udp_handle => {
                match result {
                    Ok(Ok(())) => info!("UDP server stopped"),
                    Ok(Err(e)) => error!("UDP server error: {}", e),
                    Err(e) => error!("UDP server join error: {}", e),
                }
            }
            result = &mut tcp_handle => {
                match result {
                    Ok(Ok(())) => info!("TCP server stopped"),
                    Ok(Err(e)) => error!("TCP server error: {}", e),
                    Err(e) => error!("TCP server join error: {}", e),
                }
            }
        }

        // Give running queries time to finish
        info!("Shutting down gracefully...");
        tokio::time::sleep(SHUTDOWN_GRACE_PERIOD).await;
        info!("FastDNS stopped.");
    });
}

/// Initialize tracing/logging based on config.
fn init_logging(config: &FastDnsConfig) {
    let log_level = if config.verbose {
        "debug"
    } else {
        &config.log_level
    };

    if config.log_file.is_empty() {
        // Stderr only
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("fastdns={}", log_level)));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .compact()
            .try_init();
    } else {
        // File + stderr logging
        let file_appender = tracing_appender::rolling::daily(&config.log_file, "fastdns.log");
        let (file_writer, _guard) = tracing_appender::non_blocking(file_appender);

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("fastdns={}", log_level)));

        let _ = tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(file_writer)
            .with_target(false)
            .compact()
            .try_init();
    }
}

/// Check bind address privileges.
fn check_bind_privileges(bind: &str, healthcheck: bool) {
    if healthcheck {
        return;
    }
    if let Ok(addr) = bind.parse::<SocketAddr>() {
        if addr.port() < 1024 {
            #[cfg(unix)]
            {
                let is_root = unsafe { libc::geteuid() == 0 };
                if !is_root {
                    error!("Binding to privileged port {} requires root. Use sudo or a non‑privileged port.", addr.port());
                    process::exit(1);
                }
            }
            #[cfg(windows)]
            {
                warn!(
                    "Binding to privileged port {} may require administrator privileges.",
                    addr.port()
                );
            }
        }
    }
}

/// Parse record type from string.
fn parse_rtype(rtype_str: &str) -> u16 {
    match rtype_str.to_uppercase().as_str() {
        "A" => 1u16,
        "AAAA" => 28,
        "CNAME" => 5,
        "MX" => 15,
        "NS" => 2,
        "TXT" => 16,
        "SOA" => 6,
        "SRV" => 33,
        _ => {
            error!(
                "Unknown record type: {}. Use A, AAAA, CNAME, MX, NS, TXT, SOA, SRV",
                rtype_str
            );
            process::exit(1);
        }
    }
}

/// Run a single diagnostic query (UDP recursive).
async fn run_diagnostic_query(name: &str, rtype_str: &str, ipv6: bool, dnssec: bool) {
    let rtype = parse_rtype(rtype_str);
    info!("🔍 Diagnostic query: {} {}", name, rtype_str);

    match crate::resolver::recursive::RecursiveResolver::new(ipv6, dnssec, 100_000).await {
        Ok(resolver) => {
            let start = std::time::Instant::now();
            match resolver.resolve(name, rtype, 1).await {
                Ok(records) => {
                    let elapsed = start.elapsed();
                    info!("✅ Resolved in {:?}", elapsed);
                    for rec in &records {
                        info!(
                            "   {} {} {} → {} (TTL={})",
                            rec.name_str(),
                            rec.rtype,
                            rec.rclass,
                            rec.rdata_str(),
                            rec.ttl
                        );
                    }
                }
                Err(e) => {
                    error!("❌ Resolution failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("❌ Failed to create resolver: {}", e);
        }
    }
}

/// Run a diagnostic query using DoH transport.
async fn run_diagnostic_query_doh(name: &str, rtype_str: &str, ipv6: bool, dnssec: bool) {
    let rtype = parse_rtype(rtype_str);
    info!("🔍 Diagnostic DoH query: {} {}", name, rtype_str);

    match crate::resolver::recursive::RecursiveResolver::new(ipv6, dnssec, 100_000).await {
        Ok(resolver) => {
            let start = std::time::Instant::now();
            match resolver.resolve_via_doh(name, rtype, 1).await {
                Ok(records) => {
                    let elapsed = start.elapsed();
                    info!("✅ DoH resolved in {:?}", elapsed);
                    for rec in &records {
                        info!(
                            "   {} {} {} → {} (TTL={})",
                            rec.name_str(),
                            rec.rtype,
                            rec.rclass,
                            rec.rdata_str(),
                            rec.ttl
                        );
                    }
                }
                Err(e) => error!("❌ DoH resolution failed: {}", e),
            }
        }
        Err(e) => error!("❌ Failed to create resolver: {}", e),
    }
}

/// Run a diagnostic query using DoT transport.
async fn run_diagnostic_query_dot(name: &str, rtype_str: &str) {
    let rtype = parse_rtype(rtype_str);
    info!("🔍 Diagnostic DoT query: {} {}", name, rtype_str);

    let question = crate::dns::types::Question {
        qname: crate::dns::types::encode_domain_name(name).unwrap_or_default(),
        qtype: rtype,
        qclass: 1,
    };
    let header = crate::dns::types::Header::new_query(rand::random(), false);
    let msg = crate::dns::types::Message {
        header,
        questions: vec![question],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let query_bytes = crate::dns::wire::encode_message(&msg).unwrap_or_default();

    let start = std::time::Instant::now();
    match crate::transport::dot::dot_query_with_fallback(&query_bytes).await {
        Ok(response_data) => match crate::dns::wire::decode_message(&response_data) {
            Ok(response) => {
                let elapsed = start.elapsed();
                if response.header.rcode == 0 {
                    info!("✅ DoT resolved in {:?}", elapsed);
                    for rec in &response.answers {
                        info!(
                            "   {} {} {} → {} (TTL={})",
                            rec.name_str(),
                            rec.rtype,
                            rec.rclass,
                            rec.rdata_str(),
                            rec.ttl
                        );
                    }
                } else {
                    error!("❌ DoT returned rcode={}", response.header.rcode);
                }
            }
            Err(e) => error!("❌ DoT response parse failed: {}", e),
        },
        Err(e) => error!("❌ DoT resolution failed: {}", e),
    }
}

// ---------------------------------------------------------------
// Service management (cross-platform)
// ---------------------------------------------------------------

/// Check if FastDNS is already running (macOS).
#[cfg(target_os = "macos")]
fn is_fastdns_running() -> bool {
    std::process::Command::new("pgrep")
        .args(["-x", "fastdns"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check if a launchd service is loaded.
#[cfg(target_os = "macos")]
fn is_launchd_service_loaded(label: &str) -> bool {
    std::process::Command::new("launchctl")
        .args(["print", &format!("system/{}", label)])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Fully clean an existing installation before re-installing.
#[cfg(target_os = "macos")]
fn clean_old_installation() {
    let plist_daemon = "/Library/LaunchDaemons/com.fastdns.daemon.plist";
    let plist_health = "/Library/LaunchDaemons/com.fastdns.healthcheck.plist";
    let binary = "/usr/local/bin/fastdns";

    let was_running = is_fastdns_running();
    let was_loaded = is_launchd_service_loaded("com.fastdns.daemon");

    if !was_running && !was_loaded && !std::path::Path::new(binary).exists() {
        println!("   ✅ Nessuna installazione precedente trovata.");
        return;
    }

    println!("🧹 Rimuovo installazione precedente...");

    // 1. Kill any running fastdns process
    if was_running {
        println!(
            "   ⛔ FastDNS è in esecuzione (PID {}), lo fermo...",
            std::process::Command::new("pgrep")
                .args(["-x", "fastdns"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default()
        );
        let _ = std::process::Command::new("pkill")
            .args(["-9", "fastdns"])
            .status();
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // 2. Unload launchd plists
    for plist in [plist_daemon, plist_health] {
        if std::path::Path::new(plist).exists() {
            println!("   🛑 Scarico {}", plist);
            let _ = std::process::Command::new("launchctl")
                .args(["unload", plist])
                .status();
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }

    // 3. Remove plist files
    for plist in [plist_daemon, plist_health] {
        if std::path::Path::new(plist).exists() {
            println!("   🗑️  Rimuovo {}", plist);
            let _ = std::fs::remove_file(plist);
        }
    }

    // 4. Remove binary
    if std::path::Path::new(binary).exists() {
        println!("   🗑️  Rimuovo {}", binary);
        let _ = std::fs::remove_file(binary);
    }

    // 5. Reset system DNS back to DHCP (router)
    println!("   🔄 Ripristino DNS di sistema...");
    let _ = std::process::Command::new("networksetup")
        .args(["-setdnsservers", "Wi-Fi", "empty"])
        .status();
    let _ = std::process::Command::new("networksetup")
        .args(["-setdnsservers", "Ethernet", "empty"])
        .status();
    let _ = std::process::Command::new("dscacheutil")
        .args(["-flushcache"])
        .status();
    let _ = std::process::Command::new("killall")
        .args(["-HUP", "mDNSResponder"])
        .status();

    println!("   ✅ Vecchia installazione rimossa.");
    std::thread::sleep(std::time::Duration::from_secs(1));
}

/// Generate a launchd plist with ProgramArguments matching the current config.
#[cfg(target_os = "macos")]
fn generate_plist(config: &FastDnsConfig, plist_path: &str) -> Result<(), String> {
    use std::io::Write;

    // Build ProgramArguments array from config
    let mut args: Vec<String> = vec![
        "/usr/local/bin/fastdns".to_string(),
        "-b".to_string(),
        config.bind.clone(),
        "-c".to_string(),
        config.cache_size.to_string(),
    ];

    if config.dnssec {
        args.push("--dnssec".to_string());
    }
    if config.ipv6 {
        args.push("--ipv6".to_string());
    }
    if let Some(ref up) = config.upstream {
        args.push("--upstream".to_string());
        args.push(up.clone());
        if config.doh {
            args.push("--doh".to_string());
        } else if config.dot {
            args.push("--dot".to_string());
        }
    }
    if config.blocklist_mode != "none" {
        args.push("--blocklist-mode".to_string());
        args.push(config.blocklist_mode.clone());
    }
    if !config.api_bind.is_empty() {
        args.push("--api-bind".to_string());
        args.push(config.api_bind.clone());
    }
    if config.metrics {
        args.push("--metrics".to_string());
    }
    if !config.log_file.is_empty() {
        args.push("--log-file".to_string());
        args.push(config.log_file.clone());
    }
    if config.log_level != "info" {
        args.push("--log-level".to_string());
        args.push(config.log_level.clone());
    }
    if config.rate_limit_qps != 100 {
        args.push("--rate-limit-qps".to_string());
        args.push(config.rate_limit_qps.to_string());
    }

    // Build XML plist
    let mut plist = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fastdns.daemon</string>
    <key>ProgramArguments</key>
    <array>
"#,
    );

    for arg in &args {
        plist.push_str(&format!("        <string>{}</string>\n", escape_xml(arg)));
    }

    plist.push_str(
        r#"    </array>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>UserName</key>
    <string>root</string>
    <key>StandardOutPath</key>
    <string>/var/log/fastdns.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/fastdns.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_BACKTRACE</key>
        <string>1</string>
    </dict>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>WatchPaths</key>
    <array>
        <string>/etc/resolv.conf</string>
    </array>
</dict>
</plist>
"#,
    );

    let mut file =
        std::fs::File::create(plist_path).map_err(|e| format!("Failed to create plist: {}", e))?;
    file.write_all(plist.as_bytes())
        .map_err(|e| format!("Failed to write plist: {}", e))?;

    Ok(())
}

/// Escape XML special characters for plist strings.
#[cfg(target_os = "macos")]
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Install FastDNS as a system service, using `config` for dynamic plist generation.
fn install_service_route(config: &FastDnsConfig) {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::PermissionsExt;

        println!("╔══════════════════════════════════════════╗");
        println!("║   🚀 FastDNS macOS Installer             ║");
        println!("╚══════════════════════════════════════════╝");
        println!();

        // ── FASE 0: Cleanup ────────────────────────────
        clean_old_installation();
        println!();

        // ── FASE 1: Copia binario ──────────────────────
        let binary_path =
            std::env::current_exe().unwrap_or_else(|_| "target/release/fastdns".into());
        let install_dir = "/usr/local/bin";
        let installed_binary = format!("{}/fastdns", install_dir);

        println!("📋 Copio il binario in {}...", installed_binary);
        std::fs::create_dir_all(install_dir).ok();
        match std::fs::copy(&binary_path, &installed_binary) {
            Ok(_) => {
                std::fs::set_permissions(&installed_binary, std::fs::Permissions::from_mode(0o755))
                    .ok();
                println!("   ✅ Binario installato: {}", installed_binary);
            }
            Err(e) => {
                eprintln!("   ❌ Errore copia binario: {}", e);
                return;
            }
        }
        println!();

        // ── FASE 2: Genera plist ───────────────────────
        let plist_dst = "/Library/LaunchDaemons/com.fastdns.daemon.plist";

        println!("📋 Genero launchd plist con i parametri correnti...");
        match generate_plist(config, plist_dst) {
            Ok(()) => {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(plist_dst, std::fs::Permissions::from_mode(0o644)).ok();
                println!("   ✅ Plist generato: {}", plist_dst);
            }
            Err(e) => {
                eprintln!("   ❌ Errore generazione plist: {}", e);
                return;
            }
        }
        println!();

        // ── FASE 3: Carica daemon ──────────────────────
        println!("📋 Carico il daemon via launchctl...");

        // Su macOS 15+ con SIP, `launchctl load -w` da terminale fallisce con EIO 5.
        // Il metodo che funziona sempre è osascript, che apre un popup di autenticazione GUI
        // e lancia launchctl con le giuste entitlement di sistema.
        //
        // Tentativo 1: launchctl load -w diretto (funziona su macOS pre-15 o SIP ridotto)
        let mut loaded = false;

        if let Ok(s) = std::process::Command::new("launchctl")
            .args(["load", "-w", plist_dst])
            .status()
        {
            loaded = s.success();
        }

        if !loaded {
            // Tentativo 2: osascript → apre finestra di autenticazione GUI
            println!("   ⚠️  Richiesta autenticazione aggiuntiva (SIP su macOS 15+).");
            println!("   🔑 Apparirà una finestra: inserisci la password di amministratore.");
            std::thread::sleep(std::time::Duration::from_secs(1));

            if let Ok(s) = std::process::Command::new("osascript")
                .args([
                    "-e",
                    &format!(
                        "do shell script \"launchctl load -w {}\" with administrator privileges",
                        plist_dst
                    ),
                ])
                .status()
            {
                loaded = s.success();
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        // Verifica con launchctl print
        if loaded || is_launchd_service_loaded("com.fastdns.daemon") {
            println!("   ✅ Daemon caricato correttamente.");
        } else {
            eprintln!("   ❌ Impossibile caricare il daemon. Prova manualmente:");
            eprintln!("      launchctl load -w {}", plist_dst);
            eprintln!("   Se il problema persiste, potrebbe servire un riavvio.");
        }
        println!();

        // ── FASE 4: Attendi bind ───────────────────────
        println!("⏳ Attendo l'avvio del demone...");
        std::thread::sleep(std::time::Duration::from_secs(3));

        // ── FASE 5: Imposta DNS sistema ────────────────
        println!("📋 Imposto DNS di sistema su 127.0.0.1...");
        match crate::system_dns::set_system_dns("127.0.0.1") {
            Ok(()) => println!("   ✅ DNS di sistema impostato a 127.0.0.1"),
            Err(e) => {
                eprintln!("   ⚠️  {} ", e);
                eprintln!("   Per impostare manualmente: sudo networksetup -setdnsservers Wi-Fi 127.0.0.1");
            }
        }
        println!("   Per revert: sudo networksetup -setdnsservers Wi-Fi empty");
        println!();

        // ── FASE 6: Verifica ────────────────────────────
        println!("📋 Verifico la risoluzione DNS...");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let output = std::process::Command::new("dig")
            .args(["@127.0.0.1", "google.com", "+short", "+timeout=3"])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let ips = String::from_utf8_lossy(&out.stdout);
                let ips: Vec<&str> = ips.lines().filter(|l| !l.is_empty()).collect();
                if !ips.is_empty() {
                    println!("   ✅ Risoluzione OK: google.com → {}", ips.join(", "));
                } else {
                    eprintln!("   ⚠️  dig non ha restituito IP. Il demone potrebbe aver bisogno di più tempo.");
                }
            }
            _ => {
                eprintln!(
                    "   ⚠️  Verifica fallita. Il demone potrebbe essere ancora in fase di avvio."
                );
                eprintln!("   Controlla con: dig @127.0.0.1 google.com");
                eprintln!("                 launchctl print system/com.fastdns.daemon");
            }
        }
        println!();

        println!("╔══════════════════════════════════════════╗");
        println!("║   ✅ FastDNS installato con successo!   ║");
        println!("╚══════════════════════════════════════════╝");
    }

    #[cfg(target_os = "windows")]
    {
        println!("📦 Installing FastDNS as Windows service...");
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "fastdns.exe".to_string());
        let bin_path = format!("\"{}\" -b 127.0.0.1:53 -c 250000 --dnssec", exe_path);

        // Clean: remove old service if exists
        println!("📋 Removing previous FastDNS service (if any)...");
        let _ = std::process::Command::new("sc")
            .args(["stop", "FastDNS"])
            .status();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = std::process::Command::new("sc")
            .args(["delete", "FastDNS"])
            .status();
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Create new service
        println!("📋 Creating new FastDNS service...");
        let status = std::process::Command::new("sc")
            .args([
                "create",
                "FastDNS",
                "binPath=",
                &bin_path,
                "start=",
                "auto",
                "DisplayName=",
                "FastDNS Recursive Resolver",
                "type=",
                "own",
                "error=",
                "normal",
            ])
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("✅ Windows service 'FastDNS' created.");
                println!("   Starting service...");
                let _ = std::process::Command::new("sc")
                    .args(["start", "FastDNS"])
                    .status();
                println!("   ✅ Service started.");
            }
            Ok(_) => eprintln!("❌ Service creation failed. Run as Administrator."),
            Err(e) => eprintln!("❌ sc.exe not found: {}. Run as Administrator.", e),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        eprintln!("❌ --install-service not supported on this platform.");
        eprintln!("   Run: cargo run --release (as root)");
    }
}

/// Uninstall FastDNS system service.
fn uninstall_service_route() {
    #[cfg(target_os = "macos")]
    {
        let status = std::process::Command::new("sudo")
            .args(["bash", "scripts/macos/uninstall.sh"])
            .status();
        match status {
            Ok(s) if s.success() => println!("✅ FastDNS uninstalled."),
            _ => println!("📋 Run: sudo bash scripts/macos/uninstall.sh"),
        }
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("sc")
            .args(["stop", "FastDNS"])
            .status();
        let status = std::process::Command::new("sc")
            .args(["delete", "FastDNS"])
            .status();
        match status {
            Ok(s) if s.success() => println!("✅ FastDNS service removed."),
            _ => eprintln!("❌ Run as Administrator: sc delete FastDNS"),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        eprintln!("❌ --uninstall-service not supported on this platform.");
    }
}
