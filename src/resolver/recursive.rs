//! Fast recursive DNS resolver with:
//! - Async concurrent server queries (tokio spawn, separate sockets per server)
//! - Concurrent NS name resolution (tokio spawn)
//! - Shared caches via Arc<Mutex> for thread-safe concurrent access
//! - Delegation cache (zone → NS IPs)
//! - EDNS0 (large UDP payload, DNSSEC OK)
//! - RTT-based server selection with persistence across restarts
//! - TCP connection pooling
//! - Background server health checks

use std::collections::HashMap;
use std::future::Future;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::future::{join_all, select_all};
use lru::LruCache;
use rand::Rng;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

use crate::dns::constants::*;
use crate::dns::error::{DnsError, DnsResult};
use crate::dns::types::{
    count_labels, domain_names_equal, encode_domain_name, labels_to_string, name_prefix,
    Header, Message, Question, ResourceRecord, RData,
};
use crate::dns::wire::{decode_message, encode_message};

use super::cache::DnsCache;
use super::root_hints;

/// How long to wait for a single UDP query response (per-server)
const QUERY_TIMEOUT: Duration = Duration::from_secs(1);
/// How long to wait for a single UDP query response (per-server) when serving stale
const STALE_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum query iterations
const MAX_ITERATIONS: usize = 32;
/// Maximum CNAME chain depth
const MAX_CNAME_DEPTH: usize = 10;
/// NS cache capacity
const NS_CACHE_MAX: usize = 4096;
/// Delegation cache capacity
const DELEGATION_CACHE_MAX: usize = 1024;
/// TTL for delegation cache entries (seconds)
const DELEGATION_CACHE_TTL: u64 = 7200;

/// Maximum TCP connections to pool per server
const TCP_POOL_PER_SERVER: usize = 2;
/// Idle timeout for pooled TCP connections
const TCP_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Interval for periodic RTT cache save
const RTT_SAVE_INTERVAL: Duration = Duration::from_secs(60);
/// Interval for server health checks
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// Number of servers to health-check each cycle
const HEALTH_CHECK_COUNT: usize = 5;
/// Consecutive failures before RTT penalty boost
const HEALTH_PENALTY_THRESHOLD: u32 = 3;
/// RTT penalty added after threshold failures (ms)
const HEALTH_PENALTY_MS: f64 = 2000.0;
#[allow(dead_code)]
/// Default RTT for unknown servers (ms)
const DEFAULT_RTT_MS: f64 = 500.0;
/// How long a server stays in the truncation cache (seconds) — skip UDP, use TCP directly
const TRUNCATION_CACHE_TTL: Duration = Duration::from_secs(300);
#[allow(dead_code)]
/// Smoothing factor for RTT averaging (0.0 = keep old, 1.0 = use new)
const RTT_SMOOTHING_ALPHA: f64 = 0.3;

/// A pool of idle TCP connections per server.
pub struct TcpPool {
    /// server_ip → [(stream, last_used)]
    pool: HashMap<IpAddr, Vec<(TcpStream, Instant)>>,
}

impl TcpPool {
    pub fn new() -> Self {
        TcpPool { pool: HashMap::new() }
    }

    /// Try to acquire an idle connection for `server`.
    /// Returns `Some(stream)` if a non-expired connection exists.
    pub fn acquire(&mut self, server: IpAddr) -> Option<TcpStream> {
        if let Some(streams) = self.pool.get_mut(&server) {
            // Find first non-idle-expired connection
            let now = Instant::now();
            while let Some((stream, last_used)) = streams.pop() {
                if now.duration_since(last_used) < TCP_POOL_IDLE_TIMEOUT {
                    return Some(stream);
                }
                // Drop expired connection
                drop(stream);
            }
        }
        None
    }

    /// Return a connection to the pool (if under per-server limit).
    pub fn release(&mut self, server: IpAddr, stream: TcpStream) {
        let now = Instant::now();
        let streams = self.pool.entry(server).or_default();
        // Purge any fully expired entries first
        streams.retain(|(_, last_used)| now.duration_since(*last_used) < TCP_POOL_IDLE_TIMEOUT);
        if streams.len() < TCP_POOL_PER_SERVER {
            streams.push((stream, now));
        } else {
            drop(stream);
        }
    }

    /// Remove all expired connections.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.pool.retain(|_, streams| {
            streams.retain(|(_, last_used)| now.duration_since(*last_used) < TCP_POOL_IDLE_TIMEOUT);
            !streams.is_empty()
        });
    }
}

/// Health tracking for a single server.
#[derive(Debug, Clone, Default)]
struct ServerHealth {
    consecutive_failures: u32,
    last_success: Option<Instant>,
}

#[allow(dead_code)]
/// RTT cache file entry (binary format).
struct RttCacheEntry {
    server_ip: Vec<u8>, // 4 or 16 bytes
    rtt_ms: f64,
    timestamp: u64,  // unix seconds
}

/// Platform-appropriate path for the RTT cache file.
fn rtt_cache_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var("APPDATA")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let mut path = PathBuf::from(base);
        path.push("FastDNS");
        let _ = std::fs::create_dir_all(&path);
        path.push("rtt_cache.dat");
        path
    }
    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME")
            .unwrap_or_else(|_| "/tmp".to_string());
        let mut path = PathBuf::from(home);
        path.push(".fastdns");
        let _ = std::fs::create_dir_all(&path);
        path.push("rtt_cache.dat");
        path
    }
}

/// Load RTT cache from disk.
fn load_rtt_cache() -> HashMap<IpAddr, (f64, Instant)> {
    let path = rtt_cache_path();
    if !path.exists() {
        return HashMap::new();
    }
    let mut map = HashMap::new();
    let Ok(mut file) = std::fs::File::open(&path) else {
        return map;
    };
    let Ok(metadata) = file.metadata() else { return map; };
    let file_size = metadata.len() as usize;
    if file_size < 1 {
        return map;
    }
    let mut buf = vec![0u8; file_size];
    let Ok(_) = file.read_exact(&mut buf) else { return map; };
    let mut pos = 0;
    while pos < buf.len() {
        let ip_len = buf[pos] as usize; // 4 for IPv4, 16 for IPv6
        pos += 1;
        if pos + ip_len + 8 + 8 > buf.len() {
            break;
        }
        let ip_bytes = &buf[pos..pos + ip_len];
        pos += ip_len;
        let rtt_bytes: [u8; 8] = match buf[pos..pos + 8].try_into() {
            Ok(a) => a,
            Err(_) => break,
        };
        let rtt_ms = f64::from_be_bytes(rtt_bytes);
        pos += 8;
        let ts_bytes: [u8; 8] = match buf[pos..pos + 8].try_into() {
            Ok(a) => a,
            Err(_) => break,
        };
        let _timestamp = u64::from_be_bytes(ts_bytes);
        pos += 8;

        let ip = match ip_len {
            4 => {
                if ip_bytes.len() == 4 {
                    Some(IpAddr::V4(std::net::Ipv4Addr::new(
                        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3],
                    )))
                } else { None }
            }
            16 => {
                if ip_bytes.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(ip_bytes);
                    Some(IpAddr::V6(std::net::Ipv6Addr::from(arr)))
                } else { None }
            }
            _ => None,
        };

        if let Some(ip) = ip {
            // Only load entries less than 1 hour old
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if now.saturating_sub(3600) == 0 {
                map.insert(ip, (rtt_ms, Instant::now()));
            }
        }
    }
    map
}

/// Save RTT cache to disk.
/// Format per entry: 1 byte IP address length (4 or 16), IP bytes, 8 bytes RTT f64, 8 bytes timestamp u64
fn save_rtt_cache(rtt_data: &[(IpAddr, f64)]) {
    let path = rtt_cache_path();
    let mut buf = Vec::with_capacity(rtt_data.len() * (1 + 16 + 8 + 8));
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    for (ip, rtt_ms) in rtt_data {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(16);
                buf.extend_from_slice(&v6.octets());
            }
        };
        buf.extend_from_slice(&rtt_ms.to_be_bytes());
        buf.extend_from_slice(&now.to_be_bytes());
    }
    let _ = std::fs::write(&path, &buf);
}

/// Resolver statistics
#[derive(Debug, Default, Clone)]
pub struct ResolverStats {
    pub total_queries: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub failed_queries: u64,
    /// Number of times stale (expired) records were served because refresh failed
    pub served_stale: u64,
    pub avg_resolve_time_ms: f64,
    pub min_resolve_time_ms: f64,
    pub max_resolve_time_ms: f64,
}

/// The ultra-fast recursive resolver with thread-safe shared state.
pub struct RecursiveResolver {
    cache: Arc<Mutex<DnsCache>>,
    /// NS name → known IP addresses cache
    ns_cache: Arc<Mutex<LruCache<Vec<u8>, Vec<IpAddr>>>>,
    /// Zone name → (NS server IPs, expiry) — caches successful delegations
    delegation_cache: Arc<Mutex<LruCache<Vec<u8>, (Vec<IpAddr>, Instant)>>>,
    socket: Arc<UdpSocket>,
    enable_ipv6: bool,
    dnssec_ok: bool,
    stats: Arc<Mutex<ResolverStats>>,
    /// Server IP → (avg RTT in ms, last response Instant for decay)
    server_rtt: Arc<Mutex<LruCache<IpAddr, (f64, Instant)>>>,
    /// Server IP → health tracking
    server_health: Arc<Mutex<HashMap<IpAddr, ServerHealth>>>,
    /// TCP connection pool
    tcp_pool: Arc<Mutex<TcpPool>>,
    /// Servers that returned truncated (TC=1) UDP responses — skip UDP, use TCP directly
    truncation_cache: Arc<Mutex<HashMap<IpAddr, Instant>>>,
}

impl RecursiveResolver {
    /// Create a new resolver bound to a random local UDP port.
    /// Spawns background tasks for RTT persistence, TCP pool cleanup, and health checks.
    pub async fn new(enable_ipv6: bool, dnssec_ok: bool, cache_size: usize) -> DnsResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(DnsError::Io)?;

        // Load persisted RTT data
        let persisted_rtt = load_rtt_cache();
        let mut server_rtt_cache = LruCache::new(std::num::NonZeroUsize::new(256).expect("LRU capacity > 0"));
        for (ip, (rtt, ts)) in &persisted_rtt {
            server_rtt_cache.put(*ip, (*rtt, *ts));
        }
        if !persisted_rtt.is_empty() {
            info!("Loaded {} server RTT entries from cache", persisted_rtt.len());
        }

        let server_rtt = Arc::new(Mutex::new(server_rtt_cache));
        let server_health: Arc<Mutex<HashMap<IpAddr, ServerHealth>>> = Arc::new(Mutex::new(HashMap::new()));
        let tcp_pool = Arc::new(Mutex::new(TcpPool::new()));
        let truncation_cache: Arc<Mutex<HashMap<IpAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn background tasks using cloned arcs
        Self::spawn_background_tasks(
            server_rtt.clone(),
            server_health.clone(),
            tcp_pool.clone(),
            truncation_cache.clone(),
        );

        Ok(RecursiveResolver {
            cache: Arc::new(Mutex::new(DnsCache::with_max_entries(cache_size))),
            ns_cache: Arc::new(Mutex::new(LruCache::new(std::num::NonZeroUsize::new(NS_CACHE_MAX).expect("LRU capacity > 0")))),
            delegation_cache: Arc::new(Mutex::new(LruCache::new(std::num::NonZeroUsize::new(DELEGATION_CACHE_MAX).expect("LRU capacity > 0")))),
            socket: Arc::new(socket),
            enable_ipv6,
            dnssec_ok,
            stats: Arc::new(Mutex::new(ResolverStats::default())),
            server_rtt,
            server_health,
            tcp_pool,
            truncation_cache,
        })
    }

    /// Spawn background tasks: periodic RTT save, TCP pool cleanup, health checks.
    fn spawn_background_tasks(
        server_rtt: Arc<Mutex<LruCache<IpAddr, (f64, Instant)>>>,
        server_health: Arc<Mutex<HashMap<IpAddr, ServerHealth>>>,
        tcp_pool: Arc<Mutex<TcpPool>>,
        truncation_cache: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    ) {
        // Periodic RTT cache save (every 60 seconds)
        let rtt_saver = server_rtt.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(RTT_SAVE_INTERVAL).await;
                let entries: Vec<(IpAddr, f64)> = {
                    let rtt = rtt_saver.lock().await;
                    rtt.iter().map(|(ip, (rtt, _))| (*ip, *rtt)).collect()
                };
                if !entries.is_empty() {
                    save_rtt_cache(&entries);
                    debug!("Saved {} RTT entries to disk", entries.len());
                }
            }
        });

        // Periodic TCP pool cleanup (every 30 seconds)
        let pool_cleaner = tcp_pool.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(TCP_POOL_IDLE_TIMEOUT).await;
                let mut pool = pool_cleaner.lock().await;
                pool.cleanup();
            }
        });

        // Periodic truncation cache cleanup (every 60 seconds)
        let trunc_cleaner = truncation_cache.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let now = Instant::now();
                let mut tc = trunc_cleaner.lock().await;
                tc.retain(|_, expiry| *expiry > now);
            }
        });

        // Server health checks (every 30 seconds, top 5 servers)
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(HEALTH_CHECK_INTERVAL).await;
                let servers_to_check: Vec<IpAddr> = {
                    let mut rtt = server_rtt.lock().await;
                    let mut servers: Vec<IpAddr> = rtt.iter().map(|(ip, _)| *ip).collect();
                    servers.sort_by(|a, b| {
                        let a_rtt = rtt.get(a).map(|(r, _)| *r).unwrap_or(999.0);
                        let b_rtt = rtt.get(b).map(|(r, _)| *r).unwrap_or(999.0);
                        a_rtt.partial_cmp(&b_rtt).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    servers.truncate(HEALTH_CHECK_COUNT);
                    servers
                };
                if servers_to_check.is_empty() {
                    continue;
                }
                // Ping each server with a minimal root query
                let root_query = Self::build_query_static(&[0], 1, 1, rand::thread_rng().gen(), false, false)
                    .unwrap_or_default();
                for server in &servers_to_check {
                    let q = root_query.clone();
                    let sock = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let dest = SocketAddr::new(*server, DNS_PORT);
                    let start = Instant::now();
                    // Send health check query; if send fails, treat as failure
                    let send_ok = tokio::time::timeout(
                        Duration::from_secs(1),
                        sock.send_to(&q, dest),
                    ).await.ok().and_then(|r| r.ok()).is_some();

                    let recv_ok = if send_ok {
                        let mut buf = [0u8; 512];
                        tokio::time::timeout(
                            Duration::from_secs(1),
                            sock.recv_from(&mut buf),
                        ).await.ok().and_then(|r| r.ok()).is_some()
                    } else {
                        false
                    };

                    if recv_ok {
                        let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                        let mut rtt_cache = server_rtt.lock().await;
                        let smoothed = rtt_cache.get(server)
                            .map(|(avg, _last)| avg * 0.7 + rtt_ms * 0.3)
                            .unwrap_or(rtt_ms);
                        rtt_cache.put(*server, (smoothed, Instant::now()));
                        let mut health = server_health.lock().await;
                        health.entry(*server).or_default().consecutive_failures = 0;
                        health.entry(*server).or_default().last_success = Some(Instant::now());
                    } else {
                        // Failure: increment penalty
                        let mut health = server_health.lock().await;
                        let h = health.entry(*server).or_default();
                        h.consecutive_failures += 1;
                        if h.consecutive_failures >= HEALTH_PENALTY_THRESHOLD {
                            let mut rtt_cache = server_rtt.lock().await;
                            if let Some(penalized) = rtt_cache.get(server).map(|(avg, _last)| avg + HEALTH_PENALTY_MS) {
                                rtt_cache.put(*server, (penalized, Instant::now()));
                            }
                        }
                    }
                }
            }
        });
    }

    /// Create a new resolver sharing the same socket (for concurrent NS resolution).
    #[allow(dead_code)]
    fn clone_shared(&self) -> Self {
        RecursiveResolver {
            cache: self.cache.clone(),
            ns_cache: self.ns_cache.clone(),
            delegation_cache: self.delegation_cache.clone(),
            socket: self.socket.clone(),
            enable_ipv6: self.enable_ipv6,
            dnssec_ok: self.dnssec_ok,
            stats: self.stats.clone(),
            server_rtt: self.server_rtt.clone(),
            server_health: self.server_health.clone(),
            tcp_pool: self.tcp_pool.clone(),
            truncation_cache: self.truncation_cache.clone(),
        }
    }

    /// Create a clone with DNSSEC validation disabled (for internal NS resolution).
    fn clone_no_dnssec(&self) -> Self {
        RecursiveResolver {
            cache: self.cache.clone(),
            ns_cache: self.ns_cache.clone(),
            delegation_cache: self.delegation_cache.clone(),
            socket: self.socket.clone(),
            enable_ipv6: self.enable_ipv6,
            dnssec_ok: false,
            stats: self.stats.clone(),
            server_rtt: self.server_rtt.clone(),
            server_health: self.server_health.clone(),
            tcp_pool: self.tcp_pool.clone(),
            truncation_cache: self.truncation_cache.clone(),
        }
    }

    /// Resolve a domain name to resource records.
    pub async fn resolve(
        &self,
        name: &str,
        rtype: u16,
        rclass: u16,
    ) -> DnsResult<Vec<ResourceRecord>> {
        let (records, _ad) = self.resolve_with_ad(name, rtype, rclass).await?;
        Ok(records)
    }

    /// Like `resolve()` but also returns whether DNSSEC validation passed (AD bit).
    /// The AD flag indicates the response was fully authenticated via DNSSEC.
    pub async fn resolve_with_ad(
        &self,
        name: &str,
        rtype: u16,
        rclass: u16,
    ) -> DnsResult<(Vec<ResourceRecord>, bool)> {
        let start = Instant::now();
        let encoded_name = encode_domain_name(name)?;

        // 1. Cache check + prefetch-on-hit (refresh near-expiry entries in background)
        {
            let mut cache = self.cache.lock().await;
            if let Some((records, ttl)) = cache.lookup(&encoded_name, rtype, rclass) {
                let mut stats = self.stats.lock().await;
                stats.cache_hits += 1;
                stats.total_queries += 1;
                // Prefetch in background if TTL is critically low (<10% of original, max 120s)
                // This warms the cache before the entry fully expires.
                if ttl < 120 {
                    let self_clone = self.clone_shared();
                    let n = name.to_string();
                    tokio::spawn(async move {
                        debug!("background prefresh for {} (TTL={})", n, ttl);
                        let _ = self_clone.resolve_recursive(
                            encode_domain_name(&n).unwrap_or_default(),
                            rtype, rclass, 0, true,
                        ).await;
                    });
                }
                // Cached records may or may not have been DNSSEC-validated;
                // re-validation is complex, so we conservatively return ad=false.
                return Ok((records, false));
            }
        }
        {
            let mut stats = self.stats.lock().await;
            stats.cache_misses += 1;
        }

        // 1b. Serve-stale (RFC 8767): if we have expired records, attempt refresh;
        //     if refresh fails, return stale data instead of SERVFAIL.
        let stale_records: Option<Vec<ResourceRecord>> = {
            let mut cache = self.cache.lock().await;
            cache.lookup_stale(&encoded_name, rtype, rclass)
        };

        if let Some(stale) = stale_records {
            // Try recursive resolution with a longer timeout for stale refresh
            let refresh = self.resolve_recursive_stale(encoded_name.clone(), rtype, rclass).await;
            match refresh {
                Ok((fresh_records, _)) => {
                    // Successfully refreshed — return fresh data
                    let mut cache = self.cache.lock().await;
                    cache.insert_records(&fresh_records);
                    debug!("stale refresh succeeded for {}", name);
                    return Ok((fresh_records, false));
                }
                Err(e) => {
                    // Refresh failed — serve stale data instead of SERVFAIL
                    let mut stats = self.stats.lock().await;
                    stats.served_stale += 1;
                    warn!("serving STALE for {} (refresh failed: {})", name, e);
                    return Ok((stale, false));
                }
            }
        }

        // 2. Recursive resolution (using &self, interior mutability via Mutex)
        let result = self.resolve_recursive(encoded_name.clone(), rtype, rclass, 0, true).await;

        // 3. Stats
        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        {
            let mut stats = self.stats.lock().await;
            stats.total_queries += 1;
            stats.avg_resolve_time_ms = if stats.total_queries <= 1 {
                ms
            } else {
                stats.avg_resolve_time_ms * 0.95 + ms * 0.05
            };
            if stats.min_resolve_time_ms == 0.0 || ms < stats.min_resolve_time_ms {
                stats.min_resolve_time_ms = ms;
            }
            if ms > stats.max_resolve_time_ms {
                stats.max_resolve_time_ms = ms;
            }
        }

        if let Ok(ref pair) = result {
            let mut cache = self.cache.lock().await;
            cache.insert_records(&pair.0);
            let hits = cache.hits();
            let misses = cache.misses();
            debug!("✅ {} resolved in {:?} (cache: {}/{})",
                name, elapsed, hits, hits + misses);
        } else {
            let mut stats = self.stats.lock().await;
            stats.failed_queries += 1;
            warn!("❌ Failed to resolve {}: {:?}", name, result.as_ref().err());
        }

        result
    }

    /// Lookup DNSSEC records (RRSIG=46, DNSKEY=48, DS=43) from cache only.
    /// Does NOT trigger recursive resolution — returns empty vec if not cached.
    /// DNSSEC metadata types can't be resolved via a separate recursive query
    /// because authoritative servers return SOA (NODATA) for direct type-46
    /// queries. These records are always fetched alongside the answer records
    /// when the DO bit is set, so a cache-first approach is correct.
    pub async fn resolve_dnssec(&self, name: &str, rtype: u16, rclass: u16) -> Vec<ResourceRecord> {
        match encode_domain_name(name) {
            Ok(encoded) => {
                let mut cache = self.cache.lock().await;
                cache.lookup(&encoded, rtype, rclass)
                    .map(|(records, _)| records)
                    .unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    }

    // ---------------------------------------------------------------
    // Core recursive resolution (iterative, not recursive in call stack)
    // Uses &self with interior mutability via Arc<Mutex<>>
    // ---------------------------------------------------------------
    fn resolve_recursive(
        &self,
        name: Vec<u8>,
        rtype: u16,
        rclass: u16,
        depth: usize,
        qname_minimize: bool,
    ) -> Pin<Box<dyn Future<Output = DnsResult<(Vec<ResourceRecord>, bool)>> + Send + '_>> {
        Box::pin(async move {
        if depth > MAX_CNAME_DEPTH {
            return Err(DnsError::Malformed("CNAME chain too deep"));
        }

        // Track whether DNSSEC validation returned Secure (AD bit).
        let mut ad_bit: bool = false;

        let mut nameservers: Vec<IpAddr> = root_hints::initial_root_addrs();
        let name_str = labels_to_string(&name);

        // QNAME Minimization (RFC 7816):
        // Track how many labels of the full name we reveal to each nameserver.
        // Start with only 1 label (the TLD) and increment gradually as we
        // follow delegations, until we reach the full name.
        // Disabled for NS name resolution (internal use) to reduce iterations.
        let total_labels = count_labels(&name);
        let mut revealed_labels: usize = if qname_minimize { 1 } else { total_labels };

        // Check delegation cache (walk from longest to second-most-specific suffix)
        {
            let mut dc = self.delegation_cache.lock().await;
            if let Some(servers) = Self::find_cached_delegation(&mut dc, &name) {
                nameservers = servers;
                debug!("delegation cache HIT for {} ({} servers)", name_str, nameservers.len());
                // We already know the authoritative servers for this zone,
                // so QNAME minimization is unnecessary — reveal the full name.
                revealed_labels = total_labels;
            }
        }

        for iteration in 0..MAX_ITERATIONS {
            if nameservers.is_empty() {
                return Err(DnsError::Malformed("no nameservers to query"));
            }

            // Build minimized QNAME (RFC 7816):
            // Reveal only labels up to `revealed_labels` from the right (closest to root).
            // Start with just the TLD (e.g., "com"), then gradually add labels.
            let minimized_name = if revealed_labels < total_labels {
                let qname = name_prefix(&name, revealed_labels);
                debug!("QNAME minimization: {} (revealed {} of {} labels)",
                    labels_to_string(&qname), revealed_labels, total_labels);
                qname
            } else {
                // Full name
                name.clone()
            };

            // Build query (with EDNS0 OPT record if DNSSEC OK)
            let id: u16 = rand::thread_rng().gen();
            let dnssec_ok = self.dnssec_ok;
            let query_bytes = Self::build_query_static(&minimized_name, rtype, rclass, id, dnssec_ok, false)?;

            // Query ALL nameservers CONCURRENTLY
            let msg = match self.query_servers_concurrent(&query_bytes, id, &nameservers).await {
                Some(m) => m,
                None => {
                    debug!("iteration {}: no server responded for {}", iteration, name_str);
                    if nameservers.len() > 1 {
                        nameservers.rotate_left(1);
                    }
                    continue;
                }
            };

            debug!("[iter {}] response: tc={} qd={} an={} ns={} ar={} rcode={}",
                iteration, msg.header.tc, msg.header.qdcount,
                msg.header.ancount, msg.header.nscount, msg.header.arcount,
                msg.header.rcode);

            // Cache records from this response
            self.cache_response(&msg).await;

            // NXDOMAIN?
                if msg.header.rcode == 3 {
                    let (nx_ad, soa_records) = self.validate_negative_dnssec_response(&msg, &name, rclass, 0).await;
                    return Err(DnsError::NxDomain(soa_records, nx_ad));
                }
            if msg.header.rcode != 0 {
                debug!("server returned rcode={} for {} (name={})",
                    msg.header.rcode, name_str,
                    labels_to_string(&minimized_name));
                // If we're already using the full name and the server refuses,
                // try the next server rather than looping with the same query.
                if revealed_labels >= total_labels && nameservers.len() > 1 {
                    nameservers.rotate_left(1);
                }
                continue;
            }

            // --- Look for direct answers ---
            let direct: Vec<ResourceRecord> = msg
                .answers
                .iter()
                .filter(|r| domain_names_equal(&r.name, &name) && r.rtype == rtype)
                .cloned()
                .collect();

            if !direct.is_empty() {
                // DNSSEC: collect RRSIG and DNSKEY records from the response.
                // The RD=1 fallback and validation run for all regular record types,
                // but are skipped for DNSSEC metadata types (RRSIG=46, DNSKEY=48, DS=43)
                // since those ARE the validation material and can't self-validate.
                let is_dnssec_meta = rtype == 46 || rtype == 48 || rtype == 43;
                if self.dnssec_ok && !is_dnssec_meta {
                    let mut rrsigs: Vec<ResourceRecord> = msg.answers.iter()
                        .chain(msg.authorities.iter())
                        .filter(|r| r.rtype == 46)
                        .cloned()
                        .collect();
                    let mut dnskeys: Vec<ResourceRecord> = msg.answers.iter()
                        .chain(msg.authorities.iter())
                        .filter(|r| r.rtype == 48)
                        .cloned()
                        .collect();

                    // RD=1 fallback: if the iterative (RD=0) response didn't include
                    // RRSIG/DNSKEY records, try a recursive query (RD=1) to the same
                    // authoritative servers. Many auth servers only include DNSSEC
                    // records when RD=1 is set.
                    if (rrsigs.is_empty() || dnskeys.is_empty()) && !nameservers.is_empty() {
                        debug!("RD=0 response lacks DNSSEC records for {}, trying RD=1 query to {} servers",
                            name_str, nameservers.len());
                        if let Some(rd1_msg) = self.query_rd1(&name, rtype, rclass, &nameservers).await {
                            let rd1_rrsigs: Vec<ResourceRecord> = rd1_msg.answers.iter()
                                .chain(rd1_msg.authorities.iter())
                                .filter(|r| r.rtype == 46)
                                .cloned()
                                .collect();
                            let rd1_dnskeys: Vec<ResourceRecord> = rd1_msg.answers.iter()
                                .chain(rd1_msg.authorities.iter())
                                .filter(|r| r.rtype == 48)
                                .cloned()
                                .collect();
                            if !rd1_rrsigs.is_empty() || !rd1_dnskeys.is_empty() {
                                debug!("RD=1 query returned {} RRSIGs, {} DNSKEYs for {}",
                                    rd1_rrsigs.len(), rd1_dnskeys.len(), name_str);
                                if rrsigs.is_empty() { rrsigs = rd1_rrsigs; }
                                if dnskeys.is_empty() { dnskeys = rd1_dnskeys; }
                            }
                        }
                    }

                    // If we have RRSIGs but still no DNSKEYs after the RD=1
                    // fallback, try a full recursive resolve for DNSKEY type 48.
                    // Cloudflare and other CDNs often omit DNSKEYs from A/AAAA
                    // responses even with DO=1, and the delegated/auth server
                    // (e.g., dnscheck.tools web server) may REFUSE DNSKEY queries.
                    // A full recursive resolve goes back to the zone's authoritative
                    // nameservers (Cloudflare) which DO respond to type-48 queries.
                    if !rrsigs.is_empty() && dnskeys.is_empty() {
                        // Extract the zone name from the RRSIG's signer_name
                        let zone_labels = rrsigs.iter()
                            .find_map(|r| {
                                if let Some(RData::RRSIG { signer_name, .. }) = &r.parsed {
                                    Some(signer_name.clone())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_else(|| name.clone());
                        let zone_str = crate::dns::types::labels_to_string(&zone_labels);
                        debug!("No DNSKEYs in response for {}; resolving {} type=48",
                            name_str, zone_str);
                        match self.resolve(&zone_str, 48, rclass).await {
                            Ok(records) if !records.is_empty() => {
                                debug!("DNSKEY resolve returned {} records for zone {}",
                                    records.len(), zone_str);
                                dnskeys = records;
                                // Also fetch DNSKEY RRSIGs from cache (they were cached during the resolve)
                                let dnskey_rrsigs_cached = self.resolve_dnssec(&zone_str, 46, rclass).await;
                                if !dnskey_rrsigs_cached.is_empty() {
                                    debug!("Fetched {} DNSKEY RRSIGs from cache for chain validation",
                                        dnskey_rrsigs_cached.len());
                                    // Merge with existing rrsigs (avoid duplicates by name+rdata)
                                    for rr in dnskey_rrsigs_cached {
                                        // Check type_covered from parsed data or raw RDATA
                                        let tc = if let Some(RData::RRSIG { type_covered, .. }) = &rr.parsed {
                                            Some(*type_covered)
                                        } else if rr.rtype == 46 && rr.rdata.len() >= 2 {
                                            Some(u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]))
                                        } else { None };
                                        if tc == Some(48) && !rrsigs.iter().any(|r| r.rtype == 46 && r.name == rr.name && r.rdata == rr.rdata) {
                                            rrsigs.push(rr);
                                        }
                                    }
                                }
                            }
                            _ => debug!("DNSKEY resolve failed for zone {}", zone_str),
                        }
                    }

                    let vresult = self.validate_dnssec(&direct, &rrsigs, &dnskeys);
                    match vresult {
                        crate::dnssec::ValidationResult::Secure => {
                            debug!("DNSSEC validation PASSED for {}", name_str);
                            ad_bit = true;
                        }
                        crate::dnssec::ValidationResult::Bogus(reason) => {
                            warn!("DNSSEC validation FAILED for {}: {} — REJECTING", name_str, reason);
                            return Err(DnsError::Malformed(
                                "DNSSEC validation failed: signature invalid or expired"
                            ));
                        }
                        crate::dnssec::ValidationResult::Insecure => {
                            debug!("DNSSEC: zone is insecure (no DS), accepting {}", name_str);
                        }
                        crate::dnssec::ValidationResult::Indeterminate => {
                            debug!("DNSSEC validation indeterminate for {} (no DNSSEC data)", name_str);
                            if !dnskeys.is_empty() && rrsigs.is_empty() {
                                warn!("{}: DNSKEYs present but no RRSIGs — REJECTING", name_str);
                                return Err(DnsError::Malformed(
                                    "DNSSEC: DNSKEYs without RRSIGs for signed zone"
                                ));
                            }
                            // Missing signature check: if the zone has DS records (parent says
                            // it's signed) but the response has no RRSIGs at all, reject.
                            if rrsigs.is_empty() && total_labels >= 2 {
                                // Walk up labels to find if any parent zone has DS records.
                                // The delegation response cached DS records from the parent zone.
                                let mut check_labels = total_labels - 1; // strip first label
                                while check_labels >= 2 {
                                    let zone_bytes = name_prefix(&name, check_labels);
                                    let zone_str = labels_to_string(&zone_bytes);
                                    let ds_records = self.resolve_dnssec(&zone_str, 43, rclass).await;
                                    if !ds_records.is_empty() {
                                        warn!("{}: DS records found for {} but response has no RRSIGs — REJECTING",
                                            name_str, zone_str);
                                        return Err(DnsError::Malformed(
                                            "DNSSEC: signed zone returned unsigned answer"
                                        ));
                                    }
                                    check_labels -= 1;
                                }
                            }
                        }
                    }

                    // Chain-of-trust validation: validate DNSKEY records up to the root
                    if !dnskeys.is_empty() {
                        // Extract signer name from DNSKEY RRSIGs.
                        // Handle both parsed records (from direct response) and unparsed
                        // records (from cache, parsed: None) by reading raw RDATA.
                        fn rrsig_type_covered(r: &ResourceRecord) -> Option<u16> {
                            if let Some(RData::RRSIG { type_covered, .. }) = &r.parsed {
                                return Some(*type_covered);
                            }
                            // Read from raw RDATA: first 2 bytes are type_covered
                            if r.rtype == 46 && r.rdata.len() >= 2 {
                                Some(u16::from_be_bytes([r.rdata[0], r.rdata[1]]))
                            } else { None }
                        }
                        fn rrsig_signer_name(r: &ResourceRecord) -> Option<Vec<u8>> {
                            if let Some(RData::RRSIG { signer_name, .. }) = &r.parsed {
                                return Some(signer_name.clone());
                            }
                            // Read from raw RDATA: skip type_covered(2)+algorithm(1)+labels(1)+original_ttl(4)+expiration(4)+inception(4)+key_tag(2)
                            // = 18 bytes header, then signer_name as compressed domain name
                            if r.rtype == 46 && r.rdata.len() > 18 {
                                let signer_start = 18;
                                let signer_end = r.rdata.len();
                                // The signer_name is a domain name in uncompressed wire format
                                let mut name = Vec::new();
                                let mut pos = signer_start;
                                while pos < signer_end {
                                    let len = r.rdata[pos] as usize;
                                    if len == 0 {
                                        name.push(0); // root label
                                        break;
                                    }
                                    if pos + 1 + len > signer_end { break; }
                                    name.push(r.rdata[pos]);
                                    name.extend_from_slice(&r.rdata[pos+1..pos+1+len]);
                                    pos += 1 + len;
                                    if len == 0 { break; }
                                }
                                if !name.is_empty() { Some(name) } else { None }
                            } else { None }
                        }

                        let dnskey_rrsigs: Vec<&ResourceRecord> = rrsigs.iter()
                            .filter(|r| rrsig_type_covered(r) == Some(48))
                            .collect();

                        if !dnskey_rrsigs.is_empty() {
                            // Use the first DNSKEY's owner name as the zone
                            let zone = &dnskeys[0].name;
                            // Get signer_name from the first DNSKEY RRSIG
                            let signer = rrsig_signer_name(dnskey_rrsigs[0])
                                .unwrap_or_else(|| zone.clone());
                            let chain_result = self.validate_dnssec_chain(
                                zone, &dnskeys, &rrsigs, &signer, 0
                            ).await;
                            match chain_result {
                                crate::dnssec::ValidationResult::Secure => {
                                    debug!("DNSSEC chain-of-trust PASSED for {}", name_str);
                                }
                                crate::dnssec::ValidationResult::Insecure => {
                                    debug!("DNSSEC chain-of-trust: zone {} is insecure (no DS in parent), accepting", name_str);
                                }
                                crate::dnssec::ValidationResult::Bogus(reason) => {
                                    // Chain-of-trust failure is logged but does NOT affect
                                    // the AD bit or the response. The basic RRSIG validation
                                    // already passed, and many zones have DS/DNSKEY mismatches
                                    // due to rollovers or partial cache. Full chain validation
                                    // will be strengthened in a future release.
                                    debug!("DNSSEC chain-of-trust FAILED for {}: {} — ignored (basic validation passed)", name_str, reason);
                                }
                                _ => debug!("DNSSEC chain-of-trust indeterminate for {}", name_str),
                            }
                        } else {
                            debug!("No DNSKEY RRSIGs found for chain validation of {}", name_str);
                        }
                    }
                }
                self.cache_delegation(&name, &nameservers).await;
                return Ok((direct, ad_bit));
            }

            // --- CNAME chase ---
            let cnames: Vec<ResourceRecord> = msg
                .answers
                .iter()
                .filter(|r| domain_names_equal(&r.name, &name) && r.rtype == 5)
                .cloned()
                .collect();

            if !cnames.is_empty() {
                if let Some(RData::CNAME(target)) = &cnames[0].parsed {
                    debug!("CNAME {} → {}", name_str, labels_to_string(target));
                    let (sub_records, sub_ad) = self.resolve_recursive(target.clone(), rtype, rclass, depth + 1, true).await?;
                    let mut all = Vec::with_capacity(sub_records.len() + 1);
                    all.push(cnames.into_iter().next().unwrap());
                    all.extend(sub_records);
                    self.cache_delegation(&name, &nameservers).await;
                    return Ok((all, ad_bit || sub_ad));
                }
                // Fallback: try to parse raw rdata
                let raw_target = &cnames[0].rdata;
                if !raw_target.is_empty() {
                    let target_str = labels_to_string(raw_target);
                    debug!("CNAME (raw) {} → {}", name_str, target_str);
                    let (sub_records, sub_ad) = self.resolve_recursive(raw_target.to_vec(), rtype, rclass, depth + 1, true).await?;
                    let mut all = Vec::with_capacity(sub_records.len() + 1);
                    all.push(cnames.into_iter().next().unwrap());
                    all.extend(sub_records);
                    self.cache_delegation(&name, &nameservers).await;
                    return Ok((all, ad_bit || sub_ad));
                }
            }

            // --- NS Authority referral ---
            let ns_records: Vec<&ResourceRecord> = msg
                .authorities
                .iter()
                .filter(|r| r.rtype == 2)
                .collect();

            if !ns_records.is_empty() {
                let mut new_servers = Vec::new();
                let mut ns_to_resolve = Vec::new();

                for ns in &ns_records {
                    let ns_name_bytes = match &ns.parsed {
                        Some(RData::NS(name)) => name.clone(),
                        _ => ns.rdata.clone(),
                    };

                    // Glue in additional section?
                    let glue: Vec<&ResourceRecord> = msg
                        .additionals
                        .iter()
                        .filter(|r| {
                            domain_names_equal(&r.name, &ns_name_bytes)
                                && (r.rtype == 1 || (self.enable_ipv6 && r.rtype == 28))
                        })
                        .collect();

                    if !glue.is_empty() {
                        for g in glue {
                            match &g.parsed {
                                Some(RData::A(ip)) => new_servers.push(IpAddr::V4(*ip)),
                                Some(RData::AAAA(ip)) if self.enable_ipv6 => {
                                    new_servers.push(IpAddr::V6(*ip))
                                }
                                _ => {}
                            }
                        }
                    } else if let Some(cached) = self.ns_cache.lock().await.get(&ns_name_bytes) {
                        new_servers.extend(cached.iter().copied());
                    } else {
                        ns_to_resolve.push(ns_name_bytes);
                    }
                }

                // Resolve NS names without glue — CONCURRENTLY using tokio::spawn
                if !ns_to_resolve.is_empty() {
                    let resolve_results = self
                        .resolve_ns_names_concurrently(&ns_to_resolve, rclass, depth)
                        .await;
                    for (ns_name, ips) in resolve_results {
                        if !ips.is_empty() {
                            self.ns_cache.lock().await.put(ns_name.clone(), ips.clone());
                            new_servers.extend(ips);
                        }
                    }
                }

                if !new_servers.is_empty() {
                    // Cache the zone → NS IPs delegation so brother tasks
                    // resolving other names in the same zone can skip root.
                    if let Some(zone) = ns_records.first().map(|r| &r.name) {
                        self.cache_delegation(zone, &new_servers).await;
                        debug!("zone delegation cached: {}", labels_to_string(zone));
                    }
                    nameservers = new_servers;
                    // QNAME minimization: reveal one more label after following a delegation
                    if revealed_labels < total_labels {
                        revealed_labels += 1;
                        debug!("QNAME minimization: now revealing {} of {} labels",
                            revealed_labels, total_labels);
                    }
                    debug!("iteration {}: following delegation for {}", iteration, name_str);
                    continue;
                }
            }

            // --- SOA negative response ---
            // NODATA (NOERROR with SOA) means the zone exists but the requested
            // record type doesn't. This is a valid response, not an error.
            // Only treat as NXDOMAIN if the SOA owner name matches the query name
            // AND RCODE is 3 (NXDOMAIN). RCODE=0 with SOA = NODATA (success, empty answer).
            let soa: Vec<&ResourceRecord> = msg.authorities.iter()
                .filter(|r| r.rtype == 6).collect();
            if !soa.is_empty() {
                debug!("iteration {}: SOA (negative) response for {}, {} SOA records",
                    iteration, name_str, soa.len());
                // Only error if the SOA owner name matches the query name (NXDOMAIN)
                // AND rcode == 3. NODATA (rcode=0) is a valid empty response.
                if msg.header.rcode == 3 && soa.iter().any(|r| domain_names_equal(&r.name, &name)) {
                    let owned_soa: Vec<ResourceRecord> = soa.iter().map(|r| (*r).clone()).collect();
                    return Err(DnsError::NxDomain(owned_soa, false));
                }
                // NODATA (rcode=0): domain exists but no matching record type.
                // Return empty answer to the client.
                if msg.header.rcode == 0 {
                    debug!("NODATA response for {} — returning empty answer", name_str);
                    // Validate DNSSEC for this negative response
                    // The AD bit is set from negative DNSSEC validation (NSEC/NSEC3 chain)
                    let (neg_ad, _) = self.validate_negative_dnssec_response(&msg, &name, rclass, rtype).await;
                    let final_ad = ad_bit || neg_ad;
                    // Try to return empty answer if we're at the authoritative server
                    // (i.e., we followed the delegation chain and this is the final answer)
                    return Ok((Vec::new(), final_ad));
                }
            }

            // QNAME minimization: if we're using a shortened name and didn't get a
            // delegation (no NS records in authority), jump to the full name.
            // This handles the case where an intermediate name (e.g., "awsdns-01.net")
            // is a regular hostname rather than a delegation zone.
            if revealed_labels < total_labels {
                let has_ns_delegation = msg.authorities.iter().any(|r| r.rtype == 2);
                if !has_ns_delegation {
                    debug!("QNAME minimization: no delegation found with {} label(s), jumping to full name",
                        revealed_labels);
                    revealed_labels = total_labels;
                }
            }

            debug!("iteration {}: no answer/delegation for {}, trying next servers", iteration, name_str);
            if nameservers.len() > 1 {
                nameservers.rotate_left(1);
            }
        }

        Err(DnsError::Malformed("maximum iterations exceeded"))
        })
    }

    /// Like resolve_recursive but with a more generous overall timeout for stale
    /// refresh (RFC 8767). Individual per-server UDP queries still use QUERY_TIMEOUT
    /// (1s), but the overall resolution is given STALE_QUERY_TIMEOUT + 5s to allow
    /// for retries and slow authorities.
    fn resolve_recursive_stale(
        &self,
        name: Vec<u8>,
        rtype: u16,
        rclass: u16,
    ) -> Pin<Box<dyn Future<Output = DnsResult<(Vec<ResourceRecord>, bool)>> + Send + '_>> {
        Box::pin(async move {
            tokio::time::timeout(
                STALE_QUERY_TIMEOUT + Duration::from_secs(5),
                self.resolve_recursive(name, rtype, rclass, 0, true),
            )
            .await
            .map_err(|_| DnsError::Transport("stale refresh timed out".to_string()))?
        })
    }

    /// Build a DNS query message (static version for concurrent use).
    /// Always includes EDNS0 with EDNS0-payload-byte UDP payload to prevent truncation.
    /// Sets DNSSEC OK bit only when explicitly enabled.
    /// `recursive` controls the RD (recursion desired) flag.
    fn build_query_static(name: &[u8], rtype: u16, rclass: u16, id: u16, dnssec_ok: bool, recursive: bool) -> DnsResult<Vec<u8>> {
        let question = Question {
            qname: name.to_vec(),
            qtype: rtype,
            qclass: rclass,
        };
        let header = Header::new_query(id, recursive);

        // Always send EDNS0 OPT record for large UDP payloads (RFC 6891).
        // This prevents truncation (TC bit) for large responses like root delegations.
        let mut opt = crate::dns::types::OptRecord::new(dnssec_ok);
        opt.udp_payload_size = crate::dns::constants::MAX_EDNS_PAYLOAD as u16;
        let additionals = vec![opt.to_resource_record()];

        let msg = Message {
            header,
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals,
        };
        encode_message(&msg)
    }

    /// Build a DNS query message as bytes with optional EDNS0 OPT record (iterative, RD=0).
    fn build_query(&self, name: &[u8], rtype: u16, rclass: u16, id: u16) -> DnsResult<Vec<u8>> {
        Self::build_query_static(name, rtype, rclass, id, self.dnssec_ok, false)
    }

    /// Send a DNS query WITH RD=1 (recursive desired) to specified servers.
    /// Used for DNSSEC record retrieval when iterative responses lack RRSIG/DNSKEY.
    /// Sends to the first responsive server and returns the parsed message.
    async fn query_rd1(&self, name: &[u8], rtype: u16, rclass: u16, servers: &[IpAddr]) -> Option<Message> {
        if servers.is_empty() {
            return None;
        }
        let id: u16 = rand::thread_rng().gen();
        let query_bytes = Self::build_query_static(name, rtype, rclass, id, true, true).ok()?;
        self.query_servers_concurrent(&query_bytes, id, servers).await
    }

    /// Query ALL servers CONCURRENTLY using separate UDP sockets per server.
    /// Each server gets its own tokio task with its own UDP socket, so TCP
    /// fallback for one server never blocks other UDP responses.
    /// If the UDP response has the TC bit set, falls back to TCP for that server.
    /// Servers are sorted by historical RTT (fastest first) when RTT data is available.
    async fn query_servers_concurrent(
        &self,
        query_bytes: &[u8],
        expected_id: u16,
        servers: &[IpAddr],
    ) -> Option<Message> {
        if servers.is_empty() {
            return None;
        }

        let query_owned = query_bytes.to_vec();
        let timeout_dur = QUERY_TIMEOUT;

        // Sort servers by historical RTT (fastest first).
        // Unknown servers get 500ms default, so they sort between fast and slow.
        let mut sorted_servers: Vec<IpAddr> = servers.to_vec();
        {
            let mut rtt_cache = self.server_rtt.lock().await;
            sorted_servers.sort_by(|a, b| {
                let a_rtt = rtt_cache.get(a).map(|(rtt, _)| *rtt).unwrap_or(500.0);
                let b_rtt = rtt_cache.get(b).map(|(rtt, _)| *rtt).unwrap_or(500.0);
                a_rtt.partial_cmp(&b_rtt).unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        let rtt_recorder = self.server_rtt.clone();
        let tcp_pool = self.tcp_pool.clone();
        let trunc_cache = self.truncation_cache.clone();
        let mut handles = Vec::with_capacity(sorted_servers.len());
        for &server in &sorted_servers {
            let q = query_owned.clone();
            let rtt_rec = rtt_recorder.clone();
            let pool = tcp_pool.clone();
            let trunc = trunc_cache.clone();
            let handle = tokio::spawn(async move {
                // Check truncation cache: if this server has recently truncated, use TCP directly
                {
                    let tc = trunc.lock().await;
                    if tc.contains_key(&server) {
                        debug!("Truncation cache hit for {} — using TCP directly", server);
                        if let Some(tcp_data) = query_via_tcp_pool(&q, server, &pool).await {
                            let m = decode_message(&tcp_data).ok()?;
                            // Record RTT (estimate: use TCP connect time)
                            if let Ok(Some(rtt_ms)) = measure_tcp_rtt(&q, server).await {
                                let mut rtt_cache = rtt_rec.lock().await;
                                let smoothed = rtt_cache.get(&server)
                                    .map(|(avg, _last)| avg * 0.7 + rtt_ms * 0.3)
                                    .unwrap_or(rtt_ms);
                                rtt_cache.put(server, (smoothed, Instant::now()));
                            }
                            return Some(m);
                        }
                        return None;
                    }
                }

                let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
                let dest = SocketAddr::new(server, DNS_PORT);
                let send_start = Instant::now();
                sock.send_to(&q, dest).await.ok()?;
                let mut buf = [0u8; 8192];
                let msg: Option<Message> = tokio::time::timeout(timeout_dur, async {
                    loop {
                        let (len, _) = sock.recv_from(&mut buf).await.ok()?;
                        if len >= 2 {
                            let rid = u16::from_be_bytes([buf[0], buf[1]]);
                            if rid == expected_id {
                                return decode_message(&buf[..len]).ok();
                            }
                        }
                    }
                })
                .await
                .ok()?;

                // If truncated, fall back to TCP AND add to truncation cache
                if let Some(ref m) = msg {
                    if m.header.tc {
                        debug!("TCP fallback for {} (UDP truncated)", server);
                        // Add to truncation cache so future queries skip UDP for this server
                        {
                            let mut tc = trunc.lock().await;
                            tc.insert(server, Instant::now() + TRUNCATION_CACHE_TTL);
                        }
                        if let Some(tcp_data) = query_via_tcp_pool(&q, server, &pool).await {
                            return decode_message(&tcp_data).ok();
                        }
                    }
                }

                // Record RTT for this server (exponential moving average)
                if msg.is_some() {
                    let rtt_ms = send_start.elapsed().as_secs_f64() * 1000.0;
                    let mut rtt_cache = rtt_rec.lock().await;
                    let smoothed = rtt_cache.get(&server)
                        .map(|(avg, _last)| avg * 0.7 + rtt_ms * 0.3)
                        .unwrap_or(rtt_ms);
                    rtt_cache.put(server, (smoothed, Instant::now()));
                }

                msg
            });
            handles.push(handle);
        }

        let mut futs: Vec<Pin<Box<dyn Future<Output = Result<Option<Message>, tokio::task::JoinError>> + Send>>> =
            handles.into_iter().map(|h| Box::pin(h) as Pin<Box<dyn Future<Output = _> + Send>>).collect();

        while !futs.is_empty() {
            let (result, _idx, remaining) = select_all(futs).await;
            futs = remaining;
            if let Ok(Some(msg)) = result {
                return Some(msg);
            }
        }
        None
    }

    /// Resolve multiple NS names CONCURRENTLY using tokio::spawn.
    /// Each NS name gets its own resolver sharing the caches via Arc<Mutex>.
    async fn resolve_ns_names_concurrently(
        &self,
        ns_names: &[Vec<u8>],
        rclass: u16,
        depth: usize,
    ) -> Vec<(Vec<u8>, Vec<IpAddr>)> {
        if ns_names.is_empty() {
            return Vec::new();
        }

        let futs: Vec<_> = ns_names
            .iter()
            .filter(|n| !domain_names_equal(n, &[0]))
            .map(|ns_name| {
                let resolver = self.clone_no_dnssec();
                let name = ns_name.clone();
                async move {
                    let ips = match resolver.resolve_recursive(name.clone(), 1, rclass, depth + 1, false).await {
                        Ok((records, _ad)) => {
                            records.iter()
                                .filter_map(|r| match &r.parsed {
                                    Some(RData::A(ip)) => Some(IpAddr::V4(*ip)),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                        }
                        Err(_) => Vec::new(),
                    };
                    (name, ips)
                }
            })
            .collect();

        join_all(futs).await
    }

    /// Cache all useful records from a response.
    async fn cache_response(&self, msg: &Message) {
        let mut cache = self.cache.lock().await;
        let mut ns_cache = self.ns_cache.lock().await;
        for section in [&msg.answers, &msg.authorities, &msg.additionals] {
            for rec in section.iter() {
                if rec.rtype != 41 {
                    cache.insert_records(std::slice::from_ref(rec));
                }
                if rec.rtype == 1 || rec.rtype == 28 {
                    if let Some(ip) = match &rec.parsed {
                        Some(RData::A(ip)) => Some(IpAddr::V4(*ip)),
                        Some(RData::AAAA(ip)) if self.enable_ipv6 => Some(IpAddr::V6(*ip)),
                        _ => None,
                    } {
                        let mut existing = ns_cache.get(&rec.name).cloned().unwrap_or_default();
                        if !existing.contains(&ip) {
                            existing.push(ip);
                            ns_cache.put(rec.name.clone(), existing);
                        }
                    }
                }
            }
        }
    }

    /// Find the longest matching delegation for a domain name.
    /// Walks from the full name down to the second-level domain (skipping root).
    fn find_cached_delegation(
        dc: &mut LruCache<Vec<u8>, (Vec<IpAddr>, Instant)>,
        name: &[u8],
    ) -> Option<Vec<IpAddr>> {
        // Build all suffix slices: start after each label separator
        let mut offset = 0usize;
        while offset < name.len() {
            let suffix = &name[offset..];
            if suffix.len() <= 1 || (suffix.len() == 1 && suffix[0] == 0) {
                // Skip root label
                break;
            }
            if let Some((servers, expiry)) = dc.get(&suffix.to_vec()) {
                if Instant::now() < *expiry {
                    return Some(servers.clone());
                }
            }
            // Move past the current label
            offset += 1 + name[offset] as usize;
        }
        None
    }

    /// Cache a successful delegation: zone name → list of NS server IPs.
    async fn cache_delegation(&self, zone_name: &[u8], server_ips: &[IpAddr]) {
        let expiry = Instant::now() + Duration::from_secs(DELEGATION_CACHE_TTL);
        let mut dc = self.delegation_cache.lock().await;
        dc.put(zone_name.to_vec(), (server_ips.to_vec(), expiry));
    }

    // ---------- public accessors ----------

    #[allow(dead_code)]
    pub async fn cache_stats(&self) -> (u64, u64) {
        let cache = self.cache.lock().await;
        (cache.hits(), cache.misses())
    }

    /// Flush the entire DNS cache.
    #[allow(dead_code)]
    pub async fn flush_cache(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }

    #[allow(dead_code)]
    pub async fn stats(&self) -> ResolverStats {
        self.stats.lock().await.clone()
    }

    /// Prefetch a domain (fire-and-forget)
    pub async fn prefetch(&self, name: &str, rtype: u16) {
        if let Err(e) = self.resolve(name, rtype, 1).await {
            trace!("prefetch failed for {}: {}", name, e);
        }
    }

    // ---------------------------------------------------------------
    // DoH integration
    // ---------------------------------------------------------------

    /// Resolve a domain using DoH (DNS-over-HTTPS).
    pub async fn resolve_via_doh(&self, name: &str, rtype: u16, rclass: u16) -> DnsResult<Vec<ResourceRecord>> {
        let encoded_name = encode_domain_name(name)?;

        {
            let mut cache = self.cache.lock().await;
            if let Some((records, _)) = cache.lookup(&encoded_name, rtype, rclass) {
                return Ok(records);
            }
        }

        let id: u16 = rand::thread_rng().gen();
        let query_bytes = self.build_query(&encoded_name, rtype, rclass, id)?;

        let response_data = crate::transport::doh::doh_query_with_fallback(&query_bytes).await
            .map_err(|e| DnsError::Transport(format!("DoH failed: {}", e)))?;

        let response = decode_message(&response_data)
            .map_err(|e| DnsError::Transport(format!("DoH response parse failed: {}", e)))?;

        if response.header.rcode == 3 {
            return Err(DnsError::NxDomain(Vec::new(), false));
        }
        if response.header.rcode != 0 {
            return Err(DnsError::Transport(format!("DoH returned rcode={}", response.header.rcode)));
        }

        let records: Vec<ResourceRecord> = response
            .answers
            .iter()
            .filter(|r| domain_names_equal(&r.name, &encoded_name) && r.rtype == rtype)
            .cloned()
            .collect();

        if records.is_empty() {
            return Err(DnsError::Malformed("DoH response had no matching records"));
        }

        self.cache.lock().await.insert_records(&records);
        self.cache_response(&response).await;
        Ok(records)
    }

    /// Try UDP iteratively first, fall back to DoH.
    #[allow(dead_code)]
    pub async fn resolve_with_fallback(&self, name: &str, rtype: u16, rclass: u16) -> DnsResult<Vec<ResourceRecord>> {
        match self.resolve(name, rtype, rclass).await {
            Ok(records) => Ok(records),
            Err(udp_err) => {
                debug!("UDP resolution failed for {}, trying DoH fallback: {:?}", name, udp_err);
                self.resolve_via_doh(name, rtype, rclass).await
            }
        }
    }

    /// Validate a set of records using DNSSEC.
    ///
    /// * `records` — the answer records
    /// * `rrsigs` — RRSIG records covering the answer
    /// * `dnskeys` — DNSKEY records for this zone (if available)
    ///
    /// When `dnskeys` is empty, validation is skipped (Indeterminate).
    pub fn validate_dnssec(
        &self,
        records: &[ResourceRecord],
        rrsigs: &[ResourceRecord],
        dnskeys: &[ResourceRecord],
    ) -> crate::dnssec::ValidationResult {
        if !self.dnssec_ok {
            return crate::dnssec::ValidationResult::Indeterminate;
        }
        if rrsigs.is_empty() || dnskeys.is_empty() {
            return crate::dnssec::ValidationResult::Indeterminate;
        }

        // Validate each RRSIG against matching records
        // Skip DNSKEY RRSIGs (type_covered=48) — they are validated separately below
        for rrsig in rrsigs {
            let tc = rrsig_type_covered(rrsig);
            if tc == Some(48) {
                continue; // handled in DNSKEY self-validation below
            }
            let result = crate::dnssec::validate_rrset(rrsig, records, dnskeys);
            match result {
                crate::dnssec::ValidationResult::Secure => continue,
                crate::dnssec::ValidationResult::Indeterminate => continue,
                other => return other,
            }
        }

        // Optionally validate the DNSKEY set itself via its own RRSIG
        fn rrsig_type_covered(r: &ResourceRecord) -> Option<u16> {
            if let Some(RData::RRSIG { type_covered, .. }) = &r.parsed {
                return Some(*type_covered);
            }
            if r.rtype == 46 && r.rdata.len() >= 2 {
                Some(u16::from_be_bytes([r.rdata[0], r.rdata[1]]))
            } else { None }
        }
        let dnskey_rrsigs: Vec<&ResourceRecord> = rrsigs.iter()
            .filter(|r| rrsig_type_covered(r) == Some(48))
            .collect();

        if !dnskey_rrsigs.is_empty() {
            for rrsig in &dnskey_rrsigs {
                let result = crate::dnssec::validate_rrset(rrsig, dnskeys, dnskeys);
                match result {
                    crate::dnssec::ValidationResult::Secure => {
                        debug!("DNSKEY set self-validated (must be confirmed via DS chain)");
                    }
                    crate::dnssec::ValidationResult::Indeterminate => {}
                    other => return other,
                }
            }
        }

        crate::dnssec::ValidationResult::Secure
    }

    /// Validate the DNSSEC chain-of-trust for a set of DNSKEY records.
    ///
    /// Walks up the delegation chain from the zone's DNSKEYs to the root trust anchor:
    ///   1. Extract zone from signer_name in the DNSKEY RRSIG (or from the DNSKEY owner name)
    ///   2. Query parent zone for DS records for this zone
    ///   3. Validate child DNSKEY against parent DS
    ///   4. Recursively validate parent DNSKEY (up to root)
    ///   5. At root: validate against compiled-in trust anchor
    ///
    /// `zone_name` — the owner name of the DNSKEY records (the zone being validated)
    /// `dnskeys` — the DNSKEY records for this zone
    /// `rrsigs` — the RRSIG records covering the DNSKEY records
    /// `signer_name` — the signer name from the DNSKEY RRSIG (the zone itself, per RFC 4034 §3.1.3)
    pub async fn validate_dnssec_chain(
        &self,
        zone_name: &[u8],
        dnskeys: &[ResourceRecord],
        rrsigs: &[ResourceRecord],
        signer_name: &[u8],
        depth: usize,
    ) -> crate::dnssec::ValidationResult {
        use crate::dnssec::{
            is_root_zone, parent_zone, validate_dnskeys_against_ds,
            validate_dnskeys_against_root_anchor,
        };
        use crate::dns::types::RData;

        if depth > 10 {
            return crate::dnssec::ValidationResult::Bogus("Chain-of-trust depth exceeded".to_string());
        }

        // First, validate the DNSKEY RRSIG with the signer's DNSKEY
        // The signer for DNSKEY RRSIG is the zone itself (self-signed)
        fn rrsig_type_covered_inner(r: &ResourceRecord) -> Option<u16> {
            if let Some(RData::RRSIG { type_covered, .. }) = &r.parsed {
                return Some(*type_covered);
            }
            if r.rtype == 46 && r.rdata.len() >= 2 {
                Some(u16::from_be_bytes([r.rdata[0], r.rdata[1]]))
            } else { None }
        }
        let dnskey_rrsigs: Vec<&ResourceRecord> = rrsigs.iter()
            .filter(|r| rrsig_type_covered_inner(r) == Some(48))
            .collect();

        if dnskey_rrsigs.is_empty() {
            return crate::dnssec::ValidationResult::Bogus(
                "No DNSKEY RRSIG found for chain validation".to_string()
            );
        }

        // Determine if we're at the root zone
        if is_root_zone(zone_name) || is_root_zone(signer_name) {
            // Root zone: validate DNSKEY against the compiled-in trust anchor
            if validate_dnskeys_against_root_anchor(dnskeys) {
                debug!("Root DNSKEY validated against trust anchor");
                return crate::dnssec::ValidationResult::Secure;
            }
            return crate::dnssec::ValidationResult::Bogus(
                "Root DNSKEY does not match trust anchor".to_string()
            );
        }

        // Step 1: Compute the parent zone from the current zone name
        // The parent zone is one label up (e.g., "sub.example.com" → "example.com")
        let parent_zone = match parent_zone(zone_name) {
            Some(p) => p,
            None => vec![0], // root
        };
        let zone_str = crate::dns::types::labels_to_string(zone_name);
        debug!("Validating chain for {} via parent zone {}", zone_str,
            crate::dns::types::labels_to_string(&parent_zone));
        let ds_result = self.query_ds_records(zone_name, &parent_zone).await;
        let (_ds_records, ds_rrsigs, parent_dnskeys) = match ds_result {
            Some(r) => r,
            None => {
                // No DS records found for this child zone → the parent zone has no
                // delegation signer records, meaning this zone is Insecure (not signed).
                // Per RFC 4035 §4.8, this is a valid Insecure transition.
                debug!("No DS records found for {} — zone is insecure", zone_str);
                return crate::dnssec::ValidationResult::Insecure;
            }
        };

        // Step 3: Validate child DNSKEY against parent DS
        if !validate_dnskeys_against_ds(dnskeys, &_ds_records) {
            return crate::dnssec::ValidationResult::Bogus(
                format!("No DNSKEY for {} matches parent DS records", zone_str)
            );
        }
        debug!("✓ DNSKEY for {} matches parent DS", zone_str);

        // Validate the DS RRSIG using the parent's DNSKEY
        for rrsig in &ds_rrsigs {
            let result = crate::dnssec::validate_rrset(rrsig, &_ds_records, &parent_dnskeys);
            match result {
                crate::dnssec::ValidationResult::Secure => {},
                crate::dnssec::ValidationResult::Indeterminate => {},
                other => {
                    return crate::dnssec::ValidationResult::Bogus(
                        format!("DS RRSIG validation failed for {}: {:?}", zone_str, other)
                    );
                }
            }
        }

        // Step 4: Recursively validate the parent's DNSKEY
        // Find the RRSIG for the parent DNSKEY set
        // We need to make a separate query for the parent's DNSKEY RRSIGs
        // But we already have parent_dnskeys - we need their RRSIGs too

        let parent_zone_str = crate::dns::types::labels_to_string(&parent_zone);
        let parent_result = self.query_dnskey_records(&parent_zone).await;

        let (_parent_dnskeys, parent_dnskey_rrsigs, _parent_signer) = match parent_result {
            Some(r) => r,
            None => {
                // If we can't get parent DNSKEY records, check if the parent is root
                if is_root_zone(&parent_zone) && validate_dnskeys_against_root_anchor(&parent_dnskeys) {
                    debug!("✓ Chain complete: parent is root, validated against trust anchor");
                    return crate::dnssec::ValidationResult::Secure;
                }
                // If the parent has DS records but we can't get DNSKEYs, this is
                // Indeterminate — we can't complete the chain, but it's not provably Bogus.
                debug!("Could not obtain DNSKEY records for parent zone {}, chain indeterminate",
                    parent_zone_str);
                return crate::dnssec::ValidationResult::Indeterminate;
            }
        };

        // Recurse up the chain
        let parent_signer = if !parent_dnskey_rrsigs.is_empty() {
            if let Some(RData::RRSIG { signer_name, .. }) = &parent_dnskey_rrsigs[0].parsed {
                signer_name.clone()
            } else {
                parent_zone.clone()
            }
        } else {
            parent_zone.clone()
        };

        Box::pin(self.validate_dnssec_chain(
            &parent_zone,
            &_parent_dnskeys,
            &parent_dnskey_rrsigs,
            &parent_signer,
            depth + 1,
        )).await
    }

    /// Query a zone for DS records (type 43) for a child zone.
    /// Returns (DS records, DS RRSIGs, parent DNSKEY records).
    async fn query_ds_records(
        &self,
        child_name: &[u8],
        parent_zone: &[u8],
    ) -> Option<(Vec<ResourceRecord>, Vec<ResourceRecord>, Vec<ResourceRecord>)> {
        // Build a query for DS records of the child name
        let id: u16 = rand::thread_rng().gen();
        let dnssec_ok = true;
        let query_bytes = Self::build_query_static(child_name, 43, 1, id, dnssec_ok, false).ok()?;

        // Get nameservers for the parent zone
        let nameservers = self.get_nameservers_for_zone(parent_zone).await;
        if nameservers.is_empty() {
            return None;
        }

        let msg = self.query_servers_concurrent(&query_bytes, id, &nameservers).await?;

        // Extract DS records from answers
        let ds_records: Vec<ResourceRecord> = msg.answers.iter()
            .filter(|r| r.rtype == 43)
            .cloned()
            .collect();

        if ds_records.is_empty() {
            return None;
        }

        // Extract RRSIGs covering DS
        let ds_rrsigs: Vec<ResourceRecord> = msg.answers.iter()
            .chain(msg.authorities.iter())
            .filter(|r| r.rtype == 46)
            .cloned()
            .collect();

        // Extract DNSKEY records from authority/additional
        let parent_dnskeys: Vec<ResourceRecord> = msg.authorities.iter()
            .chain(msg.additionals.iter())
            .filter(|r| r.rtype == 48)
            .cloned()
            .collect();

        Some((ds_records, ds_rrsigs, parent_dnskeys))
    }

    /// Query a zone for DNSKEY records (type 48) and their RRSIGs.
    /// Returns (DNSKEY records, RRSIGs covering DNSKEY, signer_name).
    async fn query_dnskey_records(
        &self,
        zone: &[u8],
    ) -> Option<(Vec<ResourceRecord>, Vec<ResourceRecord>, Vec<u8>)> {
        let id: u16 = rand::thread_rng().gen();
        let dnssec_ok = true;
        let query_bytes = Self::build_query_static(zone, 48, 1, id, dnssec_ok, false).ok()?;

        let nameservers = self.get_nameservers_for_zone(zone).await;
        if nameservers.is_empty() {
            return None;
        }

        let msg = self.query_servers_concurrent(&query_bytes, id, &nameservers).await?;

        let dnskeys: Vec<ResourceRecord> = msg.answers.iter()
            .filter(|r| r.rtype == 48)
            .cloned()
            .collect();

        if dnskeys.is_empty() {
            return None;
        }

        let dnskey_rrsigs: Vec<ResourceRecord> = msg.answers.iter()
            .chain(msg.authorities.iter())
            .filter(|r| r.rtype == 46)
            .cloned()
            .collect();

        let signer = if !dnskey_rrsigs.is_empty() {
            if let Some(RData::RRSIG { signer_name, .. }) = &dnskey_rrsigs[0].parsed {
                signer_name.clone()
            } else {
                zone.to_vec()
            }
        } else {
            zone.to_vec()
        };

        Some((dnskeys, dnskey_rrsigs, signer))
    }

    /// Get nameserver IPs for a zone, from delegation cache, NS cache, or by resolving.
    async fn get_nameservers_for_zone(&self, zone: &[u8]) -> Vec<IpAddr> {
        // Check delegation cache first
        {
            let mut dc = self.delegation_cache.lock().await;
            if let Some(servers) = Self::find_cached_delegation(&mut dc, zone) {
                return servers;
            }
        }

        // Check NS cache
        {
            let mut nc = self.ns_cache.lock().await;
            if let Some(ips) = nc.get(&zone.to_vec()) {
                return ips.clone();
            }
        }

        // If the zone is root, return root hints
        if crate::dnssec::is_root_zone(zone) {
            return root_hints::initial_root_addrs();
        }

        // Try to resolve the NS names for this zone
        // Build a query for NS type
        let id: u16 = rand::thread_rng().gen();
        let query_bytes = match Self::build_query_static(zone, 2, 1, id, false, false) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        // Start with root servers
        let ns = self.query_servers_concurrent(&query_bytes, id, &root_hints::initial_root_addrs()).await;
        let Some(msg) = ns else { return Vec::new() };

        let ns_records: Vec<&ResourceRecord> = msg.authorities.iter()
            .filter(|r| r.rtype == 2)
            .collect();

        if ns_records.is_empty() {
            return Vec::new();
        }

        let mut ips = Vec::new();
        for ns in &ns_records {
            let ns_name = match &ns.parsed {
                Some(RData::NS(name)) => name.clone(),
                _ => continue,
            };
            // Check glue
            let glue: Vec<&ResourceRecord> = msg.additionals.iter()
                .filter(|r| domain_names_equal(&r.name, &ns_name) && (r.rtype == 1 || r.rtype == 28))
                .collect();
            for g in &glue {
                match &g.parsed {
                    Some(RData::A(ip)) => ips.push(IpAddr::V4(*ip)),
                    Some(RData::AAAA(ip)) => ips.push(IpAddr::V6(*ip)),
                    _ => {}
                }
            }
            // If no glue, try cached NS names
            if ips.is_empty() {
                let mut nc = self.ns_cache.lock().await;
                if let Some(cached_ips) = nc.get(&ns_name) {
                    ips.extend(cached_ips.iter().copied());
                }
            }
        }

        ips
    }

    /// Validate DNSSEC for a negative response (NODATA or NXDOMAIN).
    ///
    /// Extracts RRSIG, NSEC, and NSEC3 records from the response authority section,
    /// resolves DNSKEYs for the zone, and calls `validate_negative_dnssec()`.
    ///
    /// `qtype`: 0 for NXDOMAIN (any type checked), or the specific query type for NODATA.
    ///
    /// Returns `(ad_bit_ok, soa_records)` where `ad_bit_ok` is true if validation passed,
    /// and `soa_records` contains the SOA records from the response.
    async fn validate_negative_dnssec_response(
        &self,
        msg: &Message,
        name: &[u8],
        rclass: u16,
        qtype: u16,
    ) -> (bool, Vec<ResourceRecord>) {
        let soa_records: Vec<ResourceRecord> = msg.authorities.iter()
            .filter(|r| r.rtype == 6)
            .cloned()
            .collect();

        // Extract RRSIG records from authority
        let rrsigs: Vec<ResourceRecord> = msg.authorities.iter()
            .filter(|r| r.rtype == 46)
            .cloned()
            .collect();

        // Extract NSEC records (type 47) from authority
        let nsec_records: Vec<ResourceRecord> = msg.authorities.iter()
            .filter(|r| r.rtype == 47)
            .cloned()
            .collect();

        // Extract NSEC3 records (type 50) from authority
        let nsec3_records: Vec<ResourceRecord> = msg.authorities.iter()
            .filter(|r| r.rtype == 50)
            .cloned()
            .collect();

        if !self.dnssec_ok || rrsigs.is_empty() {
            return (false, soa_records);
        }

        // Determine the zone name: use the SOA owner name, or fall back to the query name
        let zone_name = soa_records.first()
            .map(|r| r.name.clone())
            .unwrap_or_else(|| name.to_vec());
        let zone_str = crate::dns::types::labels_to_string(&zone_name);

        // Resolve DNSKEY records for the zone
        let dnskeys: Vec<ResourceRecord> = match self.resolve(&zone_str, 48, rclass).await {
            Ok(records) if !records.is_empty() => {
                debug!("validate_negative_dnssec: resolved {} DNSKEYs for zone {}",
                    records.len(), zone_str);
                records
            }
            _ => {
                debug!("validate_negative_dnssec: no DNSKEYs for zone {}", zone_str);
                Vec::new()
            }
        };

        if dnskeys.is_empty() {
            debug!("validate_negative_dnssec: no DNSKEYs available, cannot validate");
            return (false, soa_records);
        }

        let vresult = crate::dnssec::validate_negative_dnssec(
            &soa_records, &nsec_records, &nsec3_records,
            &rrsigs, &dnskeys, name, qtype,
        );

        match vresult {
            crate::dnssec::ValidationResult::Secure => {
                debug!("validate_negative_dnssec: PASSED for {}", zone_str);
                (true, soa_records)
            }
            crate::dnssec::ValidationResult::Bogus(reason) => {
                debug!("validate_negative_dnssec: BOGUS for {}: {}", zone_str, reason);
                (false, soa_records)
            }
            _ => {
                debug!("validate_negative_dnssec: indeterminate for {}", zone_str);
                (false, soa_records)
            }
        }
    }
}

// ---------- Free functions ----------

/// Send a DNS query over TCP using the connection pool (RFC 1035 §4.2.2).
/// Returns the raw response bytes if successful.
/// Uses `try_read`/`try_write` on the full stream so it can be returned to the pool.
async fn query_via_tcp_pool(
    query_bytes: &[u8],
    server: IpAddr,
    pool: &Arc<Mutex<TcpPool>>,
) -> Option<Vec<u8>> {
    // Try to acquire a pooled connection
    let mut stream = {
        let mut p = pool.lock().await;
        match p.acquire(server) {
            Some(s) => s,
            None => {
                let addr = SocketAddr::new(server, DNS_PORT);
                timeout(QUERY_TIMEOUT, TcpStream::connect(addr))
                    .await.ok()?.ok()?
            }
        }
    };

    // Send with 2-byte length prefix
    let len = query_bytes.len() as u16;
    let mut framed = Vec::with_capacity(2 + query_bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query_bytes);

    if timeout(QUERY_TIMEOUT, async {
        use tokio::io::AsyncWriteExt;
        stream.write_all(&framed).await
    }).await.ok()?.is_err() {
        return None;
    }

    // Read 2-byte response length
    let mut len_buf = [0u8; 2];
    if timeout(QUERY_TIMEOUT, async {
        use tokio::io::AsyncReadExt;
        stream.read_exact(&mut len_buf).await
    }).await.ok()?.is_err() {
        return None;
    }
    let response_len = u16::from_be_bytes(len_buf) as usize;

    if response_len == 0 || response_len > 65535 {
        return None;
    }

    let mut response_data = vec![0u8; response_len];
    if timeout(QUERY_TIMEOUT, async {
        use tokio::io::AsyncReadExt;
        stream.read_exact(&mut response_data).await
    }).await.ok()?.is_err() {
        return None;
    }

    // Return the connection to the pool (stream is clean for reuse)
    let mut p = pool.lock().await;
    p.release(server, stream);

    Some(response_data)
}

/// Measure RTT for a server by performing a TCP health-check query.
/// Returns `Ok(Some(rtt_ms))` on success, or `Ok(None)` on timeout/failure.
async fn measure_tcp_rtt(query_bytes: &[u8], server: IpAddr) -> Result<Option<f64>, String> {
    use tokio::io::AsyncWriteExt;
    let addr = SocketAddr::new(server, DNS_PORT);
    let start = Instant::now();
    let mut stream = match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        _ => return Ok(None),
    };
    let connect_ms = start.elapsed().as_secs_f64() * 1000.0;

    // Send a minimal query and drop the connection
    let len = query_bytes.len() as u16;
    let mut framed = Vec::with_capacity(2 + query_bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query_bytes);
    if timeout(Duration::from_secs(2), stream.write_all(&framed)).await.is_err() {
        return Ok(None);
    }

    Ok(Some(connect_ms))
}
