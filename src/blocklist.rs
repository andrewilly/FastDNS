//! Blocklist-based DNS filtering (ad-blocking, malware blocking)
//!
//! Inspired by grimd. Supports:
//! - Automatic download of blocklists from multiple sources
//! - hosts-file and domain-list parsing
//! - In-memory hashset for O(1) domain lookup
//! - Pattern matching for wildcard domains
//! - Whitelist overrides
//! - Periodic refresh of blocklists

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::Utc;
use std::sync::RwLock;
use tracing::{debug, info, warn};

use crate::server::udp::ServerConfig;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Blocklist operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistMode {
    /// No blocking.
    None,
    /// Ad-blocking sources only.
    Adblock,
    /// Malware blocking sources only.
    Malware,
    /// All configured sources.
    All,
}

impl BlocklistMode {
    /// Parse from the config string representation.
    pub fn from_str(s: &str) -> Self {
        match s {
            "adblock" => BlocklistMode::Adblock,
            "malware" => BlocklistMode::Malware,
            "all" => BlocklistMode::All,
            _ => BlocklistMode::None,
        }
    }
}

/// What the server should return for a blocked query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockResponse {
    /// Return NXDOMAIN (domain does not exist).
    Nxdomain,
    /// Return a nullroute IP address (e.g. 0.0.0.0 or ::).
    Nullroute,
}

impl BlockResponse {
    /// Parse from the config string representation.
    pub fn from_str(s: &str) -> Self {
        match s {
            "nullroute" => BlockResponse::Nullroute,
            _ => BlockResponse::Nxdomain,
        }
    }
}

/// Action to take for a blocked domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockAction {
    /// Return NXDOMAIN.
    Nxdomain,
    /// Null-route with the given IPv4 address.
    NullrouteV4(String),
    /// Null-route with the given IPv6 address.
    NullrouteV6(String),
    /// Return a custom DNS record (domain → value).
    Custom(String),
}

/// Statistics about the blocklist module.
#[derive(Debug, Clone, Default)]
pub struct BlocklistStats {
    /// Total number of domains in the blocklist.
    pub total_blocked: usize,
    /// Number of whitelist entries.
    pub total_whitelisted: usize,
    /// Number of custom DNS records.
    pub total_custom: usize,
    /// Number of blocklist sources loaded.
    pub sources_loaded: usize,
    /// Total number of domains blocked since startup.
    pub queries_blocked: u64,
    /// Timestamp of the last successful blocklist refresh.
    pub last_refresh: Option<String>,
    /// Total download/parse errors.
    pub errors: u64,
}

// ---------------------------------------------------------------------------
// Blocklist
// ---------------------------------------------------------------------------

/// DNS blocklist with automatic loading, periodic refresh, and
/// O(1) hashset lookups.
pub struct Blocklist {
    /// Whether the blocklist is enabled at all.
    enabled: bool,
    /// Current blocklist mode.
    mode: BlocklistMode,
    /// Set of blocked domains (normalised, lowercased).
    blocked: RwLock<HashSet<String>>,
    /// Set of whitelisted domains (always allowed).
    whitelist: RwLock<HashSet<String>>,
    /// Custom DNS records: domain → IP (or hostname).
    custom: RwLock<HashMap<String, String>>,
    /// URLs / file-paths for blocklist sources.
    sources: Vec<String>,
    /// IPv4 address used for null-routing.
    nullroute_v4: String,
    /// IPv6 address used for null-routing.
    #[allow(dead_code)]
    #[allow(dead_code)]
    nullroute_v6: String,
    /// Blocked-query response type.
    block_response: BlockResponse,
    /// Accumulated statistics.
    stats: RwLock<BlocklistStats>,
}

impl Blocklist {
    /// Create a new `Blocklist` from the server configuration.
    ///
    /// The blocklist is not loaded until [`Blocklist::load`] is called.
    pub fn new(config: &ServerConfig) -> Self {
        let mode = BlocklistMode::from_str(&config.blocklist_mode);
        let enabled = mode != BlocklistMode::None;

        info!(
            "Blocklist initialised (mode={:?}, sources={})",
            mode,
            config.blocklist_sources.len(),
        );

        // Collect manual blocklist entries
        let mut initial_blocked = HashSet::new();
        for entry in &config.blocklist {
            let normalised = normalise_domain(entry);
            if !normalised.is_empty() {
                initial_blocked.insert(normalised);
            }
        }

        // Collect manual whitelist entries
        let mut initial_whitelist = HashSet::new();
        for entry in &config.whitelist {
            let normalised = normalise_domain(entry);
            if !normalised.is_empty() {
                initial_whitelist.insert(normalised);
            }
        }

        // Collect custom DNS records (format: "domain=value" or "domain value")
        let mut initial_custom = HashMap::new();
        for entry in &config.custom_dns {
            let (domain, value) = parse_custom_dns_entry(entry);
            let normalised = normalise_domain(&domain);
            if !normalised.is_empty() && !value.is_empty() {
                initial_custom.insert(normalised, value);
            }
        }

        Blocklist {
            enabled,
            mode,
            blocked: RwLock::new(initial_blocked),
            whitelist: RwLock::new(initial_whitelist),
            custom: RwLock::new(initial_custom),
            sources: config.blocklist_sources.clone(),
            nullroute_v4: config.nullroute.clone(),
            nullroute_v6: config.nullroute_v6.clone(),
            block_response: BlockResponse::from_str(&config.block_response),
            stats: RwLock::new(BlocklistStats::default()),
        }
    }

    /// Returns `true` if the blocklist is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the current blocklist mode.
    pub fn mode(&self) -> BlocklistMode {
        self.mode
    }

    // ------------------------------------------------------------------
    // Loading & refresh
    // ------------------------------------------------------------------

    /// Download and parse all configured blocklist sources.
    ///
    /// Call this once at startup or when sources change.
    pub async fn load(&self) {
        if !self.enabled || self.mode == BlocklistMode::None {
            info!("Blocklist is disabled, skipping load");
            return;
        }

        let mut total_domains = 0usize;
        let mut sources_loaded = 0usize;
        let mut errors = 0u64;

        for source in &self.sources {
            match self.load_source(source).await {
                Ok(count) => {
                    total_domains += count;
                    sources_loaded += 1;
                }
                Err(e) => {
                    warn!("Failed to load blocklist source '{}': {}", source, e);
                    errors += 1;
                }
            }
        }

        info!(
            "Blocklist loaded: {} domains from {} sources ({} errors)",
            total_domains, sources_loaded, errors,
        );

        // Update stats
        {
            let mut stats = self.stats.write().unwrap();
            stats.total_blocked = self.blocked.read().unwrap().len();
            stats.total_whitelisted = self.whitelist.read().unwrap().len();
            stats.total_custom = self.custom.read().unwrap().len();
            stats.sources_loaded = sources_loaded;
            stats.last_refresh = Some(Utc::now().to_rfc3339());
            stats.errors += errors;
        }
    }

    /// Start a background task that refreshes the blocklist on a
    /// configurable interval (default: every 24 hours).
    pub async fn refresh(&self) {
        if !self.enabled || self.mode == BlocklistMode::None {
            return;
        }

        // Default: every 24 hours
        let interval = Duration::from_secs(24 * 60 * 60);

        loop {
            tokio::time::sleep(interval).await;
            debug!("Blocklist refresh cycle starting...");

            let mut total_domains = 0usize;
            let mut sources_loaded = 0usize;
            let mut errors = 0u64;

            // Clear existing blocked domains (preserve manual entries & whitelist)
            // We rebuild the set from scratch.
            {
                let mut blocked = self.blocked.write().unwrap();
                blocked.clear();
            }

            for source in &self.sources {
                match self.load_source(source).await {
                    Ok(count) => {
                        total_domains += count;
                        sources_loaded += 1;
                    }
                    Err(e) => {
                        warn!("Blocklist refresh: failed to load '{}': {}", source, e);
                        errors += 1;
                    }
                }
            }

            // Update stats
            {
                let mut stats = self.stats.write().unwrap();
                stats.total_blocked = self.blocked.read().unwrap().len();
                stats.sources_loaded = sources_loaded;
                stats.last_refresh = Some(Utc::now().to_rfc3339());
                stats.errors += errors;
            }

            info!(
                "Blocklist refreshed: {} domains from {} sources ({} errors)",
                total_domains, sources_loaded, errors,
            );
        }
    }

    // ------------------------------------------------------------------
    // Query methods
    // ------------------------------------------------------------------

    /// Check whether `domain` is blocked.
    ///
    /// Returns `Some(BlockAction)` when the domain is blocked or has a
    /// custom record; returns `None` when the domain is allowed.
    ///
    /// Lookup order:
    /// 1. Custom DNS record (highest priority – always returned if present)
    /// 2. Whitelist (domain is allowed → returns `None`)
    /// 3. Blocklist (domain is blocked → returns action)
    pub async fn is_blocked(&self, domain: &str) -> Option<BlockAction> {
        if !self.enabled {
            return None;
        }

        let normalised = normalise_domain(domain);
        if normalised.is_empty() {
            return None;
        }

        // 1. Check custom records first (highest priority)
        {
            let custom = self.custom.read().unwrap();
            if let Some(value) = custom.get(&normalised) {
                // If the custom record value is empty or "none", treat as unblocked
                if value.is_empty() || value == "none" {
                    return None;
                }
                return Some(BlockAction::Custom(value.clone()));
            }
            // Also check parent-domain custom records (e.g. custom record for
            // "example.com" should match "sub.example.com").
            if let Some(action) = self.check_custom_parent(&normalised, &custom) {
                return Some(action);
            }
        }

        // 2. Check whitelist (bypasses blocking)
        {
            let whitelist = self.whitelist.read().unwrap();
            if whitelist.contains(&normalised) {
                return None;
            }
            // Also check parent-domain whitelisting (whitelisting "example.com"
            // allows "sub.example.com").
            if self.is_whitelisted_parent(&normalised, &whitelist) {
                return None;
            }
        }

        // 3. Check blocklist
        {
            let blocked = self.blocked.read().unwrap();
            if blocked.contains(&normalised) {
                return Some(self.block_action());
            }
            // Wildcard / parent-domain matching: check if any parent domain
            // is in the blocklist.
            if self.is_blocked_parent(&normalised, &blocked) {
                return Some(self.block_action());
            }
        }

        None
    }

    /// Get the custom DNS record for `domain`, if one exists.
    ///
    /// Unlike `is_blocked`, this only checks exact custom records (no
    /// parent-domain fallback, no whitelist / blocklist logic).
    pub async fn get_custom(&self, domain: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }

        let normalised = normalise_domain(domain);
        if normalised.is_empty() {
            return None;
        }

        let custom = self.custom.read().unwrap();
        custom.get(&normalised).cloned().or_else(|| {
            // Check parent-domain custom records
            self.find_parent_custom(&normalised, &custom)
        })
    }

    /// Return current statistics.
    pub async fn stats(&self) -> BlocklistStats {
        let stats = self.stats.read().unwrap();
        stats.clone()
    }

    /// Record a blocked query in the statistics.
    pub async fn record_blocked(&self) {
        let mut stats = self.stats.write().unwrap();
        stats.queries_blocked += 1;
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Load a single source (URL or file path) and add its domains
    /// to the blocked set.
    async fn load_source(&self, source: &str) -> Result<usize, anyhow::Error> {
        let data = if source.starts_with("http://") || source.starts_with("https://") {
            fetch_url(source).await?
        } else {
            // Local file path
            tokio::fs::read_to_string(source).await?
        };

        let count = self.parse_and_insert(&data);
        Ok(count)
    }

    /// Parse blocklist data (hosts format or domain list) and insert
    /// domains into the blocked set.
    fn parse_and_insert(&self, data: &str) -> usize {
        let mut count = 0usize;
        let mut blocked = self.blocked.write().unwrap();

        for line in data.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Strip inline comments
            let line = strip_inline_comment(line);

            // Determine if this is a hosts-file line (IP + domain) or
            // a domain-only line.
            if let Some(domain) = parse_hosts_line(line) {
                if !domain.is_empty() && blocked.insert(domain) {
                    count += 1;
                }
            } else if let Some(domain) = parse_domain_line(line) {
                if !domain.is_empty() && blocked.insert(domain) {
                    count += 1;
                }
            }
        }

        count
    }

    /// Build the appropriate `BlockAction` for a blocked domain.
    fn block_action(&self) -> BlockAction {
        match self.block_response {
            BlockResponse::Nxdomain => BlockAction::Nxdomain,
            BlockResponse::Nullroute => BlockAction::NullrouteV4(self.nullroute_v4.clone()),
        }
    }

    /// Check parent domains of `domain` in the custom records.
    fn check_custom_parent(
        &self,
        domain: &str,
        custom: &HashMap<String, String>,
    ) -> Option<BlockAction> {
        let parents = domain_parents(domain);
        for parent in parents {
            if let Some(value) = custom.get(parent) {
                if value.is_empty() || value == "none" {
                    return None;
                }
                return Some(BlockAction::Custom(value.clone()));
            }
        }
        None
    }

    /// Find a custom record for a domain or any of its parents.
    fn find_parent_custom(&self, domain: &str, custom: &HashMap<String, String>) -> Option<String> {
        // Exact match already checked by caller; check parents.
        let parents = domain_parents(domain);
        for parent in parents {
            if let Some(value) = custom.get(parent) {
                return Some(value.clone());
            }
        }
        None
    }

    /// Return `true` if `domain` or any parent domain is whitelisted.
    fn is_whitelisted_parent(&self, domain: &str, whitelist: &HashSet<String>) -> bool {
        let parents = domain_parents(domain);
        for parent in parents {
            if whitelist.contains(parent) {
                return true;
            }
        }
        false
    }

    /// Return `true` if any parent domain of `domain` is in the blocked set.
    fn is_blocked_parent(&self, domain: &str, blocked: &HashSet<String>) -> bool {
        let parents = domain_parents(domain);
        for parent in parents {
            if blocked.contains(parent) {
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Normalise a domain name: lowercase, strip trailing dot, strip
/// leading/trailing whitespace.
fn normalise_domain(domain: &str) -> String {
    let d = domain.trim().to_lowercase();
    let d = d.trim_end_matches('.').to_string();
    // Remove leading `*` or `*.` wildcard prefixes for storage
    
    if let Some(suffix) = d.strip_prefix("*.") {
        suffix.to_string()
    } else if d == "*" {
        String::new()
    } else {
        d
    }
}

/// Strip inline comments from a line (everything after `#`).
fn strip_inline_comment(line: &str) -> &str {
    if let Some(pos) = line.find('#') {
        line[..pos].trim()
    } else {
        line
    }
}

/// Try to parse a hosts-file line. Returns `Some(domain)` on success.
///
/// Format: `IP<whitespace>domain [alias ...]`
/// We take the first token after the IP as the domain.
fn parse_hosts_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.split_whitespace();

    // First token should be an IP address (or "0.0.0.0", "127.0.0.1", "::1", etc.)
    let ip = parts.next()?;

    // Accept anything that looks like an IP, or the special "0" used by some lists
    if !looks_like_ip(ip) && ip != "0" {
        return None;
    }

    // The second token is the domain name
    let domain = parts.next()?;
    let domain = normalise_domain(domain);

    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

/// Try to parse a domain-only list line. Returns `Some(domain)` on success.
fn parse_domain_line(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Reject lines that look like IPs (hosts-format lines should have been
    // caught by parse_hosts_line, but some lists mix formats).
    if looks_like_ip(line) || line == "0" || line == "localhost" {
        return None;
    }

    // Some domain lists prefix with `||` (AdBlock Plus syntax)
    let cleaned = if let Some(rest) = line.strip_prefix("||") {
        if let Some(stripped) = rest.strip_suffix('^') {
            stripped
        } else {
            rest
        }
    } else {
        line
    };

    let domain = normalise_domain(cleaned);
    if domain.is_empty() || domain.contains('/') || domain.contains(' ') {
        None
    } else {
        Some(domain)
    }
}

/// Return `true` if `s` looks like an IPv4 or IPv6 address.
fn looks_like_ip(s: &str) -> bool {
    // Quick check for IPv4: digits and dots
    if s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return true;
    }
    // Quick check for IPv6: hex digits and colons
    if s.contains(':') {
        // Basic sanity: must not contain whitespace
        if s.chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return true;
        }
    }
    false
}

/// Parse a custom DNS entry string.
///
/// Supported formats:
/// - `domain=value`
/// - `domain value`
/// - `domain:value`
fn parse_custom_dns_entry(entry: &str) -> (String, String) {
    let entry = entry.trim();
    if let Some(pos) = entry.find('=') {
        let domain = entry[..pos].trim().to_string();
        let value = entry[pos + 1..].trim().to_string();
        (domain, value)
    } else if let Some(pos) = entry.find(':') {
        let domain = entry[..pos].trim().to_string();
        let value = entry[pos + 1..].trim().to_string();
        (domain, value)
    } else if let Some(pos) = entry.find(char::is_whitespace) {
        let domain = entry[..pos].trim().to_string();
        let value = entry[pos + 1..].trim().to_string();
        (domain, value)
    } else {
        // Just a domain with no value – treat as a simple host override?
        (entry.to_string(), String::new())
    }
}

/// Return all parent domains of `domain`, from most specific to least.
///
/// Example: `sub.example.com` → `["example.com", "com"]`
fn domain_parents(domain: &str) -> Vec<&str> {
    let mut parents = Vec::new();
    let bytes = domain.as_bytes();

    // Find each '.' from the right, collecting parents closest-first
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'.' {
            parents.push(&domain[i + 1..]);
        }
    }

    // Reverse so closest parent is first: "sub.example.com" → ["example.com", "com"]
    parents.reverse();
    parents
}

// ---------------------------------------------------------------------------
// HTTP fetch
// ---------------------------------------------------------------------------

/// Fetch a URL and return the response body as a string.
async fn fetch_url(url: &str) -> Result<String, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("FastDNS/1.0 (blocklist fetcher)")
        .build()?;

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} fetching {}", response.status().as_u16(), url);
    }

    let body = response.text().await?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalise_domain() {
        assert_eq!(normalise_domain("Example.COM"), "example.com");
        assert_eq!(normalise_domain("EXAMPLE.COM."), "example.com");
        assert_eq!(normalise_domain("  Sub.Example.com  "), "sub.example.com");
        assert_eq!(normalise_domain("*.example.com"), "example.com");
        assert_eq!(normalise_domain(""), "");
    }

    #[test]
    fn test_domain_parents() {
        let parents = domain_parents("sub.example.com");
        assert_eq!(parents, vec!["example.com", "com"]);

        let parents = domain_parents("example.com");
        assert_eq!(parents, vec!["com"]);

        let parents = domain_parents("com");
        assert_eq!(parents.len(), 0);
    }

    #[test]
    fn test_parse_hosts_line() {
        assert_eq!(
            parse_hosts_line("0.0.0.0 example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_hosts_line("127.0.0.1 bad.example.com"),
            Some("bad.example.com".to_string())
        );
        assert_eq!(
            parse_hosts_line("::1 bad.example.com"),
            Some("bad.example.com".to_string())
        );
        assert_eq!(
            parse_hosts_line("0 bad.example.com"),
            Some("bad.example.com".to_string())
        );
        // IP with trailing comment
        assert_eq!(
            parse_hosts_line("0.0.0.0 example.com # comment"),
            Some("example.com".to_string())
        );
        // Invalid: no IP
        assert_eq!(parse_hosts_line("example.com"), None);
        // Invalid: no domain
        assert_eq!(parse_hosts_line("0.0.0.0"), None);
        // Empty
        assert_eq!(parse_hosts_line(""), None);
    }

    #[test]
    fn test_parse_domain_line() {
        assert_eq!(
            parse_domain_line("example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain_line("bad.example.com"),
            Some("bad.example.com".to_string())
        );
        // AdBlock Plus syntax
        assert_eq!(
            parse_domain_line("||example.com^"),
            Some("example.com".to_string())
        );
        assert_eq!(
            parse_domain_line("||example.com"),
            Some("example.com".to_string())
        );
        // IP should be rejected
        assert_eq!(parse_domain_line("0.0.0.0"), None);
        assert_eq!(parse_domain_line("127.0.0.1"), None);
        // localhost
        assert_eq!(parse_domain_line("localhost"), None);
        // Comment
        assert_eq!(parse_domain_line("# comment"), None);
    }

    #[test]
    fn test_looks_like_ip() {
        assert!(looks_like_ip("0.0.0.0"));
        assert!(looks_like_ip("127.0.0.1"));
        assert!(looks_like_ip("::1"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(looks_like_ip("192.168.1.1"));
        assert!(!looks_like_ip("example.com"));
        assert!(!looks_like_ip("localhost"));
    }

    #[test]
    fn test_parse_custom_dns_entry() {
        let (d, v) = parse_custom_dns_entry("myhost.example.com=192.168.1.100");
        assert_eq!(d, "myhost.example.com");
        assert_eq!(v, "192.168.1.100");

        let (d, v) = parse_custom_dns_entry("myhost.example.com 192.168.1.100");
        assert_eq!(d, "myhost.example.com");
        assert_eq!(v, "192.168.1.100");

        let (d, v) = parse_custom_dns_entry("myhost.example.com:192.168.1.100");
        assert_eq!(d, "myhost.example.com");
        assert_eq!(v, "192.168.1.100");
    }

    #[test]
    fn test_strip_inline_comment() {
        assert_eq!(strip_inline_comment("example.com # block"), "example.com");
        assert_eq!(strip_inline_comment("example.com"), "example.com");
        assert_eq!(strip_inline_comment("# full comment"), "");
    }

    #[test]
    fn test_blocklist_mode_from_str() {
        assert_eq!(BlocklistMode::from_str("adblock"), BlocklistMode::Adblock);
        assert_eq!(BlocklistMode::from_str("malware"), BlocklistMode::Malware);
        assert_eq!(BlocklistMode::from_str("all"), BlocklistMode::All);
        assert_eq!(BlocklistMode::from_str("none"), BlocklistMode::None);
        assert_eq!(BlocklistMode::from_str("unknown"), BlocklistMode::None);
        assert_eq!(BlocklistMode::from_str(""), BlocklistMode::None);
    }

    #[test]
    fn test_block_response_from_str() {
        assert_eq!(
            BlockResponse::from_str("nullroute"),
            BlockResponse::Nullroute
        );
        assert_eq!(BlockResponse::from_str("nxdomain"), BlockResponse::Nxdomain);
        assert_eq!(BlockResponse::from_str("unknown"), BlockResponse::Nxdomain);
    }

    #[tokio::test]
    async fn test_parse_and_insert_hosts_format() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        let data = "\
# Blocklist
0.0.0.0 ads.example.com
0.0.0.0 tracker.example.com
127.0.0.1 malware.example.com
# More
::1 bad.example.com
";

        let count = bl.parse_and_insert(data);
        assert_eq!(count, 4);

        let blocked = bl.blocked.read().unwrap();
        assert!(blocked.contains("ads.example.com"));
        assert!(blocked.contains("tracker.example.com"));
        assert!(blocked.contains("malware.example.com"));
        assert!(blocked.contains("bad.example.com"));
        assert!(!blocked.contains("good.example.com"));
    }

    #[tokio::test]
    async fn test_parse_and_insert_domain_format() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        let data = "\
# Domain list
ads.example.com
tracker.example.com
malware.example.com
";

        let count = bl.parse_and_insert(data);
        assert_eq!(count, 3);

        let blocked = bl.blocked.read().unwrap();
        assert!(blocked.contains("ads.example.com"));
        assert!(blocked.contains("tracker.example.com"));
        assert!(blocked.contains("malware.example.com"));
    }

    #[tokio::test]
    async fn test_whitelist_overrides_blocklist() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        // Add a blocked domain
        {
            let mut blocked = bl.blocked.write().unwrap();
            blocked.insert("ads.example.com".to_string());
        }
        // Add the same domain to the whitelist (simulating manual whitelist)
        {
            let mut whitelist = bl.whitelist.write().unwrap();
            whitelist.insert("ads.example.com".to_string());
        }

        let action = bl.is_blocked("ads.example.com").await;
        assert!(action.is_none(), "Whitelist should override blocklist");
    }

    #[tokio::test]
    async fn test_custom_overrides_everything() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        // Add blocked domain
        {
            let mut blocked = bl.blocked.write().unwrap();
            blocked.insert("myhost.example.com".to_string());
        }
        // Add custom record
        {
            let mut custom = bl.custom.write().unwrap();
            custom.insert("myhost.example.com".to_string(), "10.0.0.1".to_string());
        }

        let action = bl.is_blocked("myhost.example.com").await;
        assert_eq!(action, Some(BlockAction::Custom("10.0.0.1".to_string())));
    }

    #[tokio::test]
    async fn test_wildcard_blocklist_match() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        // Block parent domain
        {
            let mut blocked = bl.blocked.write().unwrap();
            blocked.insert("example.com".to_string());
        }

        // Subdomain should be blocked too (parent-domain matching)
        let action = bl.is_blocked("sub.example.com").await;
        assert!(action.is_some(), "Subdomain should be blocked via parent");

        let action = bl.is_blocked("deep.sub.example.com").await;
        assert!(
            action.is_some(),
            "Deep subdomain should be blocked via parent"
        );
    }

    #[tokio::test]
    async fn test_custom_does_not_match_parent_if_exact_exists() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        // Add a custom record for the exact domain
        {
            let mut custom = bl.custom.write().unwrap();
            custom.insert("sub.example.com".to_string(), "10.0.0.5".to_string());
        }

        let action = bl.is_blocked("sub.example.com").await;
        assert_eq!(action, Some(BlockAction::Custom("10.0.0.5".to_string())));

        // A different subdomain should not get this custom record
        let action = bl.is_blocked("other.example.com").await;
        assert!(action.is_none() || !matches!(action, Some(BlockAction::Custom(_))));
    }

    #[tokio::test]
    async fn test_get_custom_exact() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        {
            let mut custom = bl.custom.write().unwrap();
            custom.insert("myhost.example.com".to_string(), "10.0.0.1".to_string());
        }

        let result = bl.get_custom("myhost.example.com").await;
        assert_eq!(result, Some("10.0.0.1".to_string()));

        let result = bl.get_custom("unknown.example.com").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_custom_parent_fallback() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        {
            let mut custom = bl.custom.write().unwrap();
            custom.insert("example.com".to_string(), "10.0.0.1".to_string());
        }

        let result = bl.get_custom("sub.example.com").await;
        assert_eq!(result, Some("10.0.0.1".to_string()));
    }

    #[tokio::test]
    async fn test_block_action_nxdomain() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);
        assert_eq!(bl.block_action(), BlockAction::Nxdomain);
    }

    #[tokio::test]
    async fn test_block_action_nullroute() {
        let mut config = dummy_config();
        config.block_response = "nullroute".to_string();
        config.nullroute = "0.0.0.0".to_string();
        let bl = Blocklist::new(&config);
        assert_eq!(
            bl.block_action(),
            BlockAction::NullrouteV4("0.0.0.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_disabled_blocklist() {
        let mut config = dummy_config();
        config.blocklist_mode = "none".to_string();
        let bl = Blocklist::new(&config);

        {
            let mut blocked = bl.blocked.write().unwrap();
            blocked.insert("ads.example.com".to_string());
        }

        // Should return None when disabled
        let action = bl.is_blocked("ads.example.com").await;
        assert!(action.is_none());
    }

    #[tokio::test]
    async fn test_records_blocked() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        bl.record_blocked().await;
        bl.record_blocked().await;

        let stats = bl.stats().await;
        assert_eq!(stats.queries_blocked, 2);
    }

    #[tokio::test]
    async fn test_stats_after_load() {
        let config = dummy_config();
        let bl = Blocklist::new(&config);

        // Manually add some domains
        {
            let mut blocked = bl.blocked.write().unwrap();
            blocked.insert("a.com".to_string());
            blocked.insert("b.com".to_string());
        }
        {
            let mut whitelist = bl.whitelist.write().unwrap();
            whitelist.insert("c.com".to_string());
        }

        let stats = bl.stats().await;
        assert_eq!(stats.total_blocked, 0);
        assert_eq!(stats.total_whitelisted, 0);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn dummy_config() -> ServerConfig {
        ServerConfig {
            bind_addr: "127.0.0.1:53".parse().unwrap(),
            enable_ipv6: false,
            dnssec_ok: false,
            prefetch_domains: Vec::new(),
            cache_size: 1000,
            verbose: false,
            upstream: None,
            rate_limit_qps: 100,
            rate_limit_burst: 200,
            log_file: String::new(),
            api_bind: None,
            metrics_enabled: false,
            dnssec_policy: "ad".to_string(),
            blocklist_mode: "all".to_string(),
            blocklist_sources: Vec::new(),
            blocklist: Vec::new(),
            whitelist: Vec::new(),
            custom_dns: Vec::new(),
            nullroute: "0.0.0.0".to_string(),
            nullroute_v6: "::".to_string(),
            block_response: "nxdomain".to_string(),
        }
    }
}
