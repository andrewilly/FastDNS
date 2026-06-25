//! Configuration management for FastDNS.
//!
//! Supports:
//! - TOML configuration file (`fastdns.toml`)
//! - CLI arguments (override config file)
//! - Environment variables (RUST_LOG, etc.)

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::server::udp::ServerConfig;

/// Default bind address
const DEFAULT_BIND: &str = "127.0.0.1:53";

/// Default cache size
const DEFAULT_CACHE_SIZE: usize = 250_000;

/// Default upstream DNS
#[allow(dead_code)]
const DEFAULT_UPSTREAM: &str = "1.1.1.1:53";

/// Maximum cache size limit
const MAX_CACHE_SIZE: usize = 10_000_000;

/// Configuration loaded from TOML file (optional), merged with CLI args.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FastDnsConfig {
    /// Bind address for DNS server
    pub bind: String,

    /// Enable IPv6 resolution (AAAA records)
    pub ipv6: bool,

    /// Enable DNSSEC OK bit
    pub dnssec: bool,

    /// Disable startup domain prefetching
    pub no_prefetch: bool,

    /// Maximum cache entries
    pub cache_size: usize,

    /// Verbose logging
    pub verbose: bool,

    /// Upstream DNS server for forwarding mode (e.g., "1.1.1.1:53")
    /// When set, FastDNS acts as a forwarder instead of recursive resolver.
    pub upstream: Option<String>,

    /// Enable DNS-over-HTTPS forwarding
    pub doh: bool,

    /// Enable DNS-over-TLS forwarding
    pub dot: bool,

    /// Blocklist mode: "none", "adblock", "malware", "all"
    pub blocklist_mode: String,

    /// URLs or file paths for blocklist sources
    pub blocklist_sources: Vec<String>,

    /// Manual blocklist entries (domains to block)
    pub blocklist: Vec<String>,

    /// Manual whitelist entries (domains to never block)
    pub whitelist: Vec<String>,

    /// Custom DNS records (domain -> IP/hostname)
    pub custom_dns: Vec<String>,

    /// Nullroute IPv4 address for blocked queries
    pub nullroute: String,

    /// Nullroute IPv6 address for blocked queries
    pub nullroute_v6: String,

    /// Response to blocked queries: "nxdomain" or "nullroute"
    pub block_response: String,

    /// Rate limit: max queries per second per client IP
    pub rate_limit_qps: u64,

    /// Rate limit burst size
    pub rate_limit_burst: u32,

    /// Log file path (empty = stderr only)
    pub log_file: String,

    /// Log level: "error", "warn", "info", "debug", "trace"
    pub log_level: String,

    /// REST API bind address (empty = disabled)
    pub api_bind: String,

    /// Enable Prometheus metrics
    pub metrics: bool,

    /// Path to TLS certificate for DoT
    pub tls_cert: String,

    /// Path to TLS private key for DoT
    pub tls_key: String,

    /// DNSSEC enforcement: "ad" (set AD bit), "enforce" (reject bogus), "off"
    pub dnssec_policy: String,

    /// Path to config file
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

impl Default for FastDnsConfig {
    fn default() -> Self {
        FastDnsConfig {
            bind: DEFAULT_BIND.to_string(),
            ipv6: false,
            dnssec: false,
            no_prefetch: false,
            cache_size: DEFAULT_CACHE_SIZE,
            verbose: false,
            upstream: None,
            doh: false,
            dot: false,
            blocklist_mode: "none".to_string(),
            blocklist_sources: vec![
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".to_string(),
                "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt".to_string(),
                "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt".to_string(),
            ],
            blocklist: vec![],
            whitelist: vec![],
            custom_dns: vec![],
            nullroute: "0.0.0.0".to_string(),
            nullroute_v6: "::".to_string(),
            block_response: "nxdomain".to_string(),
            rate_limit_qps: 100,
            rate_limit_burst: 200,
            log_file: String::new(),
            log_level: "info".to_string(),
            api_bind: String::new(),
            metrics: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            dnssec_policy: "ad".to_string(),
            config_path: None,
        }
    }
}

impl FastDnsConfig {
    /// Load config from TOML file. Returns default if file doesn't exist.
    pub fn from_file(path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        if !path_buf.exists() {
            warn!("Config file '{}' not found, using defaults", path);
            return FastDnsConfig::default();
        }
        match std::fs::read_to_string(&path_buf) {
            Ok(content) => match toml::from_str::<FastDnsConfig>(&content) {
                Ok(mut cfg) => {
                    cfg.config_path = Some(path_buf);
                    cfg
                }
                Err(e) => {
                    warn!(
                        "Failed to parse config file '{}': {}. Using defaults.",
                        path, e
                    );
                    FastDnsConfig::default()
                }
            },
            Err(e) => {
                warn!(
                    "Failed to read config file '{}': {}. Using defaults.",
                    path, e
                );
                FastDnsConfig::default()
            }
        }
    }

    /// Merge CLI overrides into config file values.
    /// CLI values take precedence when explicitly set.
    pub fn merge_cli(&mut self, cli: &CliOverrides) {
        if let Some(bind) = &cli.bind {
            self.bind = bind.clone();
        }
        if cli.ipv6 {
            self.ipv6 = true;
        }
        if cli.dnssec {
            self.dnssec = true;
        }
        if cli.no_prefetch {
            self.no_prefetch = true;
        }
        if let Some(cs) = cli.cache_size {
            self.cache_size = cs;
        }
        if cli.verbose {
            self.verbose = true;
        }
        if let Some(up) = &cli.upstream {
            self.upstream = Some(up.clone());
        }
        if cli.doh {
            self.doh = true;
        }
        if cli.dot {
            self.dot = true;
        }
        if let Some(bm) = &cli.blocklist_mode {
            self.blocklist_mode = bm.clone();
        }
        if let Some(lf) = &cli.log_file {
            self.log_file = lf.clone();
        }
        if let Some(ll) = &cli.log_level {
            self.log_level = ll.clone();
        }
        if let Some(ab) = &cli.api_bind {
            self.api_bind = ab.clone();
        }
        if cli.metrics {
            self.metrics = true;
        }
    }

    /// Validate configuration and return errors.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate bind address
        if self.bind.parse::<SocketAddr>().is_err() {
            errors.push(format!("Invalid bind address '{}'", self.bind));
        }

        // Validate cache size
        if self.cache_size == 0 {
            errors.push("Cache size must be > 0".into());
        }
        if self.cache_size > MAX_CACHE_SIZE {
            errors.push(format!(
                "Cache size {} exceeds maximum {}",
                self.cache_size, MAX_CACHE_SIZE
            ));
        }

        // Validate upstream
        if let Some(ref up) = self.upstream {
            if up.parse::<SocketAddr>().is_err() {
                errors.push(format!("Invalid upstream address '{}'", up));
            }
        }

        // Validate blocklist response
        if self.block_response != "nxdomain" && self.block_response != "nullroute" {
            errors.push("block_response must be 'nxdomain' or 'nullroute'".into());
        }

        // Validate blocklist mode
        match self.blocklist_mode.as_str() {
            "none" | "adblock" | "malware" | "all" => {}
            _ => {
                errors.push("blocklist_mode must be 'none', 'adblock', 'malware', or 'all'".into())
            }
        }

        // Validate dnssec_policy
        match self.dnssec_policy.as_str() {
            "ad" | "enforce" | "off" => {}
            _ => errors.push("dnssec_policy must be 'ad', 'enforce', or 'off'".into()),
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Convert to server config.
    pub fn to_server_config(&self) -> ServerConfig {
        ServerConfig {
            bind_addr: self.bind.parse().expect("valid bind address"),
            enable_ipv6: self.ipv6,
            dnssec_ok: self.dnssec,
            prefetch_domains: if self.no_prefetch {
                Vec::new()
            } else {
                PREFETCH_DOMAINS.iter().map(|s| s.to_string()).collect()
            },
            cache_size: self.cache_size,
            verbose: self.verbose,
            upstream: self.upstream.clone(),
            rate_limit_qps: self.rate_limit_qps,
            rate_limit_burst: self.rate_limit_burst,
            log_file: self.log_file.clone(),
            api_bind: if self.api_bind.is_empty() {
                None
            } else {
                Some(self.api_bind.clone())
            },
            metrics_enabled: self.metrics,
            dnssec_policy: self.dnssec_policy.clone(),
            blocklist_mode: self.blocklist_mode.clone(),
            blocklist_sources: self.blocklist_sources.clone(),
            blocklist: self.blocklist.clone(),
            whitelist: self.whitelist.clone(),
            custom_dns: self.custom_dns.clone(),
            nullroute: self.nullroute.clone(),
            nullroute_v6: self.nullroute_v6.clone(),
            block_response: self.block_response.clone(),
        }
    }
}

/// CLI overrides — fields that can override config file values.
pub struct CliOverrides {
    pub bind: Option<String>,
    pub ipv6: bool,
    pub dnssec: bool,
    pub no_prefetch: bool,
    pub cache_size: Option<usize>,
    pub verbose: bool,
    pub upstream: Option<String>,
    pub doh: bool,
    pub dot: bool,
    pub blocklist_mode: Option<String>,
    pub log_file: Option<String>,
    pub log_level: Option<String>,
    pub api_bind: Option<String>,
    pub metrics: bool,
}

/// Domains to pre-fetch at startup (~500 top domains).
const PREFETCH_DOMAINS: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "instagram.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "whatsapp.com",
    "reddit.com",
    "linkedin.com",
    "netflix.com",
    "tiktok.com",
    "zoom.us",
    "office.com",
    "live.com",
    "microsoftonline.com",
    "duckduckgo.com",
    "bing.com",
    "yahoo.com",
    "baidu.com",
    "pinterest.com",
    "tumblr.com",
    "discord.com",
    "twitch.tv",
    "github.com",
    "stackoverflow.com",
    "gitlab.com",
    "adobe.com",
    "salesforce.com",
    "oracle.com",
    "ibm.com",
    "samsung.com",
    "huawei.com",
    "xiaomi.com",
    "nokia.com",
    "paypal.com",
    "ebay.com",
    "aliexpress.com",
    "alibaba.com",
    "shopify.com",
    "etsy.com",
    "walmart.com",
    "target.com",
    "bestbuy.com",
    "homedepot.com",
    "costco.com",
    "ikea.com",
    "imdb.com",
    "rottentomatoes.com",
    "spotify.com",
    "soundcloud.com",
    "bandcamp.com",
    "vimeo.com",
    "dailymotion.com",
    "medium.com",
    "wordpress.com",
    "blogger.com",
    "godaddy.com",
    "namecheap.com",
    "googleapis.com",
    "gmail.com",
    "googlemail.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "fbcdn.net",
    "facebook.net",
    "messenger.com",
    "amazonaws.com",
    "aws.amazon.com",
    "cloudfront.net",
    "icloud.com",
    "icloud-content.com",
    "azure.com",
    "azureedge.net",
    "azurefd.net",
    "office365.com",
    "sharepoint.com",
    "outlook.com",
    "hotmail.com",
    "msn.com",
    "xbox.com",
    "xboxlive.com",
    "skype.com",
    "teams.microsoft.com",
    "nuget.org",
    "docs.microsoft.com",
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "fastly.net",
    "fastlylb.net",
    "cloudflare.net",
    "cloudflare-dns.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "twimg.com",
    "t.co",
    "snapchat.com",
    "sc-cdn.net",
    "telegram.org",
    "t.me",
    "discordapp.net",
    "discord.com",
    "digitalocean.com",
    "linode.com",
    "vultr.com",
    "heroku.com",
    "herokuapp.com",
    "netlify.com",
    "vercel.com",
    "mongodb.com",
    "supabase.com",
    "docker.com",
    "docker.io",
    "kubernetes.io",
    "npmjs.com",
    "pypi.org",
    "crates.io",
    "cnn.com",
    "bbc.com",
    "bbc.co.uk",
    "nytimes.com",
    "wsj.com",
    "washingtonpost.com",
    "reuters.com",
    "bloomberg.com",
    "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "americanexpress.com",
    "discover.com",
    "netflix.com",
    "netflix.net",
    "nflxvideo.net",
    "hulu.com",
    "disneyplus.com",
    "primevideo.com",
    "roblox.com",
    "epicgames.com",
    "steampowered.com",
    "steamcdn-a.akamaihd.net",
    "battle.net",
    "blizzard.com",
    "nintendo.com",
    "playstation.com",
    "iana.org",
    "icann.org",
    "ietf.org",
];
