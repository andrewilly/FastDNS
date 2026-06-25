//! DNS-over-HTTPS (DoH) transport — RFC 8484
//!
//! Sends DNS queries via HTTPS POST to a DoH endpoint.
//! Supports Cloudflare, Google, and custom endpoints.

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use tokio::sync::OnceCell;
use tracing::debug;

use crate::dns::error::{DnsError, DnsResult};

/// Default DoH endpoints (fastest/nearest anycast)
pub const CLOUDFLARE_DOH: &str = "https://cloudflare-dns.com/dns-query";
pub const GOOGLE_DOH: &str = "https://dns.google/dns-query";
pub const QUAD9_DOH: &str = "https://dns.quad9.net/dns-query";

/// Timeout for a single DoH query
const DOH_TIMEOUT: Duration = Duration::from_secs(3);

/// Global reqwest client (lazy-initialized, connection-pooled)
static HTTP_CLIENT: OnceCell<Arc<Client>> = OnceCell::const_new();

async fn get_client() -> Arc<Client> {
    HTTP_CLIENT
        .get_or_init(|| async {
            Arc::new(
                Client::builder()
                    .timeout(DOH_TIMEOUT)
                    .connect_timeout(Duration::from_secs(2))
                    .http2_prior_knowledge() // DoH uses HTTP/2
                    .https_only(true)
                    .user_agent("FastDNS/0.1")
                    .build()
                    .expect("Failed to build reqwest Client"),
            )
        })
        .await
        .clone()
}

/// Send a DNS query via DoH (POST mode) and return the raw response bytes.
///
/// * `query_bytes` — the raw DNS query message (wire format)
/// * `endpoint` — the DoH endpoint URL (e.g., CLOUDFLARE_DOH)
///
/// Returns the raw DNS response message bytes.
pub async fn doh_query(query_bytes: &[u8], endpoint: &str) -> DnsResult<Vec<u8>> {
    let start = Instant::now();
    let client = get_client().await;

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query_bytes.to_vec())
        .send()
        .await
        .map_err(|e| DnsError::Transport(format!("DoH request failed: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(DnsError::Transport(format!(
            "DoH server returned HTTP {}",
            status
        )));
    }

    let response_bytes = response
        .bytes()
        .await
        .map_err(|e| DnsError::Transport(format!("DoH response read failed: {}", e)))?;

    let elapsed = start.elapsed();
    debug!(
        "DoH query to {} completed in {:?} ({} bytes)",
        endpoint,
        elapsed,
        response_bytes.len()
    );

    Ok(response_bytes.to_vec())
}

/// Send a DNS query via DoH with automatic fallback across multiple endpoints.
///
/// Tries endpoints in order and returns the first successful response.
pub async fn doh_query_with_fallback(query_bytes: &[u8]) -> DnsResult<Vec<u8>> {
    let endpoints = [CLOUDFLARE_DOH, GOOGLE_DOH, QUAD9_DOH];

    let mut last_error = None;
    for endpoint in &endpoints {
        match doh_query(query_bytes, endpoint).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                debug!("DoH endpoint {} failed: {}", endpoint, e);
                last_error = Some(e);
            }
        }
    }

    Err(DnsError::Transport(format!(
        "All DoH endpoints failed: {:?}",
        last_error
    )))
}
