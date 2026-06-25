//! DNS-over-TLS (DoT) transport — RFC 7858
//!
//! Sends DNS queries over TCP with TLS encryption on port 853.
//! Supports Cloudflare, Google, Quad9, and custom endpoints.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tracing::debug;

use crate::dns::error::{DnsError, DnsResult};

/// Default DoT servers (IP addresses + hostnames for TLS SNI)
pub const CLOUDFLARE_DOT: (&str, &str) = ("1.1.1.1", "cloudflare-dns.com");
pub const GOOGLE_DOT: (&str, &str) = ("8.8.8.8", "dns.google");
pub const QUAD9_DOT: (&str, &str) = ("9.9.9.9", "dns.quad9.net");

/// DoT port
const DOT_PORT: u16 = 853;

/// Timeout for TCP connection and TLS handshake
const DOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Timeout for DNS query over DoT
const DOT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Global TLS connector (lazy-initialized)
static TLS_CONNECTOR: OnceLock<Arc<TlsConnector>> = OnceLock::new();

fn get_tls_connector() -> Arc<TlsConnector> {
    TLS_CONNECTOR
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            // Load Mozilla's root certificates from webpki-roots
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            Arc::new(TlsConnector::from(Arc::new(config)))
        })
        .clone()
}

/// DNS wire-format framing over TCP:
/// Each DNS message is prefixed with a 2-byte length (RFC 1035 §4.2.2)
fn wrap_dns_tcp(query: &[u8]) -> Vec<u8> {
    let len = query.len() as u16;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    framed
}

/// Send a DNS query via DoT to a specific server.
///
/// * `query_bytes` — raw DNS query message (wire format)
/// * `server` — IP address of the DoT server
/// * `hostname` — hostname for TLS SNI and certificate verification
pub async fn dot_query(query_bytes: &[u8], server: IpAddr, hostname: &str) -> DnsResult<Vec<u8>> {
    let start = Instant::now();
    let connector = get_tls_connector();
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| DnsError::Transport(format!("Invalid DoT hostname '{}': {}", hostname, e)))?;

    // TCP connect
    let addr = format!("{}:{}", server, DOT_PORT);
    let stream = timeout(DOT_CONNECT_TIMEOUT, TcpStream::connect(&addr))
        .await
        .map_err(|_| DnsError::Transport(format!("DoT connection to {} timed out", addr)))?
        .map_err(|e| DnsError::Transport(format!("DoT connection failed: {}", e)))?;

    // TLS handshake
    let tls_stream = timeout(DOT_CONNECT_TIMEOUT, connector.connect(server_name, stream))
        .await
        .map_err(|_| DnsError::Transport(format!("DoT TLS handshake to {} timed out", hostname)))?
        .map_err(|e| DnsError::Transport(format!("DoT TLS handshake failed: {}", e)))?;

    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    // Send DNS query (with 2-byte length prefix)
    let framed_query = wrap_dns_tcp(query_bytes);
    timeout(
        DOT_QUERY_TIMEOUT,
        tokio::io::AsyncWriteExt::write_all(&mut writer, &framed_query),
    )
    .await
    .map_err(|_| DnsError::Transport("DoT send timed out".to_string()))?
    .map_err(|e| DnsError::Transport(format!("DoT send failed: {}", e)))?;

    // Read response (2-byte length prefix + data)
    let len_buf = timeout(DOT_QUERY_TIMEOUT, async {
        let mut buf = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buf).await?;
        Ok::<[u8; 2], std::io::Error>(buf)
    })
    .await
    .map_err(|_| DnsError::Transport("DoT response length read timed out".to_string()))?
    .map_err(|e| DnsError::Transport(format!("DoT response length read failed: {}", e)))?;

    let response_len = u16::from_be_bytes(len_buf) as usize;
    if response_len > 65535 {
        return Err(DnsError::Transport(format!(
            "DoT response too large: {} bytes",
            response_len
        )));
    }

    let mut response_data = vec![0u8; response_len];
    timeout(
        DOT_QUERY_TIMEOUT,
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut response_data),
    )
    .await
    .map_err(|_| DnsError::Transport("DoT response data read timed out".to_string()))?
    .map_err(|e| DnsError::Transport(format!("DoT response data read failed: {}", e)))?;

    let elapsed = start.elapsed();
    debug!(
        "DoT query to {} ({}) completed in {:?} ({} bytes)",
        hostname,
        server,
        elapsed,
        response_data.len()
    );

    Ok(response_data)
}

/// Send a DNS query via DoT with automatic fallback across multiple servers.
pub async fn dot_query_with_fallback(query_bytes: &[u8]) -> DnsResult<Vec<u8>> {
    let servers: [(&str, &str); 3] = [CLOUDFLARE_DOT, GOOGLE_DOT, QUAD9_DOT];

    let mut last_error = None;
    for (ip_str, hostname) in &servers {
        let server: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        match dot_query(query_bytes, server, hostname).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                debug!("DoT {} failed: {}", hostname, e);
                last_error = Some(e);
            }
        }
    }

    Err(DnsError::Transport(format!(
        "All DoT endpoints failed: {:?}",
        last_error
    )))
}
