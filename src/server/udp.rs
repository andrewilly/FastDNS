//! UDP DNS server — listens on a local address and resolves queries.
//! Fully async using tokio. Race-condition-free design.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use futures::stream::{FuturesUnordered, StreamExt};
use tracing::{debug, error, info, warn};

use crate::dns::constants::MAX_UDP_PAYLOAD;

use crate::dns::error::DnsError;
use crate::dns::types::{Header, Message, Question, ResourceRecord};
use crate::dns::wire::{decode_message, encode_message};
use crate::resolver::recursive::RecursiveResolver;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub enable_ipv6: bool,
    pub dnssec_ok: bool,
    pub prefetch_domains: Vec<String>,
    pub cache_size: usize,
    pub verbose: bool,
    pub upstream: Option<String>,
    pub rate_limit_qps: u64,
    pub rate_limit_burst: u32,
    pub log_file: String,
    pub api_bind: Option<String>,
    pub metrics_enabled: bool,
    pub dnssec_policy: String,
    pub blocklist_mode: String,
    pub blocklist_sources: Vec<String>,
    pub blocklist: Vec<String>,
    pub whitelist: Vec<String>,
    pub custom_dns: Vec<String>,
    pub nullroute: String,
    pub nullroute_v6: String,
    pub block_response: String,
}

/// Start the DNS server.
/// `stop_signal`: when this AtomicBool is set to `true`, the server shuts down gracefully.
pub async fn run_server(
    config: ServerConfig,
    stop_signal: Arc<AtomicBool>,
    resolver: Arc<RecursiveResolver>,
) -> Result<(), DnsError> {
    let socket = Arc::new(
        UdpSocket::bind(config.bind_addr)
            .await
            .map_err(|e| {
                error!("Cannot bind to {}: {}", config.bind_addr, e);
                DnsError::Io(e)
            })?,
    );

    info!(
        "🚀 FastDNS server listening on {} (IPv6={}, DNSSEC={})",
        config.bind_addr, config.enable_ipv6, config.dnssec_ok
    );

    // Prefetch popular domains at startup (concurrent, rate-limited).
    // Resolves up to CONCURRENT_PREFETCH domains in parallel, each with a
    // short timeout so the server starts accepting queries immediately.
    if !config.prefetch_domains.is_empty() {
        let res = resolver.clone();
        let domains = config.prefetch_domains.clone();
        info!("Prefetching {} domains…", domains.len());
        tokio::spawn(async move {
            const CONCURRENT_PREFETCH: usize = 50;
            const PER_DOMAIN_TIMEOUT: Duration = Duration::from_secs(3);
            let semaphore = Arc::new(Semaphore::new(CONCURRENT_PREFETCH));
            let mut tasks: FuturesUnordered<_> = FuturesUnordered::new();

            for domain in &domains {
                let sem = Arc::clone(&semaphore);
                let res = res.clone();
                let d = domain.clone();
                tasks.push(async move {
                    let _permit = sem.acquire().await;
                    // Resolve A and AAAA concurrently
                    let a = tokio::time::timeout(PER_DOMAIN_TIMEOUT, res.prefetch(&d, 1));
                    let aaaa = tokio::time::timeout(PER_DOMAIN_TIMEOUT, res.prefetch(&d, 28));
                    let _ = tokio::join!(a, aaaa);
                });

                // Yield to drive progress if we've queued many tasks
                if tasks.len() >= CONCURRENT_PREFETCH * 2 {
                    tasks.next().await;
                }
            }

            // Drain remaining tasks
            while (tasks.next().await).is_some() {}

            info!("Pre-fetching complete ({} domains)", domains.len());
        });
    }

    let mut buf = vec![0u8; 8192];

    loop {
        let recv_fut = socket.recv_from(&mut buf);

        tokio::select! {
            result = recv_fut => {
                handle_recv(result, &resolver, &socket, &buf);
            }
            _ = async {
                while !stop_signal.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            } => {
                info!("Stop signal received, shutting down server...");
                break;
            }
        }
    }
    Ok(())
}

/// Handle a single recv_from result: spawn a task to process the query.
fn handle_recv(
    result: Result<(usize, SocketAddr), std::io::Error>,
    resolver: &Arc<RecursiveResolver>,
    socket: &Arc<UdpSocket>,
    buf: &[u8],
) {
    match result {
        Ok((len, src)) => {
            let data = buf[..len].to_vec();
            let resolver = resolver.clone();
            let socket = socket.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                if let Err(e) = handle_query(resolver, socket, data, src).await {
                    if !matches!(e, DnsError::Io(_)) {
                        warn!("Error handling query from {}: {}", src, e);
                    }
                } else {
                    let elapsed = start.elapsed();
                    debug!("Query from {} handled in {:?}", src, elapsed);
                }
            });
        }
        Err(e) => {
            error!("Error receiving datagram: {}", e);
        }
    }
}

/// Handle a single incoming DNS query.
async fn handle_query(
    resolver: Arc<RecursiveResolver>,
    socket: Arc<UdpSocket>,
    query_data: Vec<u8>,
    src: SocketAddr,
) -> Result<(), DnsError> {
    let request = match decode_message(&query_data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("Failed to parse query from {}: {}", src, e);
            if let Some(response) = quick_error_response(&query_data, 1) {
                let _ = socket.send_to(&response, src).await;
            }
            return Ok(());
        }
    };

    if request.header.qr || request.questions.is_empty() {
        return Ok(());
    }

    let question = &request.questions[0];
    let qname = question.name_str();
    let qtype = question.qtype;
    let qclass = question.qclass;

    debug!("→ {} {} ({})", qname, record_type_name(qtype), qclass);

    let wants_dnssec = client_wants_dnssec(&request);
    let result = resolver.resolve_with_ad(&qname, qtype, qclass).await;

    match result {
        Ok((records, ad_flag)) => {
            let mut additionals = Vec::new();
            if wants_dnssec {
                // DNSKEY (type 48): resolve with recursive fallback to fetch
                // public keys. Auth servers DO respond to direct DNSKEY queries.
                let zone = extract_zone(&qname);
                if let Ok((dnskeys, _)) = resolver.resolve_with_ad(&zone, 48, qclass).await {
                    additionals.extend(dnskeys);
                }

                // RRSIG (type 46): cache-only lookup. Auth servers don't respond
                // to direct RRSIG queries (they return SOA=NODATA), so we rely on
                // the RRSIGs cached during the answer + DNSKEY resolutions.
                let rrsigs = resolver.resolve_dnssec(&qname, 46, qclass).await;
                additionals.extend(rrsigs);

                // Always include an OPT record advertising DO=1
                additionals.push(dnssec_opt_record());
            }
            let response = build_response(&request.header, question, &records, additionals, wants_dnssec && ad_flag);
            let response_bytes = encode_message(&response)?;

            if response_bytes.len() > MAX_UDP_PAYLOAD {
                let mut truncated = response;
                truncated.header.tc = true;
                truncated.answers.clear();
                truncated.authorities.clear();
                truncated.additionals.clear();
                let truncated_bytes = encode_message(&truncated)?;
                let len = truncated_bytes.len().min(MAX_UDP_PAYLOAD);
                let _ = socket.send_to(&truncated_bytes[..len], src).await;
            } else {
                let _ = socket.send_to(&response_bytes, src).await;
            }
        }
        Err(e) => {
            match e {
                DnsError::NxDomain(soa, ad) => {
                    // Build proper NXDOMAIN response with SOA in authority
                    let mut header = Header::new_response(request.header.id, 3);
                    header.rd = request.header.rd;
                    header.ra = true;
                    header.ad = ad;
                    let mut additionals = Vec::new();
                    if client_wants_dnssec(&request) {
                        additionals.push(dnssec_opt_record());
                    }
                    let msg = Message {
                        header,
                        questions: vec![question.clone()],
                        answers: Vec::new(),
                        authorities: soa,
                        additionals,
                    };
                    if let Ok(bytes) = encode_message(&msg) {
                        let _ = socket.send_to(&bytes, src).await;
                    }
                }
                _ => {
                    let rcode = if e.to_string().contains("NXDOMAIN") {
                        3
                    } else {
                        2
                    };
                    if let Some(response) = quick_error_response(&query_data, rcode) {
                        let _ = socket.send_to(&response, src).await;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn build_response(
    req_header: &Header,
    question: &Question,
    answers: &[ResourceRecord],
    additionals: Vec<ResourceRecord>,
    ad: bool,
) -> Message {
    let mut header = Header::new_response(req_header.id, 0);
    header.rd = req_header.rd;
    header.ra = true;
    header.ad = ad;

    let mut cnames = Vec::new();
    let mut finals = Vec::new();

    for rec in answers {
        if rec.rtype == 5 {
            cnames.push(rec.clone());
        } else {
            finals.push(rec.clone());
        }
    }

    let mut all = Vec::with_capacity(cnames.len() + finals.len());
    all.extend(cnames);
    all.extend(finals);

    Message {
        header,
        questions: vec![question.clone()],
        answers: all,
        authorities: Vec::new(),
        additionals,
    }
}

/// Detect if the client set the DNSSEC OK (DO) bit in their EDNS0 OPT record.
/// Returns true if the query includes an OPT pseudo-record (type 41) with
/// the DO bit (bit 15 of TTL) set.
pub(crate) fn client_wants_dnssec(request: &Message) -> bool {
    request.additionals.iter().any(|r| {
        r.rtype == 41 && ((r.ttl >> 15) & 1) == 1
    })
}

/// Build an EDNS0 OPT pseudo-record signaling support for DNSSEC.
pub(crate) fn dnssec_opt_record() -> ResourceRecord {
    ResourceRecord {
        name: vec![0], // root "."
        rtype: 41,     // OPT
        rclass: 4096,  // UDP payload size
        ttl: (1 << 15), // DO bit set, version 0, extended rcode 0
        rdlength: 0,
        rdata: Vec::new(),
        parsed: None,
    }
}

/// Extract the registrable domain (zone) from a domain name.
/// For "www.google.com" returns "google.com".
/// For "google.com" returns "google.com".
pub(crate) fn extract_zone(name: &str) -> String {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() >= 2 {
        // Return the last two labels (e.g., "google.com" from "www.google.com")
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    } else {
        name.trim_end_matches('.').to_string()
    }
}

pub(crate) fn quick_error_response(query_data: &[u8], rcode: u8) -> Option<Vec<u8>> {
    if query_data.len() < 2 {
        return None;
    }
    let id = u16::from_be_bytes([query_data[0], query_data[1]]);
    let header = Header::new_response(id, rcode);
    // Try to include the original question section, so the response
    // is valid per RFC 1035 §4.1 (response must echo the question).
    let questions = if query_data.len() >= 12 {
        let qdcount = u16::from_be_bytes([query_data[4] & 0x0f, query_data[5]]);
        if qdcount > 0 {
            // Parse the first question from the original query
            match Question::from_bytes(query_data, 12) {
                Ok((q, _)) => vec![q],
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    let msg = Message {
        header,
        questions,
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    encode_message(&msg).ok()
}

pub(crate) fn record_type_name(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "TYPE??",
    }
}
