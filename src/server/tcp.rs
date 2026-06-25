//! TCP DNS server (RFC 1035 §4.2.2).
//!
//! TCP is used for zone transfers (AXFR/IXFR), and as a fallback when
//! UDP responses exceed 512 bytes (or the EDNS0 buffer size).
//! The wire format prepends a 2-byte length prefix to each DNS message.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::dns::error::DnsError;
use crate::dns::types::Header;
use crate::dns::wire::{decode_message, encode_message};
use crate::resolver::recursive::RecursiveResolver;

use super::udp::{build_response, client_wants_dnssec, dnssec_opt_record, extract_zone, record_type_name};

/// Maximum DNS message size over TCP (RFC 1035 recommends 65535).
const MAX_TCP_MESSAGE: usize = 65535;

/// Start the TCP DNS server on the given address.
/// Runs concurrently with the UDP server, sharing the same resolver.
pub async fn run_tcp_server(
    bind_addr: std::net::SocketAddr,
    resolver: Arc<RecursiveResolver>,
) -> Result<(), DnsError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| {
            error!("Cannot bind TCP to {}: {}", bind_addr, e);
            DnsError::Io(e)
        })?;

    info!("TCP server listening on {}", bind_addr);

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    let start = Instant::now();
                    if let Err(e) = handle_tcp_connection(stream, resolver).await {
                        warn!("TCP error from {}: {}", peer, e);
                    } else {
                        let elapsed = start.elapsed();
                        debug!("TCP query from {} handled in {:?}", peer, elapsed);
                    }
                });
            }
            Err(e) => {
                error!("TCP accept error: {}", e);
                // Brief pause to avoid busy-loop on persistent errors
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a single TCP connection: read one DNS query and send the response.
///
/// RFC 1035 §4.2.2: TCP messages are prefixed with a 2-byte length
/// (16-bit big-endian unsigned integer) giving the message length
/// excluding the prefix itself.
pub async fn handle_tcp_connection(
    mut stream: TcpStream,
    resolver: Arc<RecursiveResolver>,
) -> Result<(), DnsError> {
    // Read the 2-byte length prefix
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            DnsError::Malformed("TCP connection closed before length prefix")
        } else {
            DnsError::Io(e)
        }
    })?;

    let msg_len = u16::from_be_bytes(len_buf) as usize;

    if msg_len > MAX_TCP_MESSAGE || msg_len == 0 {
        return Err(DnsError::Malformed("Invalid TCP message length"));
    }

    // Read the DNS message bytes
    let mut query_data = vec![0u8; msg_len];
    stream.read_exact(&mut query_data).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            DnsError::Malformed("TCP connection closed before message body")
        } else {
            DnsError::Io(e)
        }
    })?;

    // Decode the query
    let request = match decode_message(&query_data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("Failed to parse TCP query: {}", e);
            if let Some(response) = super::udp::quick_error_response(&query_data, 1) {
                write_tcp_response(&mut stream, &response).await?;
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

    debug!("TCP → {} {} ({})", qname, record_type_name(qtype), qclass);

    let wants_dnssec = client_wants_dnssec(&request);
    let result = resolver.resolve_with_ad(&qname, qtype, qclass).await;

    let response_bytes = match result {
        Ok((records, ad_flag)) => {
            let mut additionals = Vec::new();
            if wants_dnssec {
                let zone = extract_zone(&qname);
                if let Ok((dnskeys, _)) = resolver.resolve_with_ad(&zone, 48, qclass).await {
                    additionals.extend(dnskeys);
                }
                let rrsigs = resolver.resolve_dnssec(&qname, 46, qclass).await;
                additionals.extend(rrsigs);
                additionals.push(dnssec_opt_record());
            }
            let response = build_response(&request.header, question, &records, additionals, wants_dnssec && ad_flag);
            // TCP: no truncation — full response always fits within TCP max size
            encode_message(&response)?
        }
        Err(e) => {
            match e {
                DnsError::NxDomain(soa, ad) => {
                    let mut header = Header::new_response(request.header.id, 3);
                    header.rd = request.header.rd;
                    header.ra = true;
                    header.ad = ad;
                    let mut additionals = Vec::new();
                    if wants_dnssec {
                        additionals.push(dnssec_opt_record());
                    }
                    let msg = crate::dns::types::Message {
                        header,
                        questions: vec![question.clone()],
                        answers: Vec::new(),
                        authorities: soa,
                        additionals,
                    };
                    encode_message(&msg)?
                }
                _ => {
                    let rcode = if e.to_string().contains("NXDOMAIN") {
                        3
                    } else {
                        2
                    };
                    super::udp::quick_error_response(&query_data, rcode)
                        .ok_or(DnsError::Malformed("Failed to build error response"))?
                }
            }
        }
    };

    write_tcp_response(&mut stream, &response_bytes).await
}

/// Write a DNS response to a TCP stream with the 2-byte length prefix.
async fn write_tcp_response(
    stream: &mut TcpStream,
    data: &[u8],
) -> Result<(), DnsError> {
    if data.len() > MAX_TCP_MESSAGE {
        return Err(DnsError::BufferTooSmall(data.len(), MAX_TCP_MESSAGE));
    }
    let len_prefix = (data.len() as u16).to_be_bytes();
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len_prefix);
    buf.extend_from_slice(data);

    stream.write_all(&buf).await.map_err(DnsError::Io)?;
    stream.flush().await.map_err(DnsError::Io)?;
    Ok(())
}
