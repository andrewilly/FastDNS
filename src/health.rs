use crate::dns::constants::MAX_UDP_PAYLOAD;
use crate::dns::types::{Header, Message, Question, RData};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Outcome of a health check, with a human-readable detail line.
pub struct HealthReport {
    /// Whether the resolver answered with NOERROR.
    pub ok: bool,
    /// Human-readable description (elapsed, rcode, resolved IPs...).
    pub detail: String,
}

/// Run a health check by sending a DNS query to the server.
/// Returns a structured report suitable for direct CLI output.
pub async fn run_healthcheck(bind_addr: SocketAddr, domain: &str) -> HealthReport {
    let start = Instant::now();

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return HealthReport {
                ok: false,
                detail: format!("cannot create socket: {}", e),
            }
        }
    };

    let msg = Message {
        header: Header::new_query(0x1234, true),
        questions: vec![Question::new(domain, 1, 1).unwrap()], // A record
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    let len = match msg.to_bytes(&mut buf) {
        Ok(l) => l,
        Err(e) => {
            return HealthReport {
                ok: false,
                detail: format!("cannot encode query: {}", e),
            }
        }
    };

    if let Err(e) = socket.send_to(&buf[..len], bind_addr).await {
        return HealthReport {
            ok: false,
            detail: format!("cannot send query to {}: {}", bind_addr, e),
        };
    }

    let mut resp_buf = [0u8; MAX_UDP_PAYLOAD];
    let timeout = Duration::from_secs(2);

    match tokio::time::timeout(timeout, socket.recv_from(&mut resp_buf)).await {
        Ok(Ok((resp_len, _))) => match Message::from_bytes(&resp_buf[..resp_len]) {
            Ok(resp) => {
                let elapsed_ms = start.elapsed().as_millis();
                if resp.header.rcode == 0 {
                    // Collect resolved A/AAAA addresses for a useful message.
                    let ips: Vec<String> = resp
                        .answers
                        .iter()
                        .filter_map(|r| match &r.parsed {
                            Some(RData::A(ip)) => Some(ip.to_string()),
                            Some(RData::AAAA(ip)) => Some(ip.to_string()),
                            _ => None,
                        })
                        .collect();
                    let detail = if ips.is_empty() {
                        format!("{} answered NOERROR in {} ms", bind_addr, elapsed_ms)
                    } else {
                        format!(
                            "{} resolved {} → {} in {} ms",
                            bind_addr,
                            domain,
                            ips.join(", "),
                            elapsed_ms
                        )
                    };
                    HealthReport { ok: true, detail }
                } else {
                    HealthReport {
                        ok: false,
                        detail: format!(
                            "{} answered RCODE={} in {} ms",
                            bind_addr,
                            resp.header.rcode,
                            elapsed_ms
                        ),
                    }
                }
            }
            Err(e) => HealthReport {
                ok: false,
                detail: format!("cannot parse response from {}: {}", bind_addr, e),
            },
        },
        Ok(Err(e)) => HealthReport {
            ok: false,
            detail: format!("error receiving response from {}: {}", bind_addr, e),
        },
        Err(_) => HealthReport {
            ok: false,
            detail: format!("timeout after {} ms — no response from {}", timeout.as_millis(), bind_addr),
        },
    }
}
