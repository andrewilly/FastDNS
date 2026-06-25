use crate::dns::constants::MAX_UDP_PAYLOAD;
use crate::dns::types::{Header, Message, Question};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Run a health check by sending a DNS query to the server.
pub async fn run_healthcheck(bind_addr: SocketAddr, domain: &str) -> bool {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return false,
    };

    let msg = Message {
        header: Header::new_query(0x1234, true),
        questions: vec![Question::new(domain, 1, 1).unwrap()], // A record
        answers: vec![],
        authorities: vec![],
        additionals: vec![],
    };

    let mut buf = [0u8; MAX_UDP_PAYLOAD];
    let len = msg.to_bytes(&mut buf).unwrap();

    if socket.send_to(&buf[..len], bind_addr).await.is_err() {
        return false;
    }

    let mut resp_buf = [0u8; MAX_UDP_PAYLOAD];
    let timeout = Duration::from_secs(2);

    if let Ok(Ok((len, _))) = tokio::time::timeout(timeout, socket.recv_from(&mut resp_buf)).await {
        if let Ok(resp) = Message::from_bytes(&resp_buf[..len]) {
            return resp.header.rcode == 0; // NOERROR
        }
    }

    false
}
