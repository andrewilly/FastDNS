use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::tls::create_dot_acceptor;
use crate::dns::error::DnsError;
use crate::server::tcp::handle_tcp_connection;

const MAX_CONNECTIONS: usize = 512;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Start the DNS-over-TLS listener (RFC 7858).
pub async fn start_dot(
    bind_addr: SocketAddr,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
    resolver: Arc<crate::resolver::recursive::RecursiveResolver>,
) -> Result<(), DnsError> {
    let acceptor = create_dot_acceptor(&cert_der, &key_der)
        .map_err(|e| DnsError::Transport(e))?;
    let acceptor = TlsAcceptor::from(Arc::new(acceptor));

    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| {
            error!("DoT: could not bind {}: {}", bind_addr, e);
            DnsError::Io(e)
        })?;
    info!("DoT listening on {}", bind_addr);

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (tcp_stream, tcp_peer) = listener.accept().await.map_err(|e| {
            error!("DoT: TCP accept error: {}", e);
            DnsError::Io(e)
        })?;

        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let acceptor = acceptor.clone();
        let resolver = Arc::clone(&resolver);

        tokio::spawn(async move {
            let _permit = permit;

            let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp_stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!("DoT: TLS handshake failed from {}: {}", tcp_peer, e);
                    return;
                }
                Err(_) => {
                    debug!("DoT: TLS handshake timeout from {}", tcp_peer);
                    return;
                }
            };

            if let Err(e) = handle_tcp_connection(tls_stream, resolver).await {
                warn!("DoT error from {}: {}", tcp_peer, e);
            }
        });
    }
}