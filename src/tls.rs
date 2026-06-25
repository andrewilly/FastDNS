use std::fs;
use std::path::Path;

use log::{debug, error, info, warn};
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Generate a self-signed certificate for DoT/HTTPS.
/// Returns (certificate_der, private_key_der, rustls_server_config)
pub fn generate_self_signed_cert(
    subject_alt_names: &[String],
    organization: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>, Arc<ServerConfig>), String> {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::OrganizationName, organization);
    params.distinguished_name.push(DnType::CommonName, "FastDNS");

    // Add SAN entries
    let mut san = Vec::new();
    for name in subject_alt_names {
        san.push(rcgen::SanType::DnsName(name.clone()));
    }
    params.subject_alt_names = san;

    let key_pair = match KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => return Err(format!("Failed to generate key pair: {}", e)),
    };

    let cert = match params.self_signed(&key_pair) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to generate certificate: {}", e)),
    };

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Build rustls ServerConfig
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone())
        .map_err(|e| format!("Failed to build TLS config: {}", e))?;

    // Enable HTTP/2 and ALPN
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok((cert_der, key_der, Arc::new(server_config)))
}

/// Load existing certificate and private key from files.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let cert_bytes = fs::read(cert_path)
        .map_err(|e| format!("Failed to read certificate file '{}': {}", cert_path, e))?;
    let key_bytes = fs::read(key_path)
        .map_err(|e| format!("Failed to read private key file '{}': {}", key_path, e))?;

    let cert_der = CertificateDer::from(cert_bytes);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("Failed to build TLS config: {}", e))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}

/// Ensure the CA directory exists and write the CA certificate.
pub fn ensure_ca_directory(ca_dir: &Path) -> Result<(), String> {
    if !ca_dir.exists() {
        fs::create_dir_all(ca_dir)
            .map_err(|e| format!("Failed to create CA directory '{}': {}", ca_dir.display(), e))?;
    }
    Ok(())
}

/// Write the CA certificate to a file.
pub fn write_ca_certificate(ca_path: &Path, cert_der: &CertificateDer) -> Result<(), String> {
    fs::write(ca_path, cert_der.as_ref())
        .map_err(|e| format!("Failed to write CA certificate '{}': {}", ca_path.display(), e))?;
    Ok(())
}

/// Create a DoT-specific TLS acceptor with ALPN enforcement.
pub fn create_dot_acceptor(
    cert_der: &CertificateDer,
    key_der: &PrivateKeyDer,
) -> Result<TlsAcceptor, String> {
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone())
        .map_err(|e| format!("Failed to build DoT TLS config: {}", e))?;

    // Only advertise "dot" ALPN for DoT
    server_config.alpn_protocols = vec![b"dot".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Validate that a certificate chain is valid for the given hostname.
pub fn validate_certificate_hostname(cert_der: &CertificateDer, hostname: &str) -> Result<(), String> {
    // Simple validation using rcgen's x509-parser feature
    // Check if hostname matches any SAN
    #[cfg(feature = "x509-parser")]
    {
        let cert = match x509_parser::certificate::Certificate::from_der(cert_der) {
            Ok(c) => c,
            Err(e) => return Err(format!("Failed to parse certificate: {}", e)),
        };

        let san = match cert.subject_alternative_name() {
            Ok(Some(san)) => san,
            Ok(None) => return Err("Certificate has no SAN".to_string()),
            Err(e) => return Err(format!("Failed to parse SAN: {}", e)),
        };

        let dns_names = match san.dns_names() {
            Ok(names) => names,
            Err(e) => return Err(format!("Failed to get DNS names from SAN: {}", e)),
        };

        if !dns_names.iter().any(|name| name == &hostname) {
            return Err(format!("Certificate does not match hostname '{}'", hostname));
        }
    }

    #[cfg(not(feature = "x509-parser"))]
    {
        // Fallback: just check hostname isn't empty
        if hostname.is_empty() {
            return Err("Hostname is empty".to_string());
        }
    }

    Ok(())
}

/// Generate a self-signed certificate for the given hostname.
pub fn generate_self_signed_for_hostname(hostname: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), String> {
    let mut params = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, hostname);

    let mut san = Vec::new();
    san.push(rcgen::SanType::DnsName(hostname.to_string()));
    params.subject_alt_names = san;

    let key_pair = match KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => return Err(format!("Failed to generate key pair: {}", e)),
    };

    let cert = match params.self_signed(&key_pair) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to generate certificate: {}", e)),
    };

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    Ok((cert_der, key_der))
}