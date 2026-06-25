//! DNS transport abstraction layer.
//!
//! Supports:
//! - UDP (standard DNS, port 53)
//! - DoH (DNS-over-HTTPS, RFC 8484)
//! - DoT (DNS-over-TLS, RFC 7858)
#![allow(dead_code)]

pub mod doh;
pub mod dot;

use std::net::IpAddr;
use std::time::Duration;


/// A resolved DNS response (raw bytes + source info)
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub raw_data: Vec<u8>,
    pub source: TransportSource,
    pub rtt: Duration,
}

/// Where the response came from
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSource {
    Udp(IpAddr),
    DoH,
    DoT,
}

/// DNS transport: UDP, DoH, or DoT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    Udp,
    DoH,
    DoT,
}
