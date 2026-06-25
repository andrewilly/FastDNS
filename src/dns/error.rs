//! DNS-specific error types
#![allow(dead_code)]

use std::fmt;

use super::types::ResourceRecord;

/// Errors that can occur during DNS operations
#[derive(Debug)]
pub enum DnsError {
    /// The DNS message is malformed or truncated
    Malformed(&'static str),
    /// NXDOMAIN with optional SOA records from the authoritative response
    /// and whether DNSSEC AD bit should be set
    NxDomain(Vec<ResourceRecord>, bool),
    /// Transport error (DoH/DoT/UDP failure)
    Transport(String),
    /// Buffer too small for operation
    BufferTooSmall(usize, usize),
    /// Unknown record type encountered
    UnknownRecordType(u16),
    /// Name compression pointer is invalid (loop or out of bounds)
    InvalidPointer(usize),
    /// A domain name contains an invalid label
    InvalidLabel(&'static str),
    /// Unexpected end of data
    UnexpectedEof,
    /// I/O error
    Io(std::io::Error),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Malformed(msg) => write!(f, "malformed DNS message: {msg}"),
            DnsError::NxDomain(..) => write!(f, "NXDOMAIN"),
            DnsError::Transport(msg) => write!(f, "transport error: {msg}"),
            DnsError::BufferTooSmall(need, have) => {
                write!(f, "buffer too small: need {need} bytes, have {have}")
            }
            DnsError::UnknownRecordType(t) => write!(f, "unknown record type: {t}"),
            DnsError::InvalidPointer(p) => write!(f, "invalid compression pointer at offset {p}"),
            DnsError::InvalidLabel(msg) => write!(f, "invalid label: {msg}"),
            DnsError::UnexpectedEof => write!(f, "unexpected end of data"),
            DnsError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(e: std::io::Error) -> Self {
        DnsError::Io(e)
    }
}

/// Result type for DNS operations
pub type DnsResult<T> = Result<T, DnsError>;
