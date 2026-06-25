//! Higher-level wire format helpers for encoding/decoding DNS messages.

use super::error::DnsResult;
use super::types::Message;

/// Maximum buffer size for DNS messages (conservative for EDNS0)
pub const MAX_DNS_MESSAGE_SIZE: usize = 8192;

/// Encode a DNS message into a freshly allocated buffer.
pub fn encode_message(msg: &Message) -> DnsResult<Vec<u8>> {
    let mut buf = vec![0u8; MAX_DNS_MESSAGE_SIZE];
    let len = msg.to_bytes(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

/// Decode a DNS message from raw bytes.
pub fn decode_message(data: &[u8]) -> DnsResult<Message> {
    Message::from_bytes(data)
}
