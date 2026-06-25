//! Core DNS types (RFC 1035 section 4.1)
#![allow(dead_code)]

use std::net::{Ipv4Addr, Ipv6Addr};

use super::error::{DnsError, DnsResult};

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// DNS message header (12 bytes, RFC 1035 §4.1.1 + RFC 2535 §6.1)
///
/// Flags layout (16 bits):
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///  |QR|  Opcode   |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
///  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub id: u16,
    pub qr: bool,       // true = response
    pub opcode: u8,     // 4 bits
    pub aa: bool,       // authoritative answer
    pub tc: bool,       // truncated
    pub rd: bool,       // recursion desired
    pub ra: bool,       // recursion available
    pub z: u8,          // reserved (2 bits: bit 7 and bit 6)
    pub ad: bool,       // authenticated data (bit 5)
    pub cd: bool,       // checking disabled (bit 4)
    pub rcode: u8,      // 4 bits (bits 3-0)
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn new_query(id: u16, rd: bool) -> Self {
        Header {
            id,
            qr: false,
            opcode: 0,
            aa: false,
            tc: false,
            rd,
            ra: false,
            z: 0,
            ad: false,
            cd: false,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn new_response(id: u16, rcode: u8) -> Self {
        Header {
            id,
            qr: true,
            opcode: 0,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            ad: false,
            cd: false,
            rcode,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    /// Parse header from raw bytes (exactly 12 bytes)
    #[inline]
    pub fn from_bytes(data: &[u8]) -> DnsResult<Self> {
        if data.len() < 12 {
            return Err(DnsError::BufferTooSmall(12, data.len()));
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        Ok(Header {
            id,
            qr: (flags >> 15) & 1 == 1,
            opcode: ((flags >> 11) & 0x0f) as u8,
            aa: (flags >> 10) & 1 == 1,
            tc: (flags >> 9) & 1 == 1,
            rd: (flags >> 8) & 1 == 1,
            ra: (flags >> 7) & 1 == 1,
            z: ((flags >> 6) & 0x03) as u8,  // bits 7-6: reserved (Z)
            ad: (flags >> 5) & 1 == 1,       // bit 5: authenticated data
            cd: (flags >> 4) & 1 == 1,       // bit 4: checking disabled
            rcode: (flags & 0x0f) as u8,
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Serialize header to bytes (exactly 12 bytes)
    #[inline]
    pub fn to_bytes(&self, buf: &mut [u8]) -> DnsResult<usize> {
        if buf.len() < 12 {
            return Err(DnsError::BufferTooSmall(12, buf.len()));
        }
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        let flags: u16 = (self.qr as u16) << 15
            | (self.opcode as u16) << 11
            | (self.aa as u16) << 10
            | (self.tc as u16) << 9
            | (self.rd as u16) << 8
            | (self.ra as u16) << 7
            | (self.z as u16) << 6      // Z: bits 7-6
            | (self.ad as u16) << 5     // AD: bit 5
            | (self.cd as u16) << 4     // CD: bit 4
            | self.rcode as u16;
        buf[2..4].copy_from_slice(&flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        Ok(12)
    }
}

// ---------------------------------------------------------------------------
// Question
// ---------------------------------------------------------------------------

/// DNS question section (RFC 1035 §4.1.2)
#[derive(Debug, Clone)]
pub struct Question {
    pub qname: Vec<u8>,      // raw encoded domain name (with labels)
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn new(name: &str, qtype: u16, qclass: u16) -> DnsResult<Self> {
        let encoded = encode_domain_name(name)?;
        Ok(Question {
            qname: encoded,
            qtype,
            qclass,
        })
    }

    /// Parse question starting at `offset` in `data`.
    #[inline]
    pub fn from_bytes(data: &[u8], offset: usize) -> DnsResult<(Self, usize)> {
        let (qname, off) = decode_domain_name(data, offset)?;
        if off + 4 > data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let qtype = u16::from_be_bytes([data[off], data[off + 1]]);
        let qclass = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        Ok((
            Question {
                qname,
                qtype,
                qclass,
            },
            off + 4,
        ))
    }

    /// Serialize question to buffer.
    #[inline]
    pub fn to_bytes(&self, buf: &mut [u8]) -> DnsResult<usize> {
        let total = self.qname.len() + 4;
        if buf.len() < total {
            return Err(DnsError::BufferTooSmall(total, buf.len()));
        }
        buf[..self.qname.len()].copy_from_slice(&self.qname);
        let off = self.qname.len();
        buf[off..off + 2].copy_from_slice(&self.qtype.to_be_bytes());
        buf[off + 2..off + 4].copy_from_slice(&self.qclass.to_be_bytes());
        Ok(total)
    }

    /// Return domain name as UTF-8 string (lossy).
    pub fn name_str(&self) -> String {
        labels_to_string(&self.qname)
    }
}

// ---------------------------------------------------------------------------
// Resource Record
// ---------------------------------------------------------------------------

/// A parsed DNS resource record (RFC 1035 §4.1.3)
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: Vec<u8>,    // raw encoded domain name
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
    /// Optional parsed/cached representation of rdata
    pub parsed: Option<RData>,
}

/// High-level representation of common RDATA formats
#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(Vec<u8>),
    NS(Vec<u8>),
    PTR(Vec<u8>),
    MX {
        preference: u16,
        exchange: Vec<u8>,
    },
    SOA {
        mname: Vec<u8>,
        rname: Vec<u8>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    TXT(Vec<String>),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: Vec<u8>,
    },
    RRSIG {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: Vec<u8>,
        signature: Vec<u8>,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    NSEC {
        next_domain: Vec<u8>,
        type_bit_maps: Vec<u8>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        type_bit_maps: Vec<u8>,
    },
    Unknown(Vec<u8>),
}

impl ResourceRecord {
    /// Parse a resource record starting at `offset` in `data`.
    #[inline]
    pub fn from_bytes(data: &[u8], offset: usize) -> DnsResult<(Self, usize)> {
        let (name, off) = decode_domain_name(data, offset)?;
        if off + 10 > data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let rtype = u16::from_be_bytes([data[off], data[off + 1]]);
        let rclass = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        let ttl = u32::from_be_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let rdlength = u16::from_be_bytes([data[off + 8], data[off + 9]]);
        let rdlen = rdlength as usize;
        let data_start = off + 10;
        if data_start + rdlen > data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let raw_rdata = data[data_start..data_start + rdlen].to_vec();
        let parsed = parse_rdata(rtype, &raw_rdata, data, data_start);

        // Decompress rdata if we successfully parsed it, so the stored
        // record can be safely re-serialized without stale compression pointers.
        let (rdata, rdlength) = if let Some(ref p) = parsed {
            let decompressed = decompressed_rdata(rtype, p);
            let dlen = decompressed.len() as u16;
            (decompressed, dlen)
        } else {
            (raw_rdata, rdlength)
        };

        Ok((
            ResourceRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdlength,
                rdata,
                parsed,
            },
            data_start + rdlen,
        ))
    }

    /// Serialize resource record to buffer (without compression).
    #[inline]
    pub fn to_bytes(&self, buf: &mut [u8]) -> DnsResult<usize> {
        let total = self.name.len() + 10 + self.rdlength as usize;
        if buf.len() < total {
            return Err(DnsError::BufferTooSmall(total, buf.len()));
        }
        let mut off = 0;
        buf[..self.name.len()].copy_from_slice(&self.name);
        off += self.name.len();
        buf[off..off + 2].copy_from_slice(&self.rtype.to_be_bytes());
        buf[off + 2..off + 4].copy_from_slice(&self.rclass.to_be_bytes());
        buf[off + 4..off + 8].copy_from_slice(&self.ttl.to_be_bytes());
        buf[off + 8..off + 10].copy_from_slice(&self.rdlength.to_be_bytes());
        off += 10;
        buf[off..off + self.rdlength as usize].copy_from_slice(&self.rdata);
        off += self.rdlength as usize;
        Ok(off)
    }

    /// Return owner name as string.
    pub fn name_str(&self) -> String {
        labels_to_string(&self.name)
    }

    /// Return a human-readable representation of the record data.
    pub fn rdata_str(&self) -> String {
        match &self.parsed {
            Some(RData::A(ip)) => ip.to_string(),
            Some(RData::AAAA(ip)) => ip.to_string(),
            Some(RData::CNAME(target)) | Some(RData::NS(target)) | Some(RData::PTR(target)) => {
                labels_to_string(target)
            }
            Some(RData::MX { preference, exchange }) => {
                format!("{} {}", labels_to_string(exchange), preference)
            }
            Some(RData::SOA { .. }) => "(SOA)".to_string(),
            Some(RData::TXT(parts)) => parts.join(""),
            Some(RData::SRV { priority, weight, port, target }) => {
                format!("{} {} {} {}", priority, weight, port, labels_to_string(target))
            }
            Some(RData::RRSIG { .. }) => "(RRSIG)".to_string(),
            Some(RData::DNSKEY { .. }) => "(DNSKEY)".to_string(),
            Some(RData::NSEC { .. }) => "(NSEC)".to_string(),
            Some(RData::DS { key_tag, algorithm, digest_type, .. }) => {
                format!("DS key_tag={} alg={} digest_type={}", key_tag, algorithm, digest_type)
            }
            _ => {
                if self.rdata.len() <= 20 {
                    format!("{:02x?}", self.rdata)
                } else {
                    format!("<{} bytes>", self.rdata.len())
                }
            }
    }
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A complete DNS message (RFC 1035 §4.1)
#[derive(Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// Parse a complete DNS message from raw bytes.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> DnsResult<Self> {
        let header = Header::from_bytes(data)?;
        let mut offset = 12usize;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            let (q, off) = Question::from_bytes(data, offset)?;
            questions.push(q);
            offset = off;
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            let (rr, off) = ResourceRecord::from_bytes(data, offset)?;
            answers.push(rr);
            offset = off;
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            let (rr, off) = ResourceRecord::from_bytes(data, offset)?;
            authorities.push(rr);
            offset = off;
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            let (rr, off) = ResourceRecord::from_bytes(data, offset)?;
            additionals.push(rr);
            offset = off;
        }

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Serialize message to bytes (without name compression).
    #[inline]
    pub fn to_bytes(&self, buf: &mut [u8]) -> DnsResult<usize> {
        let mut header = self.header;
        header.qdcount = self.questions.len() as u16;
        header.ancount = self.answers.len() as u16;
        header.nscount = self.authorities.len() as u16;
        header.arcount = self.additionals.len() as u16;

        let mut offset = header.to_bytes(buf)?;
        for q in &self.questions {
            offset += q.to_bytes(&mut buf[offset..])?;
        }
        for rr in &self.answers {
            offset += rr.to_bytes(&mut buf[offset..])?;
        }
        for rr in &self.authorities {
            offset += rr.to_bytes(&mut buf[offset..])?;
        }
        for rr in &self.additionals {
            offset += rr.to_bytes(&mut buf[offset..])?;
        }
        Ok(offset)
    }

    /// Find all records in the answer section matching a given type.
    pub fn answer_records(&self, rtype: u16) -> Vec<&ResourceRecord> {
        self.answers
            .iter()
            .filter(|r| r.rtype == rtype)
            .collect()
    }

    /// Find all records in the authority section matching a given type.
    pub fn authority_records(&self, rtype: u16) -> Vec<&ResourceRecord> {
        self.authorities
            .iter()
            .filter(|r| r.rtype == rtype)
            .collect()
    }

    /// Find all records in the additional section matching a given type.
    pub fn additional_records(&self, rtype: u16) -> Vec<&ResourceRecord> {
        self.additionals
            .iter()
            .filter(|r| r.rtype == rtype)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// EDNS0 OPT record (RFC 6891)
// ---------------------------------------------------------------------------

/// An EDNS0 OPT pseudo-RR (sent in the additional section)
#[derive(Debug, Clone)]
pub struct OptRecord {
    pub udp_payload_size: u16,
    pub ext_rcode: u8,
    pub edns_version: u8,
    pub dnssec_ok: bool,
    pub options: Vec<EdnsOption>,
}

#[derive(Debug, Clone)]
pub enum EdnsOption {
    Nsid,
    ClientSubnet { family: u16, source_mask: u8, scope_mask: u8, address: Vec<u8> },
    Cookie { client: Vec<u8>, server: Vec<u8> },
    Padding(Vec<u8>),
    Other(u16, Vec<u8>),
}

impl OptRecord {
    pub fn new(dnssec_ok: bool) -> Self {
        OptRecord {
            udp_payload_size: crate::dns::constants::MAX_EDNS_PAYLOAD as u16,
            ext_rcode: 0,
            edns_version: 0,
            dnssec_ok,
            options: Vec::new(),
        }
    }

    /// Build the OPT pseudo-record as a ResourceRecord for serialization.
    pub fn to_resource_record(&self) -> ResourceRecord {
        let rdata = Vec::new(); // No options for simplicity
        ResourceRecord {
            name: vec![0], // root label "."
            rtype: 41,     // OPT
            rclass: self.udp_payload_size,
            ttl: ((self.ext_rcode as u32) << 24)
                | ((self.edns_version as u32) << 16)
                | (self.dnssec_ok as u32) << 15,
            rdlength: rdata.len() as u16,
            rdata,
            parsed: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Domain name encoding / decoding
// ---------------------------------------------------------------------------

/// Encode a domain name (e.g., "www.example.com") into DNS label format.
pub fn encode_domain_name(name: &str) -> DnsResult<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Ok(vec![0]);
    }

    let mut encoded = Vec::with_capacity(name.len() + 2);
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidLabel("empty label in domain name"));
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidLabel("label exceeds 63 characters"));
        }
        let len_byte = label.len() as u8;
        encoded.push(len_byte);
        encoded.extend_from_slice(label.as_bytes());
        // Lowercase for case-insensitive canonical form
        for b in encoded.iter_mut().rev().take(label.len()) {
            b.make_ascii_lowercase();
        }
    }
    encoded.push(0);
    Ok(encoded)
}

/// Encode a domain name with 0x20 random case encoding for cache poisoning resistance.
/// Randomly sets the case of ASCII letters in labels.
pub fn encode_domain_name_mixed(name: &str, mask: &[bool]) -> DnsResult<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return Ok(vec![0]);
    }

    let mut encoded = Vec::with_capacity(name.len() + 2);
    let mut bit_idx = 0;
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidLabel("empty label in domain name"));
        }
        if label.len() > 63 {
            return Err(DnsError::InvalidLabel("label exceeds 63 characters"));
        }
        encoded.push(label.len() as u8);
        for &b in label.as_bytes().iter() {
            if b.is_ascii_alphabetic() {
                let flip = mask.get(bit_idx % mask.len()).copied().unwrap_or(false);
                bit_idx += 1;
                if flip {
                    // Toggle case (0x20)
                    encoded.push(b ^ 0x20);
                } else {
                    encoded.push(b);
                }
            } else {
                encoded.push(b);
            }
        }
    }
    encoded.push(0);
    Ok(encoded)
}

/// Decode a domain name starting at `offset` in `data`.
/// Handles name compression (pointers with 0xC0 prefix).
#[inline]
pub fn decode_domain_name(data: &[u8], offset: usize) -> DnsResult<(Vec<u8>, usize)> {
    let mut result = Vec::with_capacity(32);
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_pos = 0usize;

    loop {
        if pos >= data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let byte = data[pos];
        if byte == 0 {
            result.push(0);
            pos += 1;
            if !jumped {
                jump_pos = pos;
            }
            return Ok((result, jump_pos));
        } else if byte & 0xc0 == 0xc0 {
            if pos + 1 >= data.len() {
                return Err(DnsError::UnexpectedEof);
            }
            let ptr = ((byte & 0x3f) as usize) << 8 | data[pos + 1] as usize;
            if ptr >= offset {
                return Err(DnsError::InvalidPointer(ptr));
            }
            if !jumped {
                jump_pos = pos + 2;
                jumped = true;
            }
            pos = ptr;
        } else {
            let len = byte as usize;
            if len > 63 {
                return Err(DnsError::InvalidLabel("label exceeds 63 bytes"));
            }
            pos += 1;
            if pos + len > data.len() {
                return Err(DnsError::UnexpectedEof);
            }
            result.push(byte);
            result.extend_from_slice(&data[pos..pos + len]);
            pos += len;
        }
    }
}

/// Convert raw label-format domain name to human-readable string.
pub fn labels_to_string(labels: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;
    while i < labels.len() {
        let len = labels[i] as usize;
        if len == 0 {
            break;
        }
        i += 1;
        if i + len > labels.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&labels[i..i + len]) {
            parts.push(s.to_string());
        }
        i += len;
    }
    if parts.is_empty() {
        return ".".to_string();
    }
    parts.join(".")
}

/// Compare two domain names in label format (case-insensitive).
pub fn domain_names_equal(a: &[u8], b: &[u8]) -> bool {
    let mut ia = 0;
    let mut ib = 0;
    loop {
        if ia >= a.len() && ib >= b.len() {
            return true;
        }
        if ia >= a.len() || ib >= b.len() {
            return false;
        }
        let la = a[ia] as usize;
        let lb = b[ib] as usize;
        if la != lb {
            return false;
        }
        if la == 0 {
            return true;
        }
        ia += 1;
        ib += 1;
        for _ in 0..la {
            if ia >= a.len() || ib >= b.len() {
                return false;
            }
            if !a[ia].eq_ignore_ascii_case(&b[ib]) {
                return false;
            }
            ia += 1;
            ib += 1;
        }
    }
}

/// Count the number of labels in an encoded domain name (excluding root).
pub fn count_labels(name: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < name.len() {
        let len = name[i] as usize;
        if len == 0 {
            break;
        }
        count += 1;
        i += 1 + len;
    }
    count
}

/// Get a prefix of the domain name (first N labels), encoded.
/// e.g., for "www.example.com." with n=2 -> "example.com."
pub fn name_prefix(name: &[u8], n: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;
    let mut count = 0;
    // Find the Nth label from the right (excluding root)
    let total = count_labels(name);
    if n >= total {
        return name.to_vec();
    }
    let skip = total - n;
    while i < name.len() {
        let len = name[i] as usize;
        if len == 0 {
            result.push(0);
            break;
        }
        if count >= skip {
            result.push(name[i]);
            result.extend_from_slice(&name[i + 1..i + 1 + len]);
        }
        i += 1 + len;
        count += 1;
    }
    if result.last() != Some(&0) {
        result.push(0);
    }
    result
}

// ---------------------------------------------------------------------------
// RData parsing
// ---------------------------------------------------------------------------

fn parse_rdata(rtype: u16, rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    match rtype {
        1 => parse_a_rdata(rdata),
        28 => parse_aaaa_rdata(rdata),
        5 => parse_name_rdata(rdata, msg, rdata_offset, RData::CNAME),
        2 => parse_name_rdata(rdata, msg, rdata_offset, RData::NS),
        12 => parse_name_rdata(rdata, msg, rdata_offset, RData::PTR),
        15 => parse_mx_rdata(rdata, msg, rdata_offset),
        6 => parse_soa_rdata(rdata, msg, rdata_offset),
        16 => parse_txt_rdata(rdata),
        33 => parse_srv_rdata(rdata, msg, rdata_offset),
        46 => parse_rrsig_rdata(rdata, msg, rdata_offset),
        48 => parse_dnskey_rdata(rdata),
         43 => parse_ds_rdata(rdata),
         47 => parse_nsec_rdata(rdata, msg, rdata_offset),
        _ => {
            if rdata.len() <= 65535 {
                Some(RData::Unknown(rdata.to_vec()))
            } else {
                None
            }
        }
    }
}

/// Reconstruct uncompressed rdata from the parsed RData enum.
/// This ensures records are stored WITHOUT compression pointers,
/// so they can be safely re-serialized in a new response message.
    fn decompressed_rdata(_rtype: u16, parsed: &RData) -> Vec<u8> {
    match parsed {
        RData::A(ip) => ip.octets().to_vec(),
        RData::AAAA(ip) => ip.octets().to_vec(),
        RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => name.clone(),
        RData::MX { preference, exchange } => {
            let mut bytes = Vec::with_capacity(2 + exchange.len());
            bytes.extend_from_slice(&preference.to_be_bytes());
            bytes.extend_from_slice(exchange);
            bytes
        }
        RData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
            let mut bytes = Vec::with_capacity(mname.len() + rname.len() + 20);
            bytes.extend_from_slice(mname);
            bytes.extend_from_slice(rname);
            bytes.extend_from_slice(&serial.to_be_bytes());
            bytes.extend_from_slice(&refresh.to_be_bytes());
            bytes.extend_from_slice(&retry.to_be_bytes());
            bytes.extend_from_slice(&expire.to_be_bytes());
            bytes.extend_from_slice(&minimum.to_be_bytes());
            bytes
        }
        RData::TXT(strings) => {
            let mut bytes = Vec::new();
            for s in strings {
                bytes.push(s.len() as u8);
                bytes.extend_from_slice(s.as_bytes());
            }
            bytes
        }
        RData::SRV { priority, weight, port, target } => {
            let mut bytes = Vec::with_capacity(6 + target.len());
            bytes.extend_from_slice(&priority.to_be_bytes());
            bytes.extend_from_slice(&weight.to_be_bytes());
            bytes.extend_from_slice(&port.to_be_bytes());
            bytes.extend_from_slice(target);
            bytes
        }
        RData::RRSIG { type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, signature } => {
            let mut bytes = Vec::with_capacity(18 + signer_name.len() + signature.len());
            bytes.extend_from_slice(&type_covered.to_be_bytes());
            bytes.push(*algorithm);
            bytes.push(*labels);
            bytes.extend_from_slice(&original_ttl.to_be_bytes());
            bytes.extend_from_slice(&signature_expiration.to_be_bytes());
            bytes.extend_from_slice(&signature_inception.to_be_bytes());
            bytes.extend_from_slice(&key_tag.to_be_bytes());
            bytes.extend_from_slice(signer_name);
            bytes.extend_from_slice(signature);
            bytes
        }
        RData::DNSKEY { flags, protocol, algorithm, public_key } => {
            let mut bytes = Vec::with_capacity(4 + public_key.len());
            bytes.extend_from_slice(&flags.to_be_bytes());
            bytes.push(*protocol);
            bytes.push(*algorithm);
            bytes.extend_from_slice(public_key);
            bytes
        }
        RData::NSEC { next_domain, type_bit_maps } => {
            let mut bytes = Vec::with_capacity(next_domain.len() + type_bit_maps.len());
            bytes.extend_from_slice(next_domain);
            bytes.extend_from_slice(type_bit_maps);
            bytes
        }
        RData::DS { key_tag, algorithm, digest_type, digest } => {
            let mut bytes = Vec::with_capacity(4 + digest.len());
            bytes.extend_from_slice(&key_tag.to_be_bytes());
            bytes.push(*algorithm);
            bytes.push(*digest_type);
            bytes.extend_from_slice(digest);
            bytes
        }
        RData::NSEC3 { hash_algorithm, flags, iterations, salt, next_hashed_owner, type_bit_maps } => {
            let mut bytes = Vec::with_capacity(6 + salt.len() + next_hashed_owner.len() + type_bit_maps.len());
            bytes.push(*hash_algorithm);
            bytes.push(*flags);
            bytes.extend_from_slice(&iterations.to_be_bytes());
            bytes.push(salt.len() as u8);
            bytes.extend_from_slice(salt);
            bytes.extend_from_slice(next_hashed_owner);
            bytes.extend_from_slice(type_bit_maps);
            bytes
        }
        // For unknown types, keep the original raw rdata (no decompression needed)
        RData::Unknown(original) => original.clone(),
    }
}

fn parse_a_rdata(rdata: &[u8]) -> Option<RData> {
    if rdata.len() == 4 {
        Some(RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))
    } else {
        None
    }
}

fn parse_aaaa_rdata(rdata: &[u8]) -> Option<RData> {
    if rdata.len() == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(rdata);
        Some(RData::AAAA(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

/// Parse a domain name from rdata, supporting compression pointers.
/// The rdata is a sub-slice of the full message; we use the full message
/// and the rdata_offset to resolve compression pointers correctly.
fn parse_name_rdata(
    rdata: &[u8],
    msg: &[u8],
    rdata_offset: usize,
    ctor: fn(Vec<u8>) -> RData,
) -> Option<RData> {
    if rdata.is_empty() {
        return None;
    }
    // Use the full message starting at the rdata offset for proper pointer resolution
    match decode_domain_name_at(msg, rdata_offset) {
        Ok((name, _)) => Some(ctor(name)),
        Err(_) => None,
    }
}

/// Decode a domain name at a specific offset within the full message,
/// with full compression pointer support.
fn decode_domain_name_at(msg: &[u8], offset: usize) -> DnsResult<(Vec<u8>, usize)> {
    decode_domain_name(msg, offset)
}

fn parse_mx_rdata(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    if rdata.len() < 3 {
        return None;
    }
    let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
    // The exchange name starts at rdata_offset + 2 in the full message
    let exchange_offset = rdata_offset + 2;
    match decode_domain_name_at(msg, exchange_offset) {
        Ok((exchange, _)) => Some(RData::MX { preference, exchange }),
        Err(_) => None,
    }
}

fn parse_soa_rdata(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    let mut off = rdata_offset;
    match decode_domain_name_at(msg, off) {
        Ok((mname, new_off)) => {
            off = new_off;
            match decode_domain_name_at(msg, off) {
                Ok((rname, new_off)) => {
                    off = new_off;
                    let data_start = off - rdata_offset; // offset within rdata
                    if data_start + 20 > rdata.len() {
                        return None;
                    }
                    let serial = u32::from_be_bytes([
                        rdata[data_start], rdata[data_start + 1],
                        rdata[data_start + 2], rdata[data_start + 3],
                    ]);
                    let refresh = u32::from_be_bytes([
                        rdata[data_start + 4], rdata[data_start + 5],
                        rdata[data_start + 6], rdata[data_start + 7],
                    ]);
                    let retry = u32::from_be_bytes([
                        rdata[data_start + 8], rdata[data_start + 9],
                        rdata[data_start + 10], rdata[data_start + 11],
                    ]);
                    let expire = u32::from_be_bytes([
                        rdata[data_start + 12], rdata[data_start + 13],
                        rdata[data_start + 14], rdata[data_start + 15],
                    ]);
                    let minimum = u32::from_be_bytes([
                        rdata[data_start + 16], rdata[data_start + 17],
                        rdata[data_start + 18], rdata[data_start + 19],
                    ]);
                    Some(RData::SOA {
                        mname, rname, serial, refresh, retry, expire, minimum,
                    })
                }
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

fn parse_txt_rdata(rdata: &[u8]) -> Option<RData> {
    let mut parts = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        pos += 1;
        if pos + len > rdata.len() {
            return None;
        }
        if let Ok(s) = std::str::from_utf8(&rdata[pos..pos + len]) {
            parts.push(s.to_string());
        }
        pos += len;
    }
    Some(RData::TXT(parts))
}

fn parse_srv_rdata(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    if rdata.len() < 7 {
        return None;
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
    let port = u16::from_be_bytes([rdata[4], rdata[5]]);
    let target_offset = rdata_offset + 6;
    match decode_domain_name_at(msg, target_offset) {
        Ok((target, _)) => Some(RData::SRV { priority, weight, port, target }),
        Err(_) => None,
    }
}

fn parse_rrsig_rdata(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    if rdata.len() < 18 {
        return None;
    }
    let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let labels = rdata[3];
    let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
    let signature_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
    let signature_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);
    let signer_name_offset = rdata_offset + 18;
    match decode_domain_name_at(msg, signer_name_offset) {
        Ok((signer_name, end_offset)) => {
            let sig_start = end_offset - rdata_offset;
            if sig_start > rdata.len() {
                return None;
            }
            let signature = rdata[sig_start..].to_vec();
            Some(RData::RRSIG {
                type_covered, algorithm, labels, original_ttl,
                signature_expiration, signature_inception, key_tag,
                signer_name, signature,
            })
        }
        Err(_) => None,
    }
}

fn parse_dnskey_rdata(rdata: &[u8]) -> Option<RData> {
    if rdata.len() < 4 {
        return None;
    }
    let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
    let protocol = rdata[2];
    let algorithm = rdata[3];
    let public_key = rdata[4..].to_vec();
    Some(RData::DNSKEY { flags, protocol, algorithm, public_key })
}

fn parse_nsec_rdata(rdata: &[u8], msg: &[u8], rdata_offset: usize) -> Option<RData> {
    match decode_domain_name_at(msg, rdata_offset) {
        Ok((next_domain, end_offset)) => {
            let bitmaps_start = end_offset - rdata_offset;
            let type_bit_maps = rdata[bitmaps_start..].to_vec();
            Some(RData::NSEC { next_domain, type_bit_maps })
        }
        Err(_) => None,
    }
}

fn parse_ds_rdata(rdata: &[u8]) -> Option<RData> {
    if rdata.len() < 4 {
        return None;
    }
    let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm = rdata[2];
    let digest_type = rdata[3];
    let digest = rdata[4..].to_vec();
    Some(RData::DS { key_tag, algorithm, digest_type, digest })
}
