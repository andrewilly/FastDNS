//! DNS protocol constants (RFC 1035, RFC 3596, RFC 6891)
#![allow(dead_code)]

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAPPTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    SRV = 33,
    SSHFP = 44,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    TLSA = 52,
    CAA = 257,
    /// Catch-all for unknown types
    Unknown(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::NULL,
            11 => RecordType::WKS,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            17 => RecordType::RP,
            18 => RecordType::AFSDB,
            19 => RecordType::X25,
            20 => RecordType::ISDN,
            21 => RecordType::RT,
            22 => RecordType::NSAP,
            23 => RecordType::NSAPPTR,
            24 => RecordType::SIG,
            25 => RecordType::KEY,
            26 => RecordType::PX,
            27 => RecordType::GPOS,
            28 => RecordType::AAAA,
            29 => RecordType::LOC,
            30 => RecordType::NXT,
            33 => RecordType::SRV,
            44 => RecordType::SSHFP,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
            52 => RecordType::TLSA,
            257 => RecordType::CAA,
            _ => RecordType::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::MD => 3,
            RecordType::MF => 4,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::MB => 7,
            RecordType::MG => 8,
            RecordType::MR => 9,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MINFO => 14,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::RP => 17,
            RecordType::AFSDB => 18,
            RecordType::X25 => 19,
            RecordType::ISDN => 20,
            RecordType::RT => 21,
            RecordType::NSAP => 22,
            RecordType::NSAPPTR => 23,
            RecordType::SIG => 24,
            RecordType::KEY => 25,
            RecordType::PX => 26,
            RecordType::GPOS => 27,
            RecordType::AAAA => 28,
            RecordType::LOC => 29,
            RecordType::NXT => 30,
            RecordType::SRV => 33,
            RecordType::SSHFP => 44,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::TLSA => 52,
            RecordType::CAA => 257,
            RecordType::Unknown(v) => v,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::AAAA => "AAAA",
            RecordType::SRV => "SRV",
            RecordType::RRSIG => "RRSIG",
            RecordType::NSEC => "NSEC",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::CAA => "CAA",
            _ => "TYPE??",
        }
    }
}

/// DNS class codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
    None = 254,
    Any = 255,
    Unknown(u16),
}

impl Class {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Class::IN,
            2 => Class::CS,
            3 => Class::CH,
            4 => Class::HS,
            254 => Class::None,
            255 => Class::Any,
            _ => Class::Unknown(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::None => 254,
            Class::Any => 255,
            Class::Unknown(v) => v,
        }
    }
}

/// DNS response codes (RCODE)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    Unknown(u8),
}

impl ResponseCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormErr,
            2 => ResponseCode::ServFail,
            3 => ResponseCode::NXDomain,
            4 => ResponseCode::NotImp,
            5 => ResponseCode::Refused,
            6 => ResponseCode::YXDomain,
            7 => ResponseCode::YXRRSet,
            8 => ResponseCode::NXRRSet,
            9 => ResponseCode::NotAuth,
            10 => ResponseCode::NotZone,
            _ => ResponseCode::Unknown(value),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            ResponseCode::NoError => 0,
            ResponseCode::FormErr => 1,
            ResponseCode::ServFail => 2,
            ResponseCode::NXDomain => 3,
            ResponseCode::NotImp => 4,
            ResponseCode::Refused => 5,
            ResponseCode::YXDomain => 6,
            ResponseCode::YXRRSet => 7,
            ResponseCode::NXRRSet => 8,
            ResponseCode::NotAuth => 9,
            ResponseCode::NotZone => 10,
            ResponseCode::Unknown(v) => v,
        }
    }
}

/// DNS opcodes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
    Unknown(u8),
}

impl Opcode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            _ => Opcode::Unknown(value),
        }
    }
}

/// Maximum DNS message size over UDP
pub const MAX_UDP_PAYLOAD: usize = 4096;
/// Maximum EDNS0 UDP payload
pub const MAX_EDNS_PAYLOAD: usize = 8192;
/// Default UDP timeout in seconds
pub const UDP_TIMEOUT_SECS: u64 = 5;
/// Maximum number of retries
pub const MAX_RETRIES: u8 = 3;
/// Default TTL when not specified (1 hour)
pub const DEFAULT_TTL: u32 = 3600;
/// Port number for DNS
pub const DNS_PORT: u16 = 53;
