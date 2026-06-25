//! Root hints - the initial list of root DNS server addresses.
//!
//! These are the 13 logical root server addresses from the official
//! IANA root hints file. Updated as of 2024.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A root server entry with both IPv4 and optional IPv6 addresses.
#[derive(Debug, Clone)]
pub struct RootServer {
    #[allow(dead_code)]
    pub name: &'static str,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

/// The 13 root servers.
pub static ROOT_SERVERS: &[RootServer] = &[
    RootServer { name: "a.root-servers.net", ipv4: Ipv4Addr::new(198, 41, 0, 4), ipv6: Some(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0, 0x2e30)) },
    RootServer { name: "b.root-servers.net", ipv4: Ipv4Addr::new(170, 247, 170, 53), ipv6: Some(Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0xb, 0, 0, 0, 0x1)) },
    RootServer { name: "c.root-servers.net", ipv4: Ipv4Addr::new(192, 33, 4, 12), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc)) },
    RootServer { name: "d.root-servers.net", ipv4: Ipv4Addr::new(199, 7, 91, 13), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd)) },
    RootServer { name: "e.root-servers.net", ipv4: Ipv4Addr::new(192, 203, 230, 10), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe)) },
    RootServer { name: "f.root-servers.net", ipv4: Ipv4Addr::new(192, 5, 5, 241), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf)) },
    RootServer { name: "g.root-servers.net", ipv4: Ipv4Addr::new(192, 112, 36, 4), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d)) },
    RootServer { name: "h.root-servers.net", ipv4: Ipv4Addr::new(198, 97, 190, 53), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53)) },
    RootServer { name: "i.root-servers.net", ipv4: Ipv4Addr::new(192, 36, 148, 17), ipv6: Some(Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53)) },
    RootServer { name: "j.root-servers.net", ipv4: Ipv4Addr::new(192, 58, 128, 30), ipv6: Some(Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0, 0x2e30)) },
    RootServer { name: "k.root-servers.net", ipv4: Ipv4Addr::new(193, 0, 14, 129), ipv6: Some(Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1)) },
    RootServer { name: "l.root-servers.net", ipv4: Ipv4Addr::new(199, 7, 83, 42), ipv6: Some(Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42)) },
    RootServer { name: "m.root-servers.net", ipv4: Ipv4Addr::new(202, 12, 27, 33), ipv6: Some(Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35)) },
];

/// Returns the list of initial root server addresses to query.
pub fn initial_root_addrs() -> Vec<IpAddr> {
    let mut addrs = Vec::with_capacity(ROOT_SERVERS.len() * 2);
    for server in ROOT_SERVERS {
        addrs.push(IpAddr::V4(server.ipv4));
        if let Some(v6) = server.ipv6 {
            addrs.push(IpAddr::V6(v6));
        }
    }
    addrs
}
