use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Debug, Clone)]
pub struct Target {
    pub addr: SocketAddr,
    pub ip: String,
    pub port: u16,
    pub domain: String,
}

impl Target {
    pub fn new() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
            ip: String::new(),
            port: 8080,
            domain: String::new(),
        }
    }
}
