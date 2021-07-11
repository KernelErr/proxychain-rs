use std::net::SocketAddr;

use url::Url;

#[derive(Debug, Clone)]
pub enum ProxyProtocol {
    HTTPProxy,
    SOCKS5Proxy,
}

#[derive(Debug, Clone)]
pub struct Proxy {
    protocol: ProxyProtocol,
    url: String,
    pub host: String,
    pub port: u16,
    username: Option<String>,
    password: Option<String>,
    pub addr: SocketAddr,
}

impl Proxy {
    pub fn parse(value: &str) -> Self {
        let url = Url::parse(value).expect("Invalid proxy URL");
        let protocol = match url.scheme() {
            "http" => ProxyProtocol::HTTPProxy,
            "socks" | "socks5" => ProxyProtocol::SOCKS5Proxy,
            _ => {
                panic!("Invalid proxy scheme")
            }
        };
        let host = String::from(url.host_str().expect("Invalid proxy URL"));
        let port = match url.port() {
            Some(u) => u,
            None => match protocol {
                ProxyProtocol::HTTPProxy => 80,
                ProxyProtocol::SOCKS5Proxy => 1080,
            },
        };
        let username = if url.username().is_empty() {
            None
        } else {
            Some(String::from(url.username()))
        };
        let password = url.password().map(String::from);
        let url = String::from(value);
        let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();
        Self {
            protocol,
            url,
            host,
            port,
            username,
            password,
            addr,
        }
    }
}
