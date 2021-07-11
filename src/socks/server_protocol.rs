use log::{debug, error, info};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::usize;
use trust_dns_resolver::config::ResolverConfig;
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::proto::serialize::binary::BinDecodable;
use trust_dns_resolver::Resolver;

use crate::datatype::Target;
use crate::http::client::HttpClient;

use super::handler::Socks5Handler;
use super::handler::Socks5State;

pub fn method_request(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Method Request");

    handler.clear_buffer();
    match handler.read_stream() {
        Ok(false) => {}
        Ok(true) => {
            debug!("SOCKS5 method request interrupted.");
            return Ok(true);
        }
        Err(err) => {
            error!("During SOCKS5 method request, error occured: {}", err);
            return Err(err);
        }
    }

    let buffer = handler.buffer.as_mut();
    let buffer_len = handler.size;

    if buffer_len < 3 {
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    let version = buffer[0];
    let nmethod = buffer[1];

    if version != 0x05 {
        error!("Unsupported SOCKS version");
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    if buffer_len != (2 + nmethod as usize) {
        error!("Truncated request detected");
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    let mut support_no_auth = false;
    for method in buffer.iter().skip(2).take(nmethod as usize) {
        if *method == 0x00 {
            support_no_auth = true;
        }
    }
    if !support_no_auth {
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    debug!("SOCKS5 version:{} nmethod:{}", version, nmethod);

    handler.set_state(Socks5State::MethodResponse);

    Ok(false)
}

pub fn method_response(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Method Response");

    handler.reset_buffer();
    handler.put_buffer(0x05);
    handler.put_buffer(0x00);

    let result = handler.write_stream();
    handler.set_state(Socks5State::ConnectionRequest);

    result
}

pub fn connection_request(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Connection Request");

    handler.clear_buffer();
    match handler.read_stream() {
        Ok(false) => {}
        Ok(true) => {
            debug!("SOCKS5 connection request interrupted");
            return Ok(true);
        }
        Err(err) => {
            error!("During SOCKS5 connection request, error occured: {}", err);
            return Err(err);
        }
    }

    let buffer = handler.buffer.as_mut();
    let buffer_len = handler.size;

    let version = buffer[0];
    let cmd = buffer[1];
    let rsv = buffer[2];
    let atyp = buffer[3];

    if version != 0x05 {
        error!("Unsupported SOCKS version");
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    if cmd != 0x01 {
        error!("Unsupported SOCKS CMD: {}", cmd);
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    if rsv != 0x00 {
        error!("Unexpected SOCKS RSV detected");
        handler.set_state(Socks5State::Closed);
        return Ok(true);
    }

    let addr: SocketAddr;
    let mut target: Target = Target::new();

    match atyp {
        1 => {
            if buffer_len < 10 {
                error!("Truncated request detected");
                handler.set_state(Socks5State::Closed);
                return Ok(true);
            }
            let mut ip = [0; 4];
            handler.extract_buffer(&mut ip, 4);
            let port = (handler.buffer[8] as u16) << 8 | handler.buffer[9] as u16;
            addr = (ip, port).into();
            let ip = Ipv4Addr::from_bytes(&ip).unwrap();
            target.ip = ip.to_string();
            target.port = port;
            target.domain = target.ip.clone();
        }
        4 => {
            if buffer_len < 22 {
                error!("Truncated request detected");
                handler.set_state(Socks5State::Closed);
                return Ok(true);
            }
            let mut ip = [0; 16];
            handler.extract_buffer(&mut ip, 4);
            let port = (handler.buffer[20] as u16) << 8 | handler.buffer[21] as u16;
            addr = (ip, port).into();
            let ip = Ipv6Addr::from_bytes(&ip).unwrap();
            target.ip = ip.to_string();
            target.port = port;
            target.domain = target.ip.clone();
        }
        3 => {
            if buffer_len < 8 {
                error!("Truncated request detected");
                handler.set_state(Socks5State::Closed);
                return Ok(true);
            }

            let domain_len = buffer[4] as usize;
            let mut domain = vec![0; domain_len];
            handler.extract_buffer(&mut domain, 5);

            match String::from_utf8(domain) {
                Ok(s) => {
                    debug!("Requested domain: {}", s);
                    let resolver =
                        Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
                    let domain = s.clone();
                    let response = match resolver.lookup_ip(s) {
                        Ok(r) => r,
                        Err(err) => {
                            error!("Failed to resolve requested domain: {}", err);
                            handler.set_state(Socks5State::Closed);
                            return Ok(true);
                        }
                    };
                    let port = (handler.buffer[buffer_len - 2] as u16) << 8
                        | handler.buffer[buffer_len - 1] as u16;
                    if let Some(ip) = response.iter().next() {
                        addr = (ip, port).into();
                        target.ip = ip.to_string();
                        target.port = port;
                        target.domain = domain;
                    } else {
                        error!("No DNS record to requested domain");
                        handler.set_state(Socks5State::Closed);
                        return Ok(true);
                    }
                }
                Err(_) => {
                    error!("Unexpected request domain detected");
                    handler.set_state(Socks5State::Closed);
                    return Ok(true);
                }
            }
        }
        _ => {
            error!("Unexpected request ATYP detected");
            handler.set_state(Socks5State::Closed);
            return Ok(true);
        }
    }

    target.addr = addr;
    info!(
        "{} requested connection to {}:{}",
        handler.stream_addr().unwrap(),
        target.domain,
        target.port
    );
    handler.set_target(target);

    handler.set_state(Socks5State::ClientConnectionRequest);

    Ok(false)
}

pub fn connection_response(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Connection Response");

    handler.reset_buffer();
    handler.put_buffer(0x05);
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);
    handler.put_buffer(0x01);

    // BDN.ADDR & BND.PORT
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);
    handler.put_buffer(0x00);

    let result = handler.write_stream();
    handler.set_state(Socks5State::Relaying);

    result
}

pub fn relay_in(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Relay IN");

    handler.clear_buffer();
    match handler.read_stream() {
        Ok(false) => {}
        Ok(true) => {
            debug!("SOCKS5 Relay IN interrupted");
            return Ok(true);
        }
        Err(err) => {
            error!("During SOCKS5 Relay IN, error occured: {}", err);
            return Err(err);
        }
    }
    let client = handler.client.get_mut(0).unwrap();
    client.reset_buffer();
    client.clone_buffer(&handler.buffer);
    client.write_buffer()
}

pub fn relay_out(handler: &mut Socks5Handler<HttpClient>) -> io::Result<bool> {
    debug!("SOCKS5 Server Relay OUT");

    handler.reset_buffer();
    let client = handler.client.get_mut(0).unwrap();
    client.clear_buffer();
    match client.read_buffer() {
        Ok(false) => {}
        Ok(true) => {
            debug!("HTTP Client Relay IN interrupted");
            return Ok(true);
        }
        Err(err) => {
            error!("During HTTP Client Relay IN, error occured: {}", err);
            return Err(err);
        }
    }
    if client.size == 0 {
        return Ok(false);
    }
    handler.buffer.clone_from(&client.buffer);
    handler.write_stream()
}
