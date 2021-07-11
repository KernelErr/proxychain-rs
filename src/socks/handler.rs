use bytes::{BufMut, BytesMut};
use fnv::FnvHashMap;
use log::debug;
use mio::{event::Event, net::TcpStream, Registry, Token};
use slab::Slab;
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    usize,
};

use crate::{
    datatype::Target,
    http::client::HttpClient,
    proxy::Proxy,
    socks::server_protocol::{connection_response, relay_in, relay_out},
};

use super::server_protocol::{connection_request, method_request, method_response};

#[derive(Debug, PartialEq, Eq)]
pub enum Socks5State {
    MethodRequest,
    MethodResponse,
    ConnectionRequest,
    ClientConnectionRequest,
    ClientConnectionResponse,
    ConnectionResponse,
    Relaying,
    Closed,
}

pub struct Socks5Handler<T> {
    pub token: Token,
    stream: TcpStream,
    pub buffer: BytesMut,
    pub size: usize,
    intotal: usize,
    target: Target,
    pub state: Socks5State,
    subproxy: Vec<Proxy>,
    pub client: Slab<T>,
}

impl Socks5Handler<HttpClient> {
    pub fn new(token: Token, stream: TcpStream, subproxy: Vec<Proxy>) -> Self {
        let mut buffer = BytesMut::with_capacity(4096);
        buffer.resize(4096, 0);
        let mut outbuf = BytesMut::with_capacity(4096);
        outbuf.resize(4096, 0);
        Self {
            token,
            stream,
            buffer,
            size: 0,
            intotal: 0,
            target: Target::new(),
            state: Socks5State::MethodRequest,
            subproxy,
            client: Slab::new(),
        }
    }

    pub fn handle(
        &mut self,
        event: &Event,
        token: Token,
        unique_token: &mut Token,
        registry: &Registry,
        subtoken: &mut FnvHashMap<Token, Token>,
    ) -> io::Result<bool> {
        debug!(
            "SOCKS5 connection state: {:?}, readable: {}, writeable: {}",
            self.state,
            event.is_readable(),
            event.is_writable()
        );

        if event.is_readable() {
            let result = match self.state {
                Socks5State::MethodRequest if token == self.token => method_request(self),
                Socks5State::ConnectionRequest if token == self.token => {
                    let handle_result = connection_request(self);
                    let proxy = self.subproxy.get(0).unwrap().clone();
                    let mut client = HttpClient::new(proxy, self.target.clone());
                    let next_token = unique_token.0;
                    unique_token.0 += 1;
                    let connect_result = client.connect(Token(next_token), registry);
                    subtoken.insert(Token(next_token), self.token);
                    self.client.insert(client);
                    if connect_result.is_err() || handle_result.is_err() {
                        return Ok(true);
                    }
                    if connect_result.unwrap() || handle_result.unwrap() {
                        return Ok(true);
                    }
                    Ok(false)
                }
                Socks5State::ClientConnectionResponse => {
                    let client = self.client.get_mut(0).unwrap();
                    self.state = Socks5State::ConnectionResponse;
                    client.handle(event, None)
                }
                _ => Ok(false),
            };
            match result {
                Ok(true) | Err(_) => return Ok(true),
                _ => {}
            }
        }

        debug!(
            "SOCKS5 connection state: {:?}, readable: {}, writeable: {}",
            self.state,
            event.is_readable(),
            event.is_writable()
        );

        if event.is_writable() {
            let result = match self.state {
                Socks5State::MethodResponse => method_response(self),
                Socks5State::ClientConnectionRequest => {
                    let client = self.client.get_mut(0).unwrap();
                    self.state = Socks5State::ClientConnectionResponse;
                    client.handle(event, None)
                }
                Socks5State::ConnectionResponse => connection_response(self),
                _ => Ok(false),
            };
            match result {
                Ok(true) | Err(_) => return Ok(true),
                _ => {}
            }
        }

        if self.state == Socks5State::Relaying {
            if token != self.token {
                return relay_out(self);
            } else {
                return relay_in(self);
            }
        }

        Ok(false)
    }

    pub fn read_stream(&mut self) -> io::Result<bool> {
        loop {
            debug!("SOCKS5 buffer:{}, size: {}", self.buffer.len(), self.size);
            match self.stream.read(&mut self.buffer[self.size..]) {
                Ok(0) => {
                    self.state = Socks5State::Closed;
                    return Ok(true);
                }
                Ok(n) => {
                    self.size += n;
                    self.intotal += n;
                    if self.size == self.buffer.len() {
                        self.buffer.resize(self.buffer.len() + 1024, 0);
                    }
                }
                Err(ref err) if Socks5Handler::would_block(err) => break,
                Err(ref err) if Socks5Handler::interrupted(err) => continue,
                Err(err) => {
                    return Err(err);
                }
            }
        }
        if self.size != self.buffer.len() {
            self.buffer.resize(self.size, 0);
        }
        Ok(false)
    }

    pub fn write_stream(&mut self) -> io::Result<bool> {
        match self.stream.write(&self.buffer) {
            Ok(n) if n < self.size => {
                println!("{} {}", n, self.size);
                println!("{:?}", self.buffer);
                Err(io::ErrorKind::WriteZero.into())
            }
            Ok(_) => Ok(false),
            Err(ref err) if Socks5Handler::would_block(err) => Ok(false),
            Err(ref err) if Socks5Handler::interrupted(err) => {
                self.set_state(Socks5State::Closed);
                Ok(true)
            }
            Err(err) => Err(err),
        }
    }

    #[inline]
    pub fn set_state(&mut self, state: Socks5State) {
        self.state = state;
    }

    #[inline]
    pub fn set_target(&mut self, value: Target) {
        self.target = value;
    }

    #[inline]
    pub fn put_buffer(&mut self, value: u8) {
        self.size += 1;
        self.buffer.put_u8(value);
    }

    #[inline]
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
        self.buffer.resize(4096, 0);
        self.size = 0;
    }

    #[inline]
    pub fn reset_buffer(&mut self) {
        self.buffer.clear();
        self.size = 0;
    }

    #[inline]
    pub fn extract_buffer(&mut self, buf: &mut [u8], start: usize) {
        for (i, data) in buf.iter_mut().enumerate() {
            *data = self.buffer[i + start];
        }
    }

    #[inline]
    pub fn stream_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn would_block(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::WouldBlock
    }

    fn interrupted(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::Interrupted
    }
}
