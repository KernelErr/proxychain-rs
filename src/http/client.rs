use log::{debug, error};
use std::{io, usize};

use bytes::BytesMut;
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};
use std::io::{Read, Write};

use crate::datatype::Target;
use crate::proxy::Proxy;

use super::client_protocol::{connection_request, connection_response, relay_in, relay_out};

#[derive(Debug, PartialEq)]
pub enum HttpClientState {
    ConnectionRequest,
    ConnectionEstablished,
    RelayingIN,
    RelayingOUT,
    Closed,
}

pub struct HttpClient {
    pub remote: Proxy,
    pub target: Target,
    pub stream: Option<TcpStream>,
    pub buffer: BytesMut,
    pub size: usize,
    pub state: HttpClientState,
}

impl HttpClient {
    pub fn new(remote: Proxy, target: Target) -> Self {
        let mut buffer = BytesMut::with_capacity(4096);
        buffer.resize(4096, 0);
        Self {
            remote,
            target,
            stream: None,
            buffer,
            size: 0,
            state: HttpClientState::ConnectionRequest,
        }
    }

    pub fn handle(&mut self, event: &Event, value: Option<&BytesMut>) -> io::Result<bool> {
        debug!(
            "HTTP Client state: {:?}, readable: {}, writeable: {}",
            self.state,
            event.is_readable(),
            event.is_writable()
        );

        let result = match self.state {
            HttpClientState::ConnectionRequest => connection_request(self),
            HttpClientState::ConnectionEstablished => connection_response(self),
            HttpClientState::RelayingOUT => {
                self.buffer.clone_from(value.unwrap());
                self.size = self.buffer.len();
                relay_out(self)
            }
            HttpClientState::RelayingIN => {
                let result = relay_in(self);
                if result.is_err() {
                    return result;
                }
                if self.size == 0 && result.unwrap() {
                    return Ok(true);
                }
                Ok(false)
            }
            _ => Ok(false),
        };
        match result {
            Ok(true) | Err(_) => return Ok(true),
            _ => {}
        }

        Ok(false)
    }

    pub fn read_buffer(&mut self) -> io::Result<bool> {
        let stream = self.stream.as_mut().unwrap();
        loop {
            debug!(
                "HTTP Client buffer:{}, size: {}",
                self.buffer.len(),
                self.size
            );
            match stream.read(&mut self.buffer[self.size..]) {
                Ok(0) => {
                    self.set_state(HttpClientState::Closed);
                    return Ok(true);
                }
                Ok(n) => {
                    self.size += n;
                    if self.size == self.buffer.len() {
                        self.buffer.resize(self.buffer.len() + 1024, 0);
                    }
                }
                Err(ref err) if HttpClient::would_block(err) => break,
                Err(ref err) if HttpClient::interrupted(err) => continue,
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

    pub fn write_buffer(&mut self) -> io::Result<bool> {
        let stream = self.stream.as_mut().unwrap();
        match stream.write(&self.buffer) {
            Ok(n) if n < self.size => Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                self.size -= n;
                Ok(false)
            }
            Err(ref err) if HttpClient::would_block(err) => Ok(false),
            Err(ref err) if HttpClient::interrupted(err) => {
                self.set_state(HttpClientState::Closed);
                Ok(true)
            }
            Err(err) => Err(err),
        }
    }

    pub fn clone_buffer(&mut self, source: &BytesMut) {
        self.buffer.clone_from(source);
        self.size = source.len();
    }

    pub fn extract_statuscode(&self) -> io::Result<u16> {
        if self.size < 12 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        let status = &self.buffer[9..12];
        let mut result: u16 = 0;
        for i in status.iter().take(3) {
            result = result * 10 + (*i as u16 - 0x30);
        }

        Ok(result)
    }

    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
        self.buffer.resize(4096, 0);
        self.size = 0;
    }

    pub fn reset_buffer(&mut self) {
        self.buffer.clear();
    }

    pub fn connect(&mut self, token: Token, registry: &Registry) -> io::Result<bool> {
        if self.stream.is_none() {
            self.stream = match TcpStream::connect(self.remote.addr) {
                Ok(s) => {
                    debug!("Connect to HTTP proxy {}", self.remote.addr);
                    s.set_nodelay(true)?;
                    Some(s)
                }
                Err(err) => {
                    error!(
                        "Failed to connect to HTTP proxy {}, reason: {}",
                        self.remote.addr, err
                    );
                    return Ok(true);
                }
            };
        }

        let stream = self.stream.as_mut().unwrap();

        registry.register(stream, token, Interest::READABLE.add(Interest::WRITABLE))?;

        Ok(false)
    }

    #[inline]
    pub fn set_state(&mut self, state: HttpClientState) {
        self.state = state;
    }

    pub fn put_buff(&mut self, value: &[u8]) {
        let len = value.len();
        self.buffer.extend(value);
        self.size += len;
    }

    fn would_block(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::WouldBlock
    }

    fn interrupted(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::Interrupted
    }
}
