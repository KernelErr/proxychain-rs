use fnv::FnvHashMap;
use log::{debug, error, info, warn};
use mio::{net::TcpListener, Events, Interest, Poll, Token};
use slab::Slab;
use std::{io, net::SocketAddr};

use crate::{proxy::Proxy, socks::handler::Socks5Handler};

const SERVER: Token = Token(0);

pub struct Socks5Server {
    ip: String,
    port: u16,
    addr: SocketAddr,
    subproxy: Vec<Proxy>,
}

impl Socks5Server {
    pub fn new(proxy: Proxy) -> Self {
        let ip = proxy.host;
        let port = proxy.port;
        Self {
            ip: ip.clone(),
            port,
            addr: format!("{}:{}", ip, port).parse().unwrap(),
            subproxy: Vec::new(),
        }
    }

    pub fn serve(self) -> io::Result<()> {
        let mut poll = Poll::new()?;
        let mut slab = Slab::new();
        let mut events = Events::with_capacity(1024);
        let mut server = TcpListener::bind(self.addr).unwrap();
        let mut handler_map: FnvHashMap<Token, usize> = FnvHashMap::default();
        let mut subtoken: FnvHashMap<Token, Token> = FnvHashMap::default();

        info!("Start SOCKS5 server listening on {}:{}", self.ip, self.port);

        poll.registry()
            .register(&mut server, SERVER, Interest::READABLE)?;

        let mut unique_token = Token(SERVER.0 + 1);

        loop {
            poll.poll(&mut events, None)?;

            for event in events.iter() {
                match event.token() {
                    SERVER => loop {
                        let (mut connection, _) = match server.accept() {
                            Ok((connection, address)) => (connection, address),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => {
                                error!("Unexpected error: {}", e);
                                return Err(e);
                            }
                        };

                        let entry = slab.vacant_entry();
                        let entry_key = entry.key();
                        let token = Socks5Server::next(&mut unique_token);
                        connection.set_nodelay(true)?;
                        poll.registry().register(
                            &mut connection,
                            token,
                            Interest::READABLE.add(Interest::WRITABLE),
                        )?;
                        entry.insert(Socks5Handler::new(token, connection, self.subproxy.clone()));
                        handler_map.insert(token, entry_key);
                    },
                    token => {
                        debug!("Incoming token: {:?}", token);
                        let handler_key: usize = match handler_map.get(&token) {
                            Some(k) => *k,
                            None => {
                                if let Some(token) = subtoken.get(&token) {
                                    match handler_map.get(token) {
                                        Some(k) => *k,
                                        None => {
                                            warn!("No available handler for token {}", token.0);
                                            continue;
                                        }
                                    }
                                } else {
                                    warn!("No available handler for token {}", token.0);
                                    continue;
                                }
                            }
                        };

                        let handler = match slab.get_mut(handler_key) {
                            Some(h) => h,
                            None => {
                                subtoken.remove(&token);
                                continue;
                            }
                        };
                        let done = handler.handle(
                            event,
                            token,
                            &mut unique_token,
                            poll.registry(),
                            &mut subtoken,
                        )?;

                        if done {
                            slab.remove(handler_key);
                            handler_map.remove(&token);
                            subtoken.remove(&token);
                        }
                    }
                }
            }
        }
    }

    #[inline]
    pub fn subproxy(&mut self, proxy: Proxy) {
        self.subproxy.push(proxy);
    }

    fn next(current: &mut Token) -> Token {
        let next = current.0;
        current.0 += 1;
        Token(next)
    }
}
