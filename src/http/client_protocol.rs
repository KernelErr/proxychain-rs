use super::client::HttpClient;
use super::client::HttpClientState;
use log::{debug, error};
use std::io;

pub fn connection_request(client: &mut HttpClient) -> io::Result<bool> {
    debug!("HTTP Client Connection Request");

    client.reset_buffer();

    let msg = format!("CONNECT\x20{host}:{port}\x20HTTP/1.1\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nHost: {host}:{port}\r\n\r\n", host = client.target.domain,
 port = client.target.port);
    client.put_buff(msg.as_bytes());
    let result = client.write_buffer();

    client.set_state(HttpClientState::ConnectionEstablished);
    result
}

pub fn connection_response(client: &mut HttpClient) -> io::Result<bool> {
    debug!("HTTP Client Connection Response");

    client.clear_buffer();
    match client.read_buffer() {
        Ok(false) => {}
        Ok(true) => {
            debug!("HTTP Client connection response interrupted");
            return Ok(true);
        }
        Err(err) => {
            error!(
                "During HTTP Client connection response, error occured: {}",
                err
            );
            return Err(err);
        }
    }

    if client.size == 0 {
        return Ok(true);
    }

    let status_code = match client.extract_statuscode() {
        Ok(u) => u,
        Err(err) => {
            error!("HTTP Client got unexpected response");
            return Err(err);
        }
    };

    if status_code != 200 {
        error!("HTTP Client received non-200 response");
        return Ok(true);
    }

    debug!("HTTP Client tunnel established");
    client.set_state(HttpClientState::RelayingOUT);
    Ok(false)
}

// Receive from HTTP Proxy
pub fn relay_in(client: &mut HttpClient) -> io::Result<bool> {
    debug!("HTTP Client Relay IN");

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

    client.set_state(HttpClientState::RelayingOUT);
    Ok(false)
}

// Send to HTTP Proxy
pub fn relay_out(client: &mut HttpClient) -> io::Result<bool> {
    debug!("HTTP Client Relay OUT");

    if client.size == 0 {
        return Ok(true);
    }

    client.set_state(HttpClientState::RelayingIN);
    client.write_buffer()
}
