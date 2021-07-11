mod datatype;
mod http;
mod proxy;
mod socks;
use std::env;

use clap::{App, Arg};
use proxy::Proxy;
use socks::server::Socks5Server;

fn main() {
    let matches = App::new("proxychain")
        .version("v0.1.0")
        .author("LI Rui - https://www.lirui.tech")
        .about("A HTTP and SOSK5 proxy helper written in Rust.")
        .arg(
            Arg::with_name("in")
                .short("i")
                .long("in")
                .value_name("in")
                .help("Sets local proxy to listen on")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("out")
                .short("o")
                .long("out")
                .value_name("out")
                .help("Sets remote proxy to connect to")
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .help("Sets if enable verbose information"),
        )
        .get_matches();

    match matches.occurrences_of("v") {
        0 => {
            env::set_var("RUST_PROXYCHAIN_LOG", "info");
        }
        _ => {
            env::set_var("RUST_PROXYCHAIN_LOG", "debug");
        }
    }

    pretty_env_logger::init_custom_env("RUST_PROXYCHAIN_LOG");

    let in_proxy = Proxy::parse(matches.value_of("in").expect("IN proxy needed"));
    let out_proxy = Proxy::parse(matches.value_of("out").expect("OUT proxy needed"));

    let mut server = Socks5Server::new(in_proxy);
    server.subproxy(out_proxy);
    server.serve().unwrap();
}
