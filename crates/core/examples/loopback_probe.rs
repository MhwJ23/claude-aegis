//! Loopback probe: determines whether two SEPARATE processes sharing the same
//! AppContainer SID can reach each other over 127.0.0.1. Used to de-risk the
//! domain-proxy architecture (see PLAN.md / spike/FINDINGS.md).
//!
//! Results are written to `loopback_probe.txt` in the current directory, so the
//! outcome survives the CLI's detached-launch + output-capture quirks.
//!
//!   loopback_probe server <port>   bind loopback, write BOUND, accept one conn, write ACCEPTED
//!   loopback_probe client <port>   connect loopback, write CONNECTED or FAILED

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

fn mark(msg: &str) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("loopback_probe.txt")
        .unwrap();
    writeln!(f, "{msg}").unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("client");
    let port: u16 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(18100);
    let addr = format!("127.0.0.1:{port}");

    match mode {
        "server" => {
            let listener = TcpListener::bind(addr.as_str()).unwrap();
            mark(&format!("BOUND {addr}"));
            if let Ok((mut s, _)) = listener.accept() {
                mark(&format!("ACCEPTED {addr}"));
                let _ = s.write_all(b"ok");
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        _ => {
            // client
            let sa: SocketAddr = addr.parse().unwrap();
            match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                Ok(_) => mark(&format!("CONNECTED {addr}")),
                Err(e) => mark(&format!("FAILED {addr}: {e}")),
            }
        }
    }
}
