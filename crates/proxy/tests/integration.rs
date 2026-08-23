//! Integration tests for the proxy's CONNECT handling: a real client, a real
//! proxy listener, and a real upstream socket — exercising the allow/deny path
//! end-to-end (no AppContainer needed for the proxy's own logic).

use claude_aegis_proxy::Proxy;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

/// Start a tiny upstream TCP server (echoes a fixed reply) and return its addr.
fn spawn_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    thread::spawn(move || {
        for conn in listener.incoming() {
            if let Ok(mut c) = conn {
                let mut buf = [0u8; 64];
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"PONG");
            }
        }
    });
    addr
}

/// Start a proxy on an ephemeral loopback port and return its addr.
fn spawn_proxy(allowlist: Vec<String>) -> String {
    let (listener, addr) = Proxy::bind("127.0.0.1:0").unwrap();
    let proxy = Proxy::new(allowlist);
    thread::spawn(move || {
        let _ = proxy.serve_listener(listener);
    });
    addr
}

/// Send a CONNECT request through the proxy and return the raw response head.
fn connect(proxy_addr: &str, target: &str) -> String {
    let mut client = TcpStream::connect(proxy_addr).unwrap();
    write!(
        client,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    )
    .unwrap();
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

#[test]
fn allows_allowlisted_host_and_tunnels() {
    let upstream = spawn_upstream();
    let proxy = spawn_proxy(vec!["127.0.0.1".to_string()]);
    thread::sleep(Duration::from_millis(100));
    let resp = connect(&proxy, &upstream);
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "expected 200, got: {resp}"
    );
}

#[test]
fn denies_non_allowlisted_host() {
    let upstream = spawn_upstream();
    let proxy = spawn_proxy(vec!["google.com".to_string()]);
    thread::sleep(Duration::from_millis(100));
    // The CONNECT target is 127.0.0.1:PORT, which is not in the allow-list.
    let resp = connect(&proxy, &upstream);
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "expected 403, got: {resp}"
    );
}
