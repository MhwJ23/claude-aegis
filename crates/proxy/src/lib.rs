//! claude-aegis-proxy: loopback CONNECT proxy with domain allow-listing.
//!
//! The proxy listens on a loopback address, accepts `CONNECT host:port` requests,
//! and only tunnels connections whose target host is in the allow-list. It does
//! NOT terminate TLS — encrypted traffic passes through untouched (no MITM).
//!
//! Audit: when enabled (`--audit`), the proxy writes one JSON line per event to
//! **stdout** (`proxy_start`, `net` allow/deny). The host process redirects that
//! stdout into the shared audit log, so the sandboxed proxy never needs write
//! access to the audit file itself (which the sandboxed program could otherwise
//! tamper with — see PLAN.md / spike/FINDINGS.md).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

/// A loopback CONNECT proxy that only tunnels allow-listed domains.
#[derive(Debug, Clone)]
pub struct Proxy {
    allowlist: Vec<String>,
    /// Whether to emit audit events (JSON-lines) to stdout.
    audit: bool,
}

impl Proxy {
    /// Create a proxy that only allows connections to the given domains.
    ///
    /// A domain entry also matches its subdomains (e.g. `anthropic.com`
    /// allows `api.anthropic.com`).
    pub fn new(allowlist: Vec<String>) -> Self {
        Proxy::with_audit(allowlist, false)
    }

    /// Create a proxy that additionally writes audit events to stdout.
    pub fn with_audit(allowlist: Vec<String>, audit: bool) -> Self {
        Proxy { allowlist, audit }
    }

    /// Bind to `addr` and return the listener plus the actual bound address.
    ///
    /// Useful when `addr` uses port 0 for dynamic allocation — the caller gets
    /// the real address back.
    pub fn bind(addr: &str) -> io::Result<(TcpListener, String)> {
        let listener = TcpListener::bind(addr)?;
        let actual = listener.local_addr()?.to_string();
        Ok((listener, actual))
    }

    /// Serve connections from an already-bound listener (blocking).
    pub fn serve_listener(&self, listener: TcpListener) -> io::Result<()> {
        if self.audit
            && let Ok(addr) = listener.local_addr()
        {
            audit_print(
                "proxy_start",
                &[("addr", serde_json::Value::from(addr.to_string()))],
            );
        }
        for conn in listener.incoming() {
            match conn {
                Ok(client) => {
                    let allowlist = self.allowlist.clone();
                    let audit = self.audit;
                    std::thread::spawn(move || {
                        let _ = handle(client, &allowlist, audit);
                    });
                }
                Err(_) => continue,
            }
        }
        Ok(())
    }

    /// Bind to `addr` (e.g. `127.0.0.1:8080`) and serve connections forever.
    pub fn serve(&self, addr: &str) -> io::Result<()> {
        let (listener, _) = Proxy::bind(addr)?;
        self.serve_listener(listener)
    }
}

/// Handle a single client connection: parse CONNECT, enforce allow-list, tunnel.
fn handle(mut client: TcpStream, allowlist: &[String], audit: bool) -> io::Result<()> {
    let target = read_connect_target(&mut client)?;
    let host = host_of(&target);

    if !allowed(host, allowlist) {
        if audit {
            audit_print(
                "net",
                &[
                    ("host", serde_json::Value::from(host)),
                    ("allowed", serde_json::Value::from(false)),
                ],
            );
        }
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        return Ok(());
    }

    let server = match TcpStream::connect(&target) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Ok(());
        }
    };

    if audit {
        audit_print(
            "net",
            &[
                ("host", serde_json::Value::from(host)),
                ("allowed", serde_json::Value::from(true)),
            ],
        );
    }
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    tunnel(client, server)
}

/// Build one JSON-lines audit entry (with a `ts` field) as a string.
fn audit_line(event: &str, fields: &[(&str, serde_json::Value)]) -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut obj = serde_json::Map::new();
    obj.insert("event".to_string(), serde_json::Value::from(event));
    obj.insert("ts".to_string(), serde_json::Value::from(ts));
    for (k, v) in fields {
        obj.insert((*k).to_string(), v.clone());
    }
    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
}

/// Emit one audit line to stdout (best-effort; a write failure must not break
/// proxying).
fn audit_print(event: &str, fields: &[(&str, serde_json::Value)]) {
    let line = audit_line(event, fields);
    println!("{line}");
    let _ = io::stdout().flush();
}

/// Read the request headers and return the CONNECT target (`host:port`).
fn read_connect_target(client: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = client.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }

    let req = String::from_utf8_lossy(&buf);
    let line = req.lines().next().unwrap_or("");
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("CONNECT") {
        Ok(parts[1].to_string())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a CONNECT request",
        ))
    }
}

/// Extract the host from a `host:port` target string.
fn host_of(target: &str) -> &str {
    target.rsplit_once(':').map(|(h, _)| h).unwrap_or(target)
}

/// Whether `host` is allowed: exact match or a subdomain of an allow-list entry.
fn allowed(host: &str, allowlist: &[String]) -> bool {
    allowlist
        .iter()
        .any(|d| host == d || host.ends_with(&format!(".{d}")))
}

/// Bidirectionally copy bytes between client and server until one side closes.
fn tunnel(client: TcpStream, server: TcpStream) -> io::Result<()> {
    let mut client_reader = client.try_clone()?;
    let mut client_writer = client;
    let mut server_reader = server.try_clone()?;
    let mut server_writer = server;

    let a = std::thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut server_writer);
    });
    let b = std::thread::spawn(move || {
        let _ = io::copy(&mut server_reader, &mut client_writer);
    });
    let _ = a.join();
    let _ = b.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction_splits_port() {
        assert_eq!(host_of("api.anthropic.com:443"), "api.anthropic.com");
        assert_eq!(host_of("api.anthropic.com"), "api.anthropic.com");
    }

    #[test]
    fn allowlist_matches_exact_and_subdomain() {
        let list = vec!["anthropic.com".to_string(), "github.com".to_string()];
        assert!(allowed("anthropic.com", &list));
        assert!(allowed("api.anthropic.com", &list));
        assert!(allowed("github.com", &list));
        assert!(!allowed("evil.com", &list));
        assert!(!allowed("notanthropic.com", &list));
    }

    #[test]
    fn audit_line_escapes_untrusted_host() {
        // A host is attacker-controlled (from the CONNECT line); it must survive
        // a JSON round-trip without breaking the line structure.
        let host = "evil\"host\n.com\\";
        let line = audit_line(
            "net",
            &[
                ("host", serde_json::Value::from(host)),
                ("allowed", serde_json::Value::from(false)),
            ],
        );
        assert_eq!(line.lines().count(), 1);
        let obj: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(obj["event"], "net");
        assert_eq!(obj["host"], host);
        assert_eq!(obj["allowed"], false);
        assert!(obj["ts"].is_u64());
    }
}
