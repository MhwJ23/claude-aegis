//! Audit log: a JSON-lines trail of sandbox activity for enterprise/compliance.
//!
//! The log is append-only and human-inspectable. Each line is a single JSON
//! object carrying an `event` discriminator plus a `ts` field (Unix seconds).
//! The GUI renders these lines in a live view; the CLI writes them when
//! `--audit-log` is given.
//!
//! The proxy writes its own `net` lines into the *same* file (it runs inside the
//! sandbox and passes an audit path via `--audit-log`), so one file holds the
//! full picture: launches, exits, file grants, and network allow/deny decisions.

use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A single audited event. Serialized with a `event` tag (snake_case).
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// A process was launched inside the sandbox.
    Launch {
        profile: String,
        command: String,
        pid: u32,
    },
    /// A sandboxed process exited with `code`.
    Exit { pid: u32, code: u32 },
    /// A file-system grant was applied to the sandbox identity.
    Grant { path: String, access: String },
    /// The loopback domain proxy started listening.
    ProxyStart { addr: String },
    /// The loopback domain proxy was stopped.
    ProxyStop,
}

/// An append-only JSON-lines log file.
#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    /// The default audit log: `%LOCALAPPDATA%\claude-aegis\audit.log`
    /// (falls back to `%TEMP%` when `LOCALAPPDATA` is unset).
    pub fn open_default() -> Self {
        let dir = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(std::env::temp_dir);
        AuditLog {
            path: dir.join("claude-aegis").join("audit.log"),
        }
    }

    /// Open (or create) an audit log at an explicit path.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        AuditLog { path: path.into() }
    }

    /// The log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event as a JSON line. Creates parent directories and the file
    /// as needed. Errors are returned to the caller, which decides whether to
    /// surface them (audit failure should not normally abort a run).
    pub fn append(&self, event: &AuditEvent) -> io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut obj = serde_json::to_value(event).map_err(io::Error::other)?;
        if let serde_json::Value::Object(map) = &mut obj {
            map.insert("ts".to_string(), serde_json::Value::from(ts));
        }

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{obj}")?;
        file.flush()?;
        Ok(())
    }

    /// Read the last `n` lines (empty when the file does not exist yet).
    pub fn read_tail(&self, n: usize) -> io::Result<Vec<String>> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(n);
        Ok(lines[start..].iter().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> AuditLog {
        let path = std::env::temp_dir().join(format!("claude-aegis-audit-test-{name}.log"));
        let _ = fs::remove_file(&path);
        AuditLog::at(path)
    }

    #[test]
    fn append_writes_jsonl_with_ts_and_event_tag() {
        let log = temp_log("append");
        log.append(&AuditEvent::Launch {
            profile: "p".into(),
            command: "claude.exe".into(),
            pid: 42,
        })
        .unwrap();
        log.append(&AuditEvent::Exit { pid: 42, code: 0 }).unwrap();

        let lines = log.read_tail(10).unwrap();
        assert_eq!(lines.len(), 2);

        let launch: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(launch["event"], "launch");
        assert_eq!(launch["pid"], 42);
        assert!(launch["ts"].is_u64());

        let exit: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(exit["event"], "exit");
        assert_eq!(exit["code"], 0);
    }

    #[test]
    fn read_tail_is_empty_when_file_missing() {
        let log = AuditLog::at(std::env::temp_dir().join("claude-aegis-no-such-file.log"));
        let _ = fs::remove_file(log.path());
        assert!(log.read_tail(5).unwrap().is_empty());
    }

    #[test]
    fn read_tail_truncates_to_last_n_lines() {
        let log = temp_log("tail");
        for i in 0..5 {
            log.append(&AuditEvent::Exit {
                pid: i,
                code: i as u32,
            })
            .unwrap();
        }
        let tail = log.read_tail(2).unwrap();
        assert_eq!(tail.len(), 2);
        let last: serde_json::Value = serde_json::from_str(&tail[1]).unwrap();
        assert_eq!(last["pid"], 4);
    }
}
