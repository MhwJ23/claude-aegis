//! claude-aegis GUI backend: Tauri commands that wrap the core sandbox engine.
//!
//! The GUI is a config + launch + audit console (the sandboxed program runs in
//! its own console window — see PLAN.md). Commands are thin adapters over
//! [`claude_aegis_core`]; the sandboxing logic lives in the core crate.

use claude_aegis_core::{AuditEvent, AuditLog, Config, FileAccess, Sandbox, SandboxConfig};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Outcome of a sandboxed run, returned when the child exits.
#[derive(Serialize)]
struct RunResult {
    pid: u32,
    code: u32,
}

/// Entry point called from `main.rs`.
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            run_sandbox,
            tail_audit,
            clear_audit,
            audit_path,
            pick_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running claude-aegis GUI");
}

/// The default audit log path (shown in the UI).
#[tauri::command]
fn audit_path() -> String {
    AuditLog::open_default()
        .path()
        .to_string_lossy()
        .into_owned()
}

/// Load a `claude-aegis.toml` (default: `./claude-aegis.toml`).
#[tauri::command]
fn load_config(path: Option<String>) -> Result<Config, String> {
    let p = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(Config::FILE_NAME));
    Config::load(&p).map_err(|e| e.to_string())
}

/// Save a config as TOML.
#[tauri::command]
fn save_config(path: String, config: Config) -> Result<(), String> {
    let text = config.to_toml_string().map_err(|e| e.to_string())?;
    std::fs::write(&path, text).map_err(|e| e.to_string())
}

/// Run the configured program inside the sandbox, blocking until it exits.
#[tauri::command]
fn run_sandbox(config: Config, dir: Option<String>) -> Result<RunResult, String> {
    run_sandbox_impl(&config, dir.as_deref()).map_err(|e| e.to_string())
}

/// Read the last `n` lines of the audit log as raw JSON strings (frontend renders).
#[tauri::command]
fn tail_audit(path: Option<String>, n: usize) -> Result<Vec<String>, String> {
    let log = path
        .map(AuditLog::at)
        .unwrap_or_else(AuditLog::open_default);
    log.read_tail(n).map_err(|e| e.to_string())
}

/// Truncate the audit log.
#[tauri::command]
fn clear_audit(path: Option<String>) -> Result<(), String> {
    let log = path
        .map(AuditLog::at)
        .unwrap_or_else(AuditLog::open_default);
    std::fs::write(log.path(), "").map_err(|e| e.to_string())
}

/// Open a native folder picker; returns the chosen path, if any.
#[tauri::command]
fn pick_folder() -> Option<String> {
    rfd::FileDialog::new()
        .set_title("Choose a directory")
        .pick_folder()
        .map(|p| p.to_string_lossy().into_owned())
}

/// Shared sandbox run logic (mirrors the CLI's `cmd_run`, but launches the
/// child in a new console window and always writes the audit log).
fn run_sandbox_impl(
    config: &Config,
    dir: Option<&str>,
) -> Result<RunResult, Box<dyn std::error::Error>> {
    let exe = resolve_command(&config.command)?;
    let audit_log = AuditLog::open_default();
    let audit_path = audit_log.path().to_path_buf();

    let sandbox = Sandbox::create(&SandboxConfig {
        profile_name: config.profile.clone(),
        allowed_binaries: config.process.allow.clone(),
        audit_log: Some(audit_path.clone()),
    })?;

    for d in &config.files.read {
        sandbox.grant_dir_chain(d, FileAccess::ReadExecute)?;
    }
    for d in &config.files.write {
        sandbox.grant_dir_chain(d, FileAccess::ReadWrite)?;
    }
    if let Some(d) = dir {
        sandbox.grant_dir_chain(d, FileAccess::ReadWrite)?;
    }
    // The program binary itself (and its ancestor chain) must be reachable.
    let _ = sandbox.grant_file_chain(&exe.to_string_lossy(), FileAccess::ReadExecute);

    // Start the domain proxy *inside* the same container (same SID), writing its
    // own `net` decisions into the same audit log.
    let (proxy_addr, proxy_child) = if config.network.domains.is_empty() {
        (None, None)
    } else {
        let proxy_exe = locate_proxy()?;
        let port = pick_free_port().ok_or("could not reserve a loopback port")?;
        let addr = format!("127.0.0.1:{port}");
        let _ = sandbox.grant_file_chain(&proxy_exe.to_string_lossy(), FileAccess::ReadExecute);
        let proxy_args = [
            "--listen".to_string(),
            addr.clone(),
            "--allow".to_string(),
            config.network.domains.join(","),
            "--audit".to_string(),
        ];
        let proxy_arg_refs: Vec<&str> = proxy_args.iter().map(String::as_str).collect();
        // Redirect the proxy's stdout (its audit lines) into the audit log.
        let child = sandbox.launch_with_stdout(
            &proxy_exe.to_string_lossy(),
            &proxy_arg_refs,
            &audit_path,
        )?;
        // Give the proxy a moment to bind before the program starts.
        std::thread::sleep(std::time::Duration::from_millis(500));
        (Some(addr), Some(child))
    };

    // Launch the program in its own console window (the GUI process has none).
    let args: Vec<&str> = Vec::new();
    let child = sandbox.launch(
        &exe.to_string_lossy(),
        &args,
        proxy_addr.as_deref(),
        true,
        dir.map(std::path::Path::new),
    )?;
    let pid = child.pid();
    let code = child.wait()?;
    sandbox.record(AuditEvent::Exit { pid, code });

    if let Some(proxy) = proxy_child {
        let _ = proxy.kill();
        sandbox.record(AuditEvent::ProxyStop);
    }

    Ok(RunResult { pid, code })
}

/// Resolve a command (bare name or path) to a full executable path.
fn resolve_command(cmd: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let p = Path::new(cmd);
    if p.is_absolute() || cmd.contains('/') || cmd.contains('\\') {
        return Ok(p.to_path_buf());
    }
    let exe_name = if cmd.to_lowercase().ends_with(".exe") {
        cmd.to_string()
    } else {
        format!("{cmd}.exe")
    };
    let path_var = std::env::var_os("PATH").ok_or("PATH is not set")?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(&exe_name);
        if cand.is_file() {
            return Ok(cand);
        }
    }
    Err(format!("command not found on PATH: {cmd}").into())
}

/// Locate the `claude-aegis-proxy` binary next to this executable.
fn locate_proxy() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or("executable has no parent directory")?;
    let cand = dir.join("claude-aegis-proxy.exe");
    if cand.is_file() {
        return Ok(cand);
    }
    Err(format!(
        "proxy binary not found next to {} (build/install claude-aegis-proxy)",
        exe.display()
    )
    .into())
}

/// Reserve a free loopback port (best-effort; tiny race window).
fn pick_free_port() -> Option<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    listener.local_addr().ok().map(|a| a.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_through_toml() {
        let cfg = Config {
            profile: "p".into(),
            command: "claude".into(),
            files: claude_aegis_core::config::Files {
                read: vec!["C:\\projects".into()],
                write: vec!["C:\\scratch".into()],
            },
            network: claude_aegis_core::config::Network {
                domains: vec!["api.anthropic.com".into()],
            },
            process: claude_aegis_core::config::Process {
                allow: vec!["git.exe".into()],
            },
        };

        let toml = cfg.to_toml_string().unwrap();
        let path = std::env::temp_dir().join("claude-aegis-gui-roundtrip.toml");
        std::fs::write(&path, &toml).unwrap();
        let loaded = Config::load(&path).unwrap();

        assert_eq!(loaded.profile, "p");
        assert_eq!(loaded.command, "claude");
        assert_eq!(loaded.files.read, vec!["C:\\projects"]);
        assert_eq!(loaded.files.write, vec!["C:\\scratch"]);
        assert_eq!(loaded.network.domains, vec!["api.anthropic.com"]);
        assert_eq!(loaded.process.allow, vec!["git.exe"]);
    }
}
