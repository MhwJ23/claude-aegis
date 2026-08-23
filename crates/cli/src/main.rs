//! claude-aegis: run a program (e.g. Claude Code) inside an AppContainer sandbox.

use clap::{Parser, Subcommand};
use claude_aegis_core::{Config, FileAccess, Sandbox, SandboxConfig};
use rappct::KnownCapability;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "claude-aegis",
    version,
    about = "Run Claude Code (or any program) inside an AppContainer sandbox on Windows"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scaffold a claude-aegis.toml in the current directory.
    Init {
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
        /// Directory to write the config into (default: current directory).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Run the configured program inside the sandbox.
    Run {
        /// Path to the config file (default: ./claude-aegis.toml).
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Project directory to grant read+write (on top of the config).
        #[arg(short, long)]
        dir: Option<PathBuf>,
        /// Arguments forwarded to the sandboxed program (after `--`).
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Init { force, dir } => cmd_init(force, dir),
        Commands::Run { config, dir, args } => cmd_run(config, dir, args),
    }
}

fn cmd_init(force: bool, dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let target = dir
        .unwrap_or_else(|| PathBuf::from("."))
        .join(Config::FILE_NAME);
    if target.exists() && !force {
        return Err(format!(
            "{} already exists (use --force to overwrite)",
            target.display()
        )
        .into());
    }
    std::fs::write(&target, Config::template())?;
    println!("wrote {}", target.display());
    Ok(())
}

fn cmd_run(
    config: Option<PathBuf>,
    dir: Option<PathBuf>,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = config.unwrap_or_else(|| PathBuf::from(Config::FILE_NAME));
    let cfg = Config::load(&config_path)?;

    // Resolve the command to a full path so CreateProcessW can launch it directly.
    let exe = resolve_command(&cfg.command)?;

    let sandbox = Sandbox::create(&SandboxConfig {
        profile_name: cfg.profile.clone(),
        capabilities: vec![KnownCapability::InternetClient],
        allowed_binaries: cfg.process.allow.clone(),
    })?;

    // File grants: config read/write dirs + the `--dir` shorthand.
    for d in &cfg.files.read {
        sandbox.grant_dir_chain(d, FileAccess::ReadExecute)?;
    }
    for d in &cfg.files.write {
        sandbox.grant_dir_chain(d, FileAccess::ReadWrite)?;
    }
    if let Some(d) = &dir {
        sandbox.grant_dir_chain(&d.to_string_lossy(), FileAccess::ReadWrite)?;
    }
    // The program binary itself (and its ancestor chain) must be reachable.
    // Best-effort: system binaries (System32, Program Files) are already readable
    // by AppContainers, so a DACL edit there fails — the launch below fails loudly
    // if the binary is genuinely unreachable.
    let _ = sandbox.grant_file_chain(&exe.to_string_lossy(), FileAccess::ReadExecute);

    // Start the domain proxy *inside* the same container (same SID), so the
    // child can reach it over loopback without any admin exemption.
    let (proxy_addr, proxy_child) = if cfg.network.domains.is_empty() {
        (None, None)
    } else {
        let proxy_exe = locate_proxy()?;
        let port = pick_free_port().ok_or("could not reserve a loopback port")?;
        let addr = format!("127.0.0.1:{port}");
        let _ = sandbox.grant_file_chain(&proxy_exe.to_string_lossy(), FileAccess::ReadExecute);
        let allow = cfg.network.domains.join(",");
        let child = sandbox.launch(
            &proxy_exe.to_string_lossy(),
            &["--listen", &addr, "--allow", &allow],
            None,
        )?;
        // Give the proxy a moment to bind before the program starts.
        std::thread::sleep(std::time::Duration::from_millis(500));
        (Some(addr), Some(child))
    };

    // Launch the program inside the sandbox.
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let child = sandbox.launch(&exe.to_string_lossy(), &arg_refs, proxy_addr.as_deref())?;
    let code = child.wait()?;

    // The proxy would otherwise run forever; stop it now that the program is done.
    if let Some(proxy) = proxy_child {
        let _ = proxy.kill();
    }

    if code != 0 {
        std::process::exit(code as i32);
    }
    Ok(())
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
