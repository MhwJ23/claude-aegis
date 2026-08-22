//! claude-aegis CLI: run a program (e.g. Claude Code) inside an AppContainer sandbox.

use claude_aegis_core::{FileAccess, Sandbox, SandboxConfig};
use rappct::KnownCapability;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse flags: --profile <name> --exe <path> [--grant <dir>]* [-- <exe-args>...]
    let mut profile_name = "claude-aegis".to_string();
    let mut exe: Option<String> = None;
    let mut grants: Vec<String> = Vec::new();
    let mut exe_args: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--profile" => {
                i += 1;
                profile_name = args.get(i).ok_or("--profile needs a value")?.clone();
            }
            "--exe" => {
                i += 1;
                exe = Some(args.get(i).ok_or("--exe needs a value")?.clone());
            }
            "--grant" => {
                i += 1;
                grants.push(args.get(i).ok_or("--grant needs a value")?.clone());
            }
            "--" => {
                exe_args = args[i + 1..].to_vec();
                break;
            }
            other => exe_args.push(other.to_string()),
        }
        i += 1;
    }

    let exe = exe.ok_or("missing required flag --exe")?;

    let config = SandboxConfig {
        profile_name: profile_name.clone(),
        capabilities: vec![KnownCapability::InternetClient],
    };
    let sandbox = Sandbox::create(&config)?;

    for dir in &grants {
        sandbox.grant_path(dir, FileAccess::ReadWrite)?;
    }

    let arg_refs: Vec<&str> = exe_args.iter().map(|s| s.as_str()).collect();
    let child = sandbox.launch(&exe, &arg_refs)?;
    println!("launched pid {}", child.pid);

    Ok(())
}
