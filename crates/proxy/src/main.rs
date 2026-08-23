//! claude-aegis-proxy binary: run a loopback CONNECT proxy with a domain allow-list.

use claude_aegis_proxy::Proxy;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse: [--listen 127.0.0.1:8080] [--allow a.com,b.com] [--audit]...
    let mut listen = "127.0.0.1:8080".to_string();
    let mut allowlist: Vec<String> = Vec::new();
    let mut audit = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                listen = args.get(i).ok_or("--listen needs a value")?.clone();
            }
            "--allow" => {
                i += 1;
                let val = args.get(i).ok_or("--allow needs a value")?;
                allowlist.extend(
                    val.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
            "--audit" => audit = true,
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
        i += 1;
    }

    if allowlist.is_empty() {
        return Err("no domains allowed (use --allow domain1,domain2)".into());
    }

    eprintln!("claude-aegis-proxy listening on {listen}");
    eprintln!("allow-list: {}", allowlist.join(", "));

    let proxy = Proxy::with_audit(allowlist, audit);
    proxy.serve(&listen)?;
    Ok(())
}
