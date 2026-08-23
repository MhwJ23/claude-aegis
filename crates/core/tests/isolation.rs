//! Integration tests for real AppContainer isolation on Windows.
//!
//! These launch an actual process (`cmd.exe /c type <file>`) inside an
//! AppContainer and assert that ungranted files are unreadable while granted
//! files are readable. This is the core value proposition of the sandbox and
//! is exercised here rather than only in the manual spike.
//!
//! The secret lives under the current directory (the D:\ repo), which grants
//! `Everyone` but — critically — does *not* grant "ALL APPLICATION PACKAGES",
//! so an AppContainer's restricted token can't reach it without an explicit
//! grant. (`%TEMP%` would be a bad choice: Windows grants "ALL APPLICATION
//! PACKAGES" read+execute there by default, so any AppContainer can read it.)
//!
//! The child runs with `cwd = System32` (always reachable) so `cmd.exe` starts
//! regardless of the host's own working directory.

#![cfg(windows)]

use claude_aegis_core::{FileAccess, Sandbox, SandboxConfig};
use std::path::Path;

fn cmd_exe() -> &'static str {
    // System32 is readable/executable by "ALL APPLICATION PACKAGES", so the
    // sandboxed child can launch cmd.exe without any explicit grant.
    "C:\\Windows\\System32\\cmd.exe"
}

fn system32() -> &'static Path {
    Path::new("C:\\Windows\\System32")
}

/// A profile name unique to this test, to avoid clashing with other
/// concurrently-running tests (each test gets a distinct tag).
fn unique_profile(tag: &str) -> String {
    format!("claude-aegis-test-{}-{}", std::process::id(), tag)
}

/// Create a secret file in a distinct directory under the current dir.
fn write_secret(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::current_dir()
        .unwrap()
        .join(format!("isolation-secret-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("secret.txt");
    std::fs::write(&path, b"top-secret\n").unwrap();
    (path, dir)
}

#[test]
fn ungranted_file_is_unreadable_inside_sandbox() {
    let (secret, dir) = write_secret("deny");
    let secret_s = secret.to_string_lossy().into_owned();

    let sandbox = Sandbox::create(&SandboxConfig {
        profile_name: unique_profile("deny"),
        allowed_binaries: Vec::new(),
        audit_log: None,
    })
    .unwrap();

    let args = ["/c", "type", secret_s.as_str()];
    let child = sandbox
        .launch(cmd_exe(), &args, None, false, Some(system32()))
        .unwrap();
    let code = child.wait().unwrap();

    let _ = std::fs::remove_dir_all(&dir);
    assert_ne!(code, 0, "ungranted file was readable inside the sandbox");
}

#[test]
fn granted_file_is_readable_inside_sandbox() {
    let (secret, dir) = write_secret("grant");
    let secret_s = secret.to_string_lossy().into_owned();

    let sandbox = Sandbox::create(&SandboxConfig {
        profile_name: unique_profile("grant"),
        allowed_binaries: Vec::new(),
        audit_log: None,
    })
    .unwrap();

    sandbox
        .grant_file_chain(&secret_s, FileAccess::ReadExecute)
        .unwrap();

    let args = ["/c", "type", secret_s.as_str()];
    let child = sandbox
        .launch(cmd_exe(), &args, None, false, Some(system32()))
        .unwrap();
    let code = child.wait().unwrap();

    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(code, 0, "granted file was not readable inside the sandbox");
}

#[test]
fn orphan_subprocess_is_killed_when_child_is_dropped() {
    let sandbox = Sandbox::create(&SandboxConfig {
        profile_name: unique_profile("job"),
        allowed_binaries: Vec::new(),
        audit_log: None,
    })
    .unwrap();

    // `cmd /c start /b timeout /t 120` spawns a detached `timeout` subprocess
    // (which would otherwise sleep for 120s) and exits immediately.
    let child = sandbox
        .launch(
            cmd_exe(),
            &["/c", "start", "/b", "timeout", "/t", "120"],
            None,
            false,
            Some(system32()),
        )
        .unwrap();
    assert_eq!(child.wait().unwrap(), 0);

    // Dropping the child closes the job handle; KILL_ON_JOB_CLOSE then
    // terminates the lingering `timeout` subprocess.
    drop(child);
    std::thread::sleep(std::time::Duration::from_secs(2));

    let out = std::process::Command::new("tasklist.exe")
        .args(["/FI", "IMAGENAME eq timeout.exe", "/FO", "CSV"])
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        !listing.contains("timeout.exe"),
        "orphan subprocess survived the job close: {listing}"
    );
}
