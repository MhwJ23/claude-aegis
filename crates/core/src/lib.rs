//! claude-aegis-core: AppContainer sandbox engine for Claude Code on Windows.
//!
//! Four control dimensions (see PLAN.md):
//! 1. **File** — grant read/write access to specific paths via DACL (`grant_path`).
//! 2. **Network** — AppContainer capabilities + a loopback domain-allow-list
//!    proxy (started automatically when `proxy_allowlist` is set).
//! 3. **Process** — launch whitelisted executables inside the container
//!    (`allowed_binaries`).
//! 4. **Privilege** — the AppContainer identity *is* the privilege boundary
//!    (an AppContainer token is inherently restricted). Explicit low-integrity
//!    token reduction is a future enhancement (rappct has no such API).
//!
//! The engine wraps [`rappct`], validated end-to-end in the spike
//! (see `spike/FINDINGS.md`).

use claude_aegis_proxy::Proxy;
use rappct::acl::{grant_to_package, AccessMask, ResourcePath};
use rappct::launch::merge_parent_env;
use rappct::{
    derive_sid_from_name, launch_in_container, AppContainerProfile, AppContainerSid,
    KnownCapability, Launched, LaunchOptions, SecurityCapabilities, SecurityCapabilitiesBuilder,
    StdioConfig,
};

/// Errors surfaced by the sandbox engine.
#[derive(Debug)]
pub enum SandboxError {
    /// An error from the underlying rappct / Windows API layer.
    Rappct(rappct::AcError),
    /// An I/O error (e.g. starting the proxy).
    Io(std::io::Error),
    /// A policy rejection (e.g. binary not in the process allow-list).
    NotAllowed(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Rappct(e) => write!(f, "{e}"),
            SandboxError::Io(e) => write!(f, "{e}"),
            SandboxError::NotAllowed(msg) => write!(f, "not allowed: {msg}"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<rappct::AcError> for SandboxError {
    fn from(e: rappct::AcError) -> Self {
        SandboxError::Rappct(e)
    }
}

impl From<std::io::Error> for SandboxError {
    fn from(e: std::io::Error) -> Self {
        SandboxError::Io(e)
    }
}

/// Access level for a file or directory grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
}

impl FileAccess {
    /// Map to the Windows generic access mask (GENERIC_READ / GENERIC_WRITE).
    fn mask(self) -> AccessMask {
        match self {
            FileAccess::Read => AccessMask(0x8000_0000),
            FileAccess::Write => AccessMask(0x4000_0000),
            FileAccess::ReadWrite => AccessMask(0xC000_0000),
        }
    }
}

/// Configuration for creating a sandbox.
#[derive(Clone, Debug, Default)]
pub struct SandboxConfig {
    /// AppContainer profile name (also the package identity).
    pub profile_name: String,
    /// Network capabilities to grant the sandbox.
    pub capabilities: Vec<KnownCapability>,
    /// Process allow-list: executables the sandbox may launch.
    /// Empty means "allow all".
    pub allowed_binaries: Vec<String>,
    /// Domain allow-list for the network proxy. When non-empty, a loopback
    /// CONNECT proxy is started and `HTTPS_PROXY` is set on launched processes.
    /// Empty means "no proxy" (network governed by capabilities only).
    pub proxy_allowlist: Vec<String>,
}

/// A live AppContainer sandbox: a profile, its SID, the assembled
/// `SECURITY_CAPABILITIES`, and (optionally) a running domain proxy.
pub struct Sandbox {
    profile: AppContainerProfile,
    sid: AppContainerSid,
    caps: SecurityCapabilities,
    allowed_binaries: Vec<String>,
    proxy_addr: Option<String>,
    _proxy_thread: Option<std::thread::JoinHandle<()>>,
}

impl Sandbox {
    /// Create (or open) the AppContainer profile, assemble its capabilities,
    /// and — if configured — start the domain allow-list proxy.
    pub fn create(config: &SandboxConfig) -> Result<Self, SandboxError> {
        let profile = AppContainerProfile::ensure(
            config.profile_name.as_str(),
            config.profile_name.as_str(),
            None,
        )?;
        let sid = derive_sid_from_name(config.profile_name.as_str())?;
        let caps = SecurityCapabilitiesBuilder::new(&sid)
            .with_known(&config.capabilities)
            .build()?;

        let (proxy_addr, proxy_thread) = if config.proxy_allowlist.is_empty() {
            (None, None)
        } else {
            let proxy = Proxy::new(config.proxy_allowlist.clone());
            let (listener, addr) = Proxy::bind("127.0.0.1:0")?;
            let thread = std::thread::spawn(move || {
                let _ = proxy.serve_listener(listener);
            });
            (Some(addr), Some(thread))
        };

        Ok(Sandbox {
            profile,
            sid,
            caps,
            allowed_binaries: config.allowed_binaries.clone(),
            proxy_addr,
            _proxy_thread: proxy_thread,
        })
    }

    /// Grant file-system access on a directory to the sandbox identity.
    ///
    /// This is the "file" control dimension. Note (from the spike): an
    /// AppContainer identity must also be able to *traverse* every parent
    /// directory of the target path — callers grant the path chain explicitly.
    pub fn grant_path(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        let resource = ResourcePath::Directory(std::path::PathBuf::from(path));
        grant_to_package(resource, &self.sid, access.mask())?;
        Ok(())
    }

    /// Launch an executable inside the sandbox.
    ///
    /// `exe` is the full path to the binary; `args` are its arguments (joined
    /// into the command line). If a process allow-list is configured, `exe` is
    /// checked against it (case-insensitive) before launch. If a proxy is
    /// running, `HTTPS_PROXY`/`https_proxy` are set on the child (merged with
    /// the parent's essential environment).
    pub fn launch(&self, exe: &str, args: &[&str]) -> Result<Launched, SandboxError> {
        if !self.allowed_binaries.is_empty()
            && !self
                .allowed_binaries
                .iter()
                .any(|b| b.eq_ignore_ascii_case(exe))
        {
            return Err(SandboxError::NotAllowed(format!(
                "binary not in allow-list: {exe}"
            )));
        }

        let env = if let Some(addr) = &self.proxy_addr {
            let proxy_url = format!("http://{addr}");
            Some(merge_parent_env(vec![
                (
                    std::ffi::OsString::from("HTTPS_PROXY"),
                    std::ffi::OsString::from(&proxy_url),
                ),
                (
                    std::ffi::OsString::from("https_proxy"),
                    std::ffi::OsString::from(&proxy_url),
                ),
            ]))
        } else {
            None
        };

        let cmdline = args.join(" ");
        let opts = LaunchOptions {
            exe: exe.into(),
            cmdline: Some(cmdline),
            env,
            stdio: StdioConfig::Inherit,
            ..Default::default()
        };
        Ok(launch_in_container(&self.caps, &opts)?)
    }

    /// Delete the AppContainer profile, cleaning up the sandbox identity.
    pub fn delete(self) -> Result<(), SandboxError> {
        self.profile.delete()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_access_masks_are_standard_generic_values() {
        assert_eq!(FileAccess::Read.mask().0, 0x8000_0000);
        assert_eq!(FileAccess::Write.mask().0, 0x4000_0000);
        assert_eq!(FileAccess::ReadWrite.mask().0, 0xC000_0000);
    }
}
