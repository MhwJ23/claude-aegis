//! claude-aegis-core: AppContainer sandbox engine for Claude Code on Windows.
//!
//! Four control dimensions (see PLAN.md):
//! 1. **File** — grant read/write access to specific paths via DACL (`grant_path`).
//! 2. **Network** — AppContainer capabilities (`InternetClient`, etc.). Domain
//!    allow-listing is a separate crate (`claude-aegis-proxy`).
//! 3. **Process** — launch whitelisted executables inside the container
//!    (`allowed_binaries`).
//! 4. **Privilege** — the AppContainer identity *is* the privilege boundary
//!    (an AppContainer token is inherently restricted). Explicit low-integrity
//!    token reduction is a future enhancement (rappct has no such API).
//!
//! The engine wraps [`rappct`], validated end-to-end in the spike
//! (see `spike/FINDINGS.md`).

use rappct::acl::{grant_to_package, AccessMask, ResourcePath};
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
    /// A policy rejection (e.g. binary not in the process allow-list).
    NotAllowed(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Rappct(e) => write!(f, "{e}"),
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
}

/// A live AppContainer sandbox: a profile, its SID, and the assembled
/// `SECURITY_CAPABILITIES` used to launch contained processes.
pub struct Sandbox {
    profile: AppContainerProfile,
    sid: AppContainerSid,
    caps: SecurityCapabilities,
    allowed_binaries: Vec<String>,
}

impl Sandbox {
    /// Create (or open) the AppContainer profile and assemble its capabilities.
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
        Ok(Sandbox {
            profile,
            sid,
            caps,
            allowed_binaries: config.allowed_binaries.clone(),
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
    /// checked against it (case-insensitive) before launch.
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

        let cmdline = args.join(" ");
        let opts = LaunchOptions {
            exe: exe.into(),
            cmdline: Some(cmdline),
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
