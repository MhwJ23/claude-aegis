//! claude-aegis-core: AppContainer sandbox engine for Claude Code on Windows.
//!
//! Four control dimensions (see PLAN.md):
//! 1. **File** — grant read/write access to specific paths via DACL.
//! 2. **Network** — AppContainer capabilities (`InternetClient`, etc.).
//! 3. **Process** — launch whitelisted executables inside the container.
//! 4. **Privilege** — (future) token-based integrity reduction.
//!
//! The engine wraps [`rappct`], which was validated end-to-end in the spike
//! (see `spike/FINDINGS.md`): create profile → grant paths → build capabilities
//! → launch inside container.

use rappct::acl::{grant_to_package, AccessMask, ResourcePath};
use rappct::{
    derive_sid_from_name, launch_in_container, AppContainerProfile, AppContainerSid,
    KnownCapability, Launched, LaunchOptions, SecurityCapabilities, SecurityCapabilitiesBuilder,
    StdioConfig,
};

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
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    /// AppContainer profile name (also the package identity).
    pub profile_name: String,
    /// Network capabilities to grant the sandbox.
    pub capabilities: Vec<KnownCapability>,
}

/// A live AppContainer sandbox: a profile, its SID, and the assembled
/// `SECURITY_CAPABILITIES` used to launch contained processes.
pub struct Sandbox {
    profile: AppContainerProfile,
    sid: AppContainerSid,
    caps: SecurityCapabilities,
}

impl Sandbox {
    /// Create (or open) the AppContainer profile and assemble its capabilities.
    pub fn create(config: &SandboxConfig) -> rappct::Result<Self> {
        let profile = AppContainerProfile::ensure(
            config.profile_name.as_str(),
            config.profile_name.as_str(),
            None,
        )?;
        let sid = derive_sid_from_name(config.profile_name.as_str())?;
        let caps = SecurityCapabilitiesBuilder::new(&sid)
            .with_known(&config.capabilities)
            .build()?;
        Ok(Sandbox { profile, sid, caps })
    }

    /// Grant file-system access on a directory to the sandbox identity.
    ///
    /// This is the "file" control dimension. Note (from the spike): an
    /// AppContainer identity must also be able to *traverse* every parent
    /// directory of the target path — callers grant the path chain explicitly.
    pub fn grant_path(&self, path: &str, access: FileAccess) -> rappct::Result<()> {
        let resource = ResourcePath::Directory(std::path::PathBuf::from(path));
        grant_to_package(resource, &self.sid, access.mask())
    }

    /// Launch an executable inside the sandbox.
    ///
    /// `exe` is the full path to the binary; `args` are its arguments
    /// (joined into the command line). The child inherits stdio.
    pub fn launch(&self, exe: &str, args: &[&str]) -> rappct::Result<Launched> {
        let cmdline = args.join(" ");
        let opts = LaunchOptions {
            exe: exe.into(),
            cmdline: Some(cmdline),
            stdio: StdioConfig::Inherit,
            ..Default::default()
        };
        launch_in_container(&self.caps, &opts)
    }

    /// Delete the AppContainer profile, cleaning up the sandbox identity.
    pub fn delete(self) -> rappct::Result<()> {
        self.profile.delete()
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
