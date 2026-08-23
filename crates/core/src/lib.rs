//! claude-aegis-core: AppContainer sandbox engine for Claude Code on Windows.
//!
//! Four control dimensions (see PLAN.md):
//! 1. **File** — grant read/write access to specific paths via DACL (`grant_*`).
//! 2. **Network** — AppContainer capabilities + a loopback domain-allow-list
//!    proxy. The proxy runs *inside* the same AppContainer as the child (so
//!    same-SID loopback works without admin), see `spike/FINDINGS.md`.
//! 3. **Process** — launch whitelisted executables inside the container
//!    (`allowed_binaries`).
//! 4. **Privilege** — the AppContainer identity *is* the privilege boundary
//!    (an AppContainer token is inherently restricted). Explicit low-integrity
//!    token reduction is a future enhancement (rappct has no such API).
//!
//! The engine wraps [`rappct`], validated end-to-end in the spike
//! (see `spike/FINDINGS.md`).

pub mod audit;
pub mod config;
mod launch;

pub use audit::{AuditEvent, AuditLog};
pub use config::{Config, ConfigError};
pub use launch::Child;

use rappct::acl::{AccessMask, ResourcePath, grant_to_package};
use rappct::{AppContainerProfile, AppContainerSid, KnownCapability};

/// Errors surfaced by the sandbox engine.
#[derive(Debug)]
pub enum SandboxError {
    /// An error from the underlying rappct / Windows API layer.
    Rappct(rappct::AcError),
    /// An I/O error.
    Io(std::io::Error),
    /// A Windows API error (from the custom launch path).
    Windows(String),
    /// A policy rejection (e.g. binary not in the process allow-list).
    NotAllowed(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Rappct(e) => write!(f, "{e}"),
            SandboxError::Io(e) => write!(f, "{e}"),
            SandboxError::Windows(e) => write!(f, "{e}"),
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
    ReadExecute,
    Write,
    ReadWrite,
    /// Read + write + execute (convenience for directories hosting binaries).
    Full,
    /// Traverse-only on a directory: descend into children without listing.
    /// Used internally for the ancestor chain of a granted path.
    Traverse,
}

impl FileAccess {
    /// A short, human-readable name for the audit log.
    pub fn as_str(self) -> &'static str {
        match self {
            FileAccess::Read => "read",
            FileAccess::ReadExecute => "read_execute",
            FileAccess::Write => "write",
            FileAccess::ReadWrite => "read_write",
            FileAccess::Full => "full",
            FileAccess::Traverse => "traverse",
        }
    }

    /// Map to Windows generic access masks (GENERIC_READ / WRITE / EXECUTE).
    fn mask(self) -> AccessMask {
        match self {
            FileAccess::Read => AccessMask(0x8000_0000),
            FileAccess::ReadExecute => AccessMask(0xA000_0000),
            FileAccess::Write => AccessMask(0x4000_0000),
            FileAccess::ReadWrite => AccessMask(0xC000_0000),
            FileAccess::Full => AccessMask(0xE000_0000),
            FileAccess::Traverse => AccessMask(0x2000_0000), // GENERIC_EXECUTE
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
    /// Optional audit log path. When set, the sandbox appends launch / exit /
    /// grant events to this JSON-lines file.
    pub audit_log: Option<std::path::PathBuf>,
}

/// A live AppContainer sandbox: a profile and its SID.
///
/// The domain proxy (when configured) is launched *inside* this container by
/// the caller via [`Sandbox::launch`], so it shares the same SID and can be
/// reached over loopback without any admin exemption.
pub struct Sandbox {
    profile: AppContainerProfile,
    sid: AppContainerSid,
    profile_name: String,
    allowed_binaries: Vec<String>,
    audit: Option<AuditLog>,
}

impl Sandbox {
    /// Create (or open) the AppContainer profile and resolve its SID.
    pub fn create(config: &SandboxConfig) -> Result<Self, SandboxError> {
        let profile = AppContainerProfile::ensure(
            config.profile_name.as_str(),
            config.profile_name.as_str(),
            Some(config.profile_name.as_str()),
        )?;
        let sid = profile.sid.clone();
        Ok(Sandbox {
            profile,
            sid,
            profile_name: config.profile_name.clone(),
            allowed_binaries: config.allowed_binaries.clone(),
            audit: config.audit_log.clone().map(AuditLog::at),
        })
    }

    /// Append an event to the audit log, if one is configured.
    ///
    /// Best-effort: audit failures are ignored (a run should not abort because
    /// the audit file could not be written).
    pub fn record(&self, event: AuditEvent) {
        if let Some(audit) = &self.audit {
            let _ = audit.append(&event);
        }
    }

    /// The audit log path, when auditing is configured.
    pub fn audit_path(&self) -> Option<&std::path::Path> {
        self.audit.as_ref().map(|a| a.path())
    }

    /// The profile name (identity) this sandbox runs under.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Whether the sandbox SID already has `specific` rights on `path`.
    ///
    /// `GetEffectiveRightsFromAclW` returns *specific* access rights (generic
    /// bits mapped to specific, e.g. `GENERIC_EXECUTE` -> `FILE_TRAVERSE`), so
    /// `specific` must be specific rights, not generic. Reading the ACL is fast;
    /// only the *write* is slow — this skips the expensive grant on re-runs.
    /// Best-effort: returns `false` on any error, so we fall through to the grant.
    fn already_granted(&self, path: &str, specific: u32) -> bool {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertStringSidToSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, TRUSTEE_FORM, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_TYPE, TRUSTEE_W,
        };
        use windows::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSID};
        use windows::core::{PCWSTR, PWSTR};

        let sid_sddl = self.sid.as_string();
        let sid_w: Vec<u16> = sid_sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid = PSID(std::ptr::null_mut());
        if unsafe { ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid) }.is_err() {
            return false;
        }

        let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut p_sd = windows::Win32::Security::PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let st = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut p_dacl),
                None,
                &mut p_sd,
            )
        };
        if st.0 != 0 {
            return false;
        }

        let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
        trustee.TrusteeForm = TRUSTEE_FORM(TRUSTEE_IS_SID.0);
        trustee.TrusteeType = TRUSTEE_TYPE(TRUSTEE_IS_WELL_KNOWN_GROUP.0);
        trustee.ptstrName = PWSTR(psid.0 as *mut _);

        let mut granted: u32 = 0;
        let err = unsafe { GetEffectiveRightsFromAclW(p_dacl, &trustee, &mut granted) };

        // ConvertStringSidToSidW / GetNamedSecurityInfoW allocate with LocalAlloc.
        unsafe {
            LocalFree(Some(HLOCAL(psid.0)));
            LocalFree(Some(HLOCAL(p_sd.0)));
        }

        err.0 == 0 && (granted & specific) == specific
    }

    /// Grant access on a directory to the sandbox identity (no ancestor grants).
    pub fn grant_dir(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        let resource = ResourcePath::Directory(std::path::PathBuf::from(path));
        grant_to_package(resource, &self.sid, access.mask())?;
        self.record(AuditEvent::Grant {
            path: path.to_string(),
            access: access.as_str().to_string(),
        });
        Ok(())
    }

    /// Grant access on a file to the sandbox identity (no ancestor grants).
    pub fn grant_file(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        let resource = ResourcePath::File(std::path::PathBuf::from(path));
        grant_to_package(resource, &self.sid, access.mask())?;
        self.record(AuditEvent::Grant {
            path: path.to_string(),
            access: access.as_str().to_string(),
        });
        Ok(())
    }

    /// Grant traverse-only access on a directory, **without inheritance**.
    ///
    /// `grant_dir` uses `(OI)(CI)` inheritance (it propagates the ACE to every
    /// descendant), which is correct for a leaf you want read/write on — but
    /// catastrophic for an ancestor like the user profile: it would walk and
    /// rewrite the ACL of a huge tree. Traversal only needs to apply to the
    /// directory itself, so this sets a non-inheriting ACE (via the `File`
    /// resource type, which rappct treats with `grfInheritance = 0`).
    pub fn grant_traverse(&self, path: &str) -> Result<(), SandboxError> {
        // FILE_TRAVERSE (0x20) is the specific right for "descend into a
        // directory". Checking it (fast read) skips the slow grant on re-runs,
        // which matters because ancestors like the user profile take ~30s to
        // propagate an ACL change.
        const FILE_TRAVERSE: u32 = 0x20;
        if self.already_granted(path, FILE_TRAVERSE) {
            return Ok(());
        }
        let resource = ResourcePath::File(std::path::PathBuf::from(path));
        grant_to_package(resource, &self.sid, FileAccess::Traverse.mask())?;
        Ok(())
    }

    /// Grant `access` on a directory plus traverse-only access on every ancestor.
    ///
    /// An AppContainer identity must be able to *traverse* each parent directory
    /// to reach the target (see spike/FINDINGS.md); without this, a grant on a
    /// deep path is useless.
    pub fn grant_dir_chain(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        let mut cur = std::path::PathBuf::from(path);
        // The leaf gets the requested access; ancestors get traverse-only.
        self.grant_dir(&cur.to_string_lossy(), access)?;
        while let Some(parent) = cur.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            // Ancestors are best-effort: protected system dirs (C:\, C:\Windows)
            // are already traversable by AppContainers and reject DACL edits.
            let _ = self.grant_traverse(&parent.to_string_lossy());
            cur = parent.to_path_buf();
        }
        Ok(())
    }

    /// Grant `access` on a file plus traverse-only access on every ancestor.
    pub fn grant_file_chain(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        let full = std::path::PathBuf::from(path);
        self.grant_file(&full.to_string_lossy(), access)?;
        let mut cur = full;
        while let Some(parent) = cur.parent() {
            if parent.as_os_str().is_empty() {
                break;
            }
            let _ = self.grant_traverse(&parent.to_string_lossy());
            cur = parent.to_path_buf();
        }
        Ok(())
    }

    /// Launch an executable inside the sandbox, returning a [`Child`] handle.
    ///
    /// `exe` is the full path to the binary; `args` are its arguments. If a
    /// process allow-list is configured, `exe` is checked against it
    /// (case-insensitive) before launch. When `proxy_addr` is set, the child's
    /// HTTP(S) traffic is routed through the loopback proxy at that address.
    /// When `new_console` is true the child runs in its own console window
    /// (used by the GUI, whose own process has no console).
    pub fn launch(
        &self,
        exe: &str,
        args: &[&str],
        proxy_addr: Option<&str>,
        new_console: bool,
    ) -> Result<Child, SandboxError> {
        self.launch_internal(exe, args, proxy_addr, new_console, None)
    }

    /// Launch a process inside the sandbox with its stdout redirected to a file
    /// (append mode). Used for the domain proxy: its audit lines are written to
    /// stdout, which the host redirects into the audit log — so the sandboxed
    /// process never needs write access to the audit file itself.
    pub fn launch_with_stdout(
        &self,
        exe: &str,
        args: &[&str],
        stdout: &std::path::Path,
    ) -> Result<Child, SandboxError> {
        self.launch_internal(exe, args, None, false, Some(stdout))
    }

    fn launch_internal(
        &self,
        exe: &str,
        args: &[&str],
        proxy_addr: Option<&str>,
        new_console: bool,
        stdout_path: Option<&std::path::Path>,
    ) -> Result<Child, SandboxError> {
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

        let child = launch::launch_appcontainer(
            &self.profile_name,
            exe,
            args,
            proxy_addr,
            new_console,
            stdout_path,
        )?;
        self.record(AuditEvent::Launch {
            profile: self.profile_name.clone(),
            command: exe.to_string(),
            pid: child.pid(),
        });
        Ok(child)
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
        assert_eq!(FileAccess::ReadExecute.mask().0, 0xA000_0000);
        assert_eq!(FileAccess::Write.mask().0, 0x4000_0000);
        assert_eq!(FileAccess::ReadWrite.mask().0, 0xC000_0000);
        assert_eq!(FileAccess::Full.mask().0, 0xE000_0000);
        assert_eq!(FileAccess::Traverse.mask().0, 0x2000_0000);
    }
}
