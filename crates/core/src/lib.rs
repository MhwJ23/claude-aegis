//! claude-aegis-core: AppContainer sandbox engine for Claude Code on Windows.
//!
//! Four control dimensions (see PLAN.md):
//! 1. **File** — grant read/write access to specific paths via DACL (`grant_*`).
//! 2. **Network** — a loopback domain-allow-list proxy. The proxy runs *inside*
//!    the same AppContainer as the child (so same-SID loopback works without
//!    admin) and is the only process granted `internetClient`; a proxied child
//!    has no direct internet, so the allow-list is enforced (see `spike/FINDINGS.md`).
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

use rappct::acl::AccessMask;
use rappct::{AppContainerProfile, AppContainerSid};

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
            // Read+execute: opening a directory to descend into it needs
            // FILE_TRAVERSE *and* FILE_READ_ATTRIBUTES/SYNCHRONIZE, which bare
            // FILE_TRAVERSE (0x20) or GENERIC_EXECUTE (0x20000000) do not cover.
            FileAccess::Traverse => AccessMask(0xA000_0000),
        }
    }
}

/// Configuration for creating a sandbox.
#[derive(Clone, Debug, Default)]
pub struct SandboxConfig {
    /// AppContainer profile name (also the package identity).
    pub profile_name: String,
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

    /// Grant `mask` on a file or directory to the sandbox SID.
    ///
    /// Reimplements rappct's `grant_to_package` with the correct trustee type:
    /// rappct passes `TRUSTEE_IS_WELL_KNOWN_GROUP`, which is wrong for an
    /// AppContainer SID (a *group* SID, not a well-known group) — `SetEntriesInAclW`
    /// still writes the ACE, but the kernel ignores it at access-check time, so
    /// the grant silently has no effect. `TRUSTEE_IS_GROUP` fixes it (verified
    /// end-to-end: the same ACE works when applied via `icacls`).
    fn grant_to_sid(
        &self,
        path: &std::path::Path,
        is_dir: bool,
        mask: AccessMask,
    ) -> Result<(), SandboxError> {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_FORM,
            TRUSTEE_IS_GROUP, TRUSTEE_IS_SID, TRUSTEE_TYPE, TRUSTEE_W,
        };
        use windows::Win32::Security::{
            ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        };
        use windows::core::{PCWSTR, PWSTR};

        let sid_w: Vec<u16> = self
            .sid
            .as_string()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut psid = PSID(std::ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid)
                .map_err(|e| SandboxError::Windows(e.to_string()))?;
        }

        let mut trustee: TRUSTEE_W = unsafe { std::mem::zeroed() };
        trustee.TrusteeForm = TRUSTEE_FORM(TRUSTEE_IS_SID.0);
        trustee.TrusteeType = TRUSTEE_TYPE(TRUSTEE_IS_GROUP.0);
        trustee.ptstrName = PWSTR(psid.0 as *mut _);

        let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
        ea.grfAccessPermissions = mask.0;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.Trustee = trustee;
        // Directories grant with (OI)(CI) inheritance; files/traverse do not.
        ea.grfInheritance = if is_dir { ACE_FLAGS(0x3) } else { ACE_FLAGS(0) };

        let path_w: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut p_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
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
            unsafe { LocalFree(Some(HLOCAL(psid.0))) };
            return Err(SandboxError::Windows(format!(
                "GetNamedSecurityInfoW failed: {st:?}"
            )));
        }

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let entries = [ea];
        let st2 =
            unsafe { SetEntriesInAclW(Some(&entries), Some(p_dacl as *const ACL), &mut new_dacl) };
        if st2.0 != 0 {
            unsafe {
                LocalFree(Some(HLOCAL(psid.0)));
                LocalFree(Some(HLOCAL(p_sd.0)));
            }
            return Err(SandboxError::Windows(format!(
                "SetEntriesInAclW failed: {st2:?}"
            )));
        }

        let st3 = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(path_w.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(new_dacl as *const ACL),
                None,
            )
        };
        unsafe {
            LocalFree(Some(HLOCAL(psid.0)));
            LocalFree(Some(HLOCAL(p_sd.0)));
            LocalFree(Some(HLOCAL(new_dacl as *mut core::ffi::c_void)));
        }
        if st3.0 != 0 {
            return Err(SandboxError::Windows(format!(
                "SetNamedSecurityInfoW failed: {st3:?}"
            )));
        }
        Ok(())
    }

    /// Grant access on a directory to the sandbox identity (no ancestor grants).
    pub fn grant_dir(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        self.grant_to_sid(std::path::Path::new(path), true, access.mask())?;
        self.record(AuditEvent::Grant {
            path: path.to_string(),
            access: access.as_str().to_string(),
        });
        Ok(())
    }

    /// Grant access on a file to the sandbox identity (no ancestor grants).
    pub fn grant_file(&self, path: &str, access: FileAccess) -> Result<(), SandboxError> {
        self.grant_to_sid(std::path::Path::new(path), false, access.mask())?;
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
        self.grant_to_sid(
            std::path::Path::new(path),
            false,
            FileAccess::Traverse.mask(),
        )?;
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
        cwd: Option<&std::path::Path>,
    ) -> Result<Child, SandboxError> {
        // A child routed through the proxy gets no direct internet, so the
        // domain allow-list is enforced; a child without a proxy (domains
        // empty) keeps `internetClient` for direct access.
        self.launch_internal(
            exe,
            args,
            proxy_addr,
            new_console,
            None,
            proxy_addr.is_none(),
            cwd,
        )
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
        // The proxy is the one process that may reach the internet directly.
        self.launch_internal(exe, args, None, false, Some(stdout), true, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn launch_internal(
        &self,
        exe: &str,
        args: &[&str],
        proxy_addr: Option<&str>,
        new_console: bool,
        stdout_path: Option<&std::path::Path>,
        internet: bool,
        cwd: Option<&std::path::Path>,
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
            self.sid.as_string(),
            exe,
            args,
            proxy_addr,
            new_console,
            stdout_path,
            internet,
            cwd,
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
        // Traverse uses read+execute (not bare FILE_TRAVERSE): opening a
        // directory to descend into it needs FILE_READ_ATTRIBUTES too.
        assert_eq!(FileAccess::Traverse.mask().0, 0xA000_0000);
    }
}
