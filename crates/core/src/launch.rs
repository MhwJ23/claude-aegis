//! Custom AppContainer process launch — replicates the validated C# spike.
//!
//! rappct's `launch_in_container` fails with ERROR_FILE_NOT_FOUND on Windows 11
//! 24H2, so this module reproduces the C# spike's `CreateProcessW` path with the
//! `windows` crate.
//!
//! The AppContainer SID is **not** re-derived here: `Sandbox::create` resolves it
//! once (via `AppContainerProfile::ensure`) and passes it in as an SDDL string.
//! Re-deriving it here would produce a *different* SID than the one the file/ACL
//! grants were applied to (CreateAppContainerProfile returns a fresh SID, while
//! DeriveAppContainerSidFromAppContainerName hashes the name), silently breaking
//! the grants. See spike/FINDINGS.md.

use crate::SandboxError;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_FAILED,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    CreateWellKnownSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    WinCapabilityInternetClientSid,
};
use windows::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

// Raw CreateProcessW binding (avoids the windows crate generic Param<PCWSTR>
// conversion and keeps the application-name pointer handling explicit).
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "CreateProcessW"]
    fn CreateProcessW_raw(
        lpapplicationname: PCWSTR,
        lpcommandline: PWSTR,
        lpprocessattributes: *mut core::ffi::c_void,
        lpthreadattributes: *mut core::ffi::c_void,
        binherithandles: i32,
        dwcreationflags: u32,
        lpenvironment: *mut core::ffi::c_void,
        lpcurrentdirectory: PCWSTR,
        lpstartupinfo: *mut STARTUPINFOW,
        lpprocessinformation: *mut PROCESS_INFORMATION,
    ) -> i32;
}

/// A launched sandboxed child. The process handle is kept open so the caller
/// can wait for the child to exit.
pub struct Child {
    pid: u32,
    process: HANDLE,
    /// Job object with KILL_ON_JOB_CLOSE; closing it on drop kills any
    /// subprocesses the child left behind.
    job: HANDLE,
}

impl Child {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Block until the child exits and return its exit code.
    pub fn wait(&self) -> Result<u32, SandboxError> {
        unsafe {
            let r = WaitForSingleObject(self.process, INFINITE);
            if r == WAIT_FAILED {
                return Err(SandboxError::Windows(
                    "WaitForSingleObject failed".to_string(),
                ));
            }
            let mut code: u32 = 0;
            GetExitCodeProcess(self.process, &mut code)
                .map_err(|e| SandboxError::Windows(e.to_string()))?;
            Ok(code)
        }
    }

    /// Terminate the child process.
    pub fn kill(&self) -> Result<(), SandboxError> {
        unsafe {
            TerminateProcess(self.process, 1).map_err(|e| SandboxError::Windows(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.process);
            let _ = CloseHandle(self.job);
        }
    }
}

/// Launch a process inside an AppContainer, returning a [`Child`] handle.
///
/// When `proxy_addr` is set (e.g. `127.0.0.1:PORT`), `HTTP(S)_PROXY` is set on
/// the child so its traffic routes through the loopback domain proxy. `NO_PROXY`
/// excludes loopback itself so localhost connections stay direct.
///
/// `internet` grants the child the `internetClient` capability. It must be
/// `false` when the child is supposed to reach the network only through the
/// domain proxy — otherwise the child could connect out directly and bypass the
/// allow-list. The proxy itself is launched with `internet = true`.
// This is the raw FFI boundary mirroring CreateProcessW; a struct would just
// re-list the same fields one level deeper.
#[allow(clippy::too_many_arguments)]
pub fn launch_appcontainer(
    app_sid: &str,
    exe: &str,
    args: &[&str],
    proxy_addr: Option<&str>,
    new_console: bool,
    stdout_path: Option<&Path>,
    internet: bool,
    cwd: Option<&Path>,
) -> Result<Child, SandboxError> {
    let app_sid = sid_from_sddl(app_sid)?;
    let cap_sid = if internet {
        Some(get_internet_client_sid()?)
    } else {
        None
    };

    let mut cap_attrs = match cap_sid {
        Some(sid) => vec![SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0x4, // SE_GROUP_ENABLED
        }],
        None => Vec::new(),
    };
    let mut sc = SECURITY_CAPABILITIES {
        AppContainerSid: app_sid,
        Capabilities: if cap_attrs.is_empty() {
            std::ptr::null_mut()
        } else {
            cap_attrs.as_mut_ptr()
        },
        CapabilityCount: cap_attrs.len() as u32,
        Reserved: 0,
    };

    // A job object with KILL_ON_JOB_CLOSE: when the host closes the job handle
    // (once the sandboxed child exits), the kernel kills any subprocesses the
    // child left behind, so nothing outlives the sandbox.
    let job = unsafe {
        CreateJobObjectW(None, PCWSTR::null()).map_err(|e| SandboxError::Windows(e.to_string()))?
    };
    let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &job_info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(|e| SandboxError::Windows(e.to_string()))?;
    }

    let mut size: usize = 0;
    unsafe {
        // First call probes the required size; ERROR_INSUFFICIENT_BUFFER is expected.
        let _ = InitializeProcThreadAttributeList(None, 2, Some(0), &mut size);
    }
    let mut buf = vec![0u8; size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _);
    unsafe {
        InitializeProcThreadAttributeList(Some(attr_list), 2, Some(0), &mut size)
            .map_err(|e| SandboxError::Windows(e.to_string()))?;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(&mut sc as *mut SECURITY_CAPABILITIES as *const _),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .map_err(|e| SandboxError::Windows(e.to_string()))?;
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            Some(&job as *const HANDLE as *const core::ffi::c_void),
            std::mem::size_of::<HANDLE>(),
            None,
            None,
        )
        .map_err(|e| SandboxError::Windows(e.to_string()))?;
    }

    let exe_w: Vec<u16> = exe.encode_utf16().chain(std::iter::once(0)).collect();
    let cmdline = build_cmdline(exe, args);
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Redirect the child's stdout to a file (append mode). Used to capture the
    // domain proxy's audit lines without granting the sandbox write access to
    // the audit file — the host keeps the handle, the child just inherits it.
    let _stdout_file = if let Some(path) = stdout_path {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let handle = HANDLE(file.as_raw_handle());
        // The handle must be inheritable so CreateProcessW (with bInheritHandles)
        // can hand it to the child.
        unsafe {
            let _ = SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT);
        }
        si.StartupInfo.hStdOutput = handle;
        si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        Some(file)
    } else {
        None
    };

    // Set proxy vars on the current process; the child inherits them
    // (lpEnvironment = NULL). Avoids CREATE_UNICODE_ENVIRONMENT, which fails
    // with ERROR_ENVVAR_NOT_FOUND in the AppContainer path on 24H2.
    if let Some(addr) = proxy_addr {
        let proxy_url = format!("http://{addr}");
        // SAFETY: single-threaded CLI process; set before spawning the child.
        unsafe {
            for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
                std::env::set_var(k, &proxy_url);
            }
            // Keep the loopback proxy itself reachable directly, and leave
            // localhost dev servers unproxied.
            std::env::set_var("NO_PROXY", "127.0.0.1,localhost");
            std::env::set_var("no_proxy", "127.0.0.1,localhost");
        }
    }

    // Working directory: `None` inherits the parent's; `Some` sets it explicitly
    // (useful when the parent's CWD is outside the sandbox's granted paths).
    let cwd_w = cwd.map(|p| {
        use std::os::windows::ffi::OsStrExt;
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    });

    let ok = unsafe {
        CreateProcessW_raw(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmdline_w.as_mut_ptr()),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            i32::from(stdout_path.is_some()),
            EXTENDED_STARTUPINFO_PRESENT.0 | if new_console { CREATE_NEW_CONSOLE.0 } else { 0 },
            std::ptr::null_mut(),
            cwd_w
                .as_ref()
                .map(|w| PCWSTR(w.as_ptr()))
                .unwrap_or(PCWSTR::null()),
            &si as *const STARTUPINFOEXW as *mut STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        LocalFree(Some(HLOCAL(app_sid.0)));
        if let Some(sid) = cap_sid {
            LocalFree(Some(HLOCAL(sid.0)));
        }
    }
    if ok == 0 {
        let gle = unsafe { GetLastError() };
        unsafe {
            let _ = CloseHandle(job);
        }
        return Err(SandboxError::Windows(format!(
            "CreateProcessW failed: GLE={}",
            gle.0
        )));
    }

    let pid = pi.dwProcessId;
    unsafe {
        let _ = CloseHandle(pi.hThread);
    }
    Ok(Child {
        pid,
        process: pi.hProcess,
        job,
    })
}

/// Convert an AppContainer SID in SDDL form (e.g. `S-1-15-2-...`) to a PSID.
///
/// The caller (`Sandbox::create`) already resolved this SID from the profile, so
/// it is guaranteed to match the SID that file/ACL grants were applied to.
fn sid_from_sddl(sddl: &str) -> Result<PSID, SandboxError> {
    let w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID(std::ptr::null_mut());
    unsafe {
        ConvertStringSidToSidW(PCWSTR(w.as_ptr()), &mut psid)
            .map_err(|e| SandboxError::Windows(e.to_string()))?;
    }
    Ok(psid)
}

/// Obtain the internetClient capability SID via CreateWellKnownSid.
fn get_internet_client_sid() -> Result<PSID, SandboxError> {
    let mut cb: u32 = 0;
    unsafe {
        // First call probes the required size; ERROR_INSUFFICIENT_BUFFER is expected.
        let _ = CreateWellKnownSid(WinCapabilityInternetClientSid, None, None, &mut cb);
    }
    let mem = unsafe { LocalAlloc(LMEM_FIXED, cb as usize) }
        .map_err(|e| SandboxError::Windows(e.to_string()))?;
    let sid = PSID(mem.0);
    unsafe {
        CreateWellKnownSid(WinCapabilityInternetClientSid, None, Some(sid), &mut cb)
            .map_err(|e| SandboxError::Windows(e.to_string()))?;
    }
    Ok(sid)
}

/// Build the command line: quoted program path + args.
///
/// Args containing whitespace or quotes are wrapped in double quotes (basic
/// Windows command-line quoting, sufficient for common cases).
fn build_cmdline(exe: &str, args: &[&str]) -> String {
    let mut cmd = format!("\"{}\"", exe);
    for arg in args {
        cmd.push(' ');
        if arg.contains(char::is_whitespace) || arg.contains('"') {
            cmd.push('"');
            cmd.push_str(&arg.replace('"', "\\\""));
            cmd.push('"');
        } else {
            cmd.push_str(arg);
        }
    }
    cmd
}
