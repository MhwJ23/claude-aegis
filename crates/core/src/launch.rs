//! Custom AppContainer process launch — replicates the validated C# spike.
//!
//! rappct's `launch_in_container` fails with ERROR_FILE_NOT_FOUND on Windows 11
//! 24H2. The C# spike worked by calling `CreateAppContainerProfile` /
//! `CreateWellKnownSid` directly and passing those raw SIDs to `CreateProcessW`.
//! This module reproduces that path with the `windows` crate.
//!
//! CRITICAL: `CreateAppContainerProfile` must receive a **non-null** description
//! string. Passing NULL makes it fail, which falls back to
//! `DeriveAppContainerSidFromAppContainerName` — and that derives a *different*
//! SID than `CreateAppContainerProfile` returns, so `CreateProcessW` then fails
//! with ERROR_FILE_NOT_FOUND. See spike/FINDINGS.md.

use crate::SandboxError;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_FAILED,
};
use windows::Win32::Security::{
    CreateWellKnownSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    WinCapabilityInternetClientSid,
};
use windows::Win32::System::Memory::{LMEM_FIXED, LocalAlloc};
use windows::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

#[link(name = "Userenv")]
unsafe extern "system" {
    fn CreateAppContainerProfile(
        name: PCWSTR,
        display: PCWSTR,
        desc: PCWSTR,
        caps: *mut core::ffi::c_void,
        cap_count: u32,
        sid: *mut *mut core::ffi::c_void,
    ) -> windows::core::HRESULT;

    fn DeriveAppContainerSidFromAppContainerName(
        name: PCWSTR,
        sid: *mut *mut core::ffi::c_void,
    ) -> windows::core::HRESULT;
}

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
        }
    }
}

/// Launch a process inside an AppContainer, returning a [`Child`] handle.
///
/// When `proxy_addr` is set (e.g. `127.0.0.1:PORT`), `HTTP(S)_PROXY` is set on
/// the child so its traffic routes through the loopback domain proxy. `NO_PROXY`
/// excludes loopback itself so localhost connections stay direct.
pub fn launch_appcontainer(
    profile_name: &str,
    exe: &str,
    args: &[&str],
    proxy_addr: Option<&str>,
    new_console: bool,
    stdout_path: Option<&Path>,
) -> Result<Child, SandboxError> {
    let app_sid = get_appcontainer_sid(profile_name)?;
    let cap_sid = get_internet_client_sid()?;

    let mut cap_attrs = vec![SID_AND_ATTRIBUTES {
        Sid: cap_sid,
        Attributes: 0x4, // SE_GROUP_ENABLED
    }];
    let mut sc = SECURITY_CAPABILITIES {
        AppContainerSid: app_sid,
        Capabilities: cap_attrs.as_mut_ptr(),
        CapabilityCount: cap_attrs.len() as u32,
        Reserved: 0,
    };

    let mut size: usize = 0;
    unsafe {
        // First call probes the required size; ERROR_INSUFFICIENT_BUFFER is expected.
        let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut size);
    }
    let mut buf = vec![0u8; size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _);
    unsafe {
        InitializeProcThreadAttributeList(Some(attr_list), 1, Some(0), &mut size)
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

    let ok = unsafe {
        CreateProcessW_raw(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmdline_w.as_mut_ptr()),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            i32::from(stdout_path.is_some()),
            EXTENDED_STARTUPINFO_PRESENT.0 | if new_console { CREATE_NEW_CONSOLE.0 } else { 0 },
            std::ptr::null_mut(),
            PCWSTR::null(),
            &si as *const STARTUPINFOEXW as *mut STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        LocalFree(Some(HLOCAL(app_sid.0)));
        LocalFree(Some(HLOCAL(cap_sid.0)));
    }
    if ok == 0 {
        let gle = unsafe { GetLastError() };
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
    })
}

/// Obtain the AppContainer SID: create the profile, or derive if it already exists.
fn get_appcontainer_sid(name: &str) -> Result<PSID, SandboxError> {
    let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid_ptr: *mut core::ffi::c_void = std::ptr::null_mut();

    // NOTE: desc must be non-null — a null description makes CreateAppContainerProfile
    // fall through to derive, which yields a different SID and breaks CreateProcessW.
    let hr = unsafe {
        CreateAppContainerProfile(
            PCWSTR(w.as_ptr()),
            PCWSTR(w.as_ptr()),
            PCWSTR(w.as_ptr()),
            std::ptr::null_mut(),
            0,
            &mut sid_ptr,
        )
    };
    if hr.is_ok() && !sid_ptr.is_null() {
        return Ok(PSID(sid_ptr));
    }

    sid_ptr = std::ptr::null_mut();
    let hr2 =
        unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(w.as_ptr()), &mut sid_ptr) };
    if hr2.is_err() || sid_ptr.is_null() {
        return Err(SandboxError::Windows(format!(
            "AppContainer SID failed: create={} derive={}",
            hr.0, hr2.0
        )));
    }
    Ok(PSID(sid_ptr))
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
