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
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HLOCAL, LocalFree};
use windows::Win32::Security::{
    CreateWellKnownSid, PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    WinCapabilityInternetClientSid,
};
use windows::Win32::System::Memory::{LocalAlloc, LMEM_FIXED};
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
};

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

/// Launch a process inside an AppContainer, returning its PID.
pub fn launch_appcontainer(
    profile_name: &str,
    exe: &str,
    args: &[&str],
) -> Result<u32, SandboxError> {
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

    let ok = unsafe {
        CreateProcessW_raw(
            PCWSTR(exe_w.as_ptr()),
            PWSTR(cmdline_w.as_mut_ptr()),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            EXTENDED_STARTUPINFO_PRESENT.0,
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
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }
    Ok(pid)
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
    let hr2 = unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(w.as_ptr()), &mut sid_ptr) };
    if hr2.is_err() || sid_ptr.is_null() {
        return Err(SandboxError::Windows(format!(
            "AppContainer SID failed: create={} derive={}",
            hr.0,
            hr2.0
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
fn build_cmdline(exe: &str, args: &[&str]) -> String {
    let exe_quoted = format!("\"{}\"", exe);
    if args.is_empty() {
        exe_quoted
    } else {
        format!("{} {}", exe_quoted, args.join(" "))
    }
}
