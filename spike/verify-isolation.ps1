# spike step 2: launch a process into AppContainer and verify FILE isolation
# control experiment: normal process CAN read secret file, AppContainer process CANNOT
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class AC {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DeleteAppContainerProfile(string name);

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_CAPABILITIES {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttrList, uint dwAttrCount, uint dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr lpAttrList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPrev, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr lpAttrList);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string lpAppName, string lpCmdLine, IntPtr lpProcAttrs, IntPtr lpThreadAttrs, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnv, string lpCurDir, ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcInfo);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr h, out uint code);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);
}
"@

$EXTENDED_STARTUPINFO_PRESENT = 0x00080000
$PROC_THREAD_ATTR_SECURITY_CAPABILITIES = 0x00020011

$profileName = "claude-aegis-spike"
$secretFile = Join-Path $env:USERPROFILE "aegis-test-secret.txt"
Set-Content -Path $secretFile -Value "THIS_IS_A_SECRET" -Encoding ASCII

function Launch-IntoAppContainer([string]$cmdline) {
    $sid = [IntPtr]::Zero
    $hr = [AC]::CreateAppContainerProfile($profileName, $profileName, "spike", [IntPtr]::Zero, 0, [ref]$sid)
    if ($hr -ne 0) { throw "CreateAppContainerProfile failed 0x$($hr.ToString('X8'))" }

    $sc = New-Object AC+SECURITY_CAPABILITIES
    $sc.AppContainerSid = $sid
    $sc.Capabilities = [IntPtr]::Zero
    $sc.CapabilityCount = 0
    $sc.Reserved = 0
    $scSize = [Runtime.InteropServices.Marshal]::SizeOf($sc)
    $scPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($scSize)
    [Runtime.InteropServices.Marshal]::StructureToPtr($sc, $scPtr, $false)

    $size = [IntPtr]::Zero
    [AC]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$size) | Out-Null
    $attrList = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
    if (-not [AC]::InitializeProcThreadAttributeList($attrList, 1, 0, [ref]$size)) {
        throw "InitializeProcThreadAttributeList failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    if (-not [AC]::UpdateProcThreadAttribute($attrList, 0, [IntPtr]$PROC_THREAD_ATTR_SECURITY_CAPABILITIES, $scPtr, [IntPtr]$scSize, [IntPtr]::Zero, [IntPtr]::Zero)) {
        throw "UpdateProcThreadAttribute failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    $si = New-Object AC+STARTUPINFOEX
    $si.StartupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
    $si.lpAttributeList = $attrList
    $pi = New-Object AC+PROCESS_INFORMATION

    $ok = [AC]::CreateProcess($null, $cmdline, [IntPtr]::Zero, [IntPtr]::Zero, $false, $EXTENDED_STARTUPINFO_PRESENT, [IntPtr]::Zero, $null, [ref]$si, [ref]$pi)

    [AC]::DeleteProcThreadAttributeList($attrList)
    [Runtime.InteropServices.Marshal]::FreeHGlobal($scPtr)

    if (-not $ok) {
        return @{ ok = $false; error = [Runtime.InteropServices.Marshal]::GetLastWin32Error(); exitCode = -1; pid = -1 }
    }

    [AC]::WaitForSingleObject($pi.hProcess, 15000) | Out-Null
    $code = [uint32]0
    [AC]::GetExitCodeProcess($pi.hProcess, [ref]$code) | Out-Null
    [AC]::CloseHandle($pi.hProcess) | Out-Null
    [AC]::CloseHandle($pi.hThread) | Out-Null

    return @{ ok = $true; error = 0; exitCode = $code; pid = $pi.dwProcessId }
}

Write-Host "Secret file: $secretFile"
Write-Host ""

# A. Control: normal process reads the secret file (should SUCCEED, exit 0)
Write-Host "=== A. Control: normal process reads secret ==="
cmd.exe /c "type `"$secretFile`" >nul 2>&1"
$normalExit = $LASTEXITCODE
Write-Host "normal cmd 'type secret' exit code = $normalExit (0 = read OK)"

# B. AppContainer process reads the secret file (should FAIL, exit != 0)
Write-Host ""
Write-Host "=== B. AppContainer process reads secret ==="
$r = Launch-IntoAppContainer "cmd.exe /c type `"$secretFile`""
if ($r.ok) {
    Write-Host "AppContainer launch OK, pid=$($r.pid), exit code = $($r.exitCode) (nonzero = blocked)"
} else {
    Write-Host "AppContainer launch FAILED, Win32 error = $($r.error)"
}

Write-Host ""
Write-Host "=== VERDICT ==="
if ($r.ok -and $normalExit -eq 0 -and $r.exitCode -ne 0) {
    Write-Host "PASS: normal process read the secret (exit 0) but AppContainer process was BLOCKED (exit $($r.exitCode)). File isolation works."
} elseif (-not $r.ok) {
    Write-Host "INCONCLUSIVE: AppContainer launch failed (error $($r.error)). Need to debug CreateProcess."
} else {
    Write-Host "SUSPECT: AppContainer process exit code = $($r.exitCode). If 0, isolation did NOT block the read."
}

# cleanup
[AC]::DeleteAppContainerProfile($profileName) | Out-Null
Remove-Item $secretFile -ErrorAction SilentlyContinue
