# spike step 1: minimal check - can we create/delete an AppContainer profile?
# zero-install: PowerShell 5.1 inline C# P/Invoke only
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class AppContainerApi {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateAppContainerProfile(
        string pszAppContainerName,
        string pszDisplayName,
        string pszDescription,
        IntPtr pCapabilities,
        uint dwCapabilityCount,
        out IntPtr ppSidAppContainerSid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DeleteAppContainerProfile(string pszAppContainerName);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr hMem);
}
"@

$profileName = "claude-aegis-spike"

Write-Host "=== 1. Create AppContainer profile ==="
$sid = [IntPtr]::Zero
$hr = [AppContainerApi]::CreateAppContainerProfile($profileName, $profileName, "claude-aegis spike", [IntPtr]::Zero, 0, [ref]$sid)
Write-Host ("CreateAppContainerProfile HRESULT = 0x{0:X8}" -f $hr)

if ($hr -ne 0) {
    Write-Host ">>> FAILED: could not create profile (HRESULT != 0)"
    exit 1
}

if ($sid -ne [IntPtr]::Zero) {
    $sidString = [IntPtr]::Zero
    if ([AppContainerApi]::ConvertSidToStringSid($sid, [ref]$sidString)) {
        $str = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($sidString)
        Write-Host "AppContainer SID = $str"
        [AppContainerApi]::LocalFree($sidString) | Out-Null
    }
} else {
    Write-Host "AppContainer SID = (null)"
}

Write-Host "=== 2. Delete AppContainer profile ==="
$hr2 = [AppContainerApi]::DeleteAppContainerProfile($profileName)
Write-Host ("DeleteAppContainerProfile HRESULT = 0x{0:X8}" -f $hr2)

Write-Host ""
if ($hr -eq 0 -and $hr2 -eq 0) {
    Write-Host ">>> PASS: AppContainer profile create/delete works. Proceed to step 2."
} else {
    Write-Host ">>> ISSUE: need investigation."
}
