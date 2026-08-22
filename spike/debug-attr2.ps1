# debug 2: manual memory construction of SECURITY_CAPABILITIES, clean profile first
$ErrorActionPreference = 'Continue'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AC {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int DeleteAppContainerProfile(string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr l, uint c, uint f, ref IntPtr s);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr pv, IntPtr pr);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr l);
}
"@

$name = "claude-aegis-spike"

# clean any leftover profile (ignore result)
[AC]::DeleteAppContainerProfile($name) | Out-Null
Start-Sleep -Milliseconds 300

$sid = [IntPtr]::Zero
$hr = [AC]::CreateAppContainerProfile($name, "spike", "spike", [IntPtr]::Zero, 0, [ref]$sid)
Write-Host ("CreateAppContainerProfile HRESULT = 0x{0:X8}  sid=0x{1:X}" -f $hr, $sid.ToInt64())
if ($hr -ne 0) { Write-Host "FATAL: cannot create profile"; exit 1 }

# manual memory construction of SECURITY_CAPABILITIES (24 bytes on x64)
# offset 0: AppContainerSid (IntPtr, 8)
# offset 8: Capabilities   (IntPtr, 8)
# offset 16: CapabilityCount (uint, 4)
# offset 20: Reserved         (uint, 4)
$scPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(24)
[Runtime.InteropServices.Marshal]::WriteIntPtr($scPtr, $sid)
[Runtime.InteropServices.Marshal]::WriteIntPtr($scPtr, 8, [IntPtr]::Zero)
[Runtime.InteropServices.Marshal]::WriteInt32($scPtr, 16, 0)
[Runtime.InteropServices.Marshal]::WriteInt32($scPtr, 20, 0)
Write-Host ("scPtr=0x{0:X}  bytes: " -f $scPtr.ToInt64())
# dump 24 bytes for sanity
$bytes = New-Object byte[] 24
[Runtime.InteropServices.Marshal]::Copy($scPtr, $bytes, 0, 24)
Write-Host (($bytes | ForEach-Object { $_.ToString("X2") }) -join " ")

# attribute list
$size = [IntPtr]::Zero
[AC]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$size) | Out-Null
$attrList = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
$r2 = [AC]::InitializeProcThreadAttributeList($attrList, 1, 0, [ref]$size)
Write-Host ("InitAttrList ok={0} size={1}" -f $r2, $size)

$ATTRIBUTE = [IntPtr]0x20011
$r3 = [AC]::UpdateProcThreadAttribute($attrList, 0, $ATTRIBUTE, $scPtr, [IntPtr]24, [IntPtr]::Zero, [IntPtr]::Zero)
$e3 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host ("UpdateProcThreadAttribute ok={0} err={1}" -f $r3, $e3)

[AC]::DeleteProcThreadAttributeList($attrList)
[Runtime.InteropServices.Marshal]::FreeHGlobal($scPtr)
[AC]::DeleteAppContainerProfile($name) | Out-Null
