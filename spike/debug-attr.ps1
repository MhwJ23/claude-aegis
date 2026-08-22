# debug: step through attribute-list creation to find the ERROR_BAD_LENGTH source
$ErrorActionPreference = 'Continue'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class AC {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool InitializeProcThreadAttributeList(IntPtr l, uint c, uint f, ref IntPtr s);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr pv, IntPtr pr);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void DeleteProcThreadAttributeList(IntPtr l);
}
"@

Write-Host ("IntPtr.Size = " + [IntPtr]::Size)

$sid = [IntPtr]::Zero
$hr = [AC]::CreateAppContainerProfile("claude-aegis-spike", "spike", "spike", [IntPtr]::Zero, 0, [ref]$sid)
Write-Host ("CreateAppContainerProfile HRESULT = 0x{0:X8}  sid=0x{1:X}" -f $hr, $sid.ToInt64())

$sc = New-Object AC+SECURITY_CAPABILITIES
$sc.AppContainerSid = $sid
$sc.Capabilities = [IntPtr]::Zero
$sc.CapabilityCount = 0
$sc.Reserved = 0
$scSize = [Runtime.InteropServices.Marshal]::SizeOf($sc)
Write-Host ("scSize = " + $scSize)

# pass 1: get required size
$size = [IntPtr]::Zero
$r1 = [AC]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$size)
Write-Host ("Init pass1 ok={0} err={1} size={2}" -f $r1, [Runtime.InteropServices.Marshal]::GetLastWin32Error(), $size)

# allocate
$attrList = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
Write-Host ("allocated attrList = 0x{0:X}" -f $attrList.ToInt64())

# pass 2: initialize
$size2 = $size
$r2 = [AC]::InitializeProcThreadAttributeList($attrList, 1, 0, [ref]$size2)
Write-Host ("Init pass2 ok={0} err={1} size2={2}" -f $r2, [Runtime.InteropServices.Marshal]::GetLastWin32Error(), $size2)

# marshal struct
$scPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($scSize)
[Runtime.InteropServices.Marshal]::StructureToPtr($sc, $scPtr, $false)
Write-Host ("scPtr = 0x{0:X}" -f $scPtr.ToInt64())

# update attribute
$ATTRIBUTE = [IntPtr]0x20011
$r3 = [AC]::UpdateProcThreadAttribute($attrList, 0, $ATTRIBUTE, $scPtr, [IntPtr]$scSize, [IntPtr]::Zero, [IntPtr]::Zero)
$e3 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
Write-Host ("UpdateAttr ok={0} err={1}" -f $r3, $e3)

[AC]::DeleteProcThreadAttributeList($attrList)
[Runtime.InteropServices.Marshal]::FreeHGlobal($scPtr)
