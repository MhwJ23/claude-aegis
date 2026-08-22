using System;
using System.IO;
using System.Runtime.InteropServices;

class VerifyIsolation
{
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
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
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int DeleteAppContainerProfile(string name);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateWellKnownSid(int WellKnownSidType, IntPtr DomainSid, IntPtr pSid, ref uint cbSid);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr l, uint c, uint f, ref IntPtr s);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr pv, IntPtr pr);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr l);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr h, out uint code);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = new IntPtr(0x20009);

    static int Main()
    {
        string profileName = "claude-aegis-spike";
        string secretFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "aegis-test-secret.txt");
        File.WriteAllText(secretFile, "THIS_IS_A_SECRET");

        // control: normal process read (should succeed)
        string control = File.ReadAllText(secretFile);
        Console.WriteLine("[control] normal read OK: " + (control == "THIS_IS_A_SECRET"));

        DeleteAppContainerProfile(profileName);
        IntPtr sid;
        int hr = CreateAppContainerProfile(profileName, "spike", "spike", IntPtr.Zero, 0, out sid);
        Console.WriteLine("[profile] CreateAppContainerProfile HRESULT = 0x" + hr.ToString("X8") + " sid=" + sid);
        if (hr != 0) { Console.WriteLine("FATAL: cannot create profile"); return 1; }

        // create internetClient capability SID (well-known type 85) via CreateWellKnownSid
        const int WinCapabilityInternetClientSid = 85;
        const uint SE_GROUP_ENABLED = 0x00000004;
        uint cbSid = 0;
        CreateWellKnownSid(WinCapabilityInternetClientSid, IntPtr.Zero, IntPtr.Zero, ref cbSid);
        IntPtr capSid = Marshal.AllocHGlobal((int)cbSid);
        bool cwkOk = CreateWellKnownSid(WinCapabilityInternetClientSid, IntPtr.Zero, capSid, ref cbSid);
        Console.WriteLine("[wellknownsid] ok=" + cwkOk + " cbSid=" + cbSid);

        SID_AND_ATTRIBUTES sa = new SID_AND_ATTRIBUTES();
        sa.Sid = capSid;
        sa.Attributes = SE_GROUP_ENABLED;
        IntPtr saPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
        Marshal.StructureToPtr(sa, saPtr, false);

        SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
        sc.AppContainerSid = sid;
        sc.Capabilities = saPtr;
        sc.CapabilityCount = 1;
        sc.Reserved = 0;
        int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
        IntPtr scPtr = Marshal.AllocHGlobal(scSize);
        Marshal.StructureToPtr(sc, scPtr, false);
        Console.WriteLine("[struct] SECURITY_CAPABILITIES size = " + scSize);

        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        IntPtr attrList = Marshal.AllocHGlobal(size);
        bool initOk = InitializeProcThreadAttributeList(attrList, 1, 0, ref size);
        Console.WriteLine("[attrlist] init ok=" + initOk + " size=" + size);

        bool updOk = UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, scPtr, new IntPtr(scSize), IntPtr.Zero, IntPtr.Zero);
        int updErr = Marshal.GetLastWin32Error();
        Console.WriteLine("[update] ok=" + updOk + " err=" + updErr);

        if (updOk)
        {
            STARTUPINFOEX si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            si.lpAttributeList = attrList;

            // diagnostics: struct sizes + capability SID attributes
            Console.WriteLine("[diag] sizeof(STARTUPINFO)=" + Marshal.SizeOf(typeof(STARTUPINFO)) + " sizeof(STARTUPINFOEX)=" + Marshal.SizeOf(typeof(STARTUPINFOEX)) + " cb=" + si.StartupInfo.cb);
            if (saPtr != IntPtr.Zero)
            {
                long firstSid = Marshal.ReadIntPtr(saPtr, 0).ToInt64();
                long firstAttr = Marshal.ReadInt32(saPtr, 8);
                Console.WriteLine("[diag] sa.Sid=0x" + firstSid.ToString("X") + " Attributes=0x" + firstAttr.ToString("X"));
            }
            PROCESS_INFORMATION pi;
            string cmdline = "cmd.exe /c type \"" + secretFile + "\"";
            bool cpOk = CreateProcess(null, cmdline, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref si, out pi);
            Console.WriteLine("[createprocess] ok=" + cpOk + " err=" + Marshal.GetLastWin32Error());
            if (cpOk)
            {
                WaitForSingleObject(pi.hProcess, 15000);
                uint exitCode;
                GetExitCodeProcess(pi.hProcess, out exitCode);
                Console.WriteLine("[result] AppContainer process exit code = " + exitCode + " (0=read OK, nonzero=BLOCKED)");
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                if (exitCode != 0)
                    Console.WriteLine(">>> PASS: file isolation works (AppContainer process could NOT read secret)");
                else
                    Console.WriteLine(">>> SUSPECT: AppContainer process READ the secret (isolation did not block)");
            }
        }

        DeleteProcThreadAttributeList(attrList);
        Marshal.FreeHGlobal(scPtr);
        DeleteAppContainerProfile(profileName);
        File.Delete(secretFile);
        return 0;
    }
}
