using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

class EndToEnd
{
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }

    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize; public int dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId; }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int DeleteAppContainerProfile(string name);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool CreateWellKnownSid(int t, IntPtr d, IntPtr s, ref uint cb);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr h);

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
    static readonly IntPtr PROC_THREAD_ATTR_SECURITY_CAPABILITIES = new IntPtr(0x20009);

    static void Grant(string path, string sid, string perms)
    {
        string arg = "\"" + path + "\" /grant *" + sid + ":(OI)(CI)" + perms;
        ProcessStartInfo psi = new ProcessStartInfo("icacls", arg);
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process p = Process.Start(psi);
        p.WaitForExit();
        Console.WriteLine("[grant] " + perms + " " + path + " (exit " + p.ExitCode + ")");
    }

    static void Main()
    {
        string profileName = "claude-aegis-e2e";
        string claudeExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "npm", "node_modules", "@anthropic-ai", "claude-code", "bin", "claude.exe");
        string claudeCodeDir = Path.GetDirectoryName(Path.GetDirectoryName(claudeExe)); // .../@anthropic-ai/claude-code
        string claudeDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claude");
        string outDir = @"D:\Claude Code Modeling and Procedureing\claude-aegis\spike\out";
        Directory.CreateDirectory(outDir);

        Console.WriteLine("[claudeExe] " + claudeExe + " exists=" + File.Exists(claudeExe));

        DeleteAppContainerProfile(profileName);
        IntPtr sid;
        int hr = CreateAppContainerProfile(profileName, "e2e", "e2e", IntPtr.Zero, 0, out sid);
        Console.WriteLine("[profile] hr=0x" + hr.ToString("X8") + " sid=0x" + sid.ToInt64().ToString("X"));
        if (hr != 0) return;

        // SID string
        IntPtr sidStrPtr;
        ConvertSidToStringSid(sid, out sidStrPtr);
        string sidStr = Marshal.PtrToStringUni(sidStrPtr);
        LocalFree(sidStrPtr);
        Console.WriteLine("[sid] " + sidStr);
        Console.WriteLine("[sidcheck] len=" + sidStr.Length + " head=" + (sidStr.Length >= 4 ? sidStr.Substring(0, 4) : "?"));
        File.WriteAllText(Path.Combine(outDir, "sid.txt"), sidStr);

        // grant access: read+execute on claude-code dir, modify on .claude and out dir
        Grant(claudeCodeDir, sidStr, "RX");
        Grant(claudeDir, sidStr, "M");
        Grant(outDir, sidStr, "M");
        // AppContainer needs traverse access through the user profile to reach claude.exe's deep path
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        Grant(userProfile, sidStr, "RX");

        // capability: internetClient (well-known 85) + SE_GROUP_ENABLED
        const int WinCapabilityInternetClientSid = 85;
        const uint SE_GROUP_ENABLED = 0x4;
        uint cbSid = 0;
        CreateWellKnownSid(WinCapabilityInternetClientSid, IntPtr.Zero, IntPtr.Zero, ref cbSid);
        IntPtr capSid = Marshal.AllocHGlobal((int)cbSid);
        CreateWellKnownSid(WinCapabilityInternetClientSid, IntPtr.Zero, capSid, ref cbSid);
        SID_AND_ATTRIBUTES sa = new SID_AND_ATTRIBUTES();
        sa.Sid = capSid; sa.Attributes = SE_GROUP_ENABLED;
        IntPtr saPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)));
        Marshal.StructureToPtr(sa, saPtr, false);

        SECURITY_CAPABILITIES sc = new SECURITY_CAPABILITIES();
        sc.AppContainerSid = sid; sc.Capabilities = saPtr; sc.CapabilityCount = 1; sc.Reserved = 0;
        int scSize = Marshal.SizeOf(typeof(SECURITY_CAPABILITIES));
        IntPtr scPtr = Marshal.AllocHGlobal(scSize);
        Marshal.StructureToPtr(sc, scPtr, false);

        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
        IntPtr attrList = Marshal.AllocHGlobal(size);
        InitializeProcThreadAttributeList(attrList, 1, 0, ref size);
        bool updOk = UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTR_SECURITY_CAPABILITIES, scPtr, new IntPtr(scSize), IntPtr.Zero, IntPtr.Zero);
        Console.WriteLine("[update] ok=" + updOk);

        STARTUPINFOEX si = new STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        si.lpAttributeList = attrList;
        PROCESS_INFORMATION pi;

        // run claude.exe -p (headless) to test API connectivity inside AppContainer
        string cmdline = "\"" + claudeExe + "\" -p \"Reply with exactly: OK\"";
        Console.WriteLine("[cmd] " + cmdline);

        bool cpOk = CreateProcess(claudeExe, cmdline, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, outDir, ref si, out pi);
        Console.WriteLine("[createprocess] ok=" + cpOk + " err=" + Marshal.GetLastWin32Error());
        if (cpOk)
        {
            WaitForSingleObject(pi.hProcess, 180000);
            uint exitCode;
            GetExitCodeProcess(pi.hProcess, out exitCode);
            Console.WriteLine("[result] exit code = " + exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        // no output capture; exit code (0 = success) is the signal for --version

        DeleteProcThreadAttributeList(attrList);
        Marshal.FreeHGlobal(scPtr);
        Marshal.FreeHGlobal(saPtr);
        DeleteAppContainerProfile(profileName);
    }
}
