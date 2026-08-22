using System;
using System.Runtime.InteropServices;

class TestAttrScan
{
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int DeleteAppContainerProfile(string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr l, uint c, uint f, ref IntPtr s);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr pv, IntPtr pr);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr l);

    static void Main()
    {
        IntPtr sid;
        int hr = CreateAppContainerProfile("aegis-test", "t", "t", IntPtr.Zero, 0, out sid);
        if (hr != 0) { Console.WriteLine("profile failed"); return; }

        IntPtr buf = Marshal.AllocHGlobal(24);
        Marshal.WriteIntPtr(buf, sid);
        Marshal.WriteIntPtr(buf, 8, IntPtr.Zero);
        Marshal.WriteInt32(buf, 16, 0);
        Marshal.WriteInt32(buf, 20, 0);

        // scan attribute values 0x20001 .. 0x20020
        for (int attr = 0x20001; attr <= 0x20020; attr++)
        {
            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            IntPtr list = Marshal.AllocHGlobal(size);
            InitializeProcThreadAttributeList(list, 1, 0, ref size);

            bool ok = UpdateProcThreadAttribute(list, 0, new IntPtr(attr), buf, new IntPtr(24), IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            if (ok)
                Console.WriteLine("attr=0x" + attr.ToString("X8") + " -> ok=TRUE  err=" + err + "  <<< WORKS");
            DeleteProcThreadAttributeList(list);
        }

        Marshal.FreeHGlobal(buf);
        DeleteAppContainerProfile("aegis-test");
    }
}
