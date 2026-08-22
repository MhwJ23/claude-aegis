using System;
using System.Runtime.InteropServices;

class TestSizeScan
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

    static IntPtr MakeAttrList(uint count)
    {
        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, count, 0, ref size);
        IntPtr list = Marshal.AllocHGlobal(size);
        InitializeProcThreadAttributeList(list, count, 0, ref size);
        return list;
    }

    static void Main()
    {
        IntPtr sid;
        int hr = CreateAppContainerProfile("aegis-test", "t", "t", IntPtr.Zero, 0, out sid);
        Console.WriteLine("[profile] hr=0x" + hr.ToString("X8") + " sid=0x" + sid.ToInt64().ToString("X"));
        if (hr != 0) return;

        // 64-byte buffer, zeroed, sid at offset 0
        IntPtr buf = Marshal.AllocHGlobal(64);
        for (int i = 0; i < 64; i += 8) Marshal.WriteInt64(buf, i, 0);
        Marshal.WriteIntPtr(buf, sid);

        int[] sizes = { 8, 16, 20, 24, 28, 32, 40, 48 };
        foreach (int s in sizes)
        {
            IntPtr list = MakeAttrList(1);
            bool ok = UpdateProcThreadAttribute(list, 0, new IntPtr(0x20011), buf, new IntPtr(s), IntPtr.Zero, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            Console.WriteLine("cbSize=" + s.ToString().PadLeft(2) + " -> ok=" + ok + " err=" + err);
            DeleteProcThreadAttributeList(list);
            if (ok) { Console.WriteLine(">>> FOUND working cbSize=" + s); break; }
        }

        Marshal.FreeHGlobal(buf);
        DeleteAppContainerProfile("aegis-test");
    }
}
