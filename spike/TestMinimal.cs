using System;
using System.Runtime.InteropServices;

class TestMinimal
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr l, uint c, uint f, ref IntPtr s);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr l, uint f, IntPtr a, IntPtr v, IntPtr cb, IntPtr pv, IntPtr pr);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr l);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetCurrentProcess();

    const uint PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
    const uint PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020011;

    static void Main()
    {
        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
        IntPtr attrList = Marshal.AllocHGlobal(size);
        bool initOk = InitializeProcThreadAttributeList(attrList, 2, 0, ref size);
        Console.WriteLine("[attrlist] init ok=" + initOk + " size=" + size);

        // Test 1: PARENT_PROCESS (simple HANDLE, cbSize = IntPtr.Size)
        IntPtr hProc = GetCurrentProcess();
        IntPtr hPtr = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(hPtr, hProc);
        bool t1 = UpdateProcThreadAttribute(attrList, 0, new IntPtr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS), hPtr, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero);
        Console.WriteLine("[test1 PARENT_PROCESS] ok=" + t1 + " err=" + Marshal.GetLastWin32Error());
        Marshal.FreeHGlobal(hPtr);

        DeleteProcThreadAttributeList(attrList);
    }
}
