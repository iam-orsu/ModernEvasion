using System;
using System.Runtime.InteropServices;

namespace ThreatCheck;

internal static class NativeMethods
{
    [DllImport("amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
    public static extern int AmsiInitialize(
        [MarshalAs(UnmanagedType.LPWStr)] string appName, 
        out IntPtr amsiContext);

    [DllImport("amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
    public static extern int AmsiOpenSession(
        IntPtr amsiContext, 
        out IntPtr session);

    [DllImport("amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
    public static extern void AmsiCloseSession(
        IntPtr amsiContext, 
        IntPtr session);

    [DllImport("amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
    public static extern void AmsiUninitialize(
        IntPtr amsiContext);

    [DllImport("amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
    public static extern int AmsiScanBuffer(
        IntPtr amsiContext, 
        byte[] buffer, 
        uint length,
        [MarshalAs(UnmanagedType.LPWStr)] string contentName,
        IntPtr session, 
        out AmsiResult result);

    public enum AmsiResult
    {
        AmsiResultClean = 0,
        AmsiResultNotDetected = 1,
        AmsiResultDetected = 32768
    }
}