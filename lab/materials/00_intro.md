# Windows 11 Defender Evasion - C# from Scratch

## What This Curriculum Is and What It Is Not

This is a hands-on curriculum that teaches you to write C# programs that execute on a fully updated Windows 11 machine without Windows Defender stopping them. You will write real code, compile it, transfer it to a Windows target, and run it while Defender is fully active with default settings. Every technique you learn here is tested against production Defender, not a stripped-down version with protections turned off.

This is not a theoretical course. You will not read about evasion and then move on. You will write 8 working loaders, each one targeting a specific Defender detection layer, and you will test every single one in a live environment. When something gets caught, you will understand exactly which bytes Defender flagged and why, and you will modify the code until it passes.

This is also not a "disable Defender and run your payload" course. Anyone can turn off an antivirus. That is not a skill. On a real engagement, you cannot ask the client to disable their security products. The entire point is to write code that works while Defender is doing its job. That is what separates a red team operator who gets hired from someone who just runs other people's tools.

## Why C# and Not Python, Go, Rust, or C++

This is a question you should be asking, because the language you write your tooling in has a direct effect on whether it works on a real target and whether companies will hire you to do this work. Here is why C# is the right choice for Windows evasion in 2026:

**C# runs natively on every Windows machine.** Every Windows 11 installation comes with the .NET runtime pre-installed. When you compile a C# program, the target machine can run it without installing anything extra. If you wrote your loader in Python, you would need Python installed on the target. If you wrote it in Go or Rust, you would produce a standalone binary, but it would not have native access to the .NET runtime that is already sitting on the target. C# code runs on the same runtime that Microsoft's own tools use, which means your loader looks like a normal .NET application from the operating system's perspective.

**C# has direct access to the Windows API through P/Invoke.** P/Invoke (Platform Invocation Services) is a feature of .NET that lets you call any Windows API function directly from C# code. This matters because evasion requires calling low-level Windows functions like VirtualAlloc (to allocate memory), WriteProcessMemory (to write code into another process), and NtCreateThreadEx (to start a new thread). In C, you call these functions directly. In C#, P/Invoke gives you the same direct access without needing to write C. You get the power of low-level system programming with the speed and safety of a managed language.

**C# is what real offensive tools are written in.** Cobalt Strike's execute-assembly feature runs .NET assemblies in memory. Covenant, Sliver's .NET modules, SharpCollection, GhostPack (Rubeus, Seatbelt, SharpUp, Certify, SharpHound) are all C#. When you go to a job interview for a red team position, they will ask you about .NET offensive tooling. If you say "I write my tools in Python", you are telling them you cannot operate on Windows targets without installing dependencies. If you say "I write custom C# loaders that bypass Defender using direct syscalls and dynamic API resolution", you are speaking their language.

**C# gives you access to .NET reflection and in-memory execution.** The .NET runtime can load and execute assemblies (compiled .NET programs) entirely in memory, without ever writing them to disk. This is a massive advantage for evasion because Defender's strongest detection layer is file scanning. If your payload never touches the disk, Defender's file scanner never sees it. C# gives you System.Reflection.Assembly.Load() which loads a .NET assembly from a byte array in memory. No other mainstream language has this built into its standard runtime.

**C# compiles to MSIL, not native code, which creates specific evasion challenges you need to understand.** When you compile a C# program, it does not produce machine code like C or Rust. It produces MSIL (Microsoft Intermediate Language), which is a higher-level instruction set that the .NET runtime compiles to native code at execution time (this is called JIT, Just-In-Time compilation). This means your compiled binary contains metadata: class names, method names, string literals, and type information. Defender and other security products scan this metadata. If your class is called "ShellcodeInjector" and your method is called "InjectMalware", those strings are sitting in plain text in the compiled binary. Understanding how .NET metadata works and how to control what ends up in your binary is a critical evasion skill that only matters when you write in C#.

**The job market demands C#.** Look at any red team job posting from CrowdStrike, Mandiant, Palo Alto Unit 42, SpecterOps, TrustedSec, or NetSPI. The required skills section lists C# and .NET offensive development. The reason is simple: enterprise environments run Windows, Windows runs .NET, and the most effective offensive tools for Windows are written in C#. If you want a red team job that pays $150K-$220K+, C# evasion development is not optional. It is the core skill.

## What Windows Defender Actually Does (The Detection Layers You Will Beat)

To write code that bypasses Defender, you need to understand what Defender actually does when a program runs on a Windows 11 machine. Defender is not one single check. It is multiple detection layers running simultaneously, each watching for different things. Your code needs to bypass all of them at the same time.

**Layer 1: Static File Scanning.** When a file is created, downloaded, copied, or modified on the hard drive, Defender scans it immediately. This scan compares the file's bytes against a database of known malicious signatures. A signature is a specific sequence of bytes that Defender knows belongs to malware. For example, msfvenom's default reverse shell payload has specific byte patterns that Defender's signature database recognizes. If your file contains those bytes, Defender quarantines it before you can even run it. This is the first layer and the easiest to bypass. If you XOR-encrypt your shellcode before putting it on disk, the encrypted version has completely different bytes, and Defender's signatures do not match. That is what Loader 02 teaches.

**Layer 2: Cloud-Based Analysis (Microsoft Defender SmartScreen and Cloud Protection).** When Defender sees a file it does not recognize, it sends a hash of that file (a unique fingerprint, not the file itself) to Microsoft's cloud servers. The cloud has a much larger database of malicious samples and can run machine learning models that detect suspicious characteristics. If the cloud says the file is malicious, Defender blocks it even if the local signature database did not catch it. Cloud analysis looks at things like: is this a very small executable that imports VirtualAlloc and CreateThread? Is this a .NET assembly with obfuscated method names? Has this exact hash been seen on other machines that got compromised? This layer is harder to bypass because it uses behavior patterns, not just byte signatures.

**Layer 3: AMSI (Antimalware Scan Interface).** AMSI is a scanning interface that sits between scripting engines (PowerShell, VBScript, JavaScript, .NET) and Defender. When you run a PowerShell command, PowerShell sends the command text to AMSI before executing it. AMSI passes that text to Defender, and Defender scans it for malicious content. If Defender flags it, the command is blocked. This matters because many red team tools work through PowerShell or load .NET assemblies at runtime. Even if your .exe is not flagged on disk, the moment it runs a PowerShell command or loads a .NET assembly, AMSI scans that content and can block it. Loader 04 patches AMSI in memory so it stops scanning, which means your subsequent PowerShell commands and .NET loads are not checked.

**Layer 4: API Hooking (User-Mode Hooks on ntdll.dll).** This is where Defender gets sophisticated. When your program calls a Windows API function like VirtualAlloc or CreateRemoteThread, the call goes through ntdll.dll, which is the lowest user-mode DLL before the kernel. Defender (and EDR products) can place hooks on these functions inside ntdll.dll. A hook is a patch that redirects the function call through Defender's code first, so Defender can inspect what you are doing before the function actually executes. For example, if you call VirtualAlloc with PAGE_EXECUTE_READWRITE permissions (meaning you want memory that is both writable and executable), Defender's hook sees that and flags it as suspicious because legitimate programs rarely need executable writable memory. Loader 03 teaches direct syscalls, which skip ntdll.dll entirely and call the Windows kernel directly, bypassing all user-mode hooks.

**Layer 5: ETW (Event Tracing for Windows).** ETW is a telemetry system built into Windows. Every process generates ETW events that describe what it is doing: which DLLs it loaded, which API calls it made, which memory regions it allocated, which threads it created. Defender and EDR products consume these events in real time to detect suspicious behavior patterns. Even if your code bypasses file scanning, AMSI, and API hooks, the ETW events still report what your process did. If Defender sees a sequence like "process allocated RWX memory, wrote shellcode-sized data, changed protection to executable, created a thread at that address", it recognizes that pattern as shellcode injection and flags it. Loader 07 patches the EtwEventWrite function in ntdll.dll so it returns immediately without writing any events. After the patch, your process goes dark from Defender's telemetry perspective.

**Layer 6: Behavioral Analysis and Machine Learning.** Defender runs behavioral models that look at what a process does over time. These models check for patterns like: did this process create a suspended process and then write to its memory? Did it modify the protection of a memory region from writable to executable? Did it call QueueUserAPC on a suspended thread? These are not signature matches. They are behavioral patterns that machine learning models have been trained to recognize as malicious. This is the hardest layer to bypass because you cannot just change your bytes. You need to change your behavior. The combined evasion loader (Loader 08) addresses this by using legitimate-looking execution patterns: allocating memory as RW first and then changing to RX (which is what normal programs do), using NT functions that are not hooked, and clearing evidence from managed memory after use.

Understanding these 6 layers is the foundation of everything in this curriculum. Each loader you build targets one or more of these layers, and the final loader combines all the bypasses into a single program.

## What You Will Build (The 8 Loaders, In Depth)

Each loader is a standalone C# program that demonstrates a specific evasion technique. The loaders are ordered so each one builds on what you learned in the previous one.

**Loader 01 - Basic Shellcode Loader (lab/loaders/01_shellcode_loader.cs)**

This is your first working loader. It reads raw shellcode from a file, allocates a block of executable memory using VirtualAlloc, copies the shellcode into that memory, and creates a thread that starts executing at the shellcode's address. The shellcode runs entirely in memory and never writes itself to disk.

This loader is intentionally basic and Defender WILL catch it. The reason it gets caught teaches you something critical: the loader's compiled binary contains strings like "shellcode", it uses VirtualAlloc with executable permissions in a suspicious pattern, and the shellcode file on disk matches known Metasploit signatures. You need to see what getting caught looks like before you can understand what evasion looks like.

What you learn from this loader:
- How VirtualAlloc works (requesting memory from the operating system)
- How Marshal.Copy works (copying bytes from a managed array into unmanaged memory)
- How CreateThread works (telling the processor to start executing code at a specific memory address)
- Why the shellcode file on disk gets flagged (Defender's static signatures match Metasploit output)
- Why the binary itself gets flagged (suspicious API import pattern + string metadata)

**Loader 02 - XOR Encoder/Decoder (lab/loaders/02_xor_encoder.cs)**

This loader has two modes. In encoder mode, it takes raw shellcode and XOR-encrypts it with a key you provide, producing an encrypted file that looks like random data. In decoder/loader mode, it reads the encrypted file, decrypts it in memory using the same XOR key, and executes the decrypted shellcode.

XOR encryption is the simplest form of encoding, but it is effective against static signature scanning. Defender's signature database contains byte patterns from known payloads. When you XOR every byte of the shellcode with a key, every byte changes. The encrypted file does not match any signature because the byte sequence is completely different from the original. When the loader runs, it decrypts the shellcode in memory (where Defender's file scanner cannot see it) and then executes it.

What you learn from this loader:
- How XOR encryption works (each byte is combined with a key byte using the XOR operation, and applying XOR again with the same key restores the original byte)
- Why encrypted shellcode bypasses static signatures (the byte patterns Defender looks for no longer exist in the file)
- The difference between on-disk representation and in-memory representation (encrypted on disk, decrypted only in memory)
- Why XOR alone is not enough (Defender has other detection layers beyond file scanning)

**Loader 03 - Direct Syscalls Loader (lab/loaders/03_direct_syscalls_loader.cs)**

When a C# program calls a Windows API function like VirtualAlloc, the call goes through this chain: your code -> kernel32.dll -> ntdll.dll -> kernel (via syscall instruction). Defender places hooks in ntdll.dll, which means it can intercept and inspect every API call your program makes. Direct syscalls skip the entire chain and call the kernel directly using the syscall assembly instruction with the correct syscall number.

This loader resolves NT function addresses dynamically at runtime (so the binary's import table does not contain suspicious function names), reads the syscall numbers from the function prologues, and executes the syscalls directly. From Defender's perspective, the API hooks in ntdll.dll are never triggered because the program never calls through ntdll.dll.

What you learn from this loader:
- How the Windows API call chain works (user code -> kernel32 -> ntdll -> kernel)
- What a syscall number is (each kernel function has a unique number that changes between Windows versions)
- Why Defender hooks ntdll.dll and not kernel32.dll (ntdll.dll is the last user-mode stop before the kernel)
- How to read syscall numbers from ntdll.dll function prologues at runtime
- How dynamic API resolution works (resolving function addresses at runtime instead of declaring them as imports)

**Loader 04 - AMSI Bypass (lab/loaders/04_amsi_bypass.cs)**

AMSI (Antimalware Scan Interface) is loaded into every process that uses .NET, PowerShell, VBScript, or JavaScript. The key function is AmsiScanBuffer in amsi.dll. When a script or .NET assembly is about to execute, the runtime calls AmsiScanBuffer with the content. AmsiScanBuffer passes the content to Defender, which returns a verdict (clean or malicious).

This loader patches AmsiScanBuffer in memory by overwriting its first few bytes with instructions that immediately return a "clean" result without actually scanning anything. After the patch, every call to AmsiScanBuffer returns AMSI_RESULT_CLEAN, so Defender never sees the content that was supposed to be scanned.

The function names ("AmsiScanBuffer", "amsi.dll") are not stored as plain strings in the binary. They are constructed at runtime using integer arithmetic, so Defender's static scanner cannot find them by searching for known AMSI bypass strings.

What you learn from this loader:
- How AMSI works at the function level (which DLL, which function, what the parameters are)
- What memory patching means (overwriting a function's code in memory to change its behavior)
- Why you need to change memory protection before patching (code pages are read-only by default, you need VirtualProtect to make them writable)
- How to construct strings at runtime to avoid static detection (integer offset arithmetic)
- Why AMSI patching should happen AFTER ETW patching (the AMSI patch itself generates ETW events that Defender can see)

**Loader 05 - Reflective Injector (lab/loaders/05_reflective_injector.cs)**

Instead of running your code in your own process (which Defender is watching), this loader writes your code into the memory of another process that is already running. You pick a legitimate process like explorer.exe or svchost.exe, open a handle to it, allocate memory inside it, write your shellcode into that memory, and create a thread in that process to execute it.

The result is that your shellcode runs inside a trusted system process. In Task Manager, only explorer.exe or svchost.exe shows up. Your loader process can exit immediately after injection. From Defender's behavioral analysis perspective, the suspicious activity (memory allocation, shellcode execution) is happening inside a process that Defender expects to see running.

What you learn from this loader:
- How OpenProcess gives you a handle to another process's memory space
- How VirtualAllocEx allocates memory inside another process (the "Ex" means external)
- How WriteProcessMemory copies bytes from your process into another process
- How CreateRemoteThread creates a thread inside another process that starts executing at the address where you wrote your shellcode
- Why running inside a legitimate process provides cover (process reputation and expected behavior)

**Loader 06 - Early Bird APC Injection (lab/loaders/06_process_hollowing_alt.cs)**

Classic process hollowing (creating a process, unmapping its image, replacing it with malicious code) is heavily detected. Defender specifically watches for the NtUnmapViewOfSection + write + resume pattern. Early Bird APC injection achieves the same goal through a different mechanism.

This loader creates a legitimate Windows process (like svchost.exe) in a SUSPENDED state using CreateProcess with the CREATE_SUSPENDED flag. The process exists but has not executed a single instruction yet. The loader allocates memory inside this suspended process, writes shellcode into it, and queues the shellcode address as an APC (Asynchronous Procedure Call) on the process's main thread. When the loader resumes the thread, Windows processes the queued APC first, which means your shellcode executes before the legitimate program's own code ever runs.

The name "Early Bird" comes from the fact that your code runs at the very beginning of the process's life, before the process has loaded its own DLLs or initialized its own data. This makes it extremely difficult for behavioral analysis to distinguish your code from the legitimate process's initialization.

What you learn from this loader:
- How CREATE_SUSPENDED works (the process is created but its main thread is paused)
- What an APC is (a function that Windows queues to run on a specific thread when that thread enters an alertable state)
- Why a suspended thread is in an alertable state by default (making it a perfect APC target)
- How this differs from process hollowing (no image unmapping, no suspicious NtUnmapViewOfSection call)
- Why this is harder to detect than CreateRemoteThread (APCs are a normal Windows mechanism used by legitimate system code)

**Loader 07 - ETW Patch (lab/loaders/07_etw_patch.cs)**

ETW is the telemetry backbone of Windows. Every process generates ETW events through the EtwEventWrite function in ntdll.dll. Security products (Defender, CrowdStrike Falcon, SentinelOne, Carbon Black) consume these events to detect suspicious behavior. Even if your shellcode bypasses file scanning, AMSI, and API hooks, the ETW events still report what your process did.

This loader patches EtwEventWrite the same way Loader 04 patches AmsiScanBuffer: it overwrites the function's first bytes with instructions that return success immediately without actually writing any events. After the patch, every call to EtwEventWrite in your process returns STATUS_SUCCESS but does nothing. No events are generated, so security products receive no telemetry from your process.

The patch bytes (xor eax, eax; ret) set the return value to 0 (STATUS_SUCCESS) and return immediately. The calling code thinks the event was written successfully, but nothing was actually logged.

This loader is designed to run FIRST, before any other evasion technique. If you patch AMSI first and then patch ETW, the AMSI patching generates ETW events that Defender sees. If you patch ETW first, then patch AMSI, the AMSI patching is invisible because ETW is already dead.

What you learn from this loader:
- What ETW is and why it matters for detection (the telemetry system feeding Defender and EDR)
- Which function to patch (EtwEventWrite in ntdll.dll)
- Why the execution order matters (ETW first, then AMSI, then everything else)
- How the patch works at the assembly level (xor eax, eax sets return value to 0, ret returns from the function)
- The limitation of user-mode ETW patching (kernel-mode ETW via the Microsoft-Windows-Threat-Intelligence provider cannot be patched from user mode)

**Loader 08 - Combined Evasion Loader (lab/loaders/08_combined_evasion.cs)**

This is the final loader. It combines every technique from Loaders 01 through 07 into a single program that executes in the correct order for maximum stealth:

1. Patch ETW (silence telemetry so nothing that follows is logged)
2. Patch AMSI (disable content scanning so .NET and PowerShell payloads are not checked)
3. Read and XOR-decrypt the shellcode in memory (nothing malicious exists on disk)
4. Resolve NT functions dynamically using GetProcAddress and integer arithmetic for function names (no suspicious strings or imports in the binary)
5. Allocate memory as PAGE_READWRITE first, write the shellcode, then change protection to PAGE_EXECUTE_READ (the two-step allocation avoids the RWX flag that behavioral analysis watches for)
6. Execute via NtCreateThreadEx for local execution, or write into a remote process for injection

Every API name that would normally appear in the binary's import table is resolved dynamically at runtime. The binary's metadata uses neutral names (the compiled assembly is called "stealth_runner", not "combined_evasion"). All string literals in Console.WriteLine messages use generic terms instead of evasion terminology.

What you learn from this loader:
- How to layer multiple evasion techniques in the correct order
- Why order matters (ETW before AMSI, decryption before execution)
- How dynamic API resolution eliminates suspicious imports from the PE import table
- How to build function name strings at runtime using integer offset arithmetic
- How the two-step memory allocation (RW then RX) avoids behavioral detection
- How all the individual techniques combine into something that defeats multiple Defender layers simultaneously

## How This Gets You a Red Team Job

This is not just a coding exercise. Every technique in this curriculum maps directly to skills that red team job postings require and that interviewers test for. Here is how:

**Custom tooling development.** Every serious red team job posting lists "ability to develop custom tools" or "C#/.NET offensive development" as a required skill. Companies like CrowdStrike, Mandiant, SpecterOps, TrustedSec, NetSPI, and Praetorian want operators who can write their own tools, not operators who only run Cobalt Strike or Metasploit. When Defender catches a public tool, operators who can only run public tools are stuck. Operators who can write custom loaders adapt and keep going. After this curriculum, you can write custom loaders from scratch.

**Understanding Defender internals.** Interview questions for red team positions often include "explain how AMSI works and how you would bypass it" or "what is ETW and why does it matter for detection" or "describe the Windows API call chain from user mode to kernel mode." This curriculum teaches you the actual mechanism behind each of these, not just the bypass. You will understand the detection, the evasion, and the trade-offs.

**Threat validation and OPSEC.** Red team operators need to test their tools before using them on a real engagement. "Did you test this against Defender before running it on the client's network?" is a question you should always be able to answer yes to. This curriculum teaches you how to scan your binaries with YARA rules, strings analysis, and PE metadata inspection to identify exactly which bytes get flagged and how to fix them. That is the OPSEC (operational security) discipline that separates professional operators from script kiddies.

**Portfolio evidence.** After completing this curriculum, you will have 8 working loaders on your GitHub that demonstrate real evasion techniques with teaching comments explaining every line. This is concrete evidence of your skills that a hiring manager can read and evaluate. "I wrote a custom C# loader that uses direct syscalls and dynamic API resolution to bypass Defender on a fully updated Windows 11 machine" is a stronger interview answer than "I used Cobalt Strike."

**The salary difference is real.** Entry-level security analysts who run vulnerability scanners make $70K-$90K. Red team operators who can write custom evasion tooling in C# make $150K-$220K+ in the US market, and $125-$150/hr as contractors. The difference is the ability to develop custom tools that work against modern detection. That is exactly what this curriculum teaches.

## Prerequisites

You do not need programming experience. Document 02 teaches C# from scratch. But you do need:

**Required knowledge:**
- Basic computer literacy (installing software, navigating folders, using a terminal)
- You know what an IP address is and what a port is
- You have used Windows before (you know what Task Manager is, how to run programs from the command line)

**Required hardware:**
- A computer with at least 16 GB of RAM (two VMs run simultaneously)
- At least 100 GB free disk space
- A processor with virtualization support (Intel VT-x or AMD-V, nearly all modern CPUs)

**Required software (installed in Document 01):**
- VMware Workstation Pro (free for personal use)
- Windows 11 Pro ISO (free from Microsoft)
- Kali Linux ISO (free from kali.org)
- Visual Studio 2022 Community (free, installed on the Windows VM)
- .NET 6 SDK or later (installed with Visual Studio)

## Lab Environment

The lab is two virtual machines on an isolated network:

```
Lab Network: 192.168.10.0/24

[Your Host Machine]
      |
  [VMware Pro]
      |
      +--- [Windows 11 VM: 192.168.10.100]
      |      - Fully updated, all patches applied
      |      - Defender ON: real-time scanning, cloud protection,
      |        automatic updates, AMSI, ETW - everything at default
      |      - Visual Studio 2022 Community installed
      |      - .NET 8 SDK (or latest)
      |      - Username: kimjongun
      |      - This is the TARGET machine where loaders run
      |
      +--- [Kali Linux VM: 192.168.10.200]
             - Latest Kali build
             - msfvenom (generates shellcode payloads)
             - python3 (hosts files for transfer via HTTP)
             - smbclient (transfers files via Windows shares)
             - This is the ATTACKER machine where payloads are created
```

Defender stays enabled with default settings for the entire curriculum. You never disable it, never add exclusions, never weaken any setting. The curriculum teaches evasion against production Defender, not a gimped version.

## Curriculum Structure (11 Documents)

| Document | Title | What You Learn |
|----------|-------|----------------|
| 00 | Introduction (this) | Why C#, how Defender works, what you will build, how this gets you hired |
| 01 | Lab Setup | Build Windows 11 and Kali VMs, install all tools, verify networking |
| 02 | C# Basics | Variables, types, loops, functions, arrays, byte manipulation - taught through security examples, not textbook exercises |
| 03 | Windows API | P/Invoke, DllImport, calling VirtualAlloc/CreateThread from C#, how .NET talks to the Windows kernel |
| 04 | Memory Fundamentals | Process memory layout, virtual memory, VirtualAlloc, WriteProcessMemory, memory protection flags, thread creation |
| 05 | Shellcode Loader | Generate shellcode with msfvenom, build Loader 01, understand why Defender catches it, learn what to fix |
| 06 | Encoding Evasion | XOR encryption, build Loader 02, encrypt shellcode on disk, decrypt at runtime, bypass static signatures |
| 07 | Direct Syscalls | Windows API call chain, syscall numbers, build Loader 03, bypass Defender's ntdll.dll hooks |
| 08 | AMSI Bypass | How AMSI scans .NET and PowerShell, build Loader 04, patch AmsiScanBuffer in memory |
| 09 | Reflective Injection | Process injection, build Loaders 05 and 06, inject into remote processes, Early Bird APC |
| 10 | Combined Evasion | Build Loader 08 (ETW + AMSI + XOR + dynamic resolution + NT functions), all layers combined |
| 11 | Real World Scenarios | How these techniques work in actual red team engagements, what works against EDR, operational planning |

**Do them in order.** Each document assumes you have completed the previous ones. Document 07 (Direct Syscalls) references memory allocation from Document 04. Document 10 (Combined Evasion) combines everything from Documents 05 through 09. Skipping ahead means the code and explanations will not make sense.

## How Each Document Teaches Code

Every document uses the same teaching method. You never see a full program dumped on you at once. Instead:

1. You see 2-3 lines of code
2. The document explains what those lines do, why they are needed, and what happens when they run
3. You see the next 2-3 lines with the same treatment
4. This continues until the entire program is covered
5. Then the complete program is shown in full so you see how all the pieces connect

Every technical term is explained the first time it appears. When a document says "VirtualAlloc", it explains that VirtualAlloc is a Windows function that asks the operating system to reserve a block of memory for your program to use, and it explains what the parameters mean and why you pass the values you pass. Nothing is assumed.

## Folder Structure

```
lab/
  loaders/           <- All 8 C# loader source files with teaching comments
    01_shellcode_loader.cs
    02_xor_encoder.cs
    03_direct_syscalls_loader.cs
    04_amsi_bypass.cs
    05_reflective_injector.cs
    06_process_hollowing_alt.cs
    07_etw_patch.cs
    08_combined_evasion.cs
  materials/          <- These 11 teaching documents
    00_intro.md  through  11_real_world_scenarios.md
  scripts/            <- Helper scripts for testing and validation
```

## Rules

**1. Defender stays on.** If your code gets caught, that is data. Fix your code, not Defender. Disabling Defender is not evasion.

**2. Lab only.** Every loader runs in your isolated lab. Do not run any of this on machines you do not own and do not have explicit written permission to test.

**3. Understand every line.** Each loader is explained line by line so you understand the mechanism. Copy-pasting without understanding means you cannot adapt when Defender updates its signatures.

**4. Test everything.** After building each loader, run it in the Windows 11 VM with Defender active. Verify it works. If it gets caught, understand why and fix it.

**5. Signatures change.** Defender updates regularly. A technique that works today might get caught next month. The goal is understanding the mechanism so you can develop new bypasses when current ones stop working. That adaptability is the actual skill.

## What Comes Next

Start with Document 01 (lab/materials/01_lab_setup.md). It walks you through building your Windows 11 and Kali VMs, installing Visual Studio and the .NET SDK, setting up the network, and verifying that everything works. No code until the lab is ready.
