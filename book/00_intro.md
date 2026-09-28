# Windows 11 Defender Evasion - C# from Scratch

## What This Curriculum Is and What It Is Not

This is a hands-on curriculum that teaches you to write C# programs that run on a fully updated Windows 11 machine without Windows Defender stopping them. You will write real code, compile it, transfer it to a Windows target, and run it while Defender is fully active with default settings.

Every technique you learn here is tested against production Defender, not a stripped-down version with protections turned off.

This is not a theoretical course. You will not read about evasion and move on. You will write 8 working loaders, each one targeting a specific Defender detection layer, and you will test every single one in a live environment. When something gets caught, you will understand exactly which bytes Defender flagged and why, and you will modify the code until it passes.

This is also not a "disable Defender and run your payload" course. Anyone can turn off an antivirus. That is not a skill. On a real engagement, you cannot ask the client to disable their security products. The entire point is to write code that works while Defender is doing its job. That is what separates a red team operator who gets hired from someone who just runs other people's tools.

## Why C# and Not Python, Go, Rust, or C++

The language you write your tooling in has a direct effect on whether it works on a real target and whether companies will hire you to do this work. Here is why C# is the right choice for Windows evasion in 2026.

### C# Runs Natively on Every Windows Machine

Every Windows 11 installation comes with the .NET runtime pre-installed. The .NET runtime is a program that runs C# code. When you compile a C# program, the target machine can run it without installing anything extra.

If you wrote your loader in Python, you would need Python installed on the target. C# code runs on the same runtime that Microsoft's own tools use, which means your loader looks like a normal .NET application from the operating system's perspective.

### C# Has Direct Access to the Windows API Through P/Invoke

The Windows API is the collection of functions that Windows provides for programs to call. P/Invoke is a C# feature that lets you call any of these Windows functions from your C# code.

This matters because evasion requires calling low-level Windows functions:

- **VirtualAlloc** - asks Windows for a chunk of RAM with specific permissions
- **WriteProcessMemory** - copies bytes into another running program's RAM
- **NtCreateThreadEx** - starts a new thread of execution

In C, you call these functions directly. In C#, P/Invoke gives you the same direct access without needing to write C.

### C# Is What Real Offensive Tools Are Written In

Cobalt Strike's execute-assembly feature runs .NET assemblies in memory. Covenant, Sliver's .NET modules, SharpCollection, GhostPack (Rubeus, Seatbelt, SharpUp, Certify, SharpHound) are all C#.

When you go to a job interview for a red team position, they will ask you about .NET offensive tooling. If you say "I write my tools in Python", you are telling them you cannot operate on Windows targets without installing dependencies. If you say "I write custom C# loaders that bypass Defender using direct syscalls and dynamic API resolution", you are speaking their language.

### C# Gives You In-Memory Execution

The .NET runtime can load and run compiled .NET programs entirely in RAM, without ever writing them to your hard drive. This is a huge advantage for evasion because Defender's strongest detection layer is file scanning, where it checks files on your hard drive.

If your payload never touches the hard drive, Defender's file scanner never sees it. C# gives you `System.Reflection.Assembly.Load()` which loads a compiled .NET program from a byte array sitting in RAM. No other mainstream language has this built into its standard runtime.

### C# Compiles to MSIL, Not Native Code

When you compile a C# program, it does not produce machine code like C or Rust. It produces something called **MSIL** (Microsoft Intermediate Language), which is a set of instructions that the .NET runtime converts to machine code when the program actually runs. This conversion is called **JIT** (Just-In-Time compilation).

Because your compiled binary contains MSIL and not machine code, it also contains **metadata**: class names, method names, string literals, and type information. All of this metadata is readable text sitting in the .exe file on your hard drive. You can open the compiled .exe in Notepad right now and you will literally see your class names, function names, and every quoted string sitting there as readable text inside all the garbage characters.

Defender opens that .exe file, reads the whole thing from start to end, and checks whether any of those names or strings match something in its database of known bad names. If your class is named "ShellcodeInjector" and your method is named "InjectMalware", Defender finds those words and flags the file. Understanding how .NET metadata works and how to control what ends up in your binary is a critical evasion skill.

### The Job Market Demands C#

Look at any red team job posting from CrowdStrike, Mandiant, Palo Alto Unit 42, SpecterOps, TrustedSec, or NetSPI. The required skills section lists C# and .NET offensive development.

Enterprise environments run Windows, Windows runs .NET, and the most effective offensive tools for Windows are written in C#. If you want a red team job that pays $150K-$220K+, C# evasion development is not optional. It is the core skill.

## What Windows Defender Actually Does (The Detection Layers You Will Beat)

To write code that bypasses Defender, you need to understand what Defender actually does when a program runs on a Windows 11 machine. Defender is not a single check. It is six detection layers running at the same time, each watching for different things. Your code needs to get past all of them at once.

### Layer 1: Static File Scanning

Your computer has a hard drive where all your files are stored, and it has **RAM** (Random Access Memory) which is a rectangular chip on your motherboard, about the size of a ruler, where programs run temporarily.

When a file is created, downloaded, copied, or modified on the hard drive, Defender scans it immediately. This scan compares the file's bytes against a database of known malicious byte sequences. Each known sequence is called a **signature**.

Here is what that means practically. The tool msfvenom (which you will use on Kali Linux to generate shellcode) produces a set of bytes. That specific set of bytes is in Defender's signature database. When you save those bytes as a file on the hard drive, Defender reads the file, finds those bytes, matches them against its database, and quarantines the file before you can even run it.

This is the first layer and the easiest to bypass. If you XOR-encrypt your shellcode before saving it as a file (XOR is a simple math operation that changes every byte), the encrypted version has completely different bytes. Defender's signatures do not match because the byte sequence is completely different. That is what Loader 02 teaches.

### Layer 2: Cloud-Based Analysis

When Defender sees a file it does not recognize from its local signature database, it creates a **hash** of the file. A hash is a unique number calculated from the file's bytes, like a fingerprint for files. Two files with even one byte different will have completely different hashes.

Defender sends this hash (not the file itself) to Microsoft's cloud servers over the internet. Microsoft's cloud has a much larger database of malicious samples and runs machine learning models that detect suspicious characteristics.

If the cloud says the file is malicious, Defender blocks it even though the local signature database did not catch it. Cloud analysis looks at things like:

- Is this a very small executable that calls VirtualAlloc and CreateThread?
- Is this a .NET program with scrambled method names?
- Has this exact hash been seen on other machines that got compromised?

This layer is harder to bypass because it looks at behavior patterns, not just specific byte sequences.

### Layer 3: AMSI (Antimalware Scan Interface)

PowerShell is a Windows tool where you type commands and it runs them. When you type a PowerShell command and press Enter, something happens before the command runs.

PowerShell sends the full text of your command to a system called **AMSI** (Antimalware Scan Interface). AMSI takes that text and passes it to Defender. Defender checks the text for anything malicious. If Defender says the text is malware, AMSI tells PowerShell to block the command. If Defender says the text is clean, PowerShell runs the command.

AMSI does not only check PowerShell. It checks VBScript, JavaScript, and .NET code too. So even if your .exe file passes the file scan, the moment your program runs PowerShell commands or loads .NET code at runtime, AMSI scans that content and can block it.

**How AMSI works internally:**

AMSI works through a DLL file called amsi.dll. A **DLL** (Dynamic Link Library) is a file containing compiled functions that programs can call. The key function inside amsi.dll is called AmsiScanBuffer. Every time AMSI needs to check something, it calls AmsiScanBuffer, which sends the content to Defender.

Loader 04 patches AmsiScanBuffer in your program's RAM so it immediately returns "this is clean" without actually sending anything to Defender.

### Layer 4: API Hooking

When your C# program calls a Windows function like VirtualAlloc (which asks Windows for a chunk of RAM), the call goes through a chain of DLL files before reaching the actual Windows **kernel**. The kernel is the core of the operating system that actually controls the hardware.

The chain looks like this:

```
Your code -> kernel32.dll -> ntdll.dll -> Windows kernel
```

kernel32.dll contains commonly used Windows functions. ntdll.dll is a lower-level DLL that sits right before the kernel. Every function in kernel32.dll calls a corresponding function in ntdll.dll to do the real work.

**What Defender does here:**

Defender inserts monitoring code at the start of functions inside ntdll.dll. This monitoring code is called a **hook**. When your program calls VirtualAlloc, kernel32.dll calls ntdll.dll, and before ntdll.dll does the actual work, Defender's hook runs first.

The hook checks what you are requesting. Are you asking for RAM that the CPU can execute code from? How much RAM? It logs this information and decides if it looks suspicious. Then it lets the real function run.

Loader 03 teaches **direct syscalls**, which skip ntdll.dll entirely and talk to the Windows kernel directly. If Defender's hooks are inside ntdll.dll and your program never calls ntdll.dll, the hooks never run.

### Layer 5: ETW (Event Tracing for Windows)

**ETW** stands for Event Tracing for Windows. It is a logging system built into Windows. Every running program generates ETW events that describe what it is doing:

- Which DLL files it loaded
- Which Windows functions it called
- Which chunks of RAM it requested
- Which threads it created

Defender and other security products read these events in real time. Even if your code bypasses file scanning, AMSI, and API hooks, the ETW events still report what your program did.

ETW works through a function called EtwEventWrite in ntdll.dll. Loader 07 patches this function the same way Loader 04 patches AmsiScanBuffer: it changes the first few bytes so it immediately returns without writing any events. After the patch, your program's activity is invisible to any security tool reading ETW events.

### Layer 6: Behavioral Analysis and Machine Learning

Defender runs machine learning models that watch what a program does over time. These models look for patterns:

- Did this program create a new process in a suspended state and then write data into its RAM?
- Did it change the permissions on a chunk of RAM from writable to executable?
- Did it queue an **APC** (Asynchronous Procedure Call, a special type of function call) on a suspended thread?

These are not signature matches. Defender is not looking for specific bytes. It is looking at the sequence of actions your program takes. Machine learning models have been trained on thousands of malware samples and know which action sequences are suspicious.

This is the hardest layer to bypass because you cannot just change your bytes. You need to change your **behavior**. The combined evasion loader (Loader 08) addresses this by following the same patterns that legitimate programs use: it requests RAM as read-write first (which is normal), copies data into it, then changes the permissions to execute-read (which is what legitimate programs that compile code at runtime also do).

### Why All Six Layers Matter

Understanding these 6 layers is the foundation of everything in this curriculum. Each loader you build targets one or more of these layers, and the final loader (Loader 08) combines all the bypasses into a single program that deals with all six layers at the same time.

## What You Will Build (The 8 Loaders)

Each loader is a standalone C# program that demonstrates a specific evasion technique. The loaders are ordered so each one builds on what you learned in the previous one.

---

### Loader 01 - Basic Shellcode Loader
**File:** `lab/loaders/01_shellcode_loader.cs`

This is your first working loader. It reads raw shellcode from a file, asks Windows for a chunk of RAM that the CPU can execute code from, copies the shellcode into that RAM, and creates a thread that starts running the shellcode. The shellcode runs entirely in RAM and never writes itself to the hard drive.

This loader is intentionally basic and **Defender WILL catch it**. The reason it gets caught teaches you something critical: the compiled binary contains names like "shellcode", it asks for executable RAM in a pattern Defender knows, and the shellcode file on the hard drive matches known Metasploit signatures.

What you learn:

- How VirtualAlloc works (asking Windows for a chunk of RAM)
- How Marshal.Copy works (copying bytes into that RAM)
- How CreateThread works (telling the CPU to start running code at a specific RAM address)
- Why the shellcode file on the hard drive gets flagged (Defender's static signatures match the bytes msfvenom produces)
- Why the binary itself gets flagged (suspicious function names in the import table plus string metadata)

---

### Loader 02 - XOR Encoder/Decoder
**File:** `lab/loaders/02_xor_encoder.cs`

This loader has two modes. In encoder mode, it takes raw shellcode and XOR-encrypts every byte with a key you provide, producing an encrypted file that looks like random data. In decoder/loader mode, it reads the encrypted file, XOR-decrypts it in RAM, and attempts to execute the decrypted shellcode.

XOR encryption solves one specific problem: the encrypted shellcode file no longer matches Defender's signature database. The raw msfvenom bytes that got Loader 01's shellcode quarantined on disk are now scrambled. Defender's static scanner cannot match what it cannot recognize.

**However, this loader still gets caught.** The loader binary itself still uses DllImport for VirtualAlloc and CreateThread (which puts those function names in the import table), and still uses PAGE_EXECUTE_READWRITE (0x40). Defender's behavioral detection and API hooks still see the injection pattern. XOR encryption defeats Layer 1 (static file scanning) but not the other five layers.

What you learn:

- How XOR encryption works (each byte is combined with a key byte using XOR, and applying XOR again with the same key restores the original byte)
- Why encrypted shellcode bypasses static signatures (the byte patterns Defender looks for do not exist in the encrypted file)
- The difference between what is on the hard drive and what is in RAM (encrypted on the hard drive, decrypted only in RAM)
- Why XOR alone is not enough (the encrypted file survives disk scanning, but the loader binary and its runtime behavior are still detected by Defender's other layers)

---

### Loader 03 - Direct Syscalls Loader
**File:** `lab/loaders/03_direct_syscalls_loader.cs`

When a C# program calls a Windows function like VirtualAlloc, the call goes through the chain: your code, then kernel32.dll, then ntdll.dll, then the kernel. Defender places hooks in ntdll.dll to monitor every call.

Direct syscalls skip the entire chain and call the kernel directly using the special **syscall** instruction that the CPU understands.

This loader finds NT function addresses while the program is running (so the compiled binary's import table does not contain suspicious function names), reads the syscall numbers from the function code, and executes the syscalls directly.

What you learn:

- How the Windows API call chain works (user code to kernel32 to ntdll to kernel)
- What a syscall number is (each kernel function has a unique number that changes between Windows versions)
- Why Defender hooks ntdll.dll and not kernel32.dll (ntdll.dll is the last stop before the kernel in user-mode code)
- How to read syscall numbers from ntdll.dll function code at runtime
- How dynamic API resolution works (finding function addresses while the program runs instead of declaring them in the import table)

---

### Loader 04 - AMSI Bypass
**File:** `lab/loaders/04_amsi_bypass.cs`

AMSI is loaded into every program that uses .NET, PowerShell, VBScript, or JavaScript. The key function is AmsiScanBuffer in amsi.dll. When a script or .NET code is about to run, the runtime calls AmsiScanBuffer with the content. AmsiScanBuffer passes the content to Defender, which returns a verdict (clean or malicious).

This loader patches AmsiScanBuffer in RAM by overwriting its first few bytes with instructions that immediately return a "clean" result without actually scanning anything.

The function names ("AmsiScanBuffer", "amsi.dll") are not stored as plain text in the .exe file on your hard drive. You can open that compiled .exe in Notepad and you will NOT see "AmsiScanBuffer" anywhere in the file. Instead, those names are built at runtime from integer arithmetic, assembled character by character in RAM only when the program runs. Defender's file scanner reads the .exe on your hard drive and finds nothing to match against.

What you learn:

- How AMSI works at the function level (which DLL, which function, what the parameters are)
- What memory patching means (overwriting a function's code in RAM to change its behavior)
- Why you need to change RAM permissions before patching (code in RAM is read-only by default, you need VirtualProtect to make it writable)
- How to build strings at runtime to avoid static detection (integer offset math)
- Why AMSI patching should happen AFTER ETW patching (the AMSI patch itself generates ETW events that Defender can read)

---

### Loader 05 - Reflective Injector
**File:** `lab/loaders/05_reflective_injector.cs`

Instead of running your code in your own program, this loader writes your code into the RAM of another program that is already running. You pick a program that Windows trusts, like explorer.exe (the desktop and taskbar) or svchost.exe (a system service host).

The process:

1. Open a connection to that program's RAM space
2. Allocate RAM inside it
3. Write your shellcode into that RAM
4. Create a thread inside that program to run it

This loader teaches the cross-process injection TECHNIQUE, but **Defender will catch this loader on its own.** It uses DllImport for WriteProcessMemory and CreateRemoteThread, which puts those function names in the import table. Defender watches for the OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread combination specifically. To use cross-process injection without getting caught, you need to combine it with dynamic API resolution and ETW/AMSI patching from Loaders 03, 04, and 07. Loader 08 (combined evasion) does exactly that.

What you learn:

- How OpenProcess gives you access to another program's RAM space
- How VirtualAllocEx allocates RAM inside another program (the "Ex" means external, meaning another program)
- How WriteProcessMemory copies bytes from your program into another program
- How CreateRemoteThread creates a thread inside another program that starts running your shellcode
- Why running inside a legitimate process provides cover (when combined with other evasion techniques)
- Why cross-process injection alone is not enough (Defender watches for the API combination)

---

### Loader 06 - Early Bird APC Injection
**File:** `lab/loaders/06_process_hollowing_alt.cs`

Classic process hollowing (creating a program, removing its code, replacing it with malicious code) is heavily detected. Defender specifically watches for that pattern. Early Bird APC injection achieves the same goal through a different path.

This loader creates a legitimate Windows program (like svchost.exe) in a **SUSPENDED** state. The program exists but has not executed a single instruction yet. It is frozen.

Then the loader:

1. Allocates RAM inside this frozen program
2. Writes shellcode into it
3. Queues the shellcode address as an **APC** (Asynchronous Procedure Call) on the program's main thread

An APC is a function that Windows queues to run on a specific thread. When the loader un-freezes the thread, Windows processes the queued APC first, which means your shellcode runs before the legitimate program's own code ever starts.

The name "Early Bird" comes from the fact that your code runs at the very beginning of the process's life, before the process has loaded its own DLL files.

Like Loader 05, **this loader on its own gets caught by Defender.** It uses DllImport for CreateProcess, VirtualAllocEx, WriteProcessMemory, and QueueUserAPC, which all show up in the import table. The CREATE_SUSPENDED + write + QueueUserAPC + ResumeThread sequence is a known injection pattern that Defender watches for. To use APC injection without getting caught, you combine it with the evasion techniques from Loaders 03, 04, and 07, which is what Loader 08 does.

What you learn:

- How CREATE_SUSPENDED works (the program is created but its main thread is frozen)
- What an APC is (a function that Windows queues to run on a specific thread)
- How this differs from process hollowing (no code removal, no suspicious NtUnmapViewOfSection call)
- Why the APC technique itself is less suspicious than CreateRemoteThread (APCs are a normal Windows mechanism), but the DllImport pattern still gets caught
- Why injection techniques need to be combined with evasion techniques (dynamic API resolution, ETW/AMSI patching) to actually work

---

### Loader 07 - ETW Patch
**File:** `lab/loaders/07_etw_patch.cs`

ETW is the logging system that feeds information to Defender and other security products. Every running program generates ETW events through the EtwEventWrite function in ntdll.dll. Even if your shellcode bypasses file scanning, AMSI, and API hooks, the ETW events still report what your program did.

This loader patches EtwEventWrite the same way Loader 04 patches AmsiScanBuffer: it overwrites the function's first bytes with instructions that return success immediately without actually writing any events.

**Execution order matters.** This loader is designed to run FIRST, before any other evasion technique. If you patch AMSI first and then patch ETW, the AMSI patching generates ETW events that Defender can read. If you patch ETW first, then patch AMSI, the AMSI patching is invisible because ETW is already silent.

What you learn:

- What ETW is and why it matters for detection (the logging system feeding Defender and every EDR product)
- Which function to patch (EtwEventWrite in ntdll.dll)
- Why the execution order matters (ETW first, then AMSI, then everything else)
- How the patch works (the patch bytes set the return value to 0, which means success, and return immediately)
- The limitation of this approach (kernel-mode ETW, which runs inside the Windows kernel itself, cannot be patched from a regular program)

---

### Loader 08 - Combined Evasion Loader
**File:** `lab/loaders/08_combined_evasion.cs`

This is the final loader. It combines every technique from Loaders 01 through 07 into a single program that runs in the correct order for maximum stealth:

1. **Patch ETW** - silence the logging system so nothing that follows gets logged
2. **Patch AMSI** - disable content scanning so .NET and PowerShell content is not checked
3. **Read and XOR-decrypt** the shellcode in RAM (nothing malicious exists on the hard drive)
4. **Dynamic API resolution** - find NT function addresses at runtime using GetProcAddress and integer math for function names (no suspicious strings in the compiled binary)
5. **Two-step RAM allocation** - request RAM as read-write first, write the shellcode, then change permissions to execute-read (avoids having RAM that is both writable and executable)
6. **Execute** - run the shellcode using NtCreateThreadEx for local execution, or write it into another program for injection

Every function name that would normally appear in the compiled binary's import table is found while the program runs instead. You can open the compiled .exe in Notepad and the import table shows only neutral function names — the real Windows function names like "NtAllocateVirtualMemory" and "NtCreateThreadEx" are never written into the file on your hard drive. All text output uses generic terms instead of evasion terminology.

What you learn:

- How to layer multiple evasion techniques in the correct order
- Why order matters (ETW before AMSI, decryption before execution)
- How dynamic API resolution keeps suspicious function names out of the compiled file
- How to build function name strings at runtime using integer offset math
- How the two-step RAM allocation (read-write then execute-read) avoids behavioral detection
- How all the individual techniques combine to defeat multiple Defender layers at the same time

## How This Gets You a Red Team Job

This is not just a coding exercise. Every technique in this curriculum maps directly to skills that red team job postings require and that interviewers test for.

**Custom tooling development.**
Every serious red team job posting lists "ability to develop custom tools" or "C#/.NET offensive development" as a required skill. Companies like CrowdStrike, Mandiant, SpecterOps, TrustedSec, NetSPI, and Praetorian want operators who can write their own tools.

When Defender catches a public tool, operators who can only run public tools are stuck. Operators who can write custom loaders adapt and keep going. After this curriculum, you can write custom loaders from scratch.

**Understanding Defender internals.**
Interview questions for red team positions often include:

- "Explain how AMSI works and how you would bypass it"
- "What is ETW and why does it matter for detection?"
- "Describe the Windows API call chain from user mode to kernel mode"

This curriculum teaches you the actual mechanism behind each of these, not just the bypass. You will understand the detection, the evasion, and the trade-offs.

**Threat validation and OPSEC.**
Red team operators need to test their tools before using them on a real engagement. "Did you test this against Defender before running it on the client's network?" is a question you should always be able to answer yes to.

This curriculum teaches you how to scan your binaries with YARA rules, strings analysis, and PE metadata inspection to identify exactly which bytes get flagged and how to fix them. That is the OPSEC (operational security) discipline that separates professional operators from script kiddies.

**Portfolio evidence.**
After completing this curriculum, you will have 8 working loaders on your GitHub that demonstrate real evasion techniques with teaching comments explaining every line. This is concrete evidence of your skills that a hiring manager can read and evaluate.

"I wrote a custom C# loader that uses direct syscalls and dynamic API resolution to bypass Defender on a fully updated Windows 11 machine" is a stronger interview answer than "I used Cobalt Strike."

**The salary difference is real.**
Entry-level security analysts who run vulnerability scanners make $70K-$90K. Red team operators who can write custom evasion tooling in C# make $150K-$220K+ in the US market, and $125-$150/hr as contractors. The difference is the ability to develop custom tools that work against modern detection. That is exactly what this curriculum teaches.

## Prerequisites

You do not need programming experience. Document 02 teaches C# from scratch. But you do need:

**Required knowledge:**
- Basic computer literacy (installing software, navigating folders, using a terminal)
- You know what an IP address is and what a port is
- You have used Windows before (you know what Task Manager is, how to run programs from the command line)

**Required hardware:**
- A computer with at least 24 GB of RAM (three VMs run at the same time)
- At least 150 GB free disk space
- A processor with virtualization support (Intel VT-x or AMD-V, nearly all modern CPUs have this)

**Required software (installed in Document 01):**
- VMware Workstation Pro (free for personal use)
- Windows 11 Pro ISO (free from Microsoft)
- Kali Linux ISO (free from kali.org)
- Visual Studio 2022 Community (free, installed on the dev box VM)
- .NET 6 SDK or later (installed with Visual Studio)

## Lab Environment

The lab is three virtual machines on an isolated network. This mirrors a real red team engagement where you have a separate machine for building your tools, a separate machine for generating payloads and running listeners, and the target machine where you test your tools against real defenses.

```
Lab Network: 192.168.10.0/24

[Your Host Machine]
      |
  [VMware Pro]
      |
      +--- [Dev Box: 192.168.10.150]
      |      - Windows 11 Pro
      |      - Visual Studio 2022 Community installed
      |      - .NET 8 SDK (or latest)
      |      - Defender DISABLED (so compiled loaders are not quarantined)
      |      - Username: ammulu
      |      - This is where you COMPILE loaders. No testing here.
      |
      +--- [Target: 192.168.10.100]
      |      - Windows 11 Pro, fully updated, all patches applied
      |      - Defender ON: real-time scanning, cloud protection,
      |        automatic updates, AMSI, ETW - everything at default
      |      - No dev tools installed (no Visual Studio, no .NET SDK)
      |      - Username: kimjongun
      |      - This is the TARGET machine where loaders RUN
      |
      +--- [Kali Attacker: 192.168.10.200]
             - Latest Kali build
             - msfvenom (generates shellcode payloads)
             - python3 (hosts files for transfer via HTTP)
             - smbclient (transfers files via Windows shares)
             - This is the ATTACKER machine where payloads are created
```

The workflow is: generate shellcode on Kali, transfer it to the dev box, compile the loader on the dev box, transfer the compiled binary and encrypted shellcode to the target, and run the loader on the target. This separation is realistic because in a real engagement you never compile your malware on the machine you are attacking.

Defender stays enabled with default settings on the target machine for the entire curriculum. You never disable it, never add exclusions, never weaken any setting.

## Curriculum Structure (11 Documents)

| Document | Title | What You Learn |
|----------|-------|----------------|
| 00 | Introduction (this) | Why C#, how Defender works, what you will build, how this gets you hired |
| 01 | Lab Setup | Build Windows 11 and Kali VMs, install all tools, verify networking |
| 02 | C# Basics | Variables, types, loops, functions, arrays, byte manipulation - taught through security examples |
| 03 | Windows API | P/Invoke, DllImport, calling VirtualAlloc/CreateThread from C#, how .NET talks to the Windows kernel |
| 04 | Memory Fundamentals | Process memory layout, virtual memory, VirtualAlloc, WriteProcessMemory, memory protection flags, thread creation |
| 05 | Shellcode Loader | Generate shellcode with msfvenom, build Loader 01, Defender catches it, understand exactly what was flagged |
| 06 | Encoding Evasion | XOR encryption, build Loader 02, encrypted file survives disk scanning but loader still gets caught by other layers |
| 07 | Direct Syscalls | Windows API call chain, syscall numbers, build Loader 03, bypass Defender's ntdll.dll hooks (first loader that survives) |
| 08 | AMSI Bypass | How AMSI scans .NET and PowerShell, build Loader 04 + Loader 07, patch AmsiScanBuffer and EtwEventWrite |
| 09 | Reflective Injection | Process injection techniques (Loaders 05 and 06), Defender catches these alone, learn the technique for combining later |
| 10 | Combined Evasion | Build Loader 08 (all techniques combined), first fully stealthy callback with Defender at default settings |
| 11 | Real World Scenarios | How these techniques work in actual red team engagements, what works against EDR, operational planning |

**Do them in order.** Each document assumes you have completed the previous ones. Document 07 (Direct Syscalls) references RAM allocation from Document 04. Document 10 (Combined Evasion) combines everything from Documents 05 through 09. Skipping ahead means the code and explanations will not make sense.

## How Each Document Teaches Code

Every document uses the same teaching method. You never see a full program dumped on you at once. Instead:

1. You see 2-3 lines of code
2. The document explains what those lines do, why they are needed, and what happens when they run
3. You see the next 2-3 lines with the same treatment
4. This continues until the entire program is covered
5. Then the complete program is shown in full so you see how all the pieces connect

Every technical term is explained the first time it appears. Nothing is assumed.

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

**4. Test everything.** After building each loader, transfer it to the target (kimjongun, 192.168.10.100) and run it with Defender active. Verify it works. If it gets caught, understand why and fix it.

**5. Signatures change.** Defender updates regularly. A technique that works today might get caught next month. The goal is understanding the mechanism so you can develop new bypasses when current ones stop working. That adaptability is the actual skill.

## What Comes Next

Start with Document 01 (lab/materials/01_lab_setup.md). It walks you through building all three VMs (target, dev box, and Kali), installing Visual Studio on the dev box, disabling Defender on the dev box, setting up the network, and verifying that everything works. No code until the lab is ready.
