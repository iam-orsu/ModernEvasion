# Internal Research Summary: Windows 11 Defender Evasion (September 2026)

This is an internal reference document. Not for students. Documents which techniques work, which are detected, and how each bypasses specific Defender mechanisms.

---

## 1. Windows Defender Detection Mechanisms (as of September 2026)

### What Defender Does

Defender runs multiple detection layers simultaneously:

**Real-Time Protection (RTP)**
- Scans every file on write and on execute
- Hooks user-mode APIs in ntdll.dll to monitor process behavior
- Monitors file system operations, registry changes, process creation
- Scans memory-mapped files and loaded DLLs

**Cloud-Delivered Protection**
- Samples are sent to Microsoft's cloud for analysis within seconds
- Telemetry from 1+ billion Windows devices feeds detection models
- A novel threat on one machine hardens all others within minutes
- Machine learning models trained on billions of samples

**Behavioral Analysis**
- Monitors runtime behavior of processes (not just static signatures)
- Detects suspicious API call sequences (VirtualAlloc + WriteProcessMemory + CreateThread is a known pattern)
- Watches for process injection patterns
- Monitors for AMSI/ETW tampering attempts

**AMSI (Antimalware Scan Interface)**
- Scans PowerShell commands before execution
- Scans .NET assembly loads
- Scans VBScript and JScript execution
- amsi.dll is loaded into every PowerShell process and .NET CLR host

**ETW (Event Tracing for Windows)**
- Provides telemetry to Defender and EDR products
- Logs process creation, thread creation, image loads, network connections
- EtwEventWrite in ntdll.dll writes events that Defender consumes
- Kernel-level ETW providers are harder to blind than user-mode ones

**Signature-Based Detection**
- Static file scanning against known malicious byte patterns
- YARA-like rule matching on disk and in memory
- Known shellcode signatures (msfvenom output is heavily signatured)
- Known API import patterns (VirtualAlloc + CreateThread combination is flagged)

### Defender Engine Version Notes
- Engine 1.1.25000+ has tamper protection that catches some AMSI patches
- Cloud protection can flag unknown binaries within minutes of first execution
- SmartScreen checks file reputation on download

---

## 2. Technique Analysis: What Works and What Gets Caught

### 2.1 Basic Shellcode Loader (VirtualAlloc + CreateThread)

**How it works:** Allocate executable memory with VirtualAlloc, copy shellcode bytes into that memory, create a thread pointing at that memory with CreateThread, wait for the thread to finish.

**What Defender catches:**
- Raw msfvenom shellcode bytes on disk (signature match)
- The VirtualAlloc(PAGE_EXECUTE_READWRITE) + CreateThread import combination is a known indicator
- Behavioral detection flags the allocate-write-execute pattern

**Evasion required:**
- Encrypt shellcode at rest (XOR minimum) so static signatures do not match
- Use dynamic API resolution (GetProcAddress or syscalls) instead of P/Invoke imports
- Consider staged loading: download shellcode at runtime instead of embedding
- Use VirtualProtect to change memory permissions after writing (allocate RW, write, change to RX)

**Status:** Detected without evasion. Works with XOR + dynamic resolution + delayed execution.

### 2.2 XOR Encoding/Decoding

**How it works:** XOR each byte of shellcode with a key before embedding in the binary. At runtime, XOR again with the same key to recover original shellcode. The encrypted payload on disk does not match any known signatures.

**What Defender catches:**
- Simple single-byte XOR is sometimes detected by heuristic analysis
- The XOR decryption loop pattern itself can be flagged if it follows known templates
- Cloud analysis may flag the binary after execution based on behavior

**Evasion required:**
- Use multi-byte XOR keys (not single byte)
- Randomize the key per build
- Add junk operations between XOR operations to break pattern matching
- Combine with other techniques (syscalls, delayed execution)

**Status:** XOR alone is marginal. XOR combined with syscalls and API obfuscation bypasses static and most heuristic detection.

### 2.3 Direct Syscalls

**How it works:** Instead of calling Windows API functions through ntdll.dll (where Defender places hooks), the code executes the syscall instruction directly with the correct System Service Number (SSN). This jumps straight into kernel mode without passing through any hooked functions.

**What Defender catches:**
- Defender's user-mode hooks are completely bypassed (they only exist in ntdll.dll)
- Kernel-mode ETW providers can still see the syscall
- The presence of syscall instructions in non-ntdll code is itself suspicious to some EDRs
- Static analysis can find embedded syscall stubs

**Evasion required:**
- Use indirect syscalls (jump into a legitimate syscall instruction inside ntdll.dll) to avoid having syscall instructions in your own code
- Resolve SSNs dynamically at runtime (not hardcoded, since they change between Windows versions)
- Combine with ETW patching to reduce kernel telemetry

**Current tools:**
- SysWhispers3: generates C/ASM stubs with indirect syscall support
- SysWhispers4: adds hardware breakpoint-based SSN resolution, ARM64 support, WoW64 support
- SharpWhispers: C# implementation of SysWhispers concepts
- Manual implementation in C# using delegates and GetProcAddress

**Status:** Direct syscalls bypass user-mode hooks reliably. Indirect syscalls are the current best practice to avoid the "syscall from non-ntdll module" detection.

### 2.4 AMSI Bypass

**How it works:** AMSI is implemented as amsi.dll loaded into every PowerShell process and .NET CLR host. The AmsiScanBuffer function is the main scanning entry point. By patching the first bytes of AmsiScanBuffer in memory to return a clean result immediately (return AMSI_RESULT_CLEAN), all subsequent scans in that process return clean without checking Defender.

**Patch approach:** Write bytes to the beginning of AmsiScanBuffer that make the function return 0 (clean) immediately. Common patches:
- `mov eax, 0x80070057; ret` (return E_INVALIDARG so AMSI thinks the scan failed and allows execution)
- `xor eax, eax; ret` (return S_OK with clean result)

**What Defender catches:**
- Defender tamper protection (engine 1.1.25000+) monitors for writes to amsi.dll memory
- Known patch byte sequences are signatured
- The string "AmsiScanBuffer" in your code triggers static detection
- ETW logs the tampering attempt

**Evasion required:**
- Resolve AmsiScanBuffer address dynamically (do not use the string directly in code)
- Obfuscate the patch bytes
- Patch ETW first so the tamper attempt is not logged
- Use indirect methods: hardware breakpoints on AmsiScanBuffer to modify return value via exception handler
- Use syscalls for the memory write (NtWriteVirtualMemory instead of WriteProcessMemory)

**Status:** Classic patch is detected. Obfuscated patch with ETW blinding and dynamic resolution still works.

### 2.5 NTDLL Unhooking

**How it works:** Defender and EDR products place inline hooks (detours) on ntdll.dll functions in your process. These hooks redirect API calls through Defender's monitoring code. Unhooking means restoring the original bytes of ntdll.dll so hooks are removed.

**Methods:**
1. **Fresh copy from disk:** Read ntdll.dll from C:\Windows\System32\ntdll.dll and overwrite the .text section of the in-memory copy with the clean bytes from disk
2. **Fresh copy from KnownDlls:** Map \KnownDlls\ntdll.dll using NtOpenSection + NtMapViewOfSection (avoids disk read that Defender monitors)
3. **Suspended process:** Create a suspended child process, read its clean ntdll.dll (hooks are not yet applied to suspended processes), use those bytes to unhook your own process
4. **Selective unhooking:** Only unhook specific functions you need rather than the entire .text section (less suspicious)

**What Defender catches:**
- Reading ntdll.dll from disk is monitored
- Overwriting large sections of ntdll.dll in memory can trigger behavioral detection
- The API pattern of NtOpenSection + NtMapViewOfSection targeting KnownDlls is known

**Evasion required:**
- Use the suspended process method (creates a legitimate-looking process)
- Selective unhooking only for functions you will call
- Combine with direct/indirect syscalls for the unhooking operations themselves

**Status:** Suspended process method with selective unhooking works. Full .text overwrite from disk is increasingly detected.

### 2.6 Reflective DLL Injection

**How it works:** Load a DLL entirely from memory without using LoadLibrary (which Defender monitors). The loader manually:
1. Allocates memory in the target process
2. Copies the DLL's PE headers and sections
3. Resolves imports (fixes the Import Address Table)
4. Applies relocations (adjusts addresses)
5. Calls DllMain

Because the DLL is never written to disk, Defender's file scanner never sees it.

**What Defender catches:**
- The API call pattern (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread) is heavily monitored
- Memory scanning can find known DLL signatures in process memory
- The injection target process (if it is a system process) triggers behavioral alerts

**Evasion required:**
- Use syscalls for memory operations instead of Win32 API
- Encrypt the DLL payload and decrypt in the target process
- Use APC injection or thread hijacking instead of CreateRemoteThread
- Target a process that normally loads many DLLs (not notepad.exe)

**Status:** Works with syscalls + encryption + careful target selection. Classic API approach is caught immediately.

### 2.7 Process Hollowing Alternatives

**Process hollowing** (create suspended process, unmap its image, write malicious code, resume) is heavily detected. Better alternatives:

**Thread Hijacking:**
- Suspend an existing thread in a running process
- Allocate memory and write shellcode
- Modify the thread's instruction pointer (RIP) to point at shellcode
- Resume the thread
- Advantage: no new thread creation, which is less suspicious

**Early Bird APC Injection:**
- Create a process in suspended state
- Queue an APC (Asynchronous Procedure Call) containing shellcode to the main thread
- Resume the process; the APC executes before the main thread runs
- Advantage: APC execution looks like normal process initialization

**Module Stomping:**
- Load a legitimate DLL into the target process
- Overwrite its .text section with shellcode
- Execute by calling a function in that DLL
- Advantage: the code appears to be running from a legitimate module

**Status:** Thread hijacking and early bird APC are less detected than classic hollowing. Module stomping is the stealthiest but most complex to implement.

### 2.8 ETW Patching

**How it works:** Patch the EtwEventWrite function in ntdll.dll to return immediately without writing any events. This blinds Defender and EDR products to process behavior telemetry.

**Patch approach:** Write `xor eax, eax; ret` (return SUCCESS without doing anything) to the beginning of EtwEventWrite.

**What Defender catches:**
- Tamper protection monitors for modifications to ntdll.dll functions
- The specific patch bytes at EtwEventWrite are known
- Kernel-mode ETW providers are not affected by user-mode patches

**Evasion required:**
- Use syscalls to perform the memory write (bypass the hook on NtWriteVirtualMemory)
- Obfuscate the patch bytes
- Resolve EtwEventWrite address dynamically
- Note: this only blinds user-mode ETW. Kernel ETW (via the Threat Intelligence provider) still sees syscalls

**Status:** User-mode ETW patching works and is an important component of the evasion stack. Must be done before AMSI patch to prevent the AMSI tamper attempt from being logged.

### 2.9 LOLBins (Living Off the Land)

**MSBuild.exe** is the most relevant LOLBin for C# evasion:
- MSBuild can compile and execute inline C# code from .csproj or .xml files
- It runs under Microsoft's signature, so Defender trusts it by default
- Observed in real attacks: January 2025 TCP reverse shell via MSBuild, February 2026 campaign using MSBuild as a downloader

**Other relevant LOLBins:**
- InstallUtil.exe: can execute code via custom installer classes
- Regsvcs.exe / Regasm.exe: can execute code via COM registration
- MSBuild is preferred because it directly compiles C# inline

**Status:** MSBuild execution remains effective. Defender does not flag MSBuild itself, only known malicious patterns in the inline code.

---

## 3. The Modern Evasion Stack (September 2026)

Based on research, the effective evasion stack for bypassing Windows 11 Defender requires layering multiple techniques:

```
Order of operations:
1. ETW patch (blind telemetry first)
2. AMSI patch (disable script scanning)
3. Resolve APIs dynamically (avoid suspicious imports)
4. Decrypt shellcode in memory (XOR or AES)
5. Use indirect syscalls for memory operations (bypass user-mode hooks)
6. Execute shellcode via thread hijacking or APC injection (avoid CreateThread)
```

Single techniques are increasingly caught. The combination is what defeats modern Defender.

---

## 4. Specific Defender Signatures to Avoid

### Static Signatures
- Raw msfvenom shellcode bytes (any format: csharp, raw, hex)
- Known function names as strings: "AmsiScanBuffer", "EtwEventWrite", "VirtualAlloc"
- Known patch bytes: `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3` (AMSI patch)
- P/Invoke declarations for VirtualAlloc, CreateThread, WriteProcessMemory in combination

### Behavioral Signatures
- VirtualAlloc(PAGE_EXECUTE_READWRITE) followed by memory copy followed by thread creation
- Writing to ntdll.dll memory regions (AMSI/ETW patching)
- Opening a remote process and writing to its memory
- Creating a suspended process and modifying its memory

### Cloud/ML Signatures
- Unknown binaries with high entropy sections (encrypted payloads)
- Binaries that allocate executable memory early in execution
- Processes that spawn children and inject into them

---

## 5. Technique-to-Loader Mapping

| Loader | Primary Technique | Defender Bypass | Complexity |
|--------|------------------|-----------------|------------|
| 01_shellcode_loader.cs | VirtualAlloc + CreateThread | Baseline (gets caught without evasion) | Low |
| 02_xor_encoder.cs | XOR encryption/decryption | Defeats static signatures | Low |
| 03_direct_syscalls_loader.cs | Direct/indirect syscalls | Bypasses user-mode hooks | Medium |
| 04_amsi_bypass.cs | AmsiScanBuffer patch | Disables script scanning | Medium |
| 05_reflective_injector.cs | Manual PE loading in memory | No disk write for DLL | High |
| 06_process_hollowing_alt.cs | Thread hijacking or APC injection | No new process creation | High |
| 07_etw_patch.cs | EtwEventWrite patch | Blinds telemetry | Medium |
| 08_combined_evasion.cs | All above combined | Full evasion stack | High |

---

## 6. Sources Consulted

### Primary References
- ired.team - Red Team Notes: Defense Evasion section
- MITRE ATT&CK T1055 (Process Injection), T1620 (Reflective Code Loading)
- SysWhispers3 (github.com/klezVirus/SysWhispers3)
- SysWhispers4 (github.com/JoasASantos/SysWhispers4)
- ETW-Patcher (github.com/Gurpreet06/ETW-Patcher)
- Crypt0ace shellcode injection series (crypt0ace.github.io)

### 2025-2026 Blog Posts and Research
- Hackmosphere: "Windows Defender antivirus bypass in 2025" (direct syscalls + XOR, parts 1-2)
- HackerXone: "Windows Defender Bypass Techniques in 2026"
- RingSafe: "EDR Bypass Techniques in 2026"
- Valhguard: "The ETW Blind Spot: Red Team Tactics for Blinding Windows Event Tracing" (November 2025)
- Medium/@thesecguy: "AMSI Bypass in 2025 - Bypassing Modern AV & EDR"
- OffSec Blog: "AMSI Write Raid Bypass Vulnerability"
- IliasCyber: "Rewriting the Reflective DLL Loader" (May 2026)
- Cybersecurity News: "Windows Defender Antivirus Bypassed Using Direct Syscalls & XOR Encryption"
- ASEC: "LOLBins - Analysis of MSBuild-Based Attack Techniques"
- Elastic: "Ten Process Injection Techniques: A Technical Survey"

### Course/Certification References
- SANS SEC565: Red Team Operations and Adversary Emulation
- SANS SEC665: Purple Team Tactics - Adversary Emulation
- Offensive Security PEN-300: Evasion Techniques and Breaching Defenses
- Netero1010 Security Lab: Indirect Syscall in CSharp

### Defender Documentation
- Microsoft Learn: Cloud protection and Microsoft Defender Antivirus
- AV-TEST February 2026 evaluation results
- Trend Micro: Detecting Windows AMSI Bypass Techniques
- Todyl: Understanding AMSI bypass techniques

---

## 7. Build Order Decision

Based on research, the loaders should be built in this order because each builds on the previous:

1. **01_shellcode_loader.cs** - Teaches the basic pattern. Gets caught. Students learn what Defender detects.
2. **02_xor_encoder.cs** - First evasion layer. Defeats static signatures. Students see the improvement.
3. **07_etw_patch.cs** - Must come before AMSI bypass in execution order, so teach it early.
4. **04_amsi_bypass.cs** - Requires ETW to be patched first. Students understand why order matters.
5. **03_direct_syscalls_loader.cs** - Replaces API calls with syscalls. Major evasion improvement.
6. **05_reflective_injector.cs** - Uses syscalls for injection. Requires understanding from previous loaders.
7. **06_process_hollowing_alt.cs** - Advanced injection. Builds on all previous concepts.
8. **08_combined_evasion.cs** - Combines everything into the full stack.

Note: The teaching documents (00-11) follow a different pedagogical order that introduces concepts gradually. The build order here is for development efficiency.
