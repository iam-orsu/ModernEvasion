# Document 11: Real-World Scenarios - How Evasion Techniques Work in the Field

## Where We Are

You finished Documents 00 through 10. You have built eight loaders and learned six evasion techniques:

| Loader | Technique | Outcome against Defender |
|---|---|---|
| Loader 01 | Raw shellcode via DllImport | Caught |
| Loader 02 | XOR-encrypted shellcode | Encrypted file survived, loader caught |
| Loader 03 | Dynamic resolution + NT functions + two-step allocation | First callback (survived Defender) |
| Loader 04 | AMSI bypass (AmsiScanBuffer patch) | Low detection standalone |
| Loader 05 | Remote thread injection | Caught alone |
| Loader 06 | Early Bird APC injection | Caught alone |
| Loader 07 | ETW patch (EtwEventWrite patch) | Low detection standalone |
| Loader 08 | All techniques combined | Fully stealthy (no detection) |

You can now compile C# loaders, encrypt shellcode, patch system functions, resolve APIs dynamically, inject into other processes, and bypass Defender's six detection layers. This document explains how these techniques work in real red team engagements, what changes when you face security products beyond Defender, and what the current evasion landscape looks like.

## Why This Is Next

You learned evasion in a controlled lab with one target, one attacker, and one security product (Defender). Real engagements are different:

- The target network has hundreds or thousands of machines, not one.
- Multiple security products are running (Defender plus a third-party EDR plus a SIEM plus network monitoring).
- Security teams are actively watching for suspicious activity.
- You need to maintain access for days or weeks, not minutes.
- You need to move laterally (from one machine to others) without getting caught.
- You need to extract data without triggering network alerts.

This document bridges the gap between your lab and the field. It does not introduce new code or new loaders. Instead, it explains the decisions you make during a real engagement and how the techniques from this curriculum apply.

## Scenario 1: Initial Access on a Corporate Workstation

### The Situation

You have been hired by a company to test their security. Your goal is to get access to a workstation on the corporate network. The company uses Windows 11 with Defender (default settings) on all workstations. They do not have a third-party EDR product.

### What You Do

**Step 1: Prepare the payload.** On your attack machine (Kali), generate a Meterpreter reverse TCP payload and encrypt it with XOR. This is exactly what you did in Document 06.

**Step 2: Deliver the loader.** You need to get stealth_loader.exe (Loader 08) and encrypted.bin onto a target workstation. In a real engagement, you would not walk up to the machine and download files from a Python HTTP server. Instead, you would use one of these delivery methods:

- **Phishing email:** Send an email with the loader attached (renamed to something innocuous like "Q3_Report.exe") or a link to download it from a web server you control. The email would target a specific employee.
- **USB drop:** Leave a USB drive in the company's parking lot with the loader on it, hoping an employee plugs it in.
- **Compromised web application:** If the company has a web application with a file upload vulnerability, upload the loader through it.
- **Supply chain:** If you have access to a software package the company uses, modify it to include the loader.

For Defender-only environments, the phishing approach works well. The encrypted payload file (encrypted.bin) and the loader (stealth_loader.exe) both pass Defender's disk scan because the loader has a clean import table and the payload is XOR-encrypted.

**Step 3: Execute.** Once the employee runs the loader (perhaps by clicking what they think is a report), Loader 08's six-step sequence runs:
1. ETW is patched (no telemetry)
2. AMSI is patched (no script scanning)
3. Shellcode is decrypted in memory
4. NT functions are resolved dynamically
5. Memory is allocated (RW then RX)
6. Shellcode executes

You get a Meterpreter session on your listener.

**Step 4: Establish persistence.** A Meterpreter session dies when the user reboots or the process exits. You need persistence, a way to automatically re-establish access after a reboot. Common persistence methods include:

- Adding a scheduled task that runs your loader at startup
- Adding a registry key in HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- Creating a Windows service
- Placing a DLL in a location where a legitimate program will load it (DLL hijacking)

Each persistence method has its own detection considerations. Registry keys and scheduled tasks are monitored by Defender. DLL hijacking is harder to detect but requires finding a vulnerable application.

**Step 5: Lateral movement.** From the compromised workstation, you can scan the internal network for other machines. If the workstation has cached credentials (Kerberos tickets, NTLM hashes), you can use them to authenticate to other machines. Pass-the-hash, pass-the-ticket, and Kerberos delegation attacks let you move from one machine to another without knowing the plaintext password.

The AMSI bypass (Loader 04) is critical here. Many lateral movement tools (Rubeus for Kerberos, SharpHound for Active Directory enumeration, Seatbelt for system information gathering) are written in .NET. Without the AMSI bypass, Defender blocks these tools when they are loaded into memory.

### What Defender Sees

With Loader 08, Defender sees nothing during the initial access phase. No alerts, no quarantine, no protection history entries. The loader's telemetry is disabled (ETW patch), its code is not scanned (AMSI patch), and its behavior does not trigger ML detection (clean imports, two-step allocation).

The risk increases as you spend more time on the machine. Defender's periodic memory scans can eventually find Meterpreter's payload bytes in the target process's memory. The probability depends on the scan frequency, the payload size, and whether you use sleep obfuscation (mentioned in Document 10's variations).

## Scenario 2: Facing a Third-Party EDR Product

### The Situation

The company uses CrowdStrike Falcon, Carbon Black, SentinelOne, or another third-party EDR product in addition to Defender. EDR products are more advanced than Defender alone. They use kernel-level monitoring, memory scanning, behavioral analysis, and cloud-based threat intelligence.

### What Changes

**Kernel-level ETW is active.** Third-party EDR products typically use the Microsoft-Windows-Threat-Intelligence ETW provider, which runs in the kernel. Your user-mode EtwEventWrite patch does not affect kernel-mode providers. The EDR sees your memory allocations, thread creation, and process injection through kernel callbacks even though user-mode ETW is patched.

**User-mode hooks are more aggressive.** EDR products hook more functions than Defender does. Defender primarily hooks a few dozen critical functions in ntdll.dll. EDR products can hook hundreds of functions, including functions you might not expect (like GetProcAddress itself, or VirtualProtect). This means your dynamic resolution calls might be intercepted by EDR hooks.

**Call stack analysis.** Advanced EDR products check the call stack when a suspicious API is called. The call stack shows which functions called which other functions. If the call stack shows NtAllocateVirtualMemory being called from an unknown memory region (not from a known DLL), the EDR flags it as suspicious. Loader 08's calls go through ntdll.dll (resolved by GetProcAddress), so the call stack looks legitimate, but some EDR products check deeper.

**Memory scanning is more frequent.** Defender scans process memory periodically but not aggressively. EDR products scan more frequently and look for more patterns. They maintain databases of known shellcode byte sequences (including Meterpreter, Cobalt Strike, Sliver, etc.) and scan for those patterns in process memory.

### What You Do Differently

Against a third-party EDR, Loader 08 may not be enough. The additional techniques you would consider:

**Indirect syscalls:** Instead of calling NT functions through the ntdll.dll copy in your process (which may be hooked by the EDR), you find the `syscall` instruction inside ntdll.dll and jump to it directly from your code. The call stack then shows the return address inside ntdll.dll, which looks legitimate. Tools like SysWhispers3 and SysWhispers4 generate indirect syscall stubs for C#.

**NTDLL unhooking:** Load a fresh copy of ntdll.dll from disk, which has no EDR hooks, and resolve functions from the clean copy. You read C:\Windows\System32\ntdll.dll into memory, map it as a PE image, and use it instead of the hooked copy.

**Custom C2 frameworks:** Instead of Meterpreter (which is widely signature-matched), use a custom C2 framework or a less common one like Sliver, Havoc, or Mythic. Custom payloads have no public signatures, so EDR memory scanners are less likely to match them.

**Sleep obfuscation:** Encrypt the payload in memory during sleep periods so periodic scans do not find recognizable bytes. Tools like Ekko, Foliage, and custom ROP-based sleep obfuscation can do this.

**Module stomping:** Instead of allocating new memory for your shellcode, overwrite the code section of a loaded DLL that is not being used. The shellcode lives in memory that appears to belong to a legitimate DLL.

**Hardware breakpoint hooks:** Instead of patching function bytes (which memory integrity checks can detect), use hardware debug registers to set breakpoints on functions like EtwEventWrite. When the breakpoint triggers, your code runs instead of the function. No bytes are modified in the DLL's code, so integrity checks pass.

These are advanced techniques beyond the scope of this curriculum, but they are what red team operators use in real engagements against modern EDR.

## Scenario 3: Post-Exploitation and Data Exfiltration

### The Situation

You have access to several machines on the corporate network. Your goal now is to find sensitive data and extract it to your infrastructure without triggering network monitoring.

### How the Curriculum's Techniques Apply

**AMSI bypass for tool loading:** You need to run various .NET tools on compromised machines to enumerate the network, find domain controllers, extract credentials, and locate sensitive files. Tools like SharpHound (Active Directory enumeration), Rubeus (Kerberos attacks), and Seatbelt (host enumeration) are all .NET assemblies. Without AMSI patching, Defender blocks them. With Loader 04's AMSI patch applied in your Meterpreter process, you can load these tools using Assembly.LoadFile and they run without being scanned.

**Process injection for tool execution.** Instead of running tools in your Meterpreter process (which could crash and kill your session), inject them into separate processes. Use Loader 05 or Loader 08's remote injection to run each tool in its own sacrificial process. If the tool crashes or gets detected, only the sacrificial process is terminated, not your main session.

**ETW patching on every machine.** Each machine you access has its own ETW and AMSI. When you land on a new machine, your first action is to patch ETW and AMSI in your process before doing anything else. The execution order from Document 08 (ETW first, AMSI second) applies every time.

**Network evasion is separate from host evasion.** This curriculum covers host-level evasion (bypassing Defender on the machine). Network-level evasion (hiding your traffic from firewalls, IDS/IPS, and network monitoring) is a separate discipline. Meterpreter's traffic over TCP looks like a standard reverse TCP connection. Network monitoring tools can detect this based on:
- Connections to known-bad IP addresses
- Unusual traffic patterns (periodic check-ins at regular intervals)
- Traffic on unusual ports (4444 is a well-known Meterpreter default)
- Long-lived connections that stay open for hours

For real engagements, you would use HTTPS C2 traffic (which blends with normal web browsing), DNS C2 (which hides traffic in DNS queries), or domain fronting (which routes traffic through legitimate CDN domains). These are network-level evasion techniques outside the scope of this curriculum.

## Scenario 4: Red Team vs Blue Team Exercise

### The Situation

Your company runs an internal red vs blue exercise. The red team (you) tries to compromise targets while the blue team (defenders) tries to detect and stop you. The blue team has access to SIEM logs, EDR consoles, network monitoring, and can make real-time changes to detection rules.

### How This Changes Your Approach

**Speed matters.** In a lab, you can take your time. In a live exercise, the blue team is watching. Once you trigger any alert (even a minor one), the blue team starts investigating. They will look at the process tree, check running processes, examine network connections, and may push new detection rules. You need to move fast between access and establishing persistence.

**Minimizing artifacts is critical.** Every file you drop to disk, every process you create, every network connection you make is an artifact that the blue team can find. The best approach is:
- Drop the minimum number of files (ideally just the loader and encrypted payload)
- Delete the files after execution (the shellcode is already in memory)
- Use process injection to move your shellcode into a legitimate process
- Exit the loader process once injection is complete

**Pre-built infrastructure.** You do not want to set up your Kali listener during the exercise. Set up your C2 infrastructure beforehand: HTTPS listeners with valid certificates, redirectors that proxy traffic through legitimate domains, and multiple fallback listeners in case one is discovered.

**Multiple payloads.** If your primary payload gets detected, you need a backup. Prepare different loaders with different techniques (local execution vs injection, different XOR keys, different target processes). If Defender catches one combination, switch to another.

### The Loaders You Would Use

For a red vs blue exercise against Defender, your loadout would be:

1. **Loader 08 (combined evasion, remote mode)** as the primary payload. Patches ETW, patches AMSI, decrypts shellcode, resolves dynamically, injects into explorer.exe.

2. **Loader 08 (combined evasion, local mode)** as a backup. If remote injection fails (admin privileges not available), fall back to local execution.

3. **Loader 03 (dynamic resolution, no patches)** as a minimal fallback. If the ETW or AMSI patches are detected (because the blue team pushed new rules), this loader can still get a callback without patching anything.

4. **A staged loader** (not built in this curriculum) that downloads and executes the payload from memory without writing it to disk. This reduces the number of files on the target's hard drive.

## The Current State of Evasion (September 2026)

### What Works Against Default Defender

The techniques in this curriculum work against Windows 11 Defender at default settings as of September 2026. Specifically:

- XOR encryption defeats static file scanning
- Dynamic resolution via GetProcAddress defeats import table analysis
- EtwEventWrite patching defeats user-mode ETW telemetry
- AmsiScanBuffer patching defeats AMSI runtime scanning
- Two-step allocation (RW then RX) keeps the behavioral ML score below threshold
- NT-level functions via delegates reduce API hook effectiveness

Microsoft updates Defender's signatures and behavioral models regularly. A technique that works today might be detected after the next update. The defense against this is not to find one technique that works forever, but to understand the detection mechanisms well enough to adapt when something gets caught.

### What Does Not Work Anymore

Several techniques that were common in the past are now reliably detected:

**Classic process hollowing.** The NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext pattern is detected by Defender and every major EDR product. Document 09 covered this and explained why Loader 06 (Early Bird APC) is used instead.

**Single-step RWX allocation.** Allocating memory with PAGE_EXECUTE_READWRITE in a single VirtualAlloc call is a high-confidence detection signal. Every major security product flags it. Two-step allocation (RW then RX) is the standard replacement.

**String-based AMSI bypass.** Early AMSI bypasses used PowerShell one-liners like `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`. These strings are now in every signature database. The binary patching approach in Loader 04 works because it does not use recognizable strings.

**Direct msfvenom output.** Running msfvenom and using the raw output directly (as in Loader 01) is detected by every security product. The raw shellcode bytes match public signatures. XOR encryption (Loader 02) or custom encoding is required.

**Unencrypted Meterpreter traffic.** Raw TCP Meterpreter sessions are easily detected by network monitoring tools. HTTPS transport with legitimate-looking certificates is the minimum for production engagements.

### What is Evolving

The evasion landscape is an arms race. Attackers develop new techniques, defenders add detection for those techniques, and attackers adapt. Here are the areas where the most change is happening:

**Kernel-level telemetry.** Microsoft is investing heavily in the Microsoft-Windows-Threat-Intelligence ETW provider and other kernel-level monitoring. As this becomes more prevalent, user-mode ETW patching becomes less effective. The long-term trend is toward kernel-level evasion, which requires kernel drivers (much harder to develop and deploy) or exploiting vulnerabilities in the kernel monitoring itself.

**AI-based detection.** Security products are increasingly using machine learning models that analyze process behavior holistically rather than matching individual signatures. These models look at combinations of actions (memory allocation patterns, network connections, file operations) and score them for maliciousness. Defeating ML models requires understanding what features the model uses and ensuring your loader's behavior matches legitimate software closely enough.

**Hardware-based security.** Technologies like Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI), and Secured-Core PCs create hardware-enforced boundaries that user-mode code cannot bypass. As these technologies become standard, some evasion techniques become impossible without hardware-level attacks.

**Memory forensics.** Tools like Volatility, WinDbg, and commercial memory forensics products can analyze a memory dump and find injected code, patched functions, and suspicious memory regions. In-memory evasion (sleep obfuscation, module stomping, thread stack spoofing) is the response to this capability.

## How This Curriculum Maps to Professional Red Team Skills

### Skills You Have

After completing this curriculum, you can:

1. Write C# code that interacts with the Windows API at both the kernel32 and NT level
2. Understand how Windows Defender detects malicious software across six detection layers
3. Build loaders that bypass each detection layer using specific techniques
4. Combine multiple evasion techniques into a single tool with correct execution order
5. Generate, encrypt, and deploy shellcode payloads
6. Inject code into running processes and suspended processes
7. Patch system functions (AMSI, ETW) to disable monitoring
8. Explain each technique's mechanism, not just run pre-built tools

### Skills You Still Need

This curriculum covers host-level evasion against default Defender. A professional red team operator also needs:

**Active Directory exploitation.** Most corporate networks use Active Directory. Understanding Kerberoasting, AS-REP roasting, delegation attacks, Golden/Silver ticket attacks, and domain trust exploitation is essential. Tools like Rubeus, Impacket, and BloodHound are standard.

**Network-level evasion.** Hiding C2 traffic from firewalls, IDS/IPS, and network monitoring. HTTPS C2, DNS tunneling, domain fronting, and encrypted channels.

**Privilege escalation.** Moving from a standard user account to local administrator to domain administrator. Windows privilege escalation vectors include unquoted service paths, DLL hijacking, token impersonation, and kernel exploits.

**Cloud and Azure AD.** Many companies use Azure AD, Office 365, and cloud infrastructure. Cloud red teaming involves OAuth token theft, application consent attacks, and Azure resource exploitation.

**Reporting.** Writing clear, actionable reports that explain what you found, how you got there, what the risk is, and what the remediation is. This is what clients pay for.

**Tool development.** Building custom tools beyond what public frameworks provide. Custom C2 frameworks, custom implants, custom shellcode, and custom delivery mechanisms.

### Where to Go Next

The logical next step after this curriculum depends on what part of red teaming you want to specialize in:

**If you want to go deeper on evasion:**
- Study indirect syscalls and implement them in C#
- Build a custom C2 framework (even a simple one)
- Learn sleep obfuscation techniques
- Study how specific EDR products work and how to bypass each one
- Practice with commercial EDR trial licenses in your lab

**If you want to go wider on offensive security:**
- Set up an Active Directory lab with a domain controller and multiple machines
- Learn Kerberos attacks (Rubeus, Impacket)
- Learn Azure AD and cloud attacks
- Study web application exploitation (another common entry point)

**Certifications that validate these skills:**
- OSEP (Offensive Security Experienced Penetration Tester) covers evasion and advanced exploitation
- CRTO (Certified Red Team Operator) from Zero-Point Security covers C2 frameworks and Active Directory
- CRTL (Certified Red Team Lead) from Zero-Point Security for more advanced operations
- PNPT (Practical Network Penetration Tester) from TCM Security for a broader foundation

## Summary of the Complete Curriculum

Here is everything you learned, document by document:

| Document | Title | What You Learned |
|---|---|---|
| 00 | Introduction | What this curriculum teaches, why evasion matters, prerequisites |
| 01 | Lab Setup | Build three-machine lab: Kali attacker, Windows dev box (Defender disabled), Windows target (Defender enabled) |
| 02 | C# Basics | Variables, loops, functions, classes through security-focused examples |
| 03 | Windows API | DllImport, P/Invoke, calling Windows functions from C#, MessageBox, VirtualAlloc |
| 04 | Memory Fundamentals | Process memory, VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread |
| 05 | Shellcode Loader | Build first loader, generate msfvenom payload, understand why Defender catches it |
| 06 | Encoding Evasion | XOR encryption/decryption, bypass disk scanning, understand behavioral detection |
| 07 | Direct Syscalls | Dynamic resolution, NT functions, two-step allocation, first successful callback |
| 08 | AMSI and ETW | Patch AmsiScanBuffer and EtwEventWrite, correct execution order, blind Defender's monitoring |
| 09 | Process Injection | Remote thread injection, Early Bird APC injection, run code inside legitimate processes |
| 10 | Combined Evasion | All techniques in one loader, local and remote modes, fully stealthy callback |
| 11 | Real-World Scenarios | How techniques apply in real engagements, EDR differences, current evasion landscape |

And the eight loaders you built:

| Loader | File | Techniques Used |
|---|---|---|
| 01 | lab/loaders/01_shellcode_loader.cs | Raw shellcode, DllImport, VirtualAlloc |
| 02 | lab/loaders/02_xor_encoder.cs | XOR encryption/decryption |
| 03 | lab/loaders/03_direct_syscalls_loader.cs | Dynamic resolution, NT functions, two-step allocation |
| 04 | lab/loaders/04_amsi_bypass.cs | AmsiScanBuffer patch |
| 05 | lab/loaders/05_reflective_injector.cs | Remote thread injection |
| 06 | lab/loaders/06_process_hollowing_alt.cs | Early Bird APC injection |
| 07 | lab/loaders/07_etw_patch.cs | EtwEventWrite patch |
| 08 | lab/loaders/08_combined_evasion.cs | All techniques combined |

You started with zero C# knowledge and ended with a fully working combined evasion loader that bypasses Windows 11 Defender at full defaults. Every technique was explained at the mechanism level (how it works and why it works), not just the execution level (run this command and see what happens).

The difference between someone who runs pre-built tools and someone who is a red team operator is understanding. If a technique gets detected, the operator who understands the mechanism can modify their approach. The operator who only knows which buttons to press is stuck. This curriculum taught you the mechanisms so you can adapt when things change.
