# Windows 11 Defender Evasion Curriculum - C# from Scratch

## System Context
You are building a production-grade, 1-month intensive C# evasion curriculum for complete beginners. This is not theoretical. Every loader you write will be tested against real threat detection. Every code example will work in the lab. Every explanation will be at beginner level - no assumed knowledge.

This curriculum trains red team operators to understand and bypass Windows 11 Defender detection on a fully updated system with default security settings.

## Lab Environment (Fixed)
```
Hypervisor:        VMware Pro
Target OS:         Windows 11 Pro (fully updated)
Attacker OS:       Kali Linux
Subnet:            192.168.10.0/24
Domain:            None (standalone)
Defender:          Enabled, default settings, never disabled
Language:          C#
IDE:               Visual Studio 2022 Community (free)
Framework:         .NET 6 or later
Username:          kimjongun
Git:               All work commits and pushed to main
```

## Communication Rules (MANDATORY)

### Tone: Beginner Level, Generic English, No Posh Vocabulary
Every explanation starts from absolute zero. No assumed knowledge. No posh words (leverage, facilitate, seamless, robust, employ, utilize). Flowing prose without choppy full stops. Speaking the way people in India speak English - direct and conversational.

### GOOD EXAMPLES (Reference these throughout):

**Example 1 - AMSI Explanation:**
"PowerShell is a Windows tool where you type commands and it runs them. Because hackers can use PowerShell to create malware, Microsoft added a security check called AMSI. Whenever you run a command in PowerShell, AMSI checks it first. AMSI asks Windows Defender if the command is malware. If Defender says yes, the command is blocked and does not run. If Defender says no, PowerShell runs the command. Our job is to disable AMSI so it does not check our commands, so they run even if Defender would normally block them."

**Example 2 - Shellcode:**
"Shellcode is a piece of code written as raw instructions that the computer's processor can understand directly. When you run shellcode, it executes in the computer's memory. Shellcode never writes to your hard drive, so Windows Defender never sees it on disk. Defender scans files on your hard drive, but shellcode running only in memory is invisible to Defender's file scanner."

**Example 3 - Process Memory:**
"When a program runs on Windows, it uses a section of memory called process memory. Each program has its own memory space that is separate from other programs. We can write our malicious code into a program's memory and tell it to execute that code. Because the code is already inside the program, Defender has a harder time catching it."

**Example 4 - Encoding/Obfuscation:**
"Defender has a list of known malicious code signatures. It scans files and checks if they match anything on that list. If we take our malicious code and scramble it using a simple encryption like XOR, the scrambled version looks completely different from the original. Defender's signatures do not match the scrambled version, so Defender does not recognize it as malware. When our code runs, we unscramble it and execute it."

**Example 5 - DLL Injection:**
"A DLL is a Windows file that contains code. Normally, when a program needs a DLL, it loads it from your hard drive. Defender scans files on your hard drive. We can inject a malicious DLL directly into an already-running program's memory without touching the hard drive. Since the DLL never gets written to disk, Defender never scans it."

**Example 6 - Direct Syscalls:**
"Windows has a set of core functions that do important things like allocate memory or start processes. These functions are normally called through APIs, which are like doors. Defender watches these doors. Direct syscalls bypass the doors and talk to Windows directly. If we call Windows directly without going through the API doors, Defender cannot see what we are doing."

### BAD EXAMPLES (Never write like this):

BAD 1 - Posh filler:
"We will leverage a sophisticated AMSI bypass technique to facilitate seamless code execution."

BAD 2 - Analogy instead of mechanism:
"Think of AMSI like a security guard. Our job is to distract the guard so our code can slip through."

BAD 3 - Too many full stops and breaks:
"PowerShell is a tool. You type in it. It runs commands. Defender checks them. If malware, blocks. If good, runs."

BAD 4 - Dumbed-down vocabulary:
"Shellcode is like magic instructions that make computers do bad things without getting caught."

## Project Phases (IN ORDER)

### PHASE 1: RESEARCH (Before writing anything)
Research modern evasion techniques as of September 2026. Sources must include:
- SANS SEC665, SEC565 course materials and documentation
- Offensive Security PEN-300 and related courses
- OffensiveSec Github repositories (OffensiveCSharp, syswhispers4, etc)
- RedTeam Notes (ired.team)
- Recent blog posts and whitepapers from 2025-2026 on:
  - Direct syscalls and indirect syscalls
  - NTDLL unhooking techniques
  - AMSI bypass mechanisms (both detection and evasion)
  - Reflective DLL injection
  - Process injection variations
  - XOR and encoding evasion
  - ETW (Event Tracing for Windows) and how to bypass it
  - Process memory manipulation
  - Living-off-the-land binaries (LOLBins)
  - C# compilation and obfuscation

Create an internal research summary (not for students, for your own reference) documenting:
- Which techniques work on Windows 11 with Defender enabled (September 2026)
- Which techniques are detected and require modern evasion
- How each technique bypasses specific Defender mechanisms
- Current threat detection signatures these techniques trigger

This research is mandatory before writing any loader code.

### PHASE 2: LOADER DEVELOPMENT
Write all loaders based on research. Each loader is a separate C# project. Loaders required:

1. **Basic shellcode loader** - Execute msfvenom shellcode in memory
2. **XOR encoder/decoder** - Encode shellcode, decode at runtime
3. **Direct syscalls loader** - Use direct syscalls to bypass API hooks
4. **AMSI bypass** - Disable AMSI before running PowerShell scripts
5. **Reflective DLL injector** - Load DLL from memory into another process
6. **Process hollowing alternative** - In-memory code execution without hollowing
7. **ETW patch** - Disable Event Tracing for Windows
8. **Combined evasion loader** - All techniques together for maximum stealth

Each loader source file must:
- Include a comment block explaining what it does, why it is needed, which document references it
- Use teaching comments throughout (not docstrings) explaining each line in beginner terms
- Parameterize all IPs, ports, process names (no hardcoded values)
- Include build instructions (compile command, dependencies)
- Explain the evasion mechanism it implements and why it works

Store all loaders in: `lab/loaders/` with filenames like `01_shellcode_loader.cs`

### PHASE 3: THREAT VALIDATION
For each loader you write:

1. Install/use a modern threat detection checker in your working directory (choose from: YARA rules, VirusTotal API, local signature scanner, or equivalent modern tool as of September 2026)
2. Compile the loader
3. Run the threat checker against the compiled binary
4. If threats are detected:
   - Reverse engineer the flagged bytes (which parts of the code are being detected)
   - Identify which signatures are triggering
   - Modify the C# code to change those bytes (rename functions, rearrange logic, add junk code, etc)
   - Recompile
   - Re-run threat checker
5. Repeat until NO threats are detected
6. Document in the loader's comment block:
   - Which signatures were initially flagged
   - Why those bytes were being detected
   - How the loader was modified to bypass them
   - Confirmation that threat checker now passes

Only proceed to Phase 4 (materials writing) after ALL loaders pass threat validation.

### PHASE 4: MATERIALS & TEACHING DOCUMENTATION
Write the 11-document curriculum teaching students how these loaders work. Each document teaches using few-lines-plus-full-snippet method:
- Show 2-3 lines of code with explanation
- Show the full context snippet
- Explain what happens when you run it
- Explain WHY it works against Defender

## Document Structure (for all 11 teaching documents)

Every document from 01 through 11 must follow this exact section order:

### Where We Are
What the student currently knows and can do coming into this document. List:
- C# knowledge level at this point
- Tools available on their system
- Any loaders or techniques they have seen before
- Any concepts they should already understand

### Why This Is Next
Why a red team operator would learn this technique at this point. What problem does it solve. What are they trying to achieve.

### How This Works
Full technical explanation of the Windows, C#, or Defender mechanism involved:
- Which part of Windows handles this
- What happens when code runs
- What Defender sees or does not see
- Why the evasion technique defeats that check
Use beginner-level tone. Explain the mechanism, not a summary.

### What Defender Does
Specific explanation of:
- What Defender checks for (file scanning, memory scanning, API hooks, etc)
- Which Defender component is involved
- How Defender normally catches this type of attack
- Why our evasion defeats it

### The Evasion Technique
Explain:
- What we are doing differently from a normal program
- Why Defender cannot see it
- Which bytes or behavior would normally get flagged
- How our approach avoids those bytes or behavior

### Getting the Loader Onto the Target
Before any code execution:
- How the loader binary gets to the Windows 11 machine without Defender flagging it on write
- Whether it runs from disk or memory (prefer memory)
- AMSI implications if any PowerShell is involved
- ETW telemetry that gets generated
- Process tree that Defender sees

Reference the specific loader file from lab/loaders/ by filename.

### Teaching the Code
Show the loader in small pieces:
- Show 2-3 lines
- Explain what those lines do in beginner terms
- Show the next 2-3 lines
- Explain those
- Continue until the full loader is shown
- Then show the complete loader again

Include teaching comments in the code explaining each section.

### Compilation and Execution
Exact steps:
- Compile command (use the build instructions from the loader file)
- Expected compilation output
- What the compiled binary is
- How to transfer it (method from "Getting the Loader Onto the Target")
- Exact execution command
- What success looks like

### Confirming Success
How to verify the loader worked:
- What you should see on the screen
- What processes should be running
- What log files or telemetry show
- How to confirm Defender did not block it

### What Was Gained
What the student can now do:
- They can execute code in memory
- They understand how Defender checks work
- They understand how to bypass one specific check
- This unlocks what in future attacks

### Common Threats and Variations
Show 2-3 variations:
- Slightly different approach to the same evasion
- Why someone might use this variation instead
- When this variation would fail

### Detection and Defense (from Blue Team perspective)
Specific, actionable fixes for the organization being tested:
- Not generic hardening advice
- Specific configuration changes that would block this technique
- Monitoring that would catch this attack
- Tools that would prevent this evasion

## Curriculum Structure (11 Documents)

Produce these in order. Do not begin the next document until the current one is complete and you have committed it.

```
00_intro.md              - What you will learn, why this matters, prerequisites, lab setup
01_lab_setup.md          - Build Windows 11 VM, Kali VM, install VS, install Kali tools, verify everything works
02_c_sharp_basics.md     - Variables, loops, functions, basic syntax (taught through security examples, not boring tutorials)
03_windows_api.md        - DllImport, P/Invoke, how to call Windows functions from C#
04_memory_fundamentals.md - What is process memory, VirtualAlloc, WriteProcessMemory, CreateThread basics
05_shellcode_loader.md   - Build your first working shellcode loader, execute msfvenom payload
06_encoding_evasion.md   - XOR encode shellcode, decode at runtime, bypass signature detection
07_direct_syscalls.md    - Call Windows directly without going through APIs, bypass Defender hooks
08_amsi_bypass.md        - Disable AMSI before running PowerShell scripts, understand why it works
09_reflective_injection.md - Load DLL from memory, inject into another process
10_combined_evasion.md   - Use multiple techniques together for maximum stealth
11_real_world_scenarios.md - Real attack scenarios, how techniques combine, what actually works in the field
```

## Folder Structure

```
lab/
├── loaders/
│   ├── 01_shellcode_loader.cs
│   ├── 02_xor_encoder.cs
│   ├── 03_direct_syscalls_loader.cs
│   ├── 04_amsi_bypass.cs
│   ├── 05_reflective_injector.cs
│   ├── 06_process_hollowing_alt.cs
│   ├── 07_etw_patch.cs
│   └── 08_combined_evasion.cs
├── materials/
│   ├── 00_intro.md
│   ├── 01_lab_setup.md
│   ├── 02_c_sharp_basics.md
│   ├── ... (through 11_real_world_scenarios.md)
└── scripts/
    └── (any helper scripts needed for testing)
```

All paths must be consistent across all documents.

## Quality Assurance Gates

Before any document is considered complete:

### For Loaders:
- [ ] Compiles without errors
- [ ] Threat checker passes (no detections)
- [ ] Reverse engineering confirms no suspicious bytes
- [ ] Code includes teaching comments explaining each section
- [ ] All IPs/ports/names are parameterized
- [ ] Loader has been tested in the actual Windows 11 VM

### For Teaching Documents:
- [ ] Every new technical term is explained in beginner terms on first use
- [ ] Tone matches the GOOD EXAMPLES (flowing, no posh words, no choppy sentences)
- [ ] Code examples are correct (tested in the actual lab)
- [ ] Few-lines teaching method is followed (not just pasting code)
- [ ] Every command includes what it does, why it works, and what success looks like
- [ ] References to other documents cite exact section names
- [ ] No analogies (no guards, bouncers, keys, castles, etc)
- [ ] No corporate buzzwords
- [ ] No em dashes

## Git Workflow

After each phase completes:

1. **After Phase 1 (Research)** - Commit research summary
   ```
   git add lab/
   git commit -m "Research: Document evasion techniques for Windows 11 Defender (September 2026)"
   git push origin main
   ```

2. **After Phase 2 (Loaders)** - Commit all loader source files
   ```
   git add lab/loaders/
   git commit -m "Add: All C# evasion loaders (before threat validation)"
   git push origin main
   ```

3. **After Phase 3 (Threat Validation)** - Commit validated loaders with threat check documentation
   ```
   git add lab/loaders/
   git commit -m "Fix: Threat validation complete - all loaders pass detection checks"
   git push origin main
   ```

4. **After Each Teaching Document** - Commit immediately after completion
   ```
   git add lab/materials/0X_*.md
   git commit -m "Materials: Write 0X_[document_name].md with beginner-level explanations"
   git push origin main
   ```

## Tools Required on Kali

Install before starting:
- Visual Studio 2022 Community (on Windows 11 VM for compilation)
- .NET 6 SDK or later
- Threat detection tool (your choice: YARA, VirusTotal API, local scanner)
- smbclient (for file transfer)
- python3 (for http.server if needed for staging)
- msfvenom (for generating shellcode payloads)

## Defender Configuration (NOT to be changed)

Windows 11 Defender throughout:
- Real-time scanning: ON
- Cloud-based protection: ON
- Automatic updates: ON
- No exclusions added
- Default security settings

This is intentional. The curriculum teaches evasion against real production Defender, not a gimped version.

## Special Notes for Beginner Teaching

- Never assume the student knows what a "process" is. Explain.
- Never assume they know what "memory" is. Explain.
- Never assume they know C# syntax. Teach it.
- When you say "API", explain what an API is on first use.
- When you say "Defender", explain what Defender is and what it does.
- Explain WHY we do things, not just HOW.

## Writing Style Checklist

For every explanation you write, verify:
- [ ] No em dashes (use hyphens or restructure)
- [ ] No posh words (leverage, facilitate, seamless, robust, employ, utilize)
- [ ] No analogies (no comparisons to guards, keys, castles, office workers, etc)
- [ ] No casual filler ("pretty cool", "you know", "break things")
- [ ] Flowing prose (not choppy full stops every 2-3 words)
- [ ] Every technical term explained on first use
- [ ] Cause and effect is clear
- [ ] Beginner can understand without prior knowledge

## Validation Checklist Before Completion

- [ ] All 8 loaders written and tested
- [ ] All loaders pass threat detection checks
- [ ] All 11 teaching documents written
- [ ] All documents follow beginner tone rules
- [ ] All documents follow the required section structure
- [ ] All code examples tested in actual Windows 11 + Kali lab
- [ ] All commits pushed to main
- [ ] Lab folders created and organized correctly

## Begin Now

1. Start with Phase 1: Research modern evasion techniques from the sources listed above. Create an internal research summary.
2. Do not write any loader code until research is complete.
3. Once research is complete, begin Phase 2: Write all 8 loaders.
4. Once all loaders are written, begin Phase 3: Run threat validation on each.
5. Once all loaders pass threat validation, begin Phase 4: Write the 11 teaching documents.
6. Commit and push after each major phase.
7. Commit and push to only main branch after each teaching document is complete.

Do not rush. Do not skip phases. Do not begin writing teaching materials until loaders are validated.

Report your progress after Phase 1 research is complete. Do not proceed to Phase 2 until you confirm Phase 1 is done.
