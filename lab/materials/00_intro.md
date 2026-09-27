# Windows 11 Defender Evasion - C# from Scratch

## What You Will Learn

This curriculum teaches you how to write C# programs that run on a fully updated Windows 11 machine without being blocked by Windows Defender. You will start from zero, with no prior knowledge of C# or Windows internals, and by the end you will understand how Defender detects malicious programs and how to write code that avoids those detections.

This is a red team curriculum. Red teaming means testing an organization's security by simulating real attacks. When an organization hires a red team, the red team tries to break in using the same methods real attackers use. The difference is that the red team has permission and reports what they find so the organization can fix it. Everything in this curriculum is for authorized testing only.

You will build 8 working programs (called loaders) that demonstrate different ways to run code on a Windows 11 machine while Defender is fully enabled. Each loader teaches a specific evasion technique, and by the end you will combine all of them into one program that uses multiple layers of evasion at once.

## Why This Matters

Windows Defender is the default antivirus on every Windows 11 machine. It runs automatically, updates itself, and scans everything that runs on the system. Most organizations rely on Defender as their first line of defense, and many rely on it as their only defense.

If you are doing a red team engagement and your tools get blocked by Defender, the engagement is over before it starts. You cannot test an organization's security if their antivirus stops you from running your tools. Understanding how Defender works and how to write code that avoids its detection is a core skill for any red team operator.

This curriculum does not teach you to disable Defender. Disabling Defender is not evasion. Real targets will not let you disable their antivirus. Instead, you will learn to write code that Defender does not recognize as malicious, even though it is doing things Defender is designed to catch. That is real evasion.

## What You Will Build

Here are the 8 loaders you will create, in order. Each one builds on the previous:

**Loader 01 - Basic Shellcode Loader:** Your first program that runs shellcode (raw machine instructions) in memory. This is the foundation. It works, but Defender will catch it easily. That is on purpose because understanding why Defender catches it teaches you what Defender looks for.

**Loader 02 - XOR Encoder/Decoder:** You will take shellcode and encrypt it using XOR before putting it on disk. When the loader runs, it decrypts the shellcode in memory and then executes it. Defender scans files on disk, so if the file on disk looks like random data instead of known malicious code, Defender does not flag it.

**Loader 03 - Direct Syscalls Loader:** Windows has an API layer that programs use to talk to the operating system. Defender monitors this API layer by placing hooks (interception points) on key functions. Direct syscalls skip the API layer entirely and talk to the Windows kernel directly, bypassing Defender's hooks.

**Loader 04 - AMSI Bypass:** AMSI stands for Antimalware Scan Interface. It is a system that lets Defender scan scripts and .NET code before it runs. If you want to run PowerShell commands or load .NET tools on a target, you need to disable AMSI first. This loader patches AMSI in memory so it stops checking.

**Loader 05 - Reflective Injector:** Instead of running your code as a standalone program, this loader writes your code into the memory of another process that is already running on the system. From Defender's perspective, a legitimate program is running normally. Your code is running inside that program's memory space, hidden from view.

**Loader 06 - Process Hollowing Alternative (Early Bird APC):** This loader creates a new legitimate Windows process in a suspended state, writes your code into it before it starts, and then resumes it. Your code runs before the legitimate program's own code, inside a process that looks normal to Defender.

**Loader 07 - ETW Patch:** ETW stands for Event Tracing for Windows. It is the telemetry system that sends information about what your program is doing back to Defender and other security products. By patching ETW, your program stops sending telemetry, so Defender receives no data about your program's activity.

**Loader 08 - Combined Evasion Loader:** This is the final loader that puts everything together. It patches ETW first (so Defender gets no telemetry), patches AMSI (so script scanning is disabled), decrypts shellcode in memory (so nothing on disk is malicious), uses dynamically resolved functions (so the binary has no suspicious imports), and executes through NT functions that bypass API hooks. Multiple layers of evasion working together.

## Prerequisites

You do not need any prior programming experience. Document 02 teaches C# from scratch using security-focused examples. However, you do need these things before starting:

**Required knowledge:**
- Basic computer literacy (you know how to install software, navigate folders, use a terminal)
- You understand what an IP address is and what a port is
- You have used a computer with Windows before (you know what the Start menu is, what Task Manager is, and how to run programs)

**Required hardware:**
- A computer with at least 16 GB of RAM (you will run two virtual machines at the same time)
- At least 100 GB of free disk space
- A processor that supports virtualization (almost all modern processors do)

**Required software (you will install these in Document 01):**
- VMware Workstation Pro (free for personal use)
- Windows 11 Pro ISO (free from Microsoft)
- Kali Linux ISO (free from kali.org)
- Visual Studio 2022 Community Edition (free, installed on the Windows VM)
- .NET 6 SDK or later (installed with Visual Studio)

## Lab Environment

Every exercise in this curriculum runs in a controlled lab environment. You will set this up in Document 01. The lab has two virtual machines on an isolated network:

```
Lab Network: 192.168.10.0/24

[Your Host Machine]
      |
  [VMware Pro]
      |
      +--- [Windows 11 VM: 192.168.10.100]
      |      - Fully updated
      |      - Defender ON (real-time, cloud, auto-updates)
      |      - Visual Studio 2022 installed
      |      - .NET 6+ SDK
      |      - Username: kimjongun
      |      - This is the TARGET machine
      |
      +--- [Kali Linux VM: 192.168.10.200]
             - Latest Kali build
             - msfvenom for generating shellcode
             - python3 for hosting files
             - smbclient for file transfers
             - This is the ATTACKER machine
```

**Important:** Defender stays enabled on the Windows VM at all times with default settings. You will never disable it, add exclusions, or weaken it in any way. The whole point of this curriculum is to write code that works with Defender fully enabled.

## How This Curriculum Is Structured

There are 11 documents numbered 00 through 11. You are reading Document 00 right now. Each document covers one topic and builds on the ones before it:

| Document | Title | What You Learn |
|----------|-------|----------------|
| 00 | Introduction (this document) | What the curriculum covers and what you need |
| 01 | Lab Setup | Build your Windows 11 and Kali VMs, install all tools |
| 02 | C# Basics | Variables, loops, functions, and basic C# through security examples |
| 03 | Windows API | How to call Windows functions from C#, what P/Invoke and DllImport are |
| 04 | Memory Fundamentals | What process memory is, how to allocate and write to memory, how to create threads |
| 05 | Shellcode Loader | Build your first working shellcode loader, generate payloads with msfvenom |
| 06 | Encoding Evasion | XOR encryption, encoding shellcode on disk, decrypting at runtime |
| 07 | Direct Syscalls | What syscalls are, how to call them directly, why this bypasses Defender hooks |
| 08 | AMSI Bypass | What AMSI is, how it scans code, how to patch it in memory |
| 09 | Reflective Injection | Loading code into another process from memory, no disk writes |
| 10 | Combined Evasion | Putting all techniques together into one layered evasion program |
| 11 | Real World Scenarios | How these techniques combine in real red team engagements |

**Do them in order.** Each document assumes you have completed the previous ones. If you skip ahead, the code examples and explanations will not make sense because they reference things taught earlier.

## How Each Document Teaches

Every document uses the same teaching method. You will never see a massive wall of code dropped on you without explanation. Instead, each code example is taught like this:

First, you see 2 or 3 lines of code. The document explains what those lines do, why they are there, and what happens when they run. Then you see the next 2 or 3 lines with the same treatment. This continues until the full program is shown. After all the pieces are explained, the complete code is shown again so you can see how everything fits together.

Every technical term is explained when it first appears. If a document mentions "P/Invoke" for the first time, it tells you what P/Invoke is and why you need it before moving on. Nothing is assumed.

## Folder Structure

All your work lives in a folder called `lab/`. Inside it:

```
lab/
  loaders/          <- The 8 C# loader source files
    01_shellcode_loader.cs
    02_xor_encoder.cs
    03_direct_syscalls_loader.cs
    04_amsi_bypass.cs
    05_reflective_injector.cs
    06_process_hollowing_alt.cs
    07_etw_patch.cs
    08_combined_evasion.cs
  materials/         <- These teaching documents (00 through 11)
    00_intro.md
    01_lab_setup.md
    ...
    11_real_world_scenarios.md
  scripts/           <- Any helper scripts for testing
```

The loader source files are complete, working C# programs with teaching comments explaining every section. You can read them alongside the teaching documents for additional detail.

## Rules for This Curriculum

**1. Defender stays on.** Never disable it. Never add exclusions. Never weaken it. If your code gets caught by Defender, that is information. Fix your code, do not fix Defender.

**2. Everything runs in the lab.** Do not run any of these loaders on machines you do not own or do not have explicit written permission to test. This is for authorized security testing only.

**3. Understand, do not copy-paste.** Each loader is explained line by line so you understand what it does and why. If you just copy-paste without understanding, you will not be able to adapt when Defender updates its signatures (and it will).

**4. Test everything.** After building each loader, test it in your Windows 11 VM. Confirm that it works, confirm that Defender does not block it, and understand why it succeeds or fails.

**5. Expect updates.** Defender updates its detection signatures regularly. A technique that works today might get caught next week. The goal is not to memorize specific bypasses but to understand the mechanisms so you can develop new ones when old ones stop working.

## What Comes Next

Start with Document 01 (lab/materials/01_lab_setup.md). It walks you through setting up your Windows 11 VM and Kali Linux VM, installing all the tools you need, and verifying that everything works before you write any code.
