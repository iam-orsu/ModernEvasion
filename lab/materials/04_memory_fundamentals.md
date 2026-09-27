# Document 04: Memory Fundamentals - How Windows Manages RAM

## Where We Are

You finished Documents 02 and 03. You can:

- Write C# programs with variables, loops, arrays, XOR encryption, file I/O, and command-line arguments
- Call Windows API functions from C# using DllImport and P/Invoke
- Use VirtualAlloc, Marshal.Copy, VirtualProtect, and CreateThread

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling, target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners. All coding in this document happens on the dev box.

## Why This Is Next

In Document 03, you used VirtualAlloc, VirtualProtect, and CreateThread. You know what they do. But you used them without understanding what is actually happening inside Windows when you call them.

The loaders in Documents 05 through 10 make decisions based on how Windows manages RAM:

- Why does using VirtualAlloc with 0x04 first and then VirtualProtect with 0x20 make your loader harder for Defender to detect?
- When you call VirtualAllocEx to put RAM inside another program, what does "inside another program" actually mean?
- When Defender flags a program for requesting writable-executable RAM, what exactly is it detecting?

This document answers those questions.

## How This Works

### Your Computer's Physical RAM

Your computer has a rectangular chip on its motherboard called RAM (Random Access Memory). When your computer says "16 GB RAM" that is how much of this chip is installed. RAM is where programs actually run. When you double-click Chrome, Windows copies Chrome from your hard drive into RAM and runs it from there because RAM is thousands of times faster than a hard drive.

Two problems come up immediately:

**Problem 1: Limited RAM.** Your Windows 11 VM has 8 GB of RAM. Right now, dozens of programs are running: Explorer, Defender, the taskbar, background services, maybe Chrome or Notepad. Each needs RAM. But 8 GB is a fixed amount. What happens when they all need more than 8 GB combined?

**Problem 2: Isolation.** When Chrome gets a chunk of RAM and Notepad gets a different chunk, what stops Chrome from accidentally reading or writing into Notepad's chunk? If your shellcode loader runs, could it read passwords that another program stored in its RAM?

Windows solves both problems with a system called **virtual memory**.

### Virtual Memory: Every Program Gets Its Own Private Address Space

Open Task Manager on your dev box (Ctrl+Shift+Esc). Click the Details tab. Look at the "Memory (private working set)" column. Add up the numbers for all running processes. The total is often more than the physical RAM your VM has. How?

Windows does not give programs direct access to the physical RAM chip. Instead, Windows creates a private address space for each program. This is called virtual memory.

Here is how it works:

- Every program thinks it has its own private block of RAM that starts at address 0 and goes up to a very large number. On 64-bit Windows, each program's address space is 128 terabytes.
- This address space is not real physical RAM. It is a numbering system that Windows maintains.
- Windows keeps a **mapping table** for each program that translates virtual addresses to physical addresses. The CPU checks this table on every RAM access.

**What isolation looks like in practice:**

Chrome stores data at virtual address 0x7FF00000. Notepad stores data at virtual address 0x7FF00000. Those are NOT the same physical location. Chrome's 0x7FF00000 maps to one spot on the physical RAM chip. Notepad's 0x7FF00000 maps to a completely different spot. Chrome has no way to specify Notepad's physical location because Chrome does not even know where Notepad's data physically sits.

**How total usage can exceed physical RAM:**

Windows can take chunks of virtual memory that a program has not accessed recently and save them to a file on the hard drive called the **page file** (pagefile.sys). The physical RAM that held those chunks is now free for other programs. If the program tries to access that data again, Windows reads it back from the page file into physical RAM. This is called **paging**. It is slower, but it means programs can use more RAM than physically exists.

You can see the page file right now. Open File Explorer on your dev box, go to C:\, and if hidden files are visible, you will see pagefile.sys.

### What This Means for Shellcode

**Local execution (your own process):**

When your loader calls VirtualAlloc, Windows gives it a chunk of virtual addresses in the loader's own address space and maps them to physical RAM. The shellcode bytes exist at a virtual address that only your loader process can see. No other process can access those bytes.

**Remote injection (another process):**

When you use VirtualAllocEx to allocate RAM inside explorer.exe, Windows creates a chunk of virtual addresses in explorer.exe's address space. Your loader uses WriteProcessMemory to copy shellcode into that chunk. After the copy, the shellcode belongs to explorer.exe. Your loader can exit, and the shellcode stays because it lives in explorer.exe's RAM now.

### Pages: How Windows Divides RAM

Windows does not manage RAM byte by byte. That would be too slow. Instead, Windows divides RAM into fixed-size blocks called **pages**.

On x86-64 systems (your Windows 11 VM), each page is **4,096 bytes (4 KB)**.

Everything Windows does with RAM works in pages:

- You call VirtualAlloc and ask for **100 bytes** → Windows gives you **one full page (4,096 bytes)**. You cannot get less than one page.
- You ask for **5,000 bytes** → Windows gives you **two pages (8,192 bytes)** because 5,000 does not fit in one page.
- You call VirtualProtect to change permissions → the **entire page** changes. You cannot make half a page executable and the other half non-executable.

### Page Permissions: What the CPU Allows

Every page has permissions that control what the CPU can do with it. The CPU checks these on every read, write, and execute. If a program violates the permissions, the CPU raises an exception and Windows crashes the program ("Access Violation").

The four permissions that matter:

| Value | Name | Read | Write | Execute | Used For |
|-------|------|------|-------|---------|----------|
| 0x04 | PAGE_READWRITE | Yes | Yes | No | Data: variables, arrays, buffers |
| 0x20 | PAGE_EXECUTE_READ | Yes | No | Yes | Code: loaded .exe and .dll files |
| 0x40 | PAGE_EXECUTE_READWRITE | Yes | Yes | Yes | Suspicious: malware uses this |
| 0x01 | PAGE_NOACCESS | No | No | No | Guard pages, unallocated regions |

**0x04 (PAGE_READWRITE)** is for data storage. You can read and write, but the CPU will crash if it tries to run code from here.

**0x20 (PAGE_EXECUTE_READ)** is for code. The CPU can run instructions and read data, but nobody can write to it. This is what Windows uses for loaded programs.

**0x40 (PAGE_EXECUTE_READWRITE)** is all permissions at once. This is what **Defender watches for**. Legitimate programs almost never need RAM that is both writable and executable at the same time. Malware uses 0x40 because it is simple: write shellcode, run it, done. Defender flags this immediately.

### The Two-Step Allocation: Why It Matters

In Document 03, you learned the safe approach:

1. VirtualAlloc with **0x04** (read-write) → get writable pages
2. Marshal.Copy → write shellcode into those pages
3. VirtualProtect with **0x20** (execute-read) → make pages executable, remove write
4. CreateThread → start running the code

This is called **W^X** (Write XOR Execute): a page is either writable or executable, never both at the same time.

**Why Defender cares:**

A program that calls VirtualAlloc with 0x40 (all permissions at once) and then CreateThread at that address is a textbook shellcode injection pattern. Defender's behavioral analysis flags it immediately.

With the two-step approach, the pages are never writable and executable simultaneously:

- **While writing:** pages are read-write only. CPU cannot execute here.
- **After changing:** pages are execute-read only. Nobody can write here.

This is exactly what legitimate programs do. The .NET JIT compiler, web browsers running JavaScript, and Java's JVM all compile code at runtime using this same two-step approach. Your loader's behavior matches a legitimate runtime compiler.

### How the CPU Enforces Permissions (DEP)

These permissions are not just software settings. The CPU hardware enforces them through **DEP** (Data Execution Prevention).

The CPU has a component called the **MMU** (Memory Management Unit). On every RAM access, the MMU checks the page table (the mapping table for virtual-to-physical addresses). Each page table entry contains:

- The physical address the virtual address maps to
- Permission bits: can you read, write, execute?

If the CPU tries to execute code from a page without execute permission, the MMU raises a hardware exception. Windows catches it and terminates the program. This happens at the hardware level, before any software check. There is no way to bypass DEP from user-mode code.

This is why you cannot put shellcode in a regular C# byte array and run it. C# arrays are stored in pages with PAGE_READWRITE permission. The .NET runtime never gives them execute permission. The MMU would crash your program before a single shellcode instruction ran.

### Your Process vs. Another Process

Everything above is about your own process. For injection (Documents 09 and 10), you work with another process's virtual address space using these functions:

| Your Process | Another Process | What It Does |
|---|---|---|
| VirtualAlloc | **VirtualAllocEx** | Request pages (Ex = external process) |
| Marshal.Copy | **WriteProcessMemory** | Copy bytes into pages |
| VirtualProtect | **VirtualProtectEx** | Change page permissions |
| CreateThread | **CreateRemoteThread** | Start a thread |

The "Ex" functions take an extra parameter: a handle to the target process (from OpenProcess). The addresses they return are virtual addresses in the target process's address space, not yours.

## What Defender Does

Defender monitors RAM operations at multiple levels:

**VirtualAlloc/VirtualAllocEx calls.** Defender's API hooks log every call. A single VirtualAlloc is normal. But VirtualAlloc with executable permissions followed by writing data and creating a thread matches the shellcode injection pattern.

**Permission changes.** VirtualProtect calls that add execute permission to previously writable pages are logged. Programs that write data and then make it executable are following a code injection pattern.

**Cross-process operations.** The combination of OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread is the textbook injection sequence. Defender watches for this specifically.

**RWX pages.** Pages with PAGE_EXECUTE_READWRITE (0x40) are immediately suspicious. Legitimate programs almost never create them.

## The Evasion Technique

This document teaches foundational concepts. The evasion techniques that build on them:

- **Two-step allocation (all loaders):** Never request 0x40. Use 0x04, write data, then change to 0x20.
- **Direct syscalls (Document 07):** Skip the hooked DLL functions and call the kernel directly.
- **Dynamic API resolution (Documents 03, 05-10):** Find functions at runtime so their names stay out of the compiled binary.
- **Injection into trusted processes (Documents 09-10):** Run shellcode inside explorer.exe or svchost.exe.

## Getting the Loader Onto the Target

No loader in this document. All programs are learning exercises that run on your dev box (ammulu, 192.168.10.150). They allocate and free RAM, change permissions, and demonstrate cross-process concepts. They do not contain or execute shellcode.

## Teaching the Code

### Part 1: Viewing Your Process's Memory Layout

Before writing code, open Task Manager on your dev box. Click the Details tab. Find any running process and look at its memory column. Each process has its own separate RAM usage because each has its own virtual address space.

Here is a C# program that shows your own process's memory information:

```csharp
using System;
using System.Diagnostics;
```

`System.Diagnostics` gives you the `Process` class, which shows information about running programs.

```csharp
class Program
{
    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();
```

`Process.GetCurrentProcess()` returns a Process object representing your own running program.

```csharp
        Console.WriteLine("[*] Process: " + me.ProcessName);
        Console.WriteLine("[*] PID: " + me.Id);
```

Your process name and PID (process ID), the unique number Windows assigned when the program started.

```csharp
        Console.WriteLine("[*] Working Set (RAM in use): " + 
            (me.WorkingSet64 / 1024 / 1024) + " MB");
```

**Working set** is the amount of physical RAM your process is currently using. This is what Task Manager shows in the "Memory" column. "Working set" is the official Windows term for pages that are currently in physical RAM, not paged out to the hard drive.

```csharp
        Console.WriteLine("[*] Virtual Memory Size: " + 
            (me.VirtualMemorySize64 / 1024 / 1024) + " MB");
```

**Virtual memory size** includes pages in physical RAM AND pages paged out to the hard drive. This number is always larger than or equal to the working set.

```csharp
        Console.WriteLine("[*] Private Memory: " + 
            (me.PrivateMemorySize64 / 1024 / 1024) + " MB");
```

**Private memory** is virtual memory that belongs only to your process. Some pages are shared between processes (for example, kernel32.dll code is loaded once and shared by all processes). Private memory is RAM that only your process uses.

```csharp
        Console.WriteLine("[*] Number of threads: " + me.Threads.Count);
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
}
```

Here is the complete program:

```csharp
using System;
using System.Diagnostics;

class Program
{
    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();

        Console.WriteLine("[*] Process: " + me.ProcessName);
        Console.WriteLine("[*] PID: " + me.Id);
        Console.WriteLine("[*] Working Set (RAM in use): " + 
            (me.WorkingSet64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Virtual Memory Size: " + 
            (me.VirtualMemorySize64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Private Memory: " + 
            (me.PrivateMemorySize64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Number of threads: " + me.Threads.Count);
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
}
```

Run it with `dotnet run`:

```
[*] Process: dotnet
[*] PID: 5128
[*] Working Set (RAM in use): 42 MB
[*] Virtual Memory Size: 2048 MB
[*] Private Memory: 28 MB
[*] Number of threads: 14
```

Notice the virtual memory size (2048 MB) is much larger than the working set (42 MB). Your program has 2 GB of virtual address space mapped but only 42 MB of physical RAM. Most of the virtual address space is either paged out or mapped but not actively being used.

The thread count (14) shows that even a simple C# program has many threads. The .NET runtime creates background threads for garbage collection (automatic RAM cleanup) and JIT compilation.

### Part 2: Allocating Pages and Observing the Working Set

This program allocates pages with VirtualAlloc and shows how the working set changes.

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
```

Three using lines. `System.Runtime.InteropServices` gives you DllImport and Marshal for calling Windows functions.

```csharp
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);
```

Same DllImport declarations from Document 03. VirtualAlloc requests pages, VirtualFree gives them back.

```csharp
    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();

        me.Refresh();
        long before = me.WorkingSet64;
        Console.WriteLine("[*] Working set before allocation: " + 
            (before / 1024) + " KB");
```

`me.Refresh()` updates the process information. Without Refresh, the values might be stale.

```csharp
        uint allocSize = 1024 * 1024;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, allocSize, 0x3000, 0x04);
```

Allocate 1 MB of RAM (1,048,576 bytes). Since each page is 4,096 bytes, this is 256 pages. Permissions are 0x04 (PAGE_READWRITE).

```csharp
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated 1 MB (256 pages) at: 0x" + mem.ToString("X"));
```

Check for failure, then print the address.

```csharp
        for (int i = 0; i < (int)allocSize; i++)
        {
            Marshal.WriteByte(mem + i, 0xAA);
        }
        Console.WriteLine("[+] Wrote 0xAA to all 1 MB.");
```

Write to every byte. `Marshal.WriteByte(address, value)` writes a single byte to a specific address. We write to every byte because Windows may not assign physical RAM to pages until they are actually written to (this is called demand paging).

```csharp
        me.Refresh();
        long after = me.WorkingSet64;
        Console.WriteLine("[*] Working set after allocation: " + 
            (after / 1024) + " KB");
        Console.WriteLine("[*] Difference: " + 
            ((after - before) / 1024) + " KB");
```

The working set should have increased by about 1024 KB (1 MB).

```csharp
        VirtualFree(mem, 0, 0x8000);

        me.Refresh();
        long freed = me.WorkingSet64;
        Console.WriteLine("[*] Working set after freeing: " + 
            (freed / 1024) + " KB");
        Console.WriteLine("[*] RAM returned: " + 
            ((after - freed) / 1024) + " KB");
    }
}
```

After freeing the pages, the working set drops back down.

Here is the complete program:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();

        me.Refresh();
        long before = me.WorkingSet64;
        Console.WriteLine("[*] Working set before allocation: " + 
            (before / 1024) + " KB");

        uint allocSize = 1024 * 1024;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, allocSize, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated 1 MB (256 pages) at: 0x" + mem.ToString("X"));

        for (int i = 0; i < (int)allocSize; i++)
        {
            Marshal.WriteByte(mem + i, 0xAA);
        }
        Console.WriteLine("[+] Wrote 0xAA to all 1 MB.");

        me.Refresh();
        long after = me.WorkingSet64;
        Console.WriteLine("[*] Working set after allocation: " + 
            (after / 1024) + " KB");
        Console.WriteLine("[*] Difference: " + 
            ((after - before) / 1024) + " KB");

        VirtualFree(mem, 0, 0x8000);

        me.Refresh();
        long freed = me.WorkingSet64;
        Console.WriteLine("[*] Working set after freeing: " + 
            (freed / 1024) + " KB");
        Console.WriteLine("[*] RAM returned: " + 
            ((after - freed) / 1024) + " KB");
    }
}
```

Expected output:
```
[*] Working set before allocation: 43008 KB
[+] Allocated 1 MB (256 pages) at: 0x1F0000
[+] Wrote 0xAA to all 1 MB.
[*] Working set after allocation: 44032 KB
[*] Difference: 1024 KB
[*] Working set after freeing: 43008 KB
[*] RAM returned: 1024 KB
```

VirtualAlloc added exactly 1 MB to the working set (1024 KB), and VirtualFree removed it.

### Part 3: Page Alignment and Minimum Allocation

This program shows that Windows rounds everything up to page boundaries.

```csharp
using System;
using System.Runtime.InteropServices;
```

```csharp
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);
```

Same VirtualAlloc and VirtualFree from before.

```csharp
    static void Main(string[] args)
    {
        Console.WriteLine("[*] Requesting different sizes to see page alignment:");
        Console.WriteLine();

        uint[] sizes = { 1, 100, 4096, 4097, 8000, 16384 };
```

An array of different sizes to test. Some fit in one page, some need two, some need four.

```csharp
        foreach (uint size in sizes)
        {
            IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);
            if (mem == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed for size " + size);
                continue;
            }
```

Loop through each size, allocate that many bytes.

```csharp
            uint pages = (size + 4095) / 4096;
            uint actualBytes = pages * 4096;

            Console.WriteLine("[+] Requested: " + size + " bytes");
            Console.WriteLine("    Address: 0x" + mem.ToString("X"));
            Console.WriteLine("    Pages used: " + pages + 
                " (" + actualBytes + " bytes actual)");
            Console.WriteLine();

            VirtualFree(mem, 0, 0x8000);
        }
    }
}
```

Calculate how many pages Windows actually used. `(size + 4095) / 4096` rounds up to the next page. Print the result and free the pages.

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    static void Main(string[] args)
    {
        Console.WriteLine("[*] Requesting different sizes to see page alignment:");
        Console.WriteLine();

        uint[] sizes = { 1, 100, 4096, 4097, 8000, 16384 };

        foreach (uint size in sizes)
        {
            IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);
            if (mem == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed for size " + size);
                continue;
            }

            uint pages = (size + 4095) / 4096;
            uint actualBytes = pages * 4096;

            Console.WriteLine("[+] Requested: " + size + " bytes");
            Console.WriteLine("    Address: 0x" + mem.ToString("X"));
            Console.WriteLine("    Pages used: " + pages + 
                " (" + actualBytes + " bytes actual)");
            Console.WriteLine();

            VirtualFree(mem, 0, 0x8000);
        }
    }
}
```

Output:

```
[+] Requested: 1 bytes → Pages used: 1 (4096 bytes actual)
[+] Requested: 100 bytes → Pages used: 1 (4096 bytes actual)
[+] Requested: 4096 bytes → Pages used: 1 (4096 bytes actual)
[+] Requested: 4097 bytes → Pages used: 2 (8192 bytes actual)
[+] Requested: 8000 bytes → Pages used: 2 (8192 bytes actual)
[+] Requested: 16384 bytes → Pages used: 4 (16384 bytes actual)
```

When you ask for 1 byte, you still get 4,096 bytes (one full page). When you ask for 4,097 bytes, you get 8,192 bytes (two pages). Your shellcode is usually a few hundred bytes, but Windows gives you at least one full 4 KB page. The unused bytes are zeros.

### Part 4: Observing Permission Changes

This program shows the two-step permission transition:

```csharp
using System;
using System.Runtime.InteropServices;
```

```csharp
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);
```

Three DllImport declarations: VirtualAlloc, VirtualProtect, VirtualFree.

```csharp
    static string PermName(uint perm)
    {
        switch (perm)
        {
            case 0x04: return "PAGE_READWRITE";
            case 0x20: return "PAGE_EXECUTE_READ";
            case 0x40: return "PAGE_EXECUTE_READWRITE";
            default: return "0x" + perm.ToString("X");
        }
    }
```

A helper function that converts a permission number to a readable name.

```csharp
    static void Main(string[] args)
    {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated 1 page at: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] Permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] CPU can: READ, WRITE. CPU cannot: EXECUTE.");
        Console.WriteLine();
```

Allocate one page with read-write permissions. At this point you can write data but the CPU cannot execute code here.

```csharp
        Marshal.WriteByte(mem, 0xC3);
        Console.WriteLine("[+] Wrote 0xC3 (RET instruction) to the page.");
        Console.WriteLine("[*] Data is written. But CPU still cannot execute here.");
        Console.WriteLine();
```

Write one byte (0xC3 is the RET instruction, which returns immediately). The byte is written but the CPU still cannot run it as code because the page is read-write only.

```csharp
        uint oldPerm;
        VirtualProtect(mem, 4096, 0x20, out oldPerm);
        Console.WriteLine("[+] Changed to PAGE_EXECUTE_READ (0x20).");
        Console.WriteLine("[*] Old permission was: " + PermName(oldPerm));
        Console.WriteLine("[*] CPU can now: READ, EXECUTE. CPU cannot: WRITE.");
        Console.WriteLine();
```

Change permissions from read-write to execute-read. Now the CPU can run the code, but nobody can write to this page anymore.

```csharp
        Console.WriteLine("[*] The page went through two states:");
        Console.WriteLine("    State 1: READWRITE   -> could write, could not execute");
        Console.WriteLine("    State 2: EXECUTE_READ -> can execute, cannot write");
        Console.WriteLine("[*] NEVER writable and executable at the same time.");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    static string PermName(uint perm)
    {
        switch (perm)
        {
            case 0x04: return "PAGE_READWRITE";
            case 0x20: return "PAGE_EXECUTE_READ";
            case 0x40: return "PAGE_EXECUTE_READWRITE";
            default: return "0x" + perm.ToString("X");
        }
    }

    static void Main(string[] args)
    {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated 1 page at: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] Permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] CPU can: READ, WRITE. CPU cannot: EXECUTE.");
        Console.WriteLine();

        Marshal.WriteByte(mem, 0xC3);
        Console.WriteLine("[+] Wrote 0xC3 (RET instruction) to the page.");
        Console.WriteLine("[*] Data is written. But CPU still cannot execute here.");
        Console.WriteLine();

        uint oldPerm;
        VirtualProtect(mem, 4096, 0x20, out oldPerm);
        Console.WriteLine("[+] Changed to PAGE_EXECUTE_READ (0x20).");
        Console.WriteLine("[*] Old permission was: " + PermName(oldPerm));
        Console.WriteLine("[*] CPU can now: READ, EXECUTE. CPU cannot: WRITE.");
        Console.WriteLine();

        Console.WriteLine("[*] The page went through two states:");
        Console.WriteLine("    State 1: READWRITE   -> could write, could not execute");
        Console.WriteLine("    State 2: EXECUTE_READ -> can execute, cannot write");
        Console.WriteLine("[*] NEVER writable and executable at the same time.");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

Output:
```
[+] Allocated 1 page at: 0x<address>
[*] Permission: PAGE_READWRITE (0x04)
[*] CPU can: READ, WRITE. CPU cannot: EXECUTE.

[+] Wrote 0xC3 (RET instruction) to the page.
[*] Data is written. But CPU still cannot execute here.

[+] Changed to PAGE_EXECUTE_READ (0x20).
[*] Old permission was: PAGE_READWRITE
[*] CPU can now: READ, EXECUTE. CPU cannot: WRITE.

[*] The page went through two states:
    State 1: READWRITE   -> could write, could not execute
    State 2: EXECUTE_READ -> can execute, cannot write
[*] NEVER writable and executable at the same time.
```

### Part 5: Reading Another Process's Information

This program examines another running program without modifying it.

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
```

```csharp
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
```

OpenProcess gives you a handle to another program. CloseHandle releases the handle when you are done.

```csharp
    static void Main(string[] args)
    {
        string target = args.Length > 0 ? args[0] : "explorer";

        Process[] found = Process.GetProcessesByName(target);
        if (found.Length == 0)
        {
            Console.WriteLine("[-] " + target + " is not running.");
            return;
        }
```

Search for a running program by name. Default is "explorer" if you do not pass an argument.

```csharp
        Process proc = found[0];
        Console.WriteLine("[+] Found " + target + ".exe");
        Console.WriteLine("[*] PID: " + proc.Id);
        Console.WriteLine("[*] Working Set: " + 
            (proc.WorkingSet64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Threads: " + proc.Threads.Count);
        Console.WriteLine();
```

Print the target's PID, how much physical RAM it uses, and how many threads it has.

```csharp
        IntPtr handle = OpenProcess(0x0400, false, proc.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }
        Console.WriteLine("[+] Got handle to " + target + ".exe: 0x" + handle.ToString("X"));
        Console.WriteLine("[*] Opened with PROCESS_QUERY_INFORMATION (0x0400).");
        Console.WriteLine("[*] Can read info, but CANNOT modify the process.");
```

Open the process with read-only access (0x0400). This lets you read information but not write to its RAM or create threads inside it.

```csharp
        Console.WriteLine();
        Console.WriteLine("[*] For injection (Documents 09-10), you would use");
        Console.WriteLine("    PROCESS_ALL_ACCESS (0x001FFFFF) instead.");

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

Here is the complete program:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    static void Main(string[] args)
    {
        string target = args.Length > 0 ? args[0] : "explorer";

        Process[] found = Process.GetProcessesByName(target);
        if (found.Length == 0)
        {
            Console.WriteLine("[-] " + target + " is not running.");
            return;
        }

        Process proc = found[0];
        Console.WriteLine("[+] Found " + target + ".exe");
        Console.WriteLine("[*] PID: " + proc.Id);
        Console.WriteLine("[*] Working Set: " + 
            (proc.WorkingSet64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Threads: " + proc.Threads.Count);
        Console.WriteLine();

        IntPtr handle = OpenProcess(0x0400, false, proc.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }
        Console.WriteLine("[+] Got handle to " + target + ".exe: 0x" + handle.ToString("X"));
        Console.WriteLine("[*] Opened with PROCESS_QUERY_INFORMATION (0x0400).");
        Console.WriteLine("[*] Can read info, but CANNOT modify the process.");

        Console.WriteLine();
        Console.WriteLine("[*] For injection (Documents 09-10), you would use");
        Console.WriteLine("    PROCESS_ALL_ACCESS (0x001FFFFF) instead.");

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

Run with `dotnet run` or `dotnet run -- notepad`:

```
[+] Found explorer.exe
[*] PID: 4892
[*] Working Set: 98 MB
[*] Threads: 47

[+] Got handle to explorer.exe: 0xA4
[*] Opened with PROCESS_QUERY_INFORMATION (0x0400).
[*] Can read info, but CANNOT modify the process.

[*] For injection (Documents 09-10), you would use
    PROCESS_ALL_ACCESS (0x001FFFFF) instead.
[+] Handle closed.
```

Explorer has 47 threads. When you inject shellcode in Document 09, you add one more thread. Going from 47 to 48 is not suspicious. A standalone loader with only 2 threads running shellcode on one of them is much easier to spot.

### Part 6: The Full Local Execution Pattern with Logging

This is the complete local shellcode execution pattern from Document 03, but with step-by-step logging that shows pages, permissions, and thread counts. It runs a single 0xC3 byte (the RET instruction, which returns immediately).

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
```

```csharp
class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);
```

Five DllImport declarations for the full pattern: allocate, protect, create thread, wait, free.

```csharp
    static void Main(string[] args)
    {
        byte[] code = new byte[] { 0xC3 };
```

One byte of test code. 0xC3 is the RET instruction, which returns immediately.

```csharp
        Console.WriteLine("=== Step 1: Allocate pages (READ-WRITE) ===");
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Address: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] Permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] CAN write. CANNOT execute.");
        Console.WriteLine();
```

Step 1: get a page with read-write permission.

```csharp
        Console.WriteLine("=== Step 2: Copy code into pages ===");
        Marshal.Copy(code, 0, mem, code.Length);
        Array.Clear(code, 0, code.Length);
        Console.WriteLine("[+] Copied " + code.Length + " byte(s).");
        Console.WriteLine("[+] Source array zeroed out.");
        Console.WriteLine("[*] Code only exists in VirtualAlloc pages now.");
        Console.WriteLine();
```

Step 2: copy the byte into the page, then zero out the C# array so the byte only exists in VirtualAlloc pages.

```csharp
        Console.WriteLine("=== Step 3: Change permission to EXECUTE-READ ===");
        uint oldPerm;
        if (!VirtualProtect(mem, (uint)code.Length, 0x20, out oldPerm))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Permission changed: 0x04 -> 0x20");
        Console.WriteLine("[*] CAN execute. CANNOT write.");
        Console.WriteLine();
```

Step 3: change to execute-read. The page was never writable and executable at the same time.

```csharp
        Console.WriteLine("=== Step 4: Create thread ===");
        IntPtr thread = CreateThread(
            IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " is running.");
        Console.WriteLine();
```

Step 4: create a thread at the address. The CPU starts executing the byte at that address.

```csharp
        Console.WriteLine("=== Step 5: Wait for thread ===");
        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread finished (RET returned immediately).");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

Step 5: wait for the thread. The RET instruction returns immediately, so this finishes right away.

Here is the complete program:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    static void Main(string[] args)
    {
        byte[] code = new byte[] { 0xC3 };

        Console.WriteLine("=== Step 1: Allocate pages (READ-WRITE) ===");
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Address: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] Permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] CAN write. CANNOT execute.");
        Console.WriteLine();

        Console.WriteLine("=== Step 2: Copy code into pages ===");
        Marshal.Copy(code, 0, mem, code.Length);
        Array.Clear(code, 0, code.Length);
        Console.WriteLine("[+] Copied " + code.Length + " byte(s).");
        Console.WriteLine("[+] Source array zeroed out.");
        Console.WriteLine("[*] Code only exists in VirtualAlloc pages now.");
        Console.WriteLine();

        Console.WriteLine("=== Step 3: Change permission to EXECUTE-READ ===");
        uint oldPerm;
        if (!VirtualProtect(mem, (uint)code.Length, 0x20, out oldPerm))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Permission changed: 0x04 -> 0x20");
        Console.WriteLine("[*] CAN execute. CANNOT write.");
        Console.WriteLine();

        Console.WriteLine("=== Step 4: Create thread ===");
        IntPtr thread = CreateThread(
            IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " is running.");
        Console.WriteLine();

        Console.WriteLine("=== Step 5: Wait for thread ===");
        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread finished (RET returned immediately).");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode. The pattern stays identical.

### The Cross-Process Functions (Reference)

You do not use these functions until Document 09. But now that you understand virtual memory and pages, here is what each cross-process function does:

**VirtualAllocEx** - creates pages inside another process:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
```

Same as VirtualAlloc but the first parameter is a handle to the target process. The return value is a virtual address in the **target's** address space, not yours.

**WriteProcessMemory** - copies bytes into another process:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, uint nSize,
        out uint lpNumberOfBytesWritten);
```

`hProcess` is the target. `lpBaseAddress` is the address in the target (from VirtualAllocEx). `lpBuffer` is your byte array. Windows copies bytes across virtual address spaces through the kernel.

**VirtualProtectEx** - changes page permissions in another process:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(
        IntPtr hProcess, IntPtr lpAddress, uint dwSize,
        uint flNewProtect, out uint lpflOldProtect);
```

Same as VirtualProtect but operates on the target process's pages.

**CreateRemoteThread** - creates a thread in another process:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(
        IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter,
        uint dwCreationFlags, out uint lpThreadId);
```

`lpStartAddress` is where the thread starts running, in the target's address space. The thread lives inside the target process and keeps running even if your loader exits.

**The complete injection flow:**

1. **OpenProcess** on the target's PID with PROCESS_ALL_ACCESS
2. **VirtualAllocEx** to create read-write pages inside the target
3. **WriteProcessMemory** to copy shellcode into those pages
4. **VirtualProtectEx** to change permissions to execute-read
5. **CreateRemoteThread** to start a thread at the shellcode address

After step 5, shellcode runs inside the target. Your loader can exit. The shellcode stays because it is a thread inside the target process.

## Compilation and Execution

For every example:

1. On the dev box (ammulu): `cd C:\Users\ammulu\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`
4. For programs with arguments: `dotnet run -- explorer`

All examples are safe to run. They allocate and free RAM, read process info, and execute a single RET instruction. No shellcode.

## Confirming Success

After this document, verify:

- [ ] You understand that virtual memory gives every program its own private address space
- [ ] You know that two programs with the same virtual address use different physical RAM locations
- [ ] You understand that Windows divides RAM into pages of 4,096 bytes (4 KB)
- [ ] You know the four page permissions (RW, RX, RWX, NOACCESS) and their hex values
- [ ] You understand why PAGE_EXECUTE_READWRITE (0x40) is suspicious to Defender
- [ ] You understand the two-step allocation: RW first, write data, then change to RX
- [ ] You know why the two-step approach avoids Defender detection
- [ ] You understand working set (physical RAM) vs. virtual memory size
- [ ] You understand VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, CreateRemoteThread
- [ ] You ran the page allocation program and saw the working set change
- [ ] You ran the permission change program and saw the two-step transition

## What Was Gained

You now understand how Windows manages RAM at the page level:

- VirtualAlloc with 0x04 then VirtualProtect with 0x20 = two-step allocation to avoid writable-executable pages
- VirtualAllocEx creates pages inside another process's virtual address space
- WriteProcessMemory copies bytes across virtual address spaces through the kernel
- Defender flags 0x40 (RWX) because legitimate programs almost never need it

The loaders use these concepts in every function call. Understanding what happens at the page level means you can modify loaders, debug failures, and build new ones from scratch.

## Common Threats and Variations

### Variation 1: Large Page Allocations

Windows supports "large pages" of 2 MB instead of 4 KB. Some malware uses large pages because some security tools only monitor standard 4 KB page operations. Requires administrator access and the "Lock pages in memory" privilege.

### Variation 2: Section Objects for Cross-Process Sharing

Instead of using WriteProcessMemory (which Defender watches), some loaders create a section object. A section is a region of RAM that two processes share simultaneously. When your loader writes shellcode into the section, the target process can read it immediately because they share the same physical pages. No WriteProcessMemory call, so Defender's hook never triggers.

### Variation 3: Memory-Mapped Files

NtCreateSection and NtMapViewOfSection can map a file into a process's virtual address space. Some loaders create a temporary file with shellcode, map it into the target, and delete the file. The shellcode appears in the target's address space as if loaded from a DLL, leaving different ETW events than the VirtualAllocEx + WriteProcessMemory approach.

## Detection and Defense (Blue Team Perspective)

**Monitor page permission changes.** Log every VirtualProtect/VirtualProtectEx call that adds execute permission to previously writable pages. This catches the two-step allocation.

Blue team action: flag VirtualProtect calls where the new permission includes EXECUTE and the old included WRITE.

**Detect cross-process memory operations.** The combination of OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread in one program is a strong injection signal.

Blue team action: alert when a non-system process performs the full injection sequence against another process.

**Track working set anomalies.** If explorer.exe suddenly allocates new executable pages not from a DLL load, that is suspicious.

Blue team action: monitor RX/RWX page allocations in trusted processes that do not correspond to module load events.

**Watch for page file artifacts.** When shellcode pages get paged out to pagefile.sys, the bytes are written to the hard drive. Forensic tools can scan the page file for shellcode signatures.

Blue team action: periodically scan pagefile.sys for known shellcode patterns.

## What Comes Next

Document 05 (lab/materials/05_shellcode_loader.md) is where you build your first real working loader. You will generate shellcode with msfvenom on Kali, transfer it to the dev box, compile the loader on the dev box, transfer the compiled binary and shellcode to the target, and run it there. The loader uses the VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread pattern you have practiced. You will see Defender on the target catch it, understand why, and learn what needs to change in Document 06 to bypass the detection.
