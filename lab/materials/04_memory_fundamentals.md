# Document 04: Memory Fundamentals - How Windows Manages RAM

## Where We Are

You finished Documents 02 and 03. You can write C# programs that store data in variables, loop through arrays, XOR-encrypt bytes, read files, and parse command-line arguments. You know how to call Windows API functions from C# using DllImport and P/Invoke. You have called VirtualAlloc to request a chunk of RAM, Marshal.Copy to put bytes into it, VirtualProtect to change its permissions, and CreateThread to start running code at that address.

You have a working lab with Windows 11 (Defender on, default settings) at 192.168.10.100 and Kali at 192.168.10.200.

## Why This Is Next

In Document 03, you used VirtualAlloc, VirtualProtect, and CreateThread. You know what they do: VirtualAlloc asks Windows for RAM, VirtualProtect changes permissions on that RAM, CreateThread starts a thread at a RAM address. But you used them without understanding what is actually happening inside Windows when you call them.

This matters because the loaders in Documents 05 through 10 make decisions based on how Windows manages RAM. When you call VirtualAlloc with 0x04 (read-write) and later change it to 0x20 (execute-read) with VirtualProtect, why does that two-step approach make your loader harder for Defender to detect? When you call VirtualAllocEx to put RAM inside another program, what does "inside another program" actually mean? When Defender's behavioral analysis flags a program for requesting writable-executable RAM, what exactly is it detecting?

To answer these questions, you need to understand how Windows organizes RAM, what virtual memory is, what pages are, and how permissions work at the hardware level. This document covers all of that.

## How This Works

### Your Computer's Physical RAM

Your computer has a rectangular chip on its motherboard called RAM (Random Access Memory). When your computer says "16 GB RAM" that is how much of this chip is installed. RAM is where programs actually run. When you double-click Chrome, Windows copies Chrome from your hard drive into RAM and runs it from there because RAM is thousands of times faster than a hard drive.

Here is the problem. Your Windows 11 VM has 8 GB of RAM (or however much you gave it in Document 01). Right now, dozens of programs are running on it: Explorer (your desktop), Defender, the taskbar, background services, maybe Chrome or Notepad. Each of these programs needs RAM. But 8 GB is a fixed amount. What happens when all the running programs together need more than 8 GB?

And here is another problem. When Chrome requests RAM, it gets some chunk of the 8 GB. When Notepad requests RAM, it gets a different chunk. But what stops Chrome from accidentally reading or writing into Notepad's chunk? If Chrome has a bug, could it overwrite Defender's RAM and crash it? If your shellcode loader runs, could it read passwords that another program stored in its RAM?

Windows solves both of these problems with a system called virtual memory.

### Virtual Memory: Every Program Gets Its Own Private Address Space

Open Task Manager on your Windows VM (Ctrl+Shift+Esc). Click the Details tab. Look at the "Memory (private working set)" column. Add up the numbers for all running processes. You will find that the total is often more than the physical RAM your VM has. How is that possible?

The answer is that Windows does not give programs direct access to the physical RAM chip. Instead, Windows creates a fake address space for each program. This fake address space is called virtual memory. Every program thinks it has its own private, continuous block of RAM that starts at address 0 and goes up to a very large number (on 64-bit Windows, each program's address space is 128 terabytes, which is far more than any physical RAM chip). But this address space is not real physical RAM. It is a numbering system that Windows maintains.

When Chrome stores data at address 0x7FF00000 in its virtual address space, and Notepad stores data at address 0x7FF00000 in its virtual address space, those are not the same location. Chrome's 0x7FF00000 maps to one spot on the physical RAM chip. Notepad's 0x7FF00000 maps to a completely different spot on the physical RAM chip. Windows keeps a mapping table for each program that translates virtual addresses to physical addresses. The CPU checks this mapping table every time a program reads or writes RAM.

This is why Chrome cannot access Notepad's RAM. Chrome can only see addresses in its own virtual address space. If Chrome tries to read address 0x7FF00000, the CPU looks up Chrome's mapping table and finds the physical location assigned to Chrome at that address. Chrome has no way to specify Notepad's physical location because Chrome does not even know where Notepad's data is physically stored. The virtual address spaces are completely isolated from each other.

This also explains how the total RAM usage can exceed physical RAM. Windows can take chunks of virtual memory that a program has not accessed recently and save them to a file on the hard drive called the page file (pagefile.sys). The physical RAM that was holding those chunks is now free for other programs to use. If the program tries to access that data again, Windows reads it back from the page file into physical RAM. This is called paging. It is slower than physical RAM but it means programs can use more memory than physically exists.

You can see the page file right now. Open File Explorer on your Windows VM, go to C:\, and if hidden files are visible, you will see pagefile.sys. That file is where Windows stores RAM data that has been paged out to the hard drive.

### What This Means for Shellcode

When your shellcode loader calls VirtualAlloc, Windows gives it a chunk of virtual addresses in the loader's own address space and maps them to physical RAM. The shellcode bytes you copy into that chunk exist at a virtual address that only your loader process can see. No other process can access those bytes through its own virtual address space.

When you use VirtualAllocEx to allocate RAM inside another process (like explorer.exe for injection), Windows creates a chunk of virtual addresses in explorer.exe's address space and maps them to physical RAM. Your loader then uses WriteProcessMemory to copy shellcode into that chunk. After the copy, the shellcode exists in explorer.exe's virtual address space. Your loader can exit, and the shellcode stays in explorer.exe's RAM because it belongs to explorer.exe now, not to your loader.

### Pages: How Windows Divides RAM

Windows does not manage RAM byte by byte. That would be too slow because the CPU would need a mapping table entry for every single byte. Instead, Windows divides RAM into fixed-size blocks called pages. On x86-64 systems (which is what your Windows 11 VM runs), each page is 4,096 bytes (4 KB).

Every operation Windows does with RAM works in pages:
- When you call VirtualAlloc and ask for 100 bytes, Windows gives you one full page (4,096 bytes). You asked for 100 but you get 4,096 because Windows cannot give you less than one page.
- When you call VirtualAlloc and ask for 5,000 bytes, Windows gives you two pages (8,192 bytes) because 5,000 bytes does not fit in one page.
- When you call VirtualProtect to change permissions, the permissions change on entire pages. You cannot make the first 50 bytes of a page executable and the last 4,046 bytes non-executable. The whole page gets the same permission.

### Page Permissions: What the CPU Allows

Every page in a program's virtual address space has a set of permissions that control what the CPU is allowed to do with that page. The CPU checks these permissions on every single read, write, and execute operation. If a program tries to do something that the page's permissions do not allow, the CPU raises an exception and Windows terminates the program (you see this as an "Access Violation" crash).

The permissions that matter for the loaders:

**PAGE_READWRITE (0x04):** The CPU can read data from this page and write data to it. The CPU cannot execute code from this page. This is what regular data uses: variables, arrays, buffers, configuration data. When you call VirtualAlloc with 0x04, you get pages where you can store and modify data but the CPU will crash if it tries to run code from there.

**PAGE_EXECUTE_READ (0x20):** The CPU can execute code from this page and read data from it. The CPU cannot write to this page. This is what loaded program code uses. The .exe and .dll files that Windows loads into RAM are mapped with this permission. You can run the code and read the data, but you cannot modify it. When you call VirtualProtect with 0x20, you change the pages so the CPU can execute code from them but nobody can write to them anymore.

**PAGE_EXECUTE_READWRITE (0x40):** The CPU can read, write, and execute. All permissions at once. This is the one Defender watches for. Legitimate programs almost never need RAM that is both writable and executable at the same time. The only legitimate use case is JIT compilation (where a runtime like .NET compiles code on the fly and needs to write the compiled code and then execute it). Malware commonly uses 0x40 because it is simpler: write shellcode, then execute it, no need to change permissions in between. When Defender sees a program create 0x40 pages, it raises a flag.

**PAGE_NOACCESS (0x01):** The CPU cannot do anything with this page. Any read, write, or execute attempt crashes. Windows uses this for guard pages and unallocated regions. You will not use this in the loaders, but it is good to know it exists.

### The Two-Step Allocation and Why It Matters

In Document 03, you learned the safe approach to running shellcode:

1. Call VirtualAlloc with 0x04 (PAGE_READWRITE) to get writable pages
2. Use Marshal.Copy to write shellcode into those pages
3. Call VirtualProtect with 0x20 (PAGE_EXECUTE_READ) to make the pages executable and remove write permission
4. Call CreateThread to start running the code

This is called the two-step allocation (or W^X, which stands for "Write XOR Execute", meaning a page is either writable or executable, never both at the same time). Here is why this matters for evasion:

When a program calls VirtualAlloc with 0x40 (PAGE_EXECUTE_READWRITE), it creates pages where you can write data and the CPU can execute code at the same time. Defender's behavioral analysis flags this immediately because this combination is almost exclusively used by malware. A single VirtualAlloc call with 0x40 followed by a CreateThread at the same address is a textbook shellcode injection pattern.

When a program uses the two-step approach, the pages are never writable and executable at the same time. While you are writing shellcode into the pages, the CPU cannot execute from them (they are read-write only). After you change the permissions, the CPU can execute from them but nobody can write to them (they are execute-read only). At no point do the pages have both write and execute permission simultaneously.

This two-step pattern is what legitimate programs do. The .NET JIT compiler, web browsers running JavaScript, and Java's JVM all compile code at runtime using the same two-step approach: allocate writable pages, write the compiled code, change permissions to executable, then run it. By following the same pattern, your loader's behavior looks like a legitimate runtime compiler.

### How the CPU Enforces Page Permissions

The permissions are not just a software setting. They are enforced by the CPU hardware through a feature called DEP (Data Execution Prevention). You learned about DEP in Document 03. Here is what actually happens at the hardware level.

The CPU has a component called the MMU (Memory Management Unit). Every time the CPU reads, writes, or executes from a RAM address, the MMU checks the page table, which is the mapping table that translates virtual addresses to physical addresses. The page table entry for each page contains not just the physical address but also permission bits that say whether reading, writing, and executing are allowed.

If the CPU tries to execute code from a page that does not have execute permission, the MMU raises a hardware exception. Windows catches this exception and terminates the program with an "Access Violation" error. This happens at the hardware level, before any software check. There is no way to bypass DEP from software running in user mode (your programs). Only the Windows kernel can modify page table entries, which is why you call VirtualAlloc and VirtualProtect (which ask the kernel to make the changes) instead of modifying permissions directly.

This is why you cannot put shellcode in a regular C# byte array and execute it. C# byte arrays are stored in pages with PAGE_READWRITE permission. The .NET runtime allocates these pages and never gives them execute permission. If you somehow got the CPU to jump to the address of a C# byte array, the MMU would raise an exception and Windows would terminate your program before a single shellcode instruction ran.

### Your Process vs. Another Process

Everything discussed so far is about your own process (your running program). Your loader calls VirtualAlloc and gets pages in its own virtual address space. Marshal.Copy writes into its own pages. VirtualProtect changes permissions on its own pages. CreateThread creates a thread in its own process.

For injection (Documents 09 and 10), you work with another process's virtual address space. This requires a different set of functions:

**VirtualAllocEx** is the injection version of VirtualAlloc. The "Ex" stands for External. It takes an extra parameter: a handle to the target process (from OpenProcess). Instead of creating pages in your loader's address space, it creates pages in the target process's address space.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAllocEx(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    uint flAllocationType,
    uint flProtect);
```

`IntPtr hProcess` is the handle to the target process. You get this from OpenProcess (which you learned in Document 03).

The other parameters are the same as VirtualAlloc: where to put the pages (IntPtr.Zero lets Windows choose), how many bytes, allocation type (0x3000 for reserve + commit), and permissions (0x04 for read-write).

The return value is a virtual address, but it is a virtual address in the target process's address space, not yours. If VirtualAllocEx returns 0x1A0000, that means the pages are at address 0x1A0000 in explorer.exe's virtual memory. If you try to read address 0x1A0000 in your own process, you will either get a crash or completely different data because that address means something different in your address space.

**WriteProcessMemory** copies bytes from your process into another process's pages.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool WriteProcessMemory(
    IntPtr hProcess,
    IntPtr lpBaseAddress,
    byte[] lpBuffer,
    uint nSize,
    out uint lpNumberOfBytesWritten);
```

`IntPtr hProcess` is the handle to the target process.

`IntPtr lpBaseAddress` is the address in the target process where you want to write. This is the address returned by VirtualAllocEx.

`byte[] lpBuffer` is the byte array in your process containing the data you want to copy.

`uint nSize` is how many bytes to copy.

`out uint lpNumberOfBytesWritten` is where Windows tells you how many bytes it actually wrote.

When you call WriteProcessMemory, Windows takes the bytes from your process's RAM and copies them into the target process's RAM at the specified virtual address. This works across virtual address spaces because WriteProcessMemory is a kernel function, and the kernel has access to all processes' physical RAM.

**VirtualProtectEx** changes page permissions in another process's address space. Same as VirtualProtect but with an extra hProcess parameter.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool VirtualProtectEx(
    IntPtr hProcess,
    IntPtr lpAddress,
    uint dwSize,
    uint flNewProtect,
    out uint lpflOldProtect);
```

**CreateRemoteThread** creates a thread in another process that starts executing at a specified address.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateRemoteThread(
    IntPtr hProcess,
    IntPtr lpThreadAttributes,
    uint dwStackSize,
    IntPtr lpStartAddress,
    IntPtr lpParameter,
    uint dwCreationFlags,
    out uint lpThreadId);
```

`IntPtr lpStartAddress` is the virtual address in the target process where the shellcode is (from VirtualAllocEx). The new thread starts executing at that address, inside the target process. Your loader does not need to keep running after this call. The thread lives inside the target process and continues even if your loader exits.

### The Complete Injection Flow

Putting it all together, here is what happens when you inject shellcode into explorer.exe:

1. **OpenProcess** with PROCESS_ALL_ACCESS on explorer.exe's PID. Windows gives you a handle that grants full access to explorer.exe's virtual address space.

2. **VirtualAllocEx** with the handle, requesting read-write pages inside explorer.exe. Windows creates new pages in explorer.exe's virtual address space and maps them to physical RAM. The return value is a virtual address in explorer.exe.

3. **WriteProcessMemory** with the handle, the address from step 2, and your shellcode bytes. Windows copies the bytes from your loader's RAM into explorer.exe's RAM at the specified address.

4. **VirtualProtectEx** with the handle, changing the pages from read-write to execute-read. The pages in explorer.exe now allow the CPU to execute code from them.

5. **CreateRemoteThread** with the handle and the address from step 2. Windows creates a new thread inside explorer.exe that starts running at the shellcode address.

After step 5, the shellcode is running inside explorer.exe. In Task Manager, you see explorer.exe running with one extra thread. Your loader can exit. The shellcode continues because it is a thread inside explorer.exe, not inside your loader. Defender's behavioral analysis sees the activity (RAM allocation, thread creation) happening inside explorer.exe, which is a trusted system process.

## What Defender Does

Defender monitors RAM-related operations at multiple levels:

**VirtualAlloc and VirtualAllocEx calls.** Defender's API hooks (inside ntdll.dll) log every call to these functions. It records the size of the allocation, the permissions requested, and the process making the request. A single VirtualAlloc call is not suspicious on its own because every program allocates RAM. But a VirtualAlloc with executable permissions followed by writing data and creating a thread matches the shellcode injection pattern.

**Permission changes.** When a program calls VirtualProtect or VirtualProtectEx to add execute permission to pages that were previously read-write only, Defender logs this. Legitimate programs rarely change page permissions after allocation. Programs that write data and then make it executable are following a code injection pattern.

**Cross-process operations.** When one process opens another process with PROCESS_ALL_ACCESS and then calls VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread, Defender recognizes this as process injection. The sequence of cross-process calls is a strong signal. Defender watches specifically for the combination of OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread because this exact sequence is the textbook injection method.

**RWX pages.** Pages with PAGE_EXECUTE_READWRITE (0x40) are immediately suspicious. Defender flags any process that creates pages with this permission because legitimate programs almost never need writable-executable RAM.

## The Evasion Technique

This document teaches the foundational concepts. The evasion techniques that build on these concepts are:

- **Two-step allocation (all loaders):** Never request 0x40 (RWX). Request 0x04 (RW), write your data, then change to 0x20 (RX) with VirtualProtect. The pages are never writable and executable at the same time.

- **Direct syscalls (Document 07):** Instead of calling VirtualAlloc through kernel32.dll and ntdll.dll where Defender's hooks live, call the kernel directly. Defender's hooks never run because the call never passes through the hooked functions.

- **Dynamic API resolution (Documents 03, 05-10):** Instead of declaring VirtualAllocEx and WriteProcessMemory with DllImport (which puts their names in the import table where Defender can read them), find the functions at runtime using GetProcAddress. The compiled binary does not contain the function names.

- **Process injection into trusted processes (Documents 09-10):** Run shellcode inside explorer.exe or svchost.exe instead of your own process. Defender's behavioral analysis sees the activity inside a trusted process.

## Getting the Loader Onto the Target

No loader in this document. All programs are learning exercises that run on your Windows VM. The programs in this document allocate and free RAM, change permissions, and demonstrate cross-process concepts. They do not contain or execute shellcode.

## Teaching the Code

### Part 1: Viewing Your Process's Memory Layout

Before writing code, look at what your process's virtual address space actually looks like. Windows has a built-in way to show you.

Open Task Manager on your Windows VM. Click the Details tab. Find any running process, right-click it, and click "Create dump file." Do not actually create it. The point is that Windows can dump a process's entire virtual memory to a file, which shows that each process has its own separate memory space.

Instead, here is a C# program that shows you your own process's memory information:

```csharp
using System;
using System.Diagnostics;
```

`System.Diagnostics` gives you the `Process` class, which has properties that show information about running programs.

```csharp
class Program
{
    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();
```

`Process.GetCurrentProcess()` returns a Process object representing your own running program. From this object, you can read properties about your process.

```csharp
        Console.WriteLine("[*] Process: " + me.ProcessName);
        Console.WriteLine("[*] PID: " + me.Id);
        Console.WriteLine("[*] Working Set (RAM in use): " + 
            (me.WorkingSet64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Virtual Memory Size: " + 
            (me.VirtualMemorySize64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Private Memory: " + 
            (me.PrivateMemorySize64 / 1024 / 1024) + " MB");
```

Three different measurements:

`WorkingSet64` is the amount of physical RAM your process is currently using. "Working set" is the official Windows term for the set of pages that are currently in physical RAM (not paged out to the hard drive). This is what Task Manager shows in the "Memory" column.

`VirtualMemorySize64` is the total size of your process's virtual address space that is in use. This includes pages in physical RAM AND pages that have been paged out to the hard drive. This number is always larger than or equal to the working set.

`PrivateMemorySize64` is the amount of virtual memory that belongs only to your process and is not shared with any other process. Some RAM pages are shared between processes (for example, the pages containing kernel32.dll code are loaded once and shared by all processes). Private memory is the RAM that only your process uses.

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

Run it with `dotnet run`. You will see something like:

```
[*] Process: dotnet
[*] PID: 5128
[*] Working Set (RAM in use): 42 MB
[*] Virtual Memory Size: 2048 MB
[*] Private Memory: 28 MB
[*] Number of threads: 14
```

Notice that the virtual memory size (2048 MB) is much larger than the working set (42 MB). Your program has 2 GB of virtual address space mapped, but only 42 MB of physical RAM. Most of the virtual address space is either paged out or mapped but not actively being used.

The thread count (14) shows that even a simple C# program has many threads. The .NET runtime creates background threads for garbage collection (the automatic RAM cleanup process), JIT compilation, and other internal work. Your Main function runs on one of these threads.

### Part 2: Allocating Pages and Observing the Working Set

This program allocates pages using VirtualAlloc and shows how the working set changes:

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
```

The same DllImport declarations from Document 03. VirtualAlloc requests pages, VirtualFree gives them back.

```csharp
    static void Main(string[] args)
    {
        Process me = Process.GetCurrentProcess();

        me.Refresh();
        long before = me.WorkingSet64;
        Console.WriteLine("[*] Working set before allocation: " + 
            (before / 1024) + " KB");
```

`me.Refresh()` updates the process information. Without Refresh, the values might be stale from when the Process object was created.

```csharp
        uint allocSize = 1024 * 1024;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, allocSize, 0x3000, 0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated 1 MB (256 pages) at: 0x" + mem.ToString("X"));
```

This allocates 1 MB of RAM (1,048,576 bytes). Since each page is 4,096 bytes, this is 256 pages. The permissions are 0x04 (PAGE_READWRITE).

```csharp
        for (int i = 0; i < (int)allocSize; i++)
        {
            Marshal.WriteByte(mem + i, 0xAA);
        }
        Console.WriteLine("[+] Wrote 0xAA to all 1 MB.");
```

Writing to every byte in the allocated pages. `Marshal.WriteByte(address, value)` writes a single byte to a specific address. We write 0xAA to every byte so the pages are actually used (Windows may not assign physical RAM to pages until they are written to, a technique called lazy allocation or demand paging).

```csharp
        me.Refresh();
        long after = me.WorkingSet64;
        Console.WriteLine("[*] Working set after allocation: " + 
            (after / 1024) + " KB");
        Console.WriteLine("[*] Difference: " + 
            ((after - before) / 1024) + " KB");
```

After writing to the pages, refresh the process info and compare. The working set should have increased by approximately 1 MB (1024 KB) because those 256 pages are now in physical RAM.

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

The numbers confirm that VirtualAlloc added exactly 1 MB to the working set (1024 KB), and VirtualFree removed it. You are directly controlling the physical RAM your process uses.

### Part 3: Page Alignment and Minimum Allocation

This program shows that Windows rounds everything up to page boundaries:

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

Run it and you will see:

```
[+] Requested: 1 bytes
    Address: 0x<address>
    Pages used: 1 (4096 bytes actual)

[+] Requested: 100 bytes
    Address: 0x<address>
    Pages used: 1 (4096 bytes actual)

[+] Requested: 4096 bytes
    Address: 0x<address>
    Pages used: 1 (4096 bytes actual)

[+] Requested: 4097 bytes
    Address: 0x<address>
    Pages used: 2 (8192 bytes actual)

[+] Requested: 8000 bytes
    Address: 0x<address>
    Pages used: 2 (8192 bytes actual)

[+] Requested: 16384 bytes
    Address: 0x<address>
    Pages used: 4 (16384 bytes actual)
```

When you ask for 1 byte, you still get 4,096 bytes (one page). When you ask for 4,097 bytes, you get 8,192 bytes (two pages). Windows always rounds up to the next full page. This matters for the loaders because your shellcode is usually a few hundred bytes, but Windows gives you at least one full 4 KB page. The unused bytes in that page are zeros.

Also notice the addresses. They are all multiples of 4,096 (or more specifically, multiples of 65,536, which is the allocation granularity on Windows). Pages always start at aligned addresses.

### Part 4: Observing Permission Changes

This program shows what happens when you change page permissions:

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
            case 0x01: return "PAGE_NOACCESS";
            case 0x02: return "PAGE_READONLY";
            case 0x04: return "PAGE_READWRITE";
            case 0x10: return "PAGE_EXECUTE";
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
        Console.WriteLine("[*] Initial permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] CPU can: READ, WRITE. CPU cannot: EXECUTE.");
        Console.WriteLine();

        Marshal.WriteByte(mem, 0xC3);
        Console.WriteLine("[+] Wrote 0xC3 (RET instruction) to the page.");
        Console.WriteLine("[*] Data is written. But CPU still cannot execute here.");
        Console.WriteLine();

        uint oldPerm;
        VirtualProtect(mem, 4096, 0x20, out oldPerm);
        Console.WriteLine("[+] Changed permission to PAGE_EXECUTE_READ (0x20).");
        Console.WriteLine("[*] Old permission was: " + PermName(oldPerm));
        Console.WriteLine("[*] CPU can now: READ, EXECUTE. CPU cannot: WRITE.");
        Console.WriteLine();

        Console.WriteLine("[*] The page went through two states:");
        Console.WriteLine("    State 1: READWRITE  - we could write data, CPU could not execute");
        Console.WriteLine("    State 2: EXECUTE_READ - CPU can execute, we cannot write");
        Console.WriteLine("[*] The page was NEVER writable and executable at the same time.");
        Console.WriteLine("[*] This is the two-step allocation that avoids Defender detection.");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

This program does not execute the code (it does not call CreateThread). It only demonstrates the permission transition. The output shows the two states clearly:

```
[+] Allocated 1 page at: 0x<address>
[*] Initial permission: PAGE_READWRITE (0x04)
[*] CPU can: READ, WRITE. CPU cannot: EXECUTE.

[+] Wrote 0xC3 (RET instruction) to the page.
[*] Data is written. But CPU still cannot execute here.

[+] Changed permission to PAGE_EXECUTE_READ (0x20).
[*] Old permission was: PAGE_READWRITE
[*] CPU can now: READ, EXECUTE. CPU cannot: WRITE.

[*] The page went through two states:
    State 1: READWRITE  - we could write data, CPU could not execute
    State 2: EXECUTE_READ - CPU can execute, we cannot write
[*] The page was NEVER writable and executable at the same time.
[*] This is the two-step allocation that avoids Defender detection.
```

### Part 5: Reading Another Process's Information

This program demonstrates how your process can examine another running program. It does not inject anything. It only reads information:

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

    [DllImport("kernel32.dll")]
    static extern int GetProcessId(IntPtr hProcess);

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
        Console.WriteLine("[*] Virtual Memory: " + 
            (proc.VirtualMemorySize64 / 1024 / 1024) + " MB");
        Console.WriteLine("[*] Threads: " + proc.Threads.Count);
        Console.WriteLine();

        IntPtr handle = OpenProcess(0x0400, false, proc.Id);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed. Access denied.");
            return;
        }

        int verifyPid = GetProcessId(handle);
        Console.WriteLine("[+] Opened handle to " + target + 
            ".exe (verified PID: " + verifyPid + ")");
        Console.WriteLine("[*] Handle value: 0x" + handle.ToString("X"));
        Console.WriteLine("[*] We opened with PROCESS_QUERY_INFORMATION (0x0400).");
        Console.WriteLine("[*] This lets us read info but NOT modify the process.");
        Console.WriteLine();

        Console.WriteLine("[*] For injection (Documents 09-10), we would open with");
        Console.WriteLine("    PROCESS_ALL_ACCESS (0x001FFFFF) instead.");
        Console.WriteLine("    That grants: read, write memory, create threads.");

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

Run with `dotnet run` (targets explorer by default) or `dotnet run -- notepad` (targets Notepad if running):

```
[+] Found explorer.exe
[*] PID: 4892
[*] Working Set: 98 MB
[*] Virtual Memory: 512 MB
[*] Threads: 47

[+] Opened handle to explorer.exe (verified PID: 4892)
[*] Handle value: 0xA4
[*] We opened with PROCESS_QUERY_INFORMATION (0x0400).
[*] This lets us read info but NOT modify the process.

[*] For injection (Documents 09-10), we would open with
    PROCESS_ALL_ACCESS (0x001FFFFF) instead.
    That grants: read, write memory, create threads.
[+] Handle closed.
```

Notice that explorer.exe uses 98 MB of physical RAM and has 47 threads. When you inject shellcode in Document 09, you will add one more thread to that count. Going from 47 to 48 threads in a program that already has 47 is not suspicious. If your standalone loader only had 2 threads and suddenly one of them was running shellcode, that is easier to spot.

### Part 6: The Full Local Execution Pattern with Logging

This is the complete local shellcode execution pattern from Document 03, but with detailed logging at each step so you can see what is happening with pages and permissions. It runs a single 0xC3 byte (the RET instruction, which just returns immediately):

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
        uint pages = ((uint)code.Length + 4095) / 4096;
        Console.WriteLine("[+] Address: 0x" + mem.ToString("X"));
        Console.WriteLine("[+] Pages allocated: " + pages + 
            " (" + (pages * 4096) + " bytes)");
        Console.WriteLine("[*] Permission: PAGE_READWRITE (0x04)");
        Console.WriteLine("[*] Status: CAN write data. CANNOT execute code.");
        Console.WriteLine();

        Console.WriteLine("=== Step 2: Copy code into the pages ===");
        Marshal.Copy(code, 0, mem, code.Length);
        Array.Clear(code, 0, code.Length);
        Console.WriteLine("[+] Copied " + code.Length + " byte(s) to allocated pages.");
        Console.WriteLine("[+] Cleared the source array (zeroed out).");
        Console.WriteLine("[*] Code exists only in VirtualAlloc pages now.");
        Console.WriteLine();

        Console.WriteLine("=== Step 3: Change permission to EXECUTE-READ ===");
        uint oldPerm;
        if (!VirtualProtect(mem, (uint)code.Length, 0x20, out oldPerm))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Permission changed: 0x04 -> 0x20");
        Console.WriteLine("[*] Status: CAN execute code. CANNOT write data.");
        Console.WriteLine("[*] The pages were NEVER writable + executable at the same time.");
        Console.WriteLine();

        Console.WriteLine("=== Step 4: Create thread at the code address ===");
        Process me = Process.GetCurrentProcess();
        me.Refresh();
        int threadsBefore = me.Threads.Count;

        IntPtr thread = CreateThread(
            IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }

        me.Refresh();
        int threadsAfter = me.Threads.Count;
        Console.WriteLine("[+] Thread created with ID: " + tid);
        Console.WriteLine("[*] Threads before: " + threadsBefore + 
            ", after: " + threadsAfter);
        Console.WriteLine();

        Console.WriteLine("=== Step 5: Wait for thread to finish ===");
        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread finished (RET instruction returned immediately).");
        Console.WriteLine();

        Console.WriteLine("=== Summary ===");
        Console.WriteLine("[*] Allocated 1 page of READ-WRITE memory");
        Console.WriteLine("[*] Wrote code bytes into the page");
        Console.WriteLine("[*] Changed permission to EXECUTE-READ");
        Console.WriteLine("[*] Created a thread that ran the code");
        Console.WriteLine("[*] Thread finished and the code executed successfully");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

This is the same pattern from Document 03, Part 8, but with step-by-step logging that shows pages, permissions, and thread counts. In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode. The pattern stays identical.

## Compilation and Execution

For every example in this document:

1. On your Windows VM, open `cd C:\Users\kimjongun\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`
4. For programs with arguments: `dotnet run -- explorer` or `dotnet run -- notepad`

All examples in this document are safe to run. They allocate and free RAM, read process information, and execute a single RET instruction. They do not contain or run shellcode.

## Confirming Success

After this document, verify:

- [ ] You understand that virtual memory gives every program its own private address space
- [ ] You know that two programs with the same virtual address are actually using different physical RAM locations
- [ ] You understand that Windows divides RAM into fixed-size pages of 4,096 bytes (4 KB)
- [ ] You know that page permissions control what the CPU is allowed to do (read, write, execute)
- [ ] You understand why PAGE_EXECUTE_READWRITE (0x40) is suspicious to Defender
- [ ] You understand the two-step allocation: allocate as read-write, write data, change to execute-read
- [ ] You know why the two-step approach avoids Defender detection (pages are never writable and executable at the same time)
- [ ] You understand the difference between working set (physical RAM in use) and virtual memory size
- [ ] You can explain what happens when your loader calls VirtualAllocEx to allocate pages inside another process
- [ ] You understand the injection flow: OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, CreateRemoteThread
- [ ] You ran the page allocation program and saw the working set change
- [ ] You ran the permission change program and saw the two-step transition

## What Was Gained

You now understand how Windows manages RAM at the page level. This knowledge changes how you read the loader code in Documents 05 through 10:

- When a loader calls VirtualAlloc with 0x04 and later VirtualProtect with 0x20, you know it is doing the two-step allocation to avoid having writable-executable pages.
- When a loader calls VirtualAllocEx, you know it is creating pages inside another process's virtual address space, not its own.
- When a loader calls WriteProcessMemory, you know it is copying bytes across virtual address spaces through the kernel.
- When Defender flags a program for using 0x40 (PAGE_EXECUTE_READWRITE), you understand why: because legitimate programs almost never need pages that are both writable and executable.

The loaders use these concepts in every function call. Understanding what happens at the page level means you can modify the loaders, debug failures, and build new loaders from scratch because you understand the underlying mechanism, not just the API call names.

## Common Threats and Variations

### Variation 1: Large Page Allocations

Windows supports "large pages" that are 2 MB instead of 4 KB. Some malware uses large pages because some security tools only monitor standard 4 KB page operations. To use large pages, you call VirtualAlloc with the MEM_LARGE_PAGES flag (0x20000000) and the allocation size must be a multiple of 2 MB. The program also needs the "Lock pages in memory" privilege, which requires administrator access.

### Variation 2: Section Objects for Cross-Process Data Sharing

Instead of using WriteProcessMemory (which Defender watches), some loaders create a section object. A section is a region of RAM that two or more processes can access simultaneously. Both processes map the same section into their virtual address space. When your loader writes shellcode into the section, the target process can read it immediately because they share the same physical RAM pages. No WriteProcessMemory call is needed, so Defender's hook on WriteProcessMemory never triggers.

### Variation 3: Memory-Mapped Files

NtCreateSection and NtMapViewOfSection can map a file from the hard drive into a process's virtual address space. Some loaders abuse this by creating a temporary file containing shellcode, mapping it into the target process, and then deleting the file. The shellcode exists in the target's virtual address space as if it were loaded from a DLL. This approach leaves different ETW events than VirtualAllocEx + WriteProcessMemory.

## Detection and Defense (Blue Team Perspective)

**Monitor page permission changes.** EDR products should log every VirtualProtect and VirtualProtectEx call that adds execute permission to pages that were previously writable. This catches the two-step allocation pattern. Alert when a program changes pages from PAGE_READWRITE to PAGE_EXECUTE_READ or PAGE_EXECUTE.

Blue team action: configure EDR rules to flag VirtualProtect calls where the new permission includes EXECUTE and the old permission included WRITE.

**Detect cross-process memory operations.** The combination of OpenProcess with write access, VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread in a single program is a strong injection signal. Legitimate programs rarely perform all four operations.

Blue team action: create detection rules that alert when a non-system process performs the full injection sequence (open + allocate + write + thread create) against another process.

**Track working set anomalies.** If a process like explorer.exe suddenly allocates new executable pages that do not correspond to a DLL load, this is suspicious. Legitimate DLL loads go through the loader and are logged. Raw VirtualAlloc calls for executable memory inside a trusted process are unusual.

Blue team action: monitor for RX or RWX page allocations in trusted system processes that do not correspond to a module load event.

**Watch for page file artifacts.** When shellcode pages get paged out to the page file (pagefile.sys), the shellcode bytes are written to the hard drive. Forensic tools can scan the page file for shellcode signatures. Some loaders call VirtualLock to prevent their pages from being paged out, but this requires the "Lock pages in memory" privilege.

Blue team action: periodically scan pagefile.sys for known shellcode patterns. Also monitor for VirtualLock calls on executable pages.

## What Comes Next

Document 05 (lab/materials/05_shellcode_loader.md) is where you build your first real working loader. You will generate shellcode with msfvenom on Kali, transfer it to the Windows VM, and build a C# program that executes it in RAM using the VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread pattern you have practiced. You will see Defender catch it, understand why, and learn what needs to change in Document 06 (encoding evasion) to bypass the detection.
