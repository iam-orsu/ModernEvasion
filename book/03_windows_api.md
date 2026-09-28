# Document 03: Windows API - How Your Program Talks to Windows

## Where We Are

You finished Document 02 and can write C# programs that store data in variables, make decisions with if/else, loop through arrays, create byte arrays, write functions, XOR-encrypt data, read files, parse command-line arguments, use Marshal.Copy, and build strings from integer offsets.

Your lab has three machines on 192.168.10.0/24: the dev box (ammulu, 192.168.10.150) where you compile code (Defender disabled), the target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode generation and listeners. All coding in this document happens on the dev box.

## Why This Is Next

Every program you wrote in Document 02 does two things: it processes data (math, XOR, loops) and it prints text to the screen. That is all C# can do by itself.

But the shellcode loaders in Documents 05 through 10 need to do things that C# cannot do by itself. They need to request a chunk of RAM from Windows, mark that chunk as executable so the CPU can run code from it, copy shellcode bytes into it, and tell the CPU to start running those bytes. Only the Windows operating system can do these things. Your program has to ask Windows to do them.

The way a program asks Windows to do something is by calling a Windows API function. This document teaches you what the Windows API is, what these terms mean, and how to call Windows functions from your C# code.

## How This Works

### What Is RAM and Why Programs Need It

Your computer has a component called RAM, which stands for Random Access Memory. It is a rectangular chip, about the size of a ruler, that plugs into a slot on your motherboard. When your computer says "16 GB RAM" that is how much of it is installed.

RAM is where programs actually run. When you double-click Chrome on your desktop, Windows copies Chrome from your hard drive into RAM and runs it from there. Why not just run it from the hard drive? Because RAM is thousands of times faster than a hard drive. Your CPU (the processor chip that runs instructions) needs that speed to run programs smoothly.

Now here is the important part for us. When you close Chrome, whatever was in RAM is gone. RAM is temporary. Everything stored in RAM disappears when you shut down your computer. Defender's file scanner checks files on your hard drive, but data sitting in RAM does not get checked by the file scanner. This is why we run shellcode in RAM instead of saving it as a file on the hard drive.

Open Task Manager on your dev box (press Ctrl+Shift+Esc), click the Performance tab, and you can see how much RAM your system is using right now. That is real programs sitting in real RAM.

### What Windows Does When You Use Your Computer

Right now on your dev box, dozens of things are happening. Explorer is showing your desktop, Visual Studio is running in the background, the taskbar clock is updating every minute, your mouse cursor is moving around. None of these programs handle all of this by themselves. They all ask Windows to do the work.

When you double-click a .exe file on your desktop, Windows copies that program from the hard drive into RAM, creates a new process for it, and starts running it. When the program wants to show a window on screen, it asks Windows to create the window. Windows draws the title bar, the close button, the minimize button, and the window border.

Try it right now. Right-click on your desktop. A menu appears with options like "New," "Display settings," "Personalize." That menu was created by a Windows function. The desktop program told Windows "show a menu with these options next to the mouse cursor," and Windows drew it, positioned it, and detected your click.

This is not limited to things you see on screen:

- When a program reads a file from your hard drive, it calls a Windows function
- When a program connects to the internet, it calls a Windows function
- When Task Manager shows you running processes, it calls Windows functions to get that information
- When a program shows a "Save As" dialog, that entire dialog is a single Windows function call

Windows controls everything on the computer. Programs run on top of Windows and ask it to do things by calling functions.

### What Is the Windows API

The collection of all the functions that Windows provides for programs to call is called the **Windows API**. API stands for Application Programming Interface.

You already know what an API is from web development: you send a request to a server, and the server does the work and sends back a result. The Windows API is the same idea, except your program is calling functions on the same computer instead of sending HTTP requests to a remote server.

### Connecting This to Web APIs You Already Know

You know web APIs. When you send an HTTP GET request to `https://api.github.com/users/octocat`, GitHub's server processes your request and sends back JSON data about that user. You did not write the code that queries GitHub's database. You called their API, and their server did the work and gave you the result.

The Windows API works the same way, but instead of sending HTTP requests over the internet, your program calls functions on the local machine. Instead of URLs, you use function names. Instead of JSON request bodies, you pass parameters. Instead of JSON responses, you get return values.

**Web API example:** You call `POST /api/send-notification` with `{"title": "Alert", "message": "Build complete"}`. The server creates the notification and sends it.

**Windows API example:** You call a function named `MessageBox` with the parameters `"Alert"` and `"Build complete"`. Windows creates a dialog box on your screen with that title and message, with an OK button, and waits for you to click it.

Both cases are the same idea: you ask a system to do work for you by calling a function with parameters, and the system does the work. With web APIs, the system is a remote server. With the Windows API, the system is Windows running on your own machine.

### Where Windows API Functions Live: DLL Files

Windows has thousands of API functions. They are organized into files called **DLLs**. DLL stands for Dynamic Link Library. A DLL is a file on your hard drive that contains a collection of compiled functions that any program can call.

You can see these files right now. Open File Explorer on your dev box and go to `C:\Windows\System32\`. You will see hundreds of .dll files. Each file contains a group of related functions.

The four DLLs that matter for this curriculum:

**kernel32.dll** - Core operations.
Functions for working with RAM (requesting it, giving it back, changing permissions), managing processes (starting programs, opening running programs), managing threads (creating new threads inside a program), and working with files. This is the most important DLL for the loaders because it has the RAM and thread functions needed to run shellcode.

**user32.dll** - Screen and interface.
Creating windows, showing dialog boxes, handling mouse clicks, drawing menus. Not important for the loaders, but useful for learning because the functions produce results you can see on your screen immediately.

**ntdll.dll** - Lowest-level functions before the Windows kernel.
Every function in kernel32.dll internally calls a function in ntdll.dll to do the real work. For example, when you call VirtualAlloc from kernel32.dll, kernel32 internally calls NtAllocateVirtualMemory in ntdll.dll, and ntdll makes the actual request to the Windows kernel.

This matters for evasion: Defender inserts monitoring code inside kernel32.dll functions. If you skip kernel32.dll and call ntdll.dll directly, Defender's monitoring code never runs. Document 07 teaches this.

**amsi.dll** - Antimalware Scan Interface.
When PowerShell wants to check if a script is malicious before running it, it calls a function in amsi.dll. That function sends the script to Defender for scanning. If Defender says the script is malware, amsi.dll tells PowerShell to block it. Document 08 teaches you to modify amsi.dll's functions so they stop sending scripts to Defender.

### How C# Calls a Windows API Function

All the C# programs you wrote in Document 02 run inside something called the **.NET runtime**. The .NET runtime is a layer between your C# code and the operating system. It manages your program's RAM, handles type checking, and cleans up after your program.

Windows API functions are not written in C#. They are written in C and C++ and run directly on the operating system, outside the .NET runtime. So there is a gap: your C# code runs inside the .NET runtime, and Windows functions run outside it.

C# has a built-in feature that crosses this gap. The feature is called **P/Invoke**, which stands for Platform Invoke. "Platform" means the Windows platform (the operating system). "Invoke" means to call. P/Invoke lets you describe a Windows function in your C# code and then call it as if it were a normal C# function.

**How you use P/Invoke:**

1. Write `[DllImport("dllname.dll")]` to tell C# which DLL the function lives in
2. Describe the function's name, parameters, and return type
3. Call it like any other function

C# handles everything in between: it finds the DLL file, locates the function inside it, converts your C# data to the format the Windows function expects, calls the function, and converts the result back to C# format.

## What Defender Does

Defender monitors how programs interact with Windows API functions at three levels:

**Scanning the import table.**
When you compile a C# program that uses DllImport, the compiled file contains a list of every DLL and function your program calls. This list is called the **import table**. Defender reads this list before the program even runs.

If the import table shows VirtualAlloc + CreateThread + WriteProcessMemory together, Defender flags it as suspicious because that combination is commonly used for code injection.

**Hooking functions.**
When your program runs and calls VirtualAlloc from kernel32.dll, Defender has already modified the beginning of that function. Defender inserted a small piece of code (called a **hook**) that redirects the call to Defender's monitoring code first.

Defender checks what you are requesting (how much RAM, what permissions), logs the activity, decides if it looks suspicious, and only then lets the real VirtualAlloc run. Document 07 teaches you to bypass these hooks by calling ntdll.dll directly.

**Watching for suspicious sequences.**
A program calling VirtualAlloc alone is not suspicious. But a program that requests RAM, copies data into it, changes permissions to executable, and creates a new thread at that address matches the exact pattern of a shellcode loader. Defender watches for this sequence.

## The Evasion Technique

This document teaches the standard way to call Windows functions. You need to understand the standard way before the evasion methods in later documents make sense. The evasion variations are:

- Document 06: Encrypt the shellcode with XOR so Defender does not recognize the bytes
- Document 07: Call ntdll.dll directly instead of kernel32.dll to bypass Defender's hooks
- Document 08: Modify amsi.dll functions so they stop scanning scripts
- Document 10: All evasion techniques combined

All of them build on the standard calling pattern you learn here.

## Getting the Loader Onto the Target

No loader in this document. All programs are learning exercises that run on your dev box (ammulu, 192.168.10.150).

## Teaching the Code

### Part 1: MessageBox - Your First Windows API Call

The simplest Windows API function to start with is MessageBox. It creates a dialog box on your screen with a message and buttons. It is not useful for evasion, but it is the perfect first example because you can see the result on your screen immediately.

```csharp
using System;
using System.Runtime.InteropServices;
```

The first line you know from Document 02. It gives you access to Console.WriteLine and other basic C# tools.

The second line gives you access to P/Invoke. Remember, P/Invoke is the C# feature that lets you call Windows functions. `System.Runtime.InteropServices` is the section of C# that contains this feature. "InteropServices" means "services for working together with code outside of C#." You need this line in every program that calls Windows functions.

```csharp
class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBox(IntPtr hWnd, string text, string caption, uint type);
```

This is where you describe the Windows function to C# so it knows how to call it. Here is what each part means:

`[DllImport("user32.dll", CharSet = CharSet.Unicode)]` is an instruction attached to the function description below it. It tells C# two things: the function lives in the file user32.dll, and when passing text to this function, convert it to Unicode format (Unicode is the text encoding Windows uses internally).

`static extern` tells C# that you did not write this function yourself. The function already exists in user32.dll. You are just describing what it looks like so C# knows how to call it. `extern` means "this function is external, it exists outside of this C# program."

`int MessageBox(...)` says the function is called MessageBox and it gives back an integer when it finishes. The integer tells you which button the user clicked.

The four parameters:

`IntPtr hWnd` is the handle (reference number) of the parent window. Handles are explained in Part 4, but for now just know that if you pass `IntPtr.Zero` (which means "none"), the dialog box appears by itself, not attached to any window.

`string text` is the message shown inside the dialog box body.

`string caption` is the text in the title bar at the top of the dialog box.

`uint type` controls which buttons appear. The value `0` shows only OK. The value `1` shows OK and Cancel. The value `4` shows Yes and No.

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

Your program calls MessageBox. C# finds the function in user32.dll and calls it with your parameters. Windows receives the call, creates a dialog box with your message, your title, OK and Cancel buttons, and shows it on screen. Your program pauses here and waits for you to click a button. When you click, Windows tells your program which button was clicked by returning a number.

```csharp
        if (clicked == 1)
            Console.WriteLine("[+] You clicked OK.");
        else if (clicked == 2)
            Console.WriteLine("[+] You clicked Cancel.");
    }
}
```

MessageBox returns 1 if you clicked OK, 2 if you clicked Cancel.

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

Run it with `dotnet run`. A dialog box appears on your dev box. It has a title bar that says "Windows API Test," your message text, and two buttons. Click one. The terminal prints which button you clicked.

Your C# code did not draw the dialog box. It did not create the buttons. It did not detect your mouse click. Windows did all of that. Your code told Windows "show a dialog with this text and these buttons" and Windows handled everything else. That is what calling a Windows API function means.

### Part 2: Beep - Calling a Function from a Different DLL

MessageBox lives in user32.dll. Here is a function from kernel32.dll to show that different DLLs contain different functions, and you just change the DLL name in DllImport:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool Beep(uint frequency, uint duration);
```

This function lives in kernel32.dll. It makes a beep sound through the computer's speaker. `frequency` is the pitch in Hertz (440 is the musical note A). `duration` is how long the beep lasts in milliseconds (1000 milliseconds = 1 second). It returns `true` if the beep played successfully.

```csharp
    static void Main(string[] args)
    {
        Console.WriteLine("[*] Playing three beeps...");
        Beep(440, 300);
        Beep(554, 300);
        Beep(659, 300);
        Console.WriteLine("[+] Done.");
    }
```

Three calls to the same Windows function with different parameters. Each call tells Windows "play this frequency for this many milliseconds." Windows generates the sound through the speaker. Your code did not create audio data, did not interact with the sound hardware, did not process audio signals. One function call, and Windows did all the work.

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

Run it. You hear three tones. The pattern is always the same: write `[DllImport("dllname.dll")]`, describe the function, call it. Whether the function shows a dialog box, plays a sound, requests RAM, or opens a process, the pattern is identical.

### Part 3: GetCurrentProcessId - Getting Information from Windows

MessageBox and Beep tell Windows to do something. Windows API functions can also give you information about the system.

Right now on your dev box, there are dozens of programs running at the same time. Chrome, Explorer, Visual Studio, background services, all running together. Windows needs to know which program is which. So every time a program starts, Windows gives it a unique number. This number is called a process ID, written as PID for short. Chrome might get 4528, Notepad might get 7812, Explorer might get 1340. No two running programs ever get the same PID.

You can see this right now. Press Ctrl+Shift+Esc on your dev box to open Task Manager. If it opens in the small view, click "More details" at the bottom. Now right-click on the column headers at the top and turn on the PID column. Every program on that list has a number next to it, and that number is the PID that Windows assigned when the program started.

When we write code that needs to interact with another running program, like injecting shellcode into explorer.exe, we need to know that program's PID so we can tell Windows exactly which program we are referring to.

GetCurrentProcessId gives you your own program's PID:

```csharp
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
```

This function lives in kernel32.dll. It takes no parameters (empty parentheses). It returns a `uint` (unsigned integer), which is your program's PID.

```csharp
    static void Main(string[] args)
    {
        uint myPid = GetCurrentProcessId();
        Console.WriteLine("[+] This program's process ID is: " + myPid);
        Console.WriteLine("[*] Open Task Manager and find this number to confirm.");
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
```

`Console.ReadLine()` pauses the program until you press Enter. This gives you time to open Task Manager and verify the PID.

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
        Console.WriteLine("[*] Open Task Manager and find this number to confirm.");
        Console.WriteLine("[*] Press Enter to exit...");
        Console.ReadLine();
    }
}
```

Run it. It prints a number like 7832 or 4516. Open Task Manager, find "dotnet" in the list, and confirm the PID matches. You asked Windows "what is my process ID?" and Windows gave you the answer.

### Part 4: What Is a Handle

Almost every Windows API function that gives you access to something returns a **handle**. You need to understand what handles are before going further.

When you open a file in Notepad, Windows does not give Notepad direct access to the hard drive location where that file sits. Instead, Windows gives Notepad a number, like 164 or 2048. Notepad holds onto that number, and every time it wants to read from or write to the file, it passes that number back to Windows and says "do this to whatever 164 refers to."

A handle is a reference number that Windows gives to a program so the program can refer to a specific resource without having direct access to it. Windows keeps track of what each handle refers to internally.

Handles are used for everything in Windows:

- Open another running process with OpenProcess → Windows gives you a handle to that process
- Create a new thread with CreateThread → Windows gives you a handle to that thread
- Open a file → Windows gives you a handle to that file

In C#, handles are stored as `IntPtr` values. When a Windows function fails and cannot give you what you asked for, it returns `IntPtr.Zero` (the number zero), meaning "I could not do it, there is no valid handle." So every time you call a Windows function that returns a handle, you check if you got zero:

```csharp
        IntPtr handle = SomeWindowsFunction();
        if (handle == IntPtr.Zero)
        {
            Console.WriteLine("[-] Function failed.");
            return;
        }
```

When you are done with a handle, you tell Windows to close it using CloseHandle:

```csharp
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
```

```csharp
        CloseHandle(handle);
```

This tells Windows "I am done with this resource, you can clean it up." If you do not close handles, they stay open and take up system resources. In the loaders, the program usually exits after running shellcode, and Windows cleans up all handles when a process exits. But for longer-running programs, you should close handles when you are done.

### Part 5: VirtualAlloc - Requesting a Chunk of RAM from Windows

Now we get to the functions that matter for shellcode execution. VirtualAlloc asks Windows to give your program a chunk of RAM with specific permissions.

In Document 02, you created byte arrays with `new byte[256]`. The .NET runtime gave your program space in RAM for that array. But the .NET runtime controls that RAM completely:

- It decides where in RAM the array goes
- It can move the array during garbage collection (an automatic cleanup process where C# frees unused RAM)
- Most importantly, it marks all of its RAM as **data-only**

The CPU is not allowed to run code from RAM that the .NET runtime manages. This is because of a security feature called **DEP** (Data Execution Prevention). DEP tells the CPU "this section of RAM contains data, not code, so do not try to run it as instructions." Every modern operating system has DEP enabled.

Shellcode is code. You want the CPU to run it as instructions. So you cannot put shellcode into a regular C# byte array because DEP stops the CPU from executing it.

**VirtualAlloc solves this.** It asks Windows directly (not the .NET runtime) to give you a chunk of RAM. When you make this request, you specify what permissions you want: can you read from it, can you write to it, and can the CPU execute code from it. If you ask for execute permission, Windows gives you RAM where the CPU is allowed to run code. DEP does not block it because you explicitly asked for execute permission through a legitimate Windows function.

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);
```

`SetLastError = true` tells C# to remember the error code if VirtualAlloc fails, so you can find out why it failed.

The four parameters:

`IntPtr lpAddress` is the RAM address where you want the chunk. Pass `IntPtr.Zero` to let Windows choose the address for you. Windows knows which addresses are available, so you almost always let Windows pick.

`uint dwSize` is how many bytes of RAM you want. If your shellcode is 510 bytes, you request 510 bytes.

`uint flAllocationType` is the type of request. The value `0x3000` combines two flags. MEM_RESERVE (0x2000) tells Windows to set aside a range of virtual addresses for your program so nothing else can claim those addresses. At this point no physical RAM is used yet. MEM_COMMIT (0x1000) is where real RAM gets involved. Your dev box (ammulu) has 8 GB of RAM on its motherboard. When you pass MEM_COMMIT, Windows takes a portion of that physical 8 GB and assigns it to your program. If you ask for 4096 bytes, Windows dedicates 4096 bytes of that RAM chip to you. Those bytes are now yours to read and write. You combine both flags by adding: 0x2000 + 0x1000 = 0x3000, and you use this value in every loader because you always want both steps done at once.

`uint flProtect` sets the permissions. This is the most important parameter:

| Value | Name | What It Allows |
|-------|------|---------------|
| `0x04` | PAGE_READWRITE | Read and write. CPU cannot execute. |
| `0x20` | PAGE_EXECUTE_READ | CPU can execute and read. Cannot write. |
| `0x40` | PAGE_EXECUTE_READWRITE | Read, write, and execute. All at once. |

Using `0x40` is the simplest approach because you can write shellcode in and execute it without any extra steps. But RAM that is both writable and executable at the same time is very unusual for legitimate programs. **Defender flags this.**

The safer approach:

1. Request RAM with `0x04` (read-write only, so you can write shellcode into it)
2. Copy your shellcode bytes into that RAM
3. Change the permissions to `0x20` (execute-read only, so the CPU can run it but nobody can write to it anymore)

This way, the RAM is never writable and executable at the same time.

Now call VirtualAlloc:

```csharp
        uint size = 4096;
        IntPtr mem = VirtualAlloc(IntPtr.Zero, size, 0x3000, 0x04);
```

This asks Windows: "Give me 4096 bytes of RAM that I can read and write to. Put it wherever you want." Windows picks an address, reserves 4096 bytes there, and returns the address.

```csharp
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed. Windows did not give us RAM.");
            return;
        }
        Console.WriteLine("[+] Got RAM at address: 0x" + mem.ToString("X"));
```

If VirtualAlloc returns zero, the request failed. Otherwise, `mem` is the address in RAM where you have 4096 bytes of read-write space.

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
        Console.WriteLine("[*] Asking Windows for 4096 bytes of RAM (read-write)...");

        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x04);

        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }

        Console.WriteLine("[+] Got RAM at address: 0x" + mem.ToString("X"));
        Console.WriteLine("[*] We can read and write data here.");
        Console.WriteLine("[*] The CPU cannot execute code from here (no execute permission).");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] RAM given back to Windows.");
    }
}
```

`VirtualFree` gives the RAM back to Windows so other programs can use it. `0x8000` is MEM_RELEASE, which releases the entire chunk. In a real loader, you do not free the RAM because your shellcode needs to stay in it and keep running.

### Part 6: Copying Data Into the RAM Chunk

After VirtualAlloc gives you a chunk of RAM, that chunk is empty (all zeros). You need to copy your shellcode bytes into it. You already learned `Marshal.Copy` in Document 02. Here is how it works with VirtualAlloc:

```csharp
        byte[] data = new byte[] { 0xCC, 0x90, 0x90, 0xC3 };
```

Four test bytes. 0xCC is INT3 (a debugger breakpoint instruction), 0x90 is NOP (a "do nothing" instruction), and 0xC3 is RET (a "return" instruction). These are harmless machine instructions, not real shellcode.

```csharp
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)data.Length, 0x3000, 0x04);
```

Request RAM the same size as the data. `(uint)data.Length` converts the array length from int to uint because VirtualAlloc expects a uint.

```csharp
        Marshal.Copy(data, 0, mem, data.Length);
```

Copy the bytes from the C# array into the VirtualAlloc RAM. The parameters: source array, starting position in the array (0 means the first byte), destination address in RAM, number of bytes to copy. After this, the RAM at address `mem` contains the bytes 0xCC, 0x90, 0x90, 0xC3.

```csharp
        Array.Clear(data, 0, data.Length);
```

Zero out the original C# array. Now the bytes exist only in the VirtualAlloc RAM, not in the .NET runtime's managed RAM. If Defender's memory scanner runs, it will not find the shellcode in the C# array because you zeroed it out. The shellcode exists only in the chunk you got from VirtualAlloc.

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
        Console.WriteLine("[+] RAM allocated at: 0x" + mem.ToString("X"));

        Marshal.Copy(data, 0, mem, data.Length);
        Console.WriteLine("[+] Copied " + data.Length + " bytes into RAM.");

        Array.Clear(data, 0, data.Length);
        Console.WriteLine("[+] Zeroed out the C# array.");

        byte check = Marshal.ReadByte(mem);
        Console.WriteLine("[*] First byte in VirtualAlloc RAM: 0x" + check.ToString("X2"));
        Console.WriteLine("[*] First byte in C# array: " + data[0] + " (zero, because we cleared it)");

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] Done.");
    }
}
```

Output:
```
[*] Created 4 bytes of test data.
[+] RAM allocated at: 0x<address>
[+] Copied 4 bytes into RAM.
[+] Zeroed out the C# array.
[*] First byte in VirtualAlloc RAM: 0xCC
[*] First byte in C# array: 0 (zero, because we cleared it)
[+] Done.
```

The data is in the VirtualAlloc RAM at 0xCC. The C# array is zeroed. The data lives in only one place now.

### Part 7: VirtualProtect - Changing RAM Permissions

The RAM from VirtualAlloc has read-write permissions (0x04). Your data is in there. But the CPU still cannot execute it because the RAM does not have execute permission. DEP stops the CPU from running code in read-write RAM.

VirtualProtect changes the permissions of a chunk of RAM that already exists:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
```

`IntPtr lpAddress` is the address of the RAM chunk (from VirtualAlloc).

`uint dwSize` is the size of the chunk in bytes.

`uint flNewProtect` is the new permission value. Use `0x20` (PAGE_EXECUTE_READ) to make it executable and readable.

`out uint lpflOldProtect` is where Windows writes the old permission value. The word `out` means Windows fills in this variable for you. You need to declare it before calling the function, but you usually do not need the old value.

```csharp
        uint oldPermissions;
        bool changed = VirtualProtect(mem, (uint)data.Length, 0x20, out oldPermissions);

        if (!changed)
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] RAM permissions changed to execute-read.");
```

After this call, the CPU is allowed to run the bytes at address `mem` as instructions. You can no longer write to that RAM because execute-read does not include write permission. But that is fine because you already copied your data in.

### Part 8: CreateThread - Telling the CPU to Run Your Code

The data is in RAM. The RAM has execute permission. The last step is telling the CPU to start running the bytes at that address.

Your program already has one thread running, executing your Main function right now. A **thread** is a sequence of instructions that the CPU follows one by one. Your program can create additional threads, and each thread runs at the same time, independently of the others.

You can see threads in Task Manager: right-click any process, click "Go to details," and the Threads column shows how many threads that process has.

CreateThread creates a new thread that starts running at a specific address in RAM. If that address contains your shellcode, the CPU starts executing your shellcode:

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

This has six parameters but only one matters for what we are doing:

`IntPtr lpStartAddress` is the RAM address where the new thread starts executing. You pass the address from VirtualAlloc.

The other five use default values:

- `IntPtr.Zero` for lpThreadAttributes means default security settings
- `0` for dwStackSize means default stack size (a stack is a small chunk of RAM each thread gets for its own temporary data)
- `IntPtr.Zero` for lpParameter means no extra data passed to the thread
- `0` for dwCreationFlags means the thread starts running immediately
- `out uint lpThreadId` receives the PID-like number Windows assigns to the new thread

```csharp
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, out uint tid);

        if (thread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }
        Console.WriteLine("[+] Thread " + tid + " is now running.");
```

After this call, the CPU is running the bytes at address `mem` on a new thread. But your main thread (your Main function) keeps going too. If Main reaches the end and your program exits, the new thread dies with it. For shellcode that keeps running (a reverse shell stays connected until you close it), you need the main thread to wait.

WaitForSingleObject pauses the main thread until the new thread finishes:

```csharp
    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
```

```csharp
        WaitForSingleObject(thread, 0xFFFFFFFF);
```

`thread` is the handle to the new thread (returned by CreateThread). `0xFFFFFFFF` means wait forever. The main thread stops at this line and does nothing until the shellcode thread finishes.

Here is the complete program that puts everything together. It runs a single byte: `0xC3`, which is the machine instruction RET (return). This instruction immediately returns, ending the thread:

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
        Console.WriteLine("[+] RAM allocated at: 0x" + mem.ToString("X"));

        Marshal.Copy(code, 0, mem, code.Length);
        Console.WriteLine("[+] Code copied to RAM.");

        uint oldProtect;
        if (!VirtualProtect(mem, (uint)code.Length, 0x20, out oldProtect))
        {
            Console.WriteLine("[-] VirtualProtect failed.");
            return;
        }
        Console.WriteLine("[+] RAM is now executable.");

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
[+] RAM allocated at: 0x<address>
[+] Code copied to RAM.
[+] RAM is now executable.
[+] Thread <id> is running the code.
[+] Thread finished.
```

The CPU started executing at the address in RAM. It found the byte 0xC3 (RET), which means "return." The thread ended immediately. In Document 05, you replace `{ 0xC3 }` with real msfvenom shellcode. The only thing that changes is the bytes. The VirtualAlloc, Marshal.Copy, VirtualProtect, CreateThread, WaitForSingleObject pattern stays identical.

### Part 9: GetModuleHandle and GetProcAddress - Finding Functions Without DllImport

Every DllImport you write puts the function name into the compiled binary's **import table**. The import table is a section inside the .exe file that lists every DLL function your program calls. When C# compiles a program that has DllImport lines for VirtualAlloc, VirtualProtect, and CreateThread, those three names get written directly into the .exe file on your hard drive. You can open that compiled .exe in Notepad right now and you will literally see "VirtualAlloc", "VirtualProtect", "CreateThread" sitting there as readable text inside all the garbage characters.

Defender opens that .exe file, reads the whole thing from start to end, and checks whether any text inside it matches something in its database of known bad strings. When it finds those three function names together in the import table, it recognizes that combination as a shellcode injection tool in its database and flags the program before it even runs.

To avoid putting function names in the import table, you can find functions while the program is running using two Windows functions: GetModuleHandle and GetProcAddress.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
```

GetModuleHandle takes a DLL name and returns the address in RAM where that DLL is loaded. When a program starts, Windows automatically loads several DLLs into the program's RAM space. kernel32.dll is always loaded because every program needs it. GetModuleHandle("kernel32.dll") gives you the RAM address where kernel32.dll starts.

```csharp
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
```

GetProcAddress takes two things: the RAM address of a DLL (from GetModuleHandle) and the name of a function inside that DLL. It returns the RAM address of that function.

Together:

```csharp
        IntPtr k32 = GetModuleHandle("kernel32.dll");
        Console.WriteLine("[+] kernel32.dll is loaded at: 0x" + k32.ToString("X"));

        IntPtr funcAddr = GetProcAddress(k32, "VirtualAlloc");
        Console.WriteLine("[+] VirtualAlloc is at: 0x" + funcAddr.ToString("X"));
```

Now you have the RAM address of VirtualAlloc. But you cannot just call a RAM address in C#. C# needs to know what parameters the function takes so it calls it correctly. You tell C# using something called a delegate.

A delegate is a description of a function's shape: what parameters it takes and what it gives back. You are telling C# "when I call this, these are the parameters you need to send and this is what you will get back":

```csharp
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);
```

This says "a VirtualAllocDelegate is any function that takes these four parameters and returns an IntPtr." The `[UnmanagedFunctionPointer(CallingConvention.StdCall)]` line tells C# that this function follows the Windows calling convention. A calling convention is the agreed-upon way of passing parameters to a function. Windows functions use a method called StdCall, which is the standard Windows method.

Now convert the address to something you can call:

```csharp
        var allocFunc = (VirtualAllocDelegate)Marshal.GetDelegateForFunctionPointer(
            funcAddr, typeof(VirtualAllocDelegate));
```

`Marshal.GetDelegateForFunctionPointer` takes a RAM address and a delegate type, and gives you something you can call like a regular C# function. Now call VirtualAlloc through `allocFunc`:

```csharp
        IntPtr mem = allocFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
```

This does the same thing as calling VirtualAlloc through DllImport. The difference is that "VirtualAlloc" does not appear in the compiled binary's import table because you did not use DllImport for it. You only used DllImport for GetModuleHandle and GetProcAddress. You can open that compiled .exe in Notepad right now and you will see "GetModuleHandle" and "GetProcAddress" sitting there as readable text, but "VirtualAlloc" is nowhere in the file. Defender opens that .exe, reads the whole thing from start to end, and finds only those two functions, which appear in thousands of legitimate Windows programs. Nothing suspicious in its database matches.

In the real loaders (Documents 05 through 10), even the text "VirtualAlloc" is hidden. Instead of passing the function name as a string to GetProcAddress, the loader builds the name from numbers using FromOffsets (from Document 02):

```csharp
        string name = FromOffsets(32, 54,73,82,84,85,65,76,33,76,76,79,67);
        IntPtr funcAddr = GetProcAddress(k32, name);
```

The .exe file on your hard drive contains only the numbers (32, 54, 73...) instead of the text "VirtualAlloc". Defender opens that .exe, reads the whole thing from start to end, and finds only integers. The string "VirtualAlloc" is assembled character by character in RAM only when the program runs, and it disappears when the program exits.

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
        Console.WriteLine("[+] Created callable function from RAM address.");

        IntPtr mem = allocFunc(IntPtr.Zero, 4096, 0x3000, 0x04);
        if (mem == IntPtr.Zero)
        {
            Console.WriteLine("[-] Dynamic VirtualAlloc call failed.");
            return;
        }
        Console.WriteLine("[+] Allocated RAM at: 0x" + mem.ToString("X"));

        VirtualFree(mem, 0, 0x8000);
        Console.WriteLine("[+] RAM freed. Done.");
    }
}
```

### Part 10: OpenProcess - Accessing Another Running Program

Documents 09 and 10 inject code into other running programs. Instead of running shellcode in your loader's own process, you put it inside a trusted program like explorer.exe. This is harder for Defender to detect because the shellcode runs inside a program that Windows considers legitimate.

To interact with another running program, you first need a handle to it. OpenProcess gives you that handle:

```csharp
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
```

`dwDesiredAccess` specifies what you want to do with the process:

- `0x0400` is PROCESS_QUERY_INFORMATION. You can read information about the process (its name, how much RAM it uses) but you cannot change anything inside it. This is safe.
- `0x001FFFFF` is PROCESS_ALL_ACCESS. You get full control, including writing data into the process's RAM and creating threads inside it. The injection loaders use this.

`bInheritHandle` is almost always `false`.

`dwProcessId` is the PID of the program you want to open.

C# has a built-in way to find running programs by name:

```csharp
using System.Diagnostics;
```

`System.Diagnostics` contains tools for working with running processes. The class `Process` inside it lets you search for and get information about running programs.

```csharp
        Process[] found = Process.GetProcessesByName("explorer");
```

This searches all running programs for ones named "explorer" (you leave off the .exe part). It returns an array because there could be multiple instances of the same program running.

```csharp
        if (found.Length == 0)
        {
            Console.WriteLine("[-] explorer.exe is not running.");
            return;
        }

        int targetPid = found[0].Id;
        Console.WriteLine("[+] Found explorer.exe with PID: " + targetPid);
```

`found[0].Id` gets the PID of the first explorer.exe it found.

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

This opens explorer.exe with read-only permissions. It does not modify anything. It proves you can get a handle to another running program.

For injection (Documents 09 and 10), after getting a handle with PROCESS_ALL_ACCESS, you use three more functions:

**VirtualAllocEx** requests a chunk of RAM inside the target process. It is the same as VirtualAlloc but the RAM goes into the other program, not yours.

**WriteProcessMemory** copies bytes from your program's RAM into the target program's RAM.

**CreateRemoteThread** creates a thread in the target program. The thread starts executing at the address where you wrote your shellcode.

The full injection pattern:

1. Find the target program by name
2. OpenProcess to get a handle with full access
3. VirtualAllocEx to get RAM inside the target program
4. WriteProcessMemory to copy shellcode into that RAM
5. CreateRemoteThread to start a thread in the target that runs the shellcode

You will use these functions in Document 09. Here is the safe OpenProcess example:

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

Run with `dotnet run` (targets explorer by default) or `dotnet run -- notepad` (targets notepad if it is running).

### Part 11: The Complete Loader Pattern

Every loader in Documents 05 through 10 follows the same sequence. Now that you understand each function, here is the full pattern:

```
Step 1: Read encrypted shellcode from a file on disk (File.ReadAllBytes from Document 02)
Step 2: Get the decryption key from the command line (args from Document 02)
Step 3: Decrypt the shellcode using XOR (TransformData from Document 02)
Step 4: Request read-write RAM from Windows (VirtualAlloc with 0x04)
Step 5: Copy decrypted shellcode into that RAM (Marshal.Copy)
Step 6: Zero out the shellcode from the C# array (Array.Clear)
Step 7: Change the RAM permissions to executable (VirtualProtect with 0x20)
Step 8: Create a new thread at the shellcode address (CreateThread)
Step 9: Wait for the thread to finish (WaitForSingleObject)
```

For remote injection (putting shellcode into another program), steps 4 through 8 change:

```
Step 4: Open the target program (OpenProcess)
Step 5: Request RAM inside the target program (VirtualAllocEx)
Step 6: Copy shellcode into the target program's RAM (WriteProcessMemory)
Step 7: Change RAM permissions in the target program (VirtualProtectEx)
Step 8: Create a thread in the target program (CreateRemoteThread)
```

The idea is the same: get shellcode bytes into executable RAM and tell the CPU to run them. The only difference is whether the RAM is in your own program or in another program.

Document 05 builds the first real working loader using this pattern.

## Compilation and Execution

For every example:

1. On the dev box, open `cd C:\Users\ammulu\Desktop\CSharpLab\Lesson`
2. Replace Program.cs with the example code
3. Run: `dotnet run`
4. For programs with arguments: `dotnet run -- notepad`

The MessageBox example needs the Windows desktop (it shows a visual dialog box). All other examples work from any terminal.

## Confirming Success

After this document, verify:

- [ ] You understand that RAM is a rectangular chip on your motherboard that stores data temporarily while programs run
- [ ] You understand that programs ask Windows to do things by calling Windows API functions
- [ ] You know that DLL files in C:\Windows\System32\ contain collections of these functions
- [ ] You know what P/Invoke is (a C# feature that lets you call Windows functions using DllImport)
- [ ] You can describe a Windows function with [DllImport] and call it from C#
- [ ] You called MessageBox and saw a dialog box on screen
- [ ] You called GetCurrentProcessId and verified the PID in Task Manager
- [ ] You understand that a handle is a reference number Windows gives to your program for a resource
- [ ] You can call VirtualAlloc to request a chunk of RAM with specific permissions
- [ ] You understand why DEP stops the CPU from executing code in regular C# arrays
- [ ] You can use Marshal.Copy to put bytes into VirtualAlloc RAM
- [ ] You can use VirtualProtect to change RAM permissions to executable
- [ ] You can use CreateThread to start a new thread at a RAM address
- [ ] You can use WaitForSingleObject to keep the program alive while the thread runs
- [ ] You understand the import table and why DllImport puts function names into it
- [ ] You can use GetModuleHandle and GetProcAddress to find functions without DllImport
- [ ] You can find a running program by name and open it with OpenProcess

## What Was Gained

You now know how to call Windows functions from C#. Every C# program that interacts with the Windows operating system uses the DllImport pattern you learned here.

The specific functions you learned are the building blocks of every loader:

- **VirtualAlloc** requests a chunk of RAM from Windows with the permissions you choose
- **Marshal.Copy** puts your shellcode bytes into that RAM
- **VirtualProtect** changes the RAM permissions so the CPU can execute the bytes as code
- **CreateThread** creates a new thread that starts running at the shellcode's address
- **WaitForSingleObject** keeps the program alive while the shellcode thread runs
- **GetModuleHandle + GetProcAddress** find functions while the program runs so their names stay out of the import table
- **OpenProcess** gives you a handle to another running program for injection

The differences between the 8 loaders are which evasion techniques they add on top of this pattern: XOR encryption (Document 06), direct syscalls that bypass Defender's hooks (Document 07), patching AMSI (Document 08), reflective DLL injection (Document 09), and everything combined (Document 10).

## Common Threats and Variations

### Variation 1: Calling ntdll.dll Instead of kernel32.dll

Instead of calling VirtualAlloc from kernel32.dll, you can call NtAllocateVirtualMemory from ntdll.dll. This skips kernel32.dll entirely. Defender places its hooks inside kernel32.dll functions, so calling ntdll.dll bypasses those hooks. Document 07 covers this in full.

### Variation 2: Callback Functions Instead of CreateThread

CreateThread is a function Defender watches closely. Some loaders avoid CreateThread by using Windows functions that accept a callback. A callback is a function address that Windows calls for you. For example, `EnumChildWindows` accepts a function address and calls it for every window on screen. If you pass your shellcode's address as the callback, Windows calls your shellcode without you ever calling CreateThread. Defender has a harder time detecting this because EnumChildWindows is used by many legitimate programs.

### Variation 3: Replacing WriteProcessMemory

WriteProcessMemory is heavily monitored. Some loaders use NtWriteVirtualMemory from ntdll.dll instead, or they use shared memory sections (a feature where two programs share a chunk of RAM) to move data between processes without calling WriteProcessMemory at all.

## Detection and Defense (Blue Team Perspective)

**Import table analysis.** When a .NET binary is compiled with DllImport declarations, those function names appear in the file's import table. YARA rules can scan binaries for suspicious combinations like VirtualAlloc + CreateThread + WriteProcessMemory. Florian Roth's YARA rule repository contains rules for known offensive .NET tool patterns.

Blue team action: scan all new .NET executables for suspicious import table combinations. Alert on binaries that import injection-related API functions.

**API hook monitoring.** EDR (Endpoint Detection and Response) products hook functions like VirtualAlloc and CreateThread inside kernel32.dll. Every call is logged with its parameters: how much RAM was requested, what permissions were set, what address the new thread starts at. A program that requests executable RAM and starts a thread at that address triggers an alert.

Blue team action: configure EDR to alert when VirtualAlloc is called with executable permissions followed by CreateThread with a start address in the allocated chunk.

**RAM permission change detection.** Legitimate programs rarely call VirtualProtect to add execute permission to existing RAM. A program that writes data into RAM and then changes that RAM to executable is following the shellcode injection pattern.

Blue team action: monitor VirtualProtect calls that add execute permission. Alert when a process changes RAM from writable to executable.

**Dynamic resolution detection.** Programs that call GetProcAddress to find VirtualAlloc or CreateThread while running are using a technique common in malware. Legitimate programs typically declare their imports at compile time.

Blue team action: log GetProcAddress calls and flag when the function name being resolved is VirtualAlloc, CreateThread, WriteProcessMemory, or other injection-related functions.

## What Comes Next

Document 04 (lab/materials/04_memory_fundamentals.md) goes deeper into how Windows manages RAM. You will learn what virtual memory is (how Windows gives every program its own private address space even when they all share the same physical RAM chip), what pages are (how Windows divides RAM into fixed-size blocks), how page permissions work, and the difference between working with your own program's RAM and another program's RAM. This gives you the deeper understanding of what VirtualAlloc and WriteProcessMemory are actually doing when the loaders call them.
