# Document 02: C# Basics for Evasion Development

## Where We Are

You have a working lab from Document 01. Your Windows 11 VM has Visual Studio 2022 and the .NET SDK installed. Your Kali VM has msfvenom, python3, and smbclient. Both machines are on the same host-only network (192.168.10.0/24) and can ping each other. File transfer works both ways.

At this point you know:
- Why C# is the right language for Windows evasion (Document 00)
- How Defender's 6 detection layers work (Document 00)
- Your lab is fully set up with Defender at default settings (Document 01)
- You can compile and run C# code using `dotnet run` on the Windows VM

You have zero C# programming experience. That is fine. This document teaches you everything you need to know about C# to build every loader in this curriculum. You will not learn C# the way a textbook teaches it (calculating averages, sorting lists, building web apps). You will learn C# by manipulating bytes, converting data formats, working with memory, and calling operating system functions. Every example in this document is something you will actually use in a loader.

## Why This Is Next

You cannot build evasion tools without knowing the language they are written in. Documents 05 through 10 each build a working loader in C#, and every line of code in those loaders uses concepts taught in this document. If you skip this and jump to the loaders, you will be copying code without understanding it, and when Defender catches your loader (and it will), you will not know how to modify the code to bypass the detection.

C# is also not difficult to learn for what we need. You do not need to learn the entire language. You need to know: how to store data in variables, how to work with bytes and byte arrays, how to write functions, how to use loops, how to convert between data types, and how to structure a program. That covers about 10% of C# but it is the 10% that every loader uses.

## How This Works

C# is a programming language created by Microsoft. When you write C# code and compile it, the compiler does not produce machine code (the raw instructions your CPU runs). Instead, it produces MSIL (Microsoft Intermediate Language), which is a set of instructions for the .NET runtime. When you run the compiled program, the .NET runtime's JIT (Just-In-Time) compiler translates the MSIL into machine code on the fly.

This matters for evasion because the compiled binary (.exe or .dll) contains MSIL, not machine code. MSIL is higher-level than machine code and includes metadata: the names of your classes, methods, variables, and string literals are all embedded in the binary in readable form. If you name your class "ShellcodeInjector" and your method "InjectMalware", those exact strings are sitting in the compiled binary where Defender's scanner can find them. Understanding this is why we renamed all our loaders' classes and methods to neutral names during threat validation (Phase 3).

A C# program starts in a file with the .cs extension. The program has a structure: it belongs to a namespace (a grouping mechanism), contains a class (a container for code), and has a Main method (the entry point where execution starts). Every loader follows this structure.

## What Defender Does

Defender does not directly affect how you write C# code, but it affects what happens to the compiled output. When you compile a C# program into an .exe or .dll, Defender scans the resulting file. Defender looks at:

- **String literals in the binary.** If your code contains `Console.WriteLine("Injecting shellcode into process")`, that exact string is stored in the compiled binary. Defender's signatures include strings commonly found in malware.
- **Class and method names in .NET metadata.** The compiled binary's metadata section contains every class name, method name, and namespace name. A class called `AmsiBypass` in namespace `ShellcodeLoader` is a red flag.
- **Import table entries.** When you use `[DllImport("kernel32.dll")]` to import a Windows API function, the function name appears in the binary's import table. A binary that imports `VirtualAlloc`, `WriteProcessMemory`, and `CreateRemoteThread` together is suspicious because that combination is the classic process injection pattern.
- **Byte patterns.** The MSIL instructions for certain operations (like calling VirtualAlloc with specific flags) produce recognizable byte sequences that signature scanners match.

None of this matters while you are learning C# basics in this document. But knowing that the compiler embeds your code's names and strings into the binary explains why, in later documents, you will see techniques like building strings from integer arithmetic and resolving API functions dynamically at runtime.

## The Evasion Technique

There is no evasion technique in this document. This is a programming fundamentals document. The evasion starts in Document 05 (Shellcode Loader). However, every code pattern you learn here is chosen because it appears in the loaders. You will not learn anything in this document that you do not use later.

## Getting the Loader Onto the Target

No loader exists yet. This section applies starting from Document 05.

## Teaching the Code

### Your First C# Program

Open a Command Prompt on the Windows VM and create a new project:

```
mkdir C:\Users\kimjongun\Desktop\CSharpLab
cd C:\Users\kimjongun\Desktop\CSharpLab
dotnet new console -n Lesson01
cd Lesson01
```

This creates a folder called Lesson01 with a file called Program.cs inside it. Open Program.cs in Visual Studio or any text editor. Replace its contents with:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Red team operator reporting in.");
    }
}
```

Now run it:

```
dotnet run
```

Output: `Red team operator reporting in.`

Here is what each line does:

```csharp
using System;
```

This line tells the compiler that your program uses the `System` namespace. A namespace is a collection of pre-built code that someone else wrote. The `System` namespace contains basic things like `Console` (for printing text to the screen) and `Convert` (for converting between data types). Without this line, you would have to write `System.Console.WriteLine` instead of just `Console.WriteLine`.

```csharp
class Program
{
```

A class is a container for your code. In C#, all code must live inside a class. The name `Program` is a convention but you can name it anything. The curly brace `{` starts the class body.

```csharp
    static void Main(string[] args)
    {
```

`Main` is the entry point of your program. When you run the compiled binary, the .NET runtime looks for a method called `Main` and starts executing there. `static` means this method belongs to the class itself, not to an instance of the class (this distinction does not matter for our purposes, just know that Main must be static). `void` means this method does not return a value. `string[] args` is an array of command-line arguments passed to the program.

```csharp
        Console.WriteLine("Red team operator reporting in.");
```

`Console.WriteLine` prints text to the terminal and adds a newline at the end. The text between the double quotes is a string literal. This exact string will be embedded in the compiled binary's metadata, which is why in the actual loaders, we avoid putting evasion-related terms in Console.WriteLine messages.

```csharp
    }
}
```

Closing braces end the Main method and the Program class.

### Variables and Data Types

A variable is a named container that holds a value. In C#, every variable has a type that determines what kind of value it can hold.

Create a new file or modify Program.cs:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        // Integer: whole numbers (no decimal point)
        int port = 4444;

        // String: text
        string targetIP = "192.168.10.100";

        // Boolean: true or false
        bool connected = false;

        // Byte: a single byte (0 to 255)
        byte xorKey = 0x4A;

        // Long: large whole numbers (for memory addresses)
        long memoryAddress = 0x7FFE0000;

        Console.WriteLine("Target: " + targetIP + ":" + port);
        Console.WriteLine("XOR key: 0x" + xorKey.ToString("X2"));
        Console.WriteLine("Memory address: 0x" + memoryAddress.ToString("X"));
        Console.WriteLine("Connected: " + connected);
    }
}
```

Run it:

```
dotnet run
```

Output:
```
Target: 192.168.10.100:4444
XOR key: 0x4A
Memory address: 0x7FFE0000
Connected: False
```

The types that matter for evasion development:

- **int** holds whole numbers from -2,147,483,648 to 2,147,483,647. You use this for process IDs, port numbers, loop counters, and return codes from Windows API functions.
- **uint** holds unsigned (non-negative) whole numbers from 0 to 4,294,967,295. Windows API functions use uint for flags like memory protection values (PAGE_READWRITE = 0x04, PAGE_EXECUTE_READ = 0x20) and allocation types (MEM_COMMIT = 0x1000).
- **byte** holds a single byte from 0 to 255. Shellcode is an array of bytes. XOR keys are bytes. Every piece of raw data you work with is bytes.
- **string** holds text. You use strings for IP addresses, process names, file paths, and function names. Strings in C# are stored in the binary's metadata in clear text, which is why the loaders build sensitive strings from integer arithmetic instead of writing them directly.
- **bool** holds true or false. You use this for checking whether API calls succeeded.
- **IntPtr** holds a pointer (a memory address). On a 64-bit system, IntPtr is 8 bytes. Every Windows API function that returns a handle (a reference to an operating system resource) returns an IntPtr. When you call VirtualAlloc and it returns the address of the allocated memory, that address is an IntPtr.
- **long** holds large whole numbers. You sometimes need this for 64-bit values.

The `0x` prefix means the number is in hexadecimal (base 16). Hexadecimal is everywhere in Windows programming because memory addresses, byte values, and API constants are all written in hex. Each hex digit represents 4 bits, so two hex digits represent one byte. `0x4A` is the byte value 74 in decimal, and `0x7FFE0000` is a memory address.

The `.ToString("X2")` call converts a number to its hexadecimal string representation. "X2" means uppercase hex with at least 2 digits (so 10 becomes "0A", not "A"). "X" without a number uses the minimum digits needed.

### Byte Arrays

Shellcode is a sequence of bytes. In C#, you store a sequence of bytes in a byte array. Understanding byte arrays is the single most important data structure for this entire curriculum because every loader reads, manipulates, or writes byte arrays.

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        // A byte array with explicit values.
        // These are the first few bytes of a NOP sled (0x90 = NOP instruction).
        byte[] nopSled = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90 };

        // An empty byte array of a specific size.
        // This is how you create a buffer to hold data you will read later.
        byte[] buffer = new byte[256];

        // The length of the array (number of bytes).
        Console.WriteLine("NOP sled length: " + nopSled.Length + " bytes");
        Console.WriteLine("Buffer length: " + buffer.Length + " bytes");

        // Accessing individual bytes by index (starting from 0).
        Console.WriteLine("First byte: 0x" + nopSled[0].ToString("X2"));
        Console.WriteLine("Last byte: 0x" + nopSled[nopSled.Length - 1].ToString("X2"));

        // Printing all bytes as a hex string.
        // This is how you inspect shellcode or encrypted data.
        Console.Write("NOP sled hex: ");
        for (int i = 0; i < nopSled.Length; i++)
        {
            Console.Write(nopSled[i].ToString("X2") + " ");
        }
        Console.WriteLine();

        // Modifying a byte.
        buffer[0] = 0xCC;  // 0xCC = INT3, the software breakpoint instruction
        Console.WriteLine("Buffer[0] after modification: 0x" + buffer[0].ToString("X2"));
    }
}
```

Output:
```
NOP sled length: 5 bytes
Buffer length: 256 bytes
First byte: 0x90
Last byte: 0x90
NOP sled hex: 90 90 90 90 90
Buffer[0] after modification: 0xCC
```

Key things to understand:

- `new byte[] { 0x90, 0x90 }` creates a byte array with specific values. You will see this in the AMSI bypass loader where the patch bytes are defined this way.
- `new byte[256]` creates a byte array of 256 zeros. You will see this when allocating buffers for reading data.
- `.Length` gives you the number of bytes. Every loader uses this when telling Windows API functions how many bytes to allocate or write.
- `array[0]` accesses the first byte (arrays start at index 0 in C#). `array[array.Length - 1]` accesses the last byte.
- Byte arrays are mutable. You can change individual bytes after creation.

### The XOR Operation

XOR (exclusive or) is the encryption mechanism used in Loader 02 and referenced in every loader that handles encrypted shellcode. You need to understand it completely.

XOR is a bitwise operation. It compares two values bit by bit. For each pair of bits:
- 0 XOR 0 = 0
- 0 XOR 1 = 1
- 1 XOR 0 = 1
- 1 XOR 1 = 0

The rule is: if the bits are different, the result is 1. If they are the same, the result is 0.

The critical property of XOR is that it is reversible: if you XOR a value with a key, and then XOR the result with the same key, you get the original value back. This means XOR is both the encryption and the decryption operation.

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        // Original shellcode byte (just one byte for demonstration).
        byte original = 0xFC;  // 0xFC is the first byte of many x64 shellcodes (cld instruction)

        // XOR key byte.
        byte key = 0x4A;

        // Encrypt: XOR the original with the key.
        byte encrypted = (byte)(original ^ key);

        // Decrypt: XOR the encrypted value with the same key.
        byte decrypted = (byte)(encrypted ^ key);

        Console.WriteLine("Original:  0x" + original.ToString("X2"));
        Console.WriteLine("Key:       0x" + key.ToString("X2"));
        Console.WriteLine("Encrypted: 0x" + encrypted.ToString("X2"));
        Console.WriteLine("Decrypted: 0x" + decrypted.ToString("X2"));
        Console.WriteLine("Match: " + (original == decrypted));
    }
}
```

Output:
```
Original:  0xFC
Key:       0x4A
Encrypted: 0xB6
Decrypted: 0xFC
Match: True
```

The `^` operator is XOR in C#. The `(byte)` cast is needed because C# promotes byte operations to int, and you need to cast the result back to byte.

0xFC is a real example: it is the first byte of most x64 shellcodes generated by msfvenom. The cld (clear direction flag) instruction starts many payloads. Defender's signatures know this. When you XOR 0xFC with 0x4A, you get 0xB6, which does not match any known shellcode signature. That is how XOR encoding defeats static signature scanning.

Now here is XOR applied to an entire byte array, which is exactly how the loaders encrypt and decrypt shellcode:

```csharp
using System;

class Program
{
    // This function XORs every byte of the data array with the key array.
    // It cycles through the key bytes: data[0] ^ key[0], data[1] ^ key[1],
    // data[2] ^ key[2], data[3] ^ key[0], data[4] ^ key[1], and so on.
    // This is the exact function used in Loaders 02 through 08.
    static byte[] TransformData(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }

    static void Main(string[] args)
    {
        // Simulated shellcode (first 8 bytes of a typical x64 reverse shell).
        byte[] shellcode = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00 };

        // XOR key (4 bytes, will cycle over the shellcode).
        byte[] key = new byte[] { 0x4A, 0x7F, 0x2B, 0x1C };

        // Encrypt.
        byte[] encrypted = TransformData(shellcode, key);

        // Decrypt (same function, same key).
        byte[] decrypted = TransformData(encrypted, key);

        // Display all three.
        Console.Write("Original:  ");
        PrintHex(shellcode);
        Console.Write("Encrypted: ");
        PrintHex(encrypted);
        Console.Write("Decrypted: ");
        PrintHex(decrypted);
    }

    static void PrintHex(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            Console.Write(data[i].ToString("X2") + " ");
        }
        Console.WriteLine();
    }
}
```

Output:
```
Original:  FC 48 83 E4 F0 E8 CC 00
Encrypted: B6 37 A8 F8 BA 97 E7 1C
Decrypted: FC 48 83 E4 F0 E8 CC 00
```

The `%` operator is modulo (remainder after division). `i % key.Length` cycles through the key: when i is 0,1,2,3 you get key[0],key[1],key[2],key[3], when i is 4 you get key[0] again (because 4 % 4 = 0). This means a 4-byte key can encrypt shellcode of any length by repeating the key over and over.

This `TransformData` function is the exact function you will see in every loader that handles encrypted shellcode. It is called `TransformData` instead of `XorDecrypt` because Defender's scanners flag method names containing "Xor" or "Decrypt" as suspicious.

### Functions (Methods)

A function (called a method in C#) is a named block of code that does a specific task. You call the function by name, and it runs its code and optionally returns a result. Functions let you write code once and use it in multiple places.

Every loader is organized into functions: one function for XOR decryption, one function for patching a system function, one function for the main execution logic. Understanding how to write and call functions is essential.

```csharp
using System;

class Program
{
    // A function that converts a hex string to a byte array.
    // This is used in every loader that accepts a XOR key from the command line.
    // The command-line key is a hex string like "4A7F2B1C" and this function
    // converts it to the byte array {0x4A, 0x7F, 0x2B, 0x1C}.
    static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    // A function that converts a byte array to a hex string.
    // Useful for displaying shellcode or encrypted data.
    static string BytesToHex(byte[] data)
    {
        string result = "";
        for (int i = 0; i < data.Length; i++)
        {
            result += data[i].ToString("X2");
        }
        return result;
    }

    static void Main(string[] args)
    {
        string hexKey = "4A7F2B1C";

        // Call HexToBytes to convert the string to bytes.
        byte[] keyBytes = HexToBytes(hexKey);

        Console.WriteLine("Input hex string: " + hexKey);
        Console.Write("Converted bytes:  ");
        for (int i = 0; i < keyBytes.Length; i++)
        {
            Console.Write("0x" + keyBytes[i].ToString("X2") + " ");
        }
        Console.WriteLine();

        // Call BytesToHex to convert back.
        string reconverted = BytesToHex(keyBytes);
        Console.WriteLine("Back to hex:      " + reconverted);
    }
}
```

Output:
```
Input hex string: 4A7F2B1C
Converted bytes:  0x4A 0x7F 0x2B 0x1C
Back to hex:      4A7F2B1C
```

Breaking down the function syntax:

```csharp
static byte[] HexToBytes(string hex)
```

- `static` means this function belongs to the class, not to an instance. All functions in our loaders are static.
- `byte[]` is the return type. This function returns a byte array.
- `HexToBytes` is the function name.
- `string hex` is the parameter. When you call the function, you pass a string, and inside the function it is referred to as `hex`.

The `Convert.ToByte(hex.Substring(i * 2, 2), 16)` line is doing three things:
1. `hex.Substring(i * 2, 2)` extracts 2 characters from the hex string starting at position `i * 2`. For "4A7F2B1C", when i=0 you get "4A", when i=1 you get "7F", when i=2 you get "2B", when i=3 you get "1C".
2. `Convert.ToByte(..., 16)` converts the 2-character hex string to a byte value. The 16 means "parse this as base 16 (hexadecimal)".
3. The result is stored in `bytes[i]`.

This `HexToBytes` function appears in every loader that accepts a XOR key from the command line. When you run `loader.exe encrypted.bin 4A7F2B1C`, the "4A7F2B1C" argument is a string. The loader calls HexToBytes to convert it into the byte array needed for XOR decryption.

### Reading Files as Bytes

Every loader reads a file from disk (the shellcode file or encrypted shellcode file) and loads it into a byte array. This is one of the most fundamental operations.

```csharp
using System;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        // Create a test file with known bytes.
        string testFile = "test_payload.bin";
        byte[] testData = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00 };
        File.WriteAllBytes(testFile, testData);
        Console.WriteLine("Wrote " + testData.Length + " bytes to " + testFile);

        // Read the file back into a byte array.
        // This is how every loader reads shellcode from disk.
        byte[] fileData = File.ReadAllBytes(testFile);
        Console.WriteLine("Read " + fileData.Length + " bytes from " + testFile);

        // Verify the bytes match.
        Console.Write("Contents: ");
        for (int i = 0; i < fileData.Length; i++)
        {
            Console.Write(fileData[i].ToString("X2") + " ");
        }
        Console.WriteLine();

        // Clean up.
        File.Delete(testFile);
        Console.WriteLine("Test file deleted.");
    }
}
```

Output:
```
Wrote 8 bytes to test_payload.bin
Read 8 bytes from test_payload.bin
Contents: FC 48 83 E4 F0 E8 CC 00
Test file deleted.
```

`using System.IO;` imports the input/output namespace, which contains `File`. `File.ReadAllBytes(path)` reads the entire file into a byte array. `File.WriteAllBytes(path, bytes)` writes a byte array to a file. These are the only file operations the loaders use.

In a real loader, the shellcode file path comes from command-line arguments:

```csharp
static void Main(string[] args)
{
    if (args.Length < 1)
    {
        Console.WriteLine("Usage: loader.exe <data.bin>");
        return;
    }

    string filePath = args[0];
    byte[] data = File.ReadAllBytes(filePath);
    Console.WriteLine("Loaded " + data.Length + " bytes from " + filePath);
}
```

`args[0]` is the first command-line argument. When you run `loader.exe encrypted.bin`, args[0] is "encrypted.bin". The `if (args.Length < 1)` check prevents the program from crashing if you forget to provide the argument.

### Command-Line Arguments

Every loader accepts command-line arguments for the shellcode file path, XOR key, target process name, and other parameters. This is how the loaders are parameterized so they work with any payload, any key, and any target without changing the source code.

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        // args is an array of strings containing everything after the program name.
        // If you run: program.exe 192.168.10.200 4444 explorer
        // Then: args[0] = "192.168.10.200"
        //       args[1] = "4444"
        //       args[2] = "explorer"
        //       args.Length = 3

        if (args.Length < 2)
        {
            Console.WriteLine("Usage: program.exe <ip> <port> [process_name]");
            return;
        }

        string ip = args[0];
        int port = int.Parse(args[1]);

        // The third argument is optional.
        string processName = args.Length >= 3 ? args[2] : "explorer";

        Console.WriteLine("IP: " + ip);
        Console.WriteLine("Port: " + port);
        Console.WriteLine("Target process: " + processName);
    }
}
```

The `args.Length >= 3 ? args[2] : "explorer"` line is a ternary operator. It reads as: "if args has at least 3 elements, use args[2], otherwise use the default value explorer." This is how loaders handle optional parameters.

`int.Parse(args[1])` converts the string "4444" into the integer 4444. Command-line arguments are always strings, so you need to parse them into the correct type.

### Loops

Loops repeat a block of code multiple times. The `for` loop is the one you will use most in the loaders, primarily for iterating over byte arrays.

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        byte key = 0x4A;

        // XOR each byte with the key.
        // This is the core of every XOR encryption/decryption loop in the loaders.
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(data[i] ^ key);
        }

        Console.Write("After XOR: ");
        for (int i = 0; i < data.Length; i++)
        {
            Console.Write(data[i].ToString("X2") + " ");
        }
        Console.WriteLine();
    }
}
```

The `for` loop has three parts separated by semicolons:
1. `int i = 0` - initialization: create a counter starting at 0
2. `i < data.Length` - condition: keep looping as long as i is less than the array length
3. `i++` - increment: add 1 to i after each iteration

So the loop runs with i = 0, 1, 2, 3, 4 and stops when i reaches 5 (the array length). This visits every byte in the array exactly once.

### If Statements and Error Checking

Every Windows API call can fail. The loaders check the return value of each call and handle failures. If VirtualAlloc fails to allocate memory, it returns IntPtr.Zero (a null pointer). If OpenProcess fails to open a process handle, it also returns IntPtr.Zero. If a function returns an int status code, 0 usually means success and anything else means failure.

```csharp
using System;

class Program
{
    // Simulating an API call that might fail.
    static IntPtr SimulateVirtualAlloc(bool succeed)
    {
        if (succeed)
            return new IntPtr(0x7FFE0000);  // Simulated memory address
        else
            return IntPtr.Zero;  // Failure
    }

    static void Main(string[] args)
    {
        // Successful allocation.
        IntPtr memory = SimulateVirtualAlloc(true);
        if (memory == IntPtr.Zero)
        {
            Console.WriteLine("[-] Allocation failed.");
            return;  // Exit the program
        }
        Console.WriteLine("[+] Memory allocated at: 0x" + memory.ToString("X"));

        // Failed allocation.
        IntPtr memory2 = SimulateVirtualAlloc(false);
        if (memory2 == IntPtr.Zero)
        {
            Console.WriteLine("[-] Second allocation failed.");
            return;
        }
    }
}
```

Output:
```
[+] Memory allocated at: 0x7FFE0000
[-] Second allocation failed.
```

The pattern `if (result == IntPtr.Zero) { error handling; return; }` appears after every API call in every loader. It is the standard way to handle Windows API errors in C#. The `return` statement exits the current function (or the entire program if you are in Main).

The `[+]` and `[-]` prefixes in Console.WriteLine messages are a convention in security tools: `[+]` means success, `[-]` means failure, `[*]` means informational. You will see this throughout the loaders.

### The Unsafe Keyword and Pointers

C# is normally a "safe" language that manages memory for you. But evasion development requires direct memory manipulation, which needs "unsafe" code. The `unsafe` keyword tells the compiler that you are going to work with raw memory pointers.

You will not write unsafe code directly in most loaders because the `Marshal` class (covered next) provides safe wrappers around unsafe operations. But you need to understand what unsafe means because the loader projects compile with `AllowUnsafeBlocks` enabled, and some operations in the direct syscalls loader use unsafe code.

```csharp
using System;

class Program
{
    static unsafe void Main(string[] args)
    {
        // Allocate a byte array normally.
        byte[] data = new byte[] { 0x41, 0x42, 0x43, 0x44 };  // "ABCD" in ASCII

        // Pin the array in memory so the garbage collector does not move it.
        // "fixed" pins the array and gives you a pointer to its first byte.
        fixed (byte* ptr = data)
        {
            // ptr is now a raw pointer to the first byte of the array.
            Console.WriteLine("Address of data: 0x" + ((long)ptr).ToString("X"));
            Console.WriteLine("First byte: 0x" + (*ptr).ToString("X2"));
            Console.WriteLine("Second byte: 0x" + (*(ptr + 1)).ToString("X2"));

            // Modify a byte through the pointer.
            *(ptr + 2) = 0x58;  // Change 'C' to 'X'
        }

        // The array was modified through the pointer.
        Console.WriteLine("Modified data[2]: 0x" + data[2].ToString("X2"));
    }
}
```

To compile this, you need to enable unsafe blocks. In the .csproj file, add `<AllowUnsafeBlocks>true</AllowUnsafeBlocks>` in the PropertyGroup. The build script for the loaders already does this.

In evasion development, you use pointers when you need to pass memory addresses to Windows API functions or when you need to read/write specific bytes at specific memory locations. The `Marshal` class provides a safer way to do most of this, but understanding that pointers exist and what they do helps you understand code that uses them.

### Marshal: The Bridge Between C# and Native Memory

The `System.Runtime.InteropServices.Marshal` class is the most important class for evasion development in C#. It provides functions that let you copy data between managed memory (C# byte arrays) and unmanaged memory (raw memory addresses that Windows API functions work with).

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    // Simulating VirtualAlloc - in the real loaders, this calls the actual Windows API.
    // For this example, we use Marshal.AllocHGlobal which allocates unmanaged memory.
    static void Main(string[] args)
    {
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00 };

        // Allocate unmanaged memory (this is what VirtualAlloc does, simplified).
        IntPtr unmanagedMemory = Marshal.AllocHGlobal(data.Length);
        Console.WriteLine("Allocated " + data.Length + " bytes at: 0x" + unmanagedMemory.ToString("X"));

        // Copy bytes from the managed array to unmanaged memory.
        // This is the equivalent of what every loader does after VirtualAlloc:
        // copy shellcode from the C# byte array into the allocated memory.
        Marshal.Copy(data, 0, unmanagedMemory, data.Length);
        Console.WriteLine("Copied " + data.Length + " bytes to unmanaged memory.");

        // Read a byte back from unmanaged memory to verify.
        byte firstByte = Marshal.ReadByte(unmanagedMemory);
        Console.WriteLine("First byte at address: 0x" + firstByte.ToString("X2"));

        // Clean up - free the unmanaged memory.
        Marshal.FreeHGlobal(unmanagedMemory);
        Console.WriteLine("Memory freed.");

        // Clear the managed array (security practice: do not leave shellcode in memory).
        Array.Clear(data, 0, data.Length);
        Console.WriteLine("Managed array cleared.");
    }
}
```

Output:
```
Allocated 8 bytes at: 0x<some_address>
Copied 8 bytes to unmanaged memory.
First byte at address: 0xFC
Memory freed.
Managed array cleared.
```

The critical Marshal functions used in the loaders:

- `Marshal.Copy(byte[] source, int startIndex, IntPtr destination, int length)` copies bytes from a C# byte array to a raw memory address. Every loader uses this to copy shellcode into memory allocated by VirtualAlloc.
- `Marshal.ReadByte(IntPtr address)` reads a single byte from a memory address. Used to inspect memory contents.
- `Marshal.GetDelegateForFunctionPointer(IntPtr address, Type type)` converts a raw function pointer to a callable C# delegate. This is how the loaders call dynamically resolved NT functions. You get the function's address with GetProcAddress, then convert it to a delegate you can call like a normal function.
- `Marshal.SizeOf(Type type)` returns the size of a structure in bytes. Used when filling STARTUPINFO and other Windows API structures.

`Array.Clear(data, 0, data.Length)` zeroes out the byte array. This is a security practice: after copying shellcode to unmanaged memory, clear the managed copy so the shellcode does not stay in two places. If Defender's memory scanner runs, it only finds the shellcode in the executable memory region, not in the managed heap.

### Building Strings from Integer Arithmetic

This technique appears in Loaders 04 (AMSI Bypass), 07 (ETW Patch), and 08 (Combined Evasion). The problem: if you write `string name = "AmsiScanBuffer"` in your C# code, the string "AmsiScanBuffer" is embedded in the compiled binary exactly as written. Defender's static scanner finds it and flags your binary because "AmsiScanBuffer" is a known indicator of AMSI bypass tools.

The solution: instead of storing the string, store the integer values of each character and construct the string at runtime.

```csharp
using System;

class Program
{
    // Build a string from integer offsets above a base value.
    // The compiler stores the integers (32, 33, 77, 83, etc.), not the characters.
    // At runtime, the function adds each offset to the base and converts to a char.
    static string FromOffsets(int baseVal, params int[] offsets)
    {
        char[] c = new char[offsets.Length];
        for (int i = 0; i < offsets.Length; i++)
            c[i] = (char)(baseVal + offsets[i]);
        return new string(c);
    }

    static void Main(string[] args)
    {
        // Building "AmsiScanBuffer" from offsets.
        // 'A' = 65 = 32 + 33
        // 'm' = 109 = 32 + 77
        // 's' = 115 = 32 + 83
        // 'i' = 105 = 32 + 73
        // ... and so on.
        string name = FromOffsets(32, 33,77,83,73,51,67,65,78,34,85,70,70,69,82);
        Console.WriteLine("Built string: " + name);

        // Building "kernel32.dll" from offsets.
        string dll = FromOffsets(32, 75,69,82,78,69,76,19,18,14,68,76,76);
        Console.WriteLine("Built string: " + dll);

        // Building "ntdll" from offsets.
        string ntdll = FromOffsets(32, 78,84,68,76,76);
        Console.WriteLine("Built string: " + ntdll);
    }
}
```

Output:
```
Built string: AmsiScanBuffer
Built string: kernel32.dll
Built string: ntdll
```

How the offset arithmetic works: each character in a string has a numeric value (its ASCII code). 'A' is 65, 'a' is 97, '0' is 48. If you choose a base value of 32, then 'A' is base + 33, 'm' is base + 77, and so on. The compiler stores the integers 32, 33, 77, 83 in the binary. It does not store the string "AmsiScanBuffer". At runtime, the function adds 32 + 33 = 65 = 'A', 32 + 77 = 109 = 'm', and so on, building the string character by character.

Defender's static scanner searches the binary for known strings. It will not find "AmsiScanBuffer" because that string does not exist in the binary. It only exists in memory at runtime, after the offsets are computed.

The `params` keyword in `params int[] offsets` means you can pass any number of int arguments and C# automatically puts them into an array. So `FromOffsets(32, 33,77,83,73)` passes baseVal=32 and offsets={33,77,83,73}.

### Structures (Structs)

Windows API functions often require you to pass structured data: groups of related values packed together in a specific order and size. C# uses `struct` to define these structures, and the `StructLayout` attribute tells the compiler to arrange the fields exactly as Windows expects them.

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    // STARTUPINFO is a Windows structure used by CreateProcess.
    // It contains information about how the new process's window should appear.
    // LayoutKind.Sequential means the fields are arranged in memory in the
    // order they are declared, with no reordering by the compiler.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;              // size of this structure in bytes
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    static void Main(string[] args)
    {
        // Create an instance and set the size field.
        // cb must be set to the size of the structure. Windows uses this
        // to know which version of the structure you are using.
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);

        Console.WriteLine("STARTUPINFO size: " + si.cb + " bytes");
    }
}
```

You will see STARTUPINFO and PROCESS_INFORMATION structures in Loader 06 (Early Bird APC Injection), which uses CreateProcess to start a suspended process. The structure fields are set to specific values that control how the process is created. You do not need to memorize these structures. Each loader document explains the fields that matter for that specific technique.

### Putting It All Together: A Complete Mini-Loader

Here is a complete program that uses every concept from this document. It reads a file, XOR-decrypts it with a key from the command line, and displays the result. This is the exact workflow that every loader follows before the execution step (which requires Windows API calls covered in the next document).

```csharp
using System;
using System.IO;

class Program
{
    static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    static byte[] TransformData(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }

    static void PrintHex(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            Console.Write(data[i].ToString("X2") + " ");
            if ((i + 1) % 16 == 0) Console.WriteLine();
        }
        Console.WriteLine();
    }

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: program.exe <file> <key_hex>");
            Console.WriteLine("Example: program.exe data.bin 4A7F2B1C");
            return;
        }

        string filePath = args[0];
        string keyHex = args[1];

        // Step 1: Read file.
        if (!File.Exists(filePath))
        {
            Console.WriteLine("[-] File not found: " + filePath);
            return;
        }
        byte[] fileData = File.ReadAllBytes(filePath);
        Console.WriteLine("[+] Read " + fileData.Length + " bytes from " + filePath);

        // Step 2: Parse key.
        byte[] key = HexToBytes(keyHex);
        Console.WriteLine("[+] Key: " + keyHex + " (" + key.Length + " bytes)");

        // Step 3: Decrypt.
        byte[] decrypted = TransformData(fileData, key);
        Console.WriteLine("[+] Decrypted " + decrypted.Length + " bytes");

        // Step 4: Display first 32 bytes.
        Console.WriteLine("[*] First 32 bytes of decrypted data:");
        byte[] display = new byte[Math.Min(32, decrypted.Length)];
        Array.Copy(decrypted, display, display.Length);
        PrintHex(display);

        // Step 5: Clean up.
        Array.Clear(fileData, 0, fileData.Length);
        Array.Clear(decrypted, 0, decrypted.Length);
        Console.WriteLine("[+] Memory cleared.");
    }
}
```

This program has the same structure as Loaders 02 through 08: parse command-line arguments, read a file, convert the key, decrypt the data, and clear memory after use. The only thing missing is the Windows API calls that allocate executable memory and run the decrypted shellcode. Those come in Documents 03 (Windows API) and 04 (Memory Fundamentals).

## Compilation and Execution

To compile and run any of the examples in this document:

```
cd C:\Users\kimjongun\Desktop\CSharpLab\Lesson01
```

Edit Program.cs with the code you want to test, then:

```
dotnet run
```

For programs that take command-line arguments:

```
dotnet run -- data.bin 4A7F2B1C
```

The `--` separates dotnet's own arguments from your program's arguments. Everything after `--` is passed to your program as `args`.

For the mini-loader at the end, first create a test file on the Windows VM:

```powershell
# In PowerShell, create a test binary file.
[byte[]]$bytes = 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00, 0x00, 0x00
[System.IO.File]::WriteAllBytes("C:\Users\kimjongun\Desktop\CSharpLab\Lesson01\test.bin", $bytes)
```

Then run:

```
dotnet run -- test.bin 4A7F2B1C
```

You should see the file size, key info, decrypted bytes, and the memory-cleared confirmation.

## Confirming Success

After completing this document, you should be able to:

- [ ] Write a C# program from scratch with the correct structure (using, class, Main)
- [ ] Declare variables of the types used in loaders (int, uint, byte, string, bool, IntPtr)
- [ ] Create and manipulate byte arrays (create, access individual bytes, iterate over them)
- [ ] Write a XOR encryption/decryption function that works on byte arrays with a multi-byte key
- [ ] Convert between hex strings and byte arrays (HexToBytes and BytesToHex)
- [ ] Read and write binary files using File.ReadAllBytes and File.WriteAllBytes
- [ ] Parse command-line arguments and handle optional parameters
- [ ] Write functions with parameters and return values
- [ ] Use if statements to check for errors and exit early
- [ ] Use for loops to iterate over arrays
- [ ] Understand what Marshal.Copy does (copy bytes between managed and unmanaged memory)
- [ ] Understand what FromOffsets does (build strings from integer arithmetic to avoid static detection)
- [ ] Understand what structures are and why Windows API functions need them

## What Was Gained

You now know enough C# to read and understand every loader in this curriculum. The specific skills you have are:

- **Byte array manipulation.** Shellcode is bytes. XOR keys are bytes. Everything the loaders work with is bytes. You can create byte arrays, read them from files, encrypt/decrypt them with XOR, and convert between hex strings and byte arrays.

- **Function writing.** Every loader is organized into functions. You can write functions that take parameters, do work, and return results. You understand how the TransformData (XOR) and HexToBytes functions work.

- **Command-line argument parsing.** Every loader takes parameters from the command line so the same binary works with different payloads, keys, and targets. You can parse args, check their count, handle optional parameters, and convert strings to the right type.

- **Error handling.** Every Windows API call can fail, and every loader checks for failure. You understand the pattern: call the function, check if the return value indicates failure, print an error and exit if it does.

- **String construction.** You understand why sensitive strings (function names, DLL names) cannot be stored as literals in the binary and how FromOffsets builds them at runtime from integer arithmetic.

- **Marshal basics.** You know that Marshal.Copy bridges the gap between C# byte arrays and raw memory addresses, which is the core operation that every loader performs when copying shellcode into allocated memory.

These are not textbook C# skills. These are the specific programming capabilities needed to write evasion tools. You do not know about inheritance, generics, LINQ, async/await, or any of the advanced C# features that application developers use. You do not need them. Every loader in this curriculum uses only the concepts taught in this document plus the Windows API concepts in Documents 03 and 04.

## Common Threats and Variations

### Variation 1: Using Top-Level Statements (Modern C#)

.NET 6 and later supports "top-level statements" where you can write code without the class and Main wrapper:

```csharp
// This is valid in .NET 6+ but we do not use it in the loaders.
Console.WriteLine("Hello");
```

The loaders in this curriculum use the explicit class and Main structure because it is clearer for teaching and because it works with all .NET versions. If you see examples online using top-level statements, they do the same thing.

### Variation 2: Using var Instead of Explicit Types

C# allows `var` which infers the type automatically:

```csharp
var port = 4444;          // compiler infers int
var data = new byte[256]; // compiler infers byte[]
```

The loaders use explicit types (`int port`, `byte[] data`) because when you are learning, seeing the types makes the code easier to understand. Both styles produce identical compiled output.

### Variation 3: String Interpolation

Instead of string concatenation with `+`:

```csharp
Console.WriteLine($"Target: {targetIP}:{port}");
```

This is cleaner but produces the same result. Some loaders use concatenation (`+`) for simplicity. Both work.

## Detection and Defense (Blue Team Perspective)

From a defender's perspective, the C# concepts in this document create specific detection opportunities:

**String literal scanning.** Security teams can scan .NET binaries for suspicious string literals. If a binary contains strings like "shellcode", "inject", "bypass", "payload", or known function names like "AmsiScanBuffer", that is a strong indicator of a red team tool. This is why the loaders use integer arithmetic to build strings at runtime.

Blue team action: deploy YARA rules that scan .NET assemblies for known offensive tool strings. Tools like Florian Roth's signature-base already include rules for common C# red team tools.

**Method and class name scanning.** .NET metadata includes all class and method names. A class called "Injector" with a method called "XorDecrypt" is suspicious. This is why the loaders use neutral names like "Program" and "TransformData".

Blue team action: scan .NET assemblies for method names that match known offensive techniques. The dnfile Python library can extract .NET metadata for automated scanning.

**Import table analysis.** When a .NET binary uses P/Invoke (DllImport) to call Windows API functions, those function names appear in the binary's import table. A binary that imports VirtualAlloc, WriteProcessMemory, and CreateRemoteThread together is suspicious.

Blue team action: analyze PE import tables for suspicious API combinations. Tools like pefile and LIEF can extract this data. The combination of VirtualAlloc + any memory-writing function + any thread-creation function is a strong indicator of process injection.

## What Comes Next

Start Document 03 (lab/materials/03_windows_api.md). It teaches how to call Windows API functions from C# using P/Invoke and DllImport. You will learn how C# talks to the operating system, which is the bridge between the programming concepts you just learned and the actual evasion techniques that use Windows functions to allocate memory, write shellcode, and create threads.
