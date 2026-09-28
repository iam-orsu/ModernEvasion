# Document 02: C# Basics for Evasion Development

## Where We Are

You have a working lab from Document 01. Your dev box (ammulu, 192.168.10.150) has Visual Studio 2022 and the .NET SDK installed, with Defender disabled so compiled loaders are not quarantined. Your target machine (kimjongun, 192.168.10.100) has Defender running at full defaults. Your Kali VM (192.168.10.200) has msfvenom, python3, and smbclient. All three machines can ping each other on 192.168.10.0/24.

At this point you know:
- Why C# is the language for Windows evasion (Document 00)
- How Defender's 6 detection layers work (Document 00)
- Your lab is running with Defender at full default settings on the target (Document 01)
- You can compile and run C# with `dotnet run` on the dev box

You have zero C# programming experience. This document fixes that. By the end, you will understand every line of code in every loader this curriculum builds.

## Why This Is Next

Documents 05 through 10 each build a working evasion loader in C#. Every loader reads data from a file, changes it, puts it into RAM (your computer's temporary working storage, more on this in a moment), and tells the computer to run it. If you do not understand how C# stores data, repeats actions, reads files, and organizes code into reusable pieces, you will be copying code without understanding it. When Defender catches your loader and you need to change the code to avoid detection, you will not know what to change or why.

You do not need to learn all of C#. You need a specific set of skills: storing and changing data, working with raw bytes, repeating operations, organizing code into functions, reading files, and accepting input from the command line. That is what this document teaches, and every single concept here appears in the loaders.

## How This Works

C# is a programming language made by Microsoft. You write code in a text file ending with .cs, and the compiler turns it into a program you can run. The compiled program runs on the .NET runtime, which is pre-installed on every Windows machine. This is one of the reasons C# is ideal for evasion: you do not need to install anything on the target machine to run your code.

When you compile C# code, the compiler produces something called MSIL (Microsoft Intermediate Language), not the raw machine instructions your CPU understands. The .NET runtime translates MSIL to machine instructions when you run the program. The important thing for evasion is that the compiled .exe file contains readable information about your code sitting directly on your hard drive. You can open the compiled .exe in Notepad right now and you will literally see the class name, the function names, and every piece of text you put in double quotes sitting there as readable text inside all the garbage characters. Defender opens that .exe file, reads the whole thing from start to end, and checks whether any of those names or strings match something in its database of known bad names. This is why naming things matters, and why later documents teach you to avoid putting sensitive words in your code.

## What Defender Does

While you are learning C# basics, Defender does not directly interfere. But Defender will scan every .exe and .dll you compile. The things Defender looks for in compiled C# files include:

- Text strings embedded in the binary (like if you write `Console.WriteLine("Injecting shellcode")`, those words are stored in the file)
- Class and function names (a class called "ShellcodeInjector" is a red flag)
- The names of Windows functions your program imports (certain combinations of function names are suspicious)

None of this matters yet because the programs in this document are harmless learning exercises. But understanding that the compiler embeds your code's names and text into the output file explains decisions you will see in the loaders later.

## The Evasion Technique

No evasion technique in this document. This is programming fundamentals. Evasion starts in Document 05.

## Getting the Loader Onto the Target

No loader exists yet. This applies from Document 05 onward.

## Teaching the Code

### Setting Up Your Workspace

Open a Command Prompt on the dev box (ammulu, 192.168.10.150). All coding and compilation in this document happens on the dev box, not on the target machine:

```
mkdir C:\Users\ammulu\Desktop\CSharpLab
cd C:\Users\ammulu\Desktop\CSharpLab
dotnet new console -n Lesson
cd Lesson
```

This creates a folder with a file called Program.cs. You will edit this file for every example. Open it in Visual Studio or Notepad. Replace whatever is in there with the code from each section.

To run your code after editing:

```
dotnet run
```

### Part 1: The Structure of a C# Program

Every C# program has the same basic skeleton. Replace the contents of Program.cs with this:

```csharp
using System;
```

This first line tells C# that you want to use a collection of pre-built tools called `System`. One of those tools is `Console`, which lets you print text to the screen. Without this line, C# does not know what `Console` is.

```csharp
class Program
{
```

In C#, all your code has to live inside something called a class. A class is a named section of code. You give it a name (here it is called `Program` but the name does not matter), and everything between the opening curly brace `{` and the closing curly brace `}` belongs to that section. Every C# program needs at least one class.

```csharp
    static void Main(string[] args)
    {
```

This is the starting point of your program. When you run the compiled file, the computer looks for a function called `Main` and starts running the code inside it. Every C# program needs exactly one `Main` function. The `string[] args` part lets your program accept input from the command line, which you will use later.

```csharp
        Console.WriteLine("Red team operator reporting in.");
```

This line prints text to the screen. Whatever you put between the double quotes shows up in the terminal when you run the program. `Console.WriteLine` prints the text and then moves to the next line.

```csharp
    }
}
```

These closing braces end the `Main` function and the `Program` class.

Here is the complete program with all the pieces together:

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

Run it with `dotnet run`. You should see: `Red team operator reporting in.`

That is your first C# program. Every program in this curriculum follows this same skeleton: `using System;` at the top, a class wrapping everything, and a `Main` function where execution begins.

### Part 2: Variables - Storing Data

When your program runs, it needs to hold onto information. The port number your payload connects to, the IP address of your attacker machine, the name of a process you want to target. All of this needs to be stored somewhere while the program is running. In C#, you store information in variables.

A variable has two parts: a type (what kind of data it holds) and a name (how you refer to it). You create a variable and give it a value like this:

```csharp
        int port = 4444;
        string targetIP = "192.168.10.200";
```

`int` means this variable holds a whole number (no decimal point). `port` is the name you chose for it. `4444` is the value stored in it. `string` means this variable holds text. `targetIP` holds the text "192.168.10.200". The text has to be inside double quotes so C# knows it is text and not code.

You can print variables by combining them with text:

```csharp
        Console.WriteLine("Connecting to " + targetIP + " on port " + port);
```

The `+` sign joins pieces of text together. When you join a number with text, C# automatically converts the number to text for you. This line prints: `Connecting to 192.168.10.200 on port 4444`

Here are the variable types you will use in the loaders:

```csharp
        int processId = 1234;
        uint memorySize = 4096;
        byte singleByte = 0xFF;
        bool success = true;
        long bigNumber = 0x7FFE00000000;
```

`int` holds whole numbers. You use it for process IDs, port numbers, and return values from functions.

`uint` is the same but only holds positive numbers (no negatives). Windows functions use `uint` for things like sizes and permission flags.

`byte` holds a single byte, which is a number from 0 to 255. This is the building block of all raw data. Shellcode is just a sequence of bytes, so you will work with lots of bytes throughout this curriculum.

`bool` holds either `true` or `false`, nothing else. You use it to check if something worked or failed.

`long` holds very large numbers. You need it for 64-bit addresses on modern Windows.

The `0x` prefix means the number is written in hexadecimal (base 16) instead of decimal (base 10). Hexadecimal is used everywhere in Windows programming. The number `0xFF` is the same as 255 in decimal. The number `0x4A` is the same as 74. You do not need to memorize conversions because C# handles them, but you need to recognize that `0x` means hex.

Here is the complete program:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        int port = 4444;
        string targetIP = "192.168.10.200";
        byte singleByte = 0xFF;
        bool success = true;

        Console.WriteLine("Connecting to " + targetIP + " on port " + port);
        Console.WriteLine("Byte value: " + singleByte);
        Console.WriteLine("Success: " + success);
    }
}
```

Output:
```
Connecting to 192.168.10.200 on port 4444
Byte value: 255
Success: True
```

Notice that when you print the byte `0xFF`, it shows as `255`. That is because C# converts it to decimal for display. Later you will learn to display it as hex when you need to.

### Part 3: Making Decisions with If Statements

Your program needs to make decisions while it runs. Did the file load successfully? Did the request for RAM work? Is the user running the program with the right arguments? You handle all of this with `if` statements.

```csharp
        int result = 0;

        if (result == 0)
        {
            Console.WriteLine("[+] Operation succeeded.");
        }
```

The `if` statement checks a condition. The condition is inside the parentheses: `result == 0`. The double equals `==` means "is equal to" (a single `=` means "assign a value", which is different). If the condition is true, the code inside the curly braces runs. If the condition is false, the code is skipped entirely.

You can add an `else` block for what happens when the condition is false:

```csharp
        if (result == 0)
        {
            Console.WriteLine("[+] Operation succeeded.");
        }
        else
        {
            Console.WriteLine("[-] Operation failed.");
        }
```

If `result` is 0, you see the success message. If `result` is anything other than 0, you see the failure message. Only one of the two blocks runs, never both.

In the loaders, you see this pattern after every Windows function call. Windows functions return a value that tells you whether they worked. Typically, 0 means success and anything else means failure. Or the function returns a RAM address, and if it returns 0 (a null address), it means it failed. The loader checks the return value and exits if something went wrong:

```csharp
        IntPtr memoryAddress = IntPtr.Zero;

        if (memoryAddress == IntPtr.Zero)
        {
            Console.WriteLine("[-] Memory allocation failed.");
            return;
        }
```

`IntPtr` is a special type that holds a RAM address. `IntPtr.Zero` is the null address (address 0), which Windows returns when a function fails. The `return;` statement stops the program immediately. There is no point continuing if the RAM request failed because everything after it depends on having that RAM.

The `[+]` and `[-]` prefixes in the messages are a convention in security tools. `[+]` means something worked, `[-]` means something failed, `[*]` means general information. You will see this throughout the loaders.

Here is a complete example:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        int status = 0;

        if (status == 0)
        {
            Console.WriteLine("[+] Status check passed.");
        }
        else
        {
            Console.WriteLine("[-] Status check failed with code: " + status);
            return;
        }

        Console.WriteLine("[*] Continuing to next step...");

        bool fileLoaded = false;

        if (fileLoaded)
        {
            Console.WriteLine("[+] File is loaded.");
        }
        else
        {
            Console.WriteLine("[-] File not loaded.");
            return;
        }

        Console.WriteLine("[*] This line never runs because fileLoaded is false.");
    }
}
```

Output:
```
[+] Status check passed.
[*] Continuing to next step...
[-] File not loaded.
```

The program stops after "File not loaded" because `return;` exits Main. The last line never runs. This is exactly how the loaders handle errors: check each step, stop if it fails, continue if it succeeds.

### Part 4: Loops - Repeating Actions

Say you need to print the numbers 1 through 10. You could write 10 separate `Console.WriteLine` calls, one for each number. But that is tedious, and if you needed to print 1 through 10000, writing 10000 lines is not practical. A loop does the same action multiple times automatically.

You give it a starting point, a stopping condition, and a step size. It repeats the code inside it, adjusting the step each time, until the stopping condition is met.

```csharp
        for (int i = 1; i <= 10; i++)
        {
            Console.WriteLine(i);
        }
```

This prints:
```
1
2
3
4
5
6
7
8
9
10
```

Here is what the three parts inside the parentheses do:

`int i = 1` creates a counter variable called `i` starting at 1. This happens once, at the beginning.

`i <= 10` is the condition. Before each repetition, C# checks: is `i` still less than or equal to 10? If yes, run the code inside the braces again. If no, stop.

`i++` adds 1 to `i` after each repetition. So `i` goes 1, 2, 3, 4, 5, 6, 7, 8, 9, 10. When `i` becomes 11, the condition `i <= 10` is false, and the loop stops.

Now here is why loops matter for evasion. Shellcode is a sequence of bytes. A typical shellcode payload is 400 to 600 bytes long. If you want to change every byte (for example, to encrypt it), you need to go through each byte one by one and apply an operation to it. A loop does this:

```csharp
        byte[] data = new byte[] { 10, 20, 30, 40, 50 };

        for (int i = 0; i < data.Length; i++)
        {
            Console.WriteLine("Byte " + i + " = " + data[i]);
        }
```

This prints:
```
Byte 0 = 10
Byte 1 = 20
Byte 2 = 30
Byte 3 = 40
Byte 4 = 50
```

`data.Length` gives you the total number of items in the array (5 in this case). The counter starts at 0 because in C#, the first item in an array is at position 0, the second at position 1, and so on. The loop runs while `i < 5`, meaning it runs for i = 0, 1, 2, 3, 4. That covers all 5 positions.

When you encrypt shellcode, the loop goes through each byte, applies the encryption operation, and stores the result. When you search through a list of running processes, the loop checks each one. When you build a string character by character, the loop adds each character. Loops are in every single loader.

Here is the complete example:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Counting 1 to 10:");
        for (int i = 1; i <= 10; i++)
        {
            Console.WriteLine(i);
        }

        Console.WriteLine();
        Console.WriteLine("Walking through a byte array:");
        byte[] data = new byte[] { 10, 20, 30, 40, 50 };

        for (int i = 0; i < data.Length; i++)
        {
            Console.WriteLine("Position " + i + " = " + data[i]);
        }
    }
}
```

### Part 5: Arrays - Storing Multiple Values Together

A single variable holds one value. But shellcode is hundreds of bytes, a list of running processes has multiple entries, and a function name is a sequence of characters. You need a way to store many values of the same type together. That is what an array does.

```csharp
        byte[] shellcode = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
```

`byte[]` means "an array of bytes". The square brackets `[]` indicate it is an array, not a single value. `new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 }` creates the array with 5 bytes in it. Those hex values (0xFC, 0x48, etc.) are actual bytes from the beginning of a typical shellcode payload.

You access individual items by their position number (called an index), starting from 0:

```csharp
        byte first = shellcode[0];
        byte second = shellcode[1];
        byte last = shellcode[shellcode.Length - 1];
```

`shellcode[0]` is the first byte (0xFC). `shellcode[1]` is the second (0x48). `shellcode[shellcode.Length - 1]` is the last byte. Since the array has 5 items and indexing starts at 0, the last index is 4, which is `Length - 1`.

You can also create an empty array of a specific size and fill it later:

```csharp
        byte[] buffer = new byte[256];
```

This creates an array with 256 bytes, all set to 0. You would use this when you know how much space you need but do not have the data yet. In the loaders, you create result arrays for holding encrypted or decrypted data.

You can change individual values after creating the array:

```csharp
        buffer[0] = 0xCC;
        buffer[1] = 0x90;
```

Now the first byte of `buffer` is 0xCC and the second is 0x90. The rest are still 0.

Combining arrays with loops is how you process shellcode:

```csharp
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };

        Console.Write("Hex dump: ");
        for (int i = 0; i < data.Length; i++)
        {
            Console.Write(data[i].ToString("X2") + " ");
        }
        Console.WriteLine();
```

Output: `Hex dump: FC 48 83 E4 F0`

`.ToString("X2")` converts a byte to its hexadecimal text representation with at least 2 digits. The byte value 252 in decimal becomes "FC" in hex. The byte 72 becomes "48". `Console.Write` (without "Line") prints text without moving to the next line, so all the bytes appear on the same line with spaces between them.

Here is the complete example:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };

        Console.WriteLine("Array has " + data.Length + " bytes.");
        Console.WriteLine("First byte: 0x" + data[0].ToString("X2"));
        Console.WriteLine("Last byte: 0x" + data[data.Length - 1].ToString("X2"));

        Console.Write("All bytes: ");
        for (int i = 0; i < data.Length; i++)
        {
            Console.Write(data[i].ToString("X2") + " ");
        }
        Console.WriteLine();

        byte[] buffer = new byte[10];
        buffer[0] = 0xAA;
        buffer[1] = 0xBB;
        Console.WriteLine("Buffer[0]: 0x" + buffer[0].ToString("X2"));
        Console.WriteLine("Buffer[5]: 0x" + buffer[5].ToString("X2"));
    }
}
```

Output:
```
Array has 5 bytes.
First byte: 0xFC
Last byte: 0xF0
All bytes: FC 48 83 E4 F0
Buffer[0]: 0xAA
Buffer[5]: 0x00
```

Buffer[5] is 0x00 because empty arrays are filled with zeros by default.

### Part 6: Functions - Reusable Blocks of Code

As your programs grow, you will have blocks of code that you need to run in multiple places. Instead of writing the same code twice, you put it in a function (C# calls them methods) and call it by name whenever you need it.

A function has a name, can accept input (called parameters), does some work, and can give back a result (called a return value).

Start with a simple function that takes no input and returns nothing:

```csharp
    static void PrintBanner()
    {
        Console.WriteLine("=== Stealth Runner ===");
        Console.WriteLine("Version 1.0");
        Console.WriteLine();
    }
```

`static` means this function belongs to the class directly (just use this for now, all our functions are static). `void` means this function does not give back a result. `PrintBanner` is the name you chose. The empty parentheses `()` mean it takes no input. You call it from Main like this:

```csharp
    static void Main(string[] args)
    {
        PrintBanner();
        Console.WriteLine("Starting operations...");
    }
```

When the program reaches `PrintBanner();`, it jumps to the PrintBanner function, runs the code inside it, then comes back to Main and continues with the next line.

Now a function that takes input:

```csharp
    static void PrintStatus(string message, bool success)
    {
        if (success)
        {
            Console.WriteLine("[+] " + message);
        }
        else
        {
            Console.WriteLine("[-] " + message);
        }
    }
```

`string message` and `bool success` are parameters. When you call the function, you provide values for them:

```csharp
        PrintStatus("Memory allocated.", true);
        PrintStatus("Thread creation failed.", false);
```

Output:
```
[+] Memory allocated.
[-] Thread creation failed.
```

Now a function that returns a result. This is the pattern you will see in every loader for data processing:

```csharp
    static int AddNumbers(int a, int b)
    {
        int result = a + b;
        return result;
    }
```

`int` before the function name (instead of `void`) means this function gives back an integer when it is done. The `return` statement sends the value back to whoever called the function:

```csharp
        int total = AddNumbers(100, 50);
        Console.WriteLine("Total: " + total);
```

Output: `Total: 150`

The function does the work and gives you the answer. You store the answer in a variable and use it.

Here is a real example from the loaders. This function converts a hex string like "4A7F" into a byte array `{0x4A, 0x7F}`. Every loader that accepts a key from the command line uses this exact function:

```csharp
    static byte[] HexToBytes(string hex)
    {
```

The function is called `HexToBytes`. It takes a string as input and returns a byte array.

```csharp
        byte[] bytes = new byte[hex.Length / 2];
```

A hex string uses 2 characters per byte ("4A" is one byte, "7F" is one byte). So if the input string is 8 characters long, that is 4 bytes. We create an empty byte array of that size.

```csharp
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
```

The loop goes through each byte position. `hex.Substring(i * 2, 2)` extracts 2 characters from the string. When `i` is 0, it grabs characters at positions 0 and 1. When `i` is 1, it grabs positions 2 and 3. And so on. `Convert.ToByte(..., 16)` converts those 2 hex characters into a byte value. The `16` tells C# the characters are in base 16 (hexadecimal).

```csharp
        return bytes;
    }
```

Return the completed byte array to whoever called the function.

Here is the complete program with all the function examples:

```csharp
using System;

class Program
{
    static void PrintBanner()
    {
        Console.WriteLine("=== Function Demo ===");
        Console.WriteLine();
    }

    static void PrintStatus(string message, bool success)
    {
        if (success)
            Console.WriteLine("[+] " + message);
        else
            Console.WriteLine("[-] " + message);
    }

    static byte[] HexToBytes(string hex)
    {
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }

    static void Main(string[] args)
    {
        PrintBanner();

        PrintStatus("Program started.", true);

        string hexInput = "4A7F2B1C";
        byte[] keyBytes = HexToBytes(hexInput);

        Console.Write("[*] Converted \"" + hexInput + "\" to bytes: ");
        for (int i = 0; i < keyBytes.Length; i++)
        {
            Console.Write("0x" + keyBytes[i].ToString("X2") + " ");
        }
        Console.WriteLine();

        PrintStatus("Conversion complete.", true);
    }
}
```

Output:
```
=== Function Demo ===

[+] Program started.
[*] Converted "4A7F2B1C" to bytes: 0x4A 0x7F 0x2B 0x1C
[+] Conversion complete.
```

### Part 7: XOR - The Simplest Encryption

Now that you understand variables, arrays, loops, and functions, you are ready for the first concept that directly connects to evasion.

Here is the problem. Defender has a database of byte patterns that belong to known malware. When your shellcode sits in a file on your hard drive, Defender opens that file, reads the whole thing from start to end, and checks whether any bytes match something in its database of known bad patterns. If there is a match, it blocks the file. So you need a way to change the bytes in the file so Defender does not recognize them, but your loader can change them back when it is time to run the code.

The solution is XOR, which stands for "exclusive or." XOR is an operation you perform on two numbers. The practical thing you need to know is this: if you XOR a number with a key, you get a different number. If you XOR that result with the same key again, you get the original number back. XOR is both the lock and the key.

Let me show you with a single byte first:

```csharp
        byte original = 0xFC;
        byte key = 0x4A;
```

`0xFC` is the first byte of most shellcode payloads. It is the machine instruction `cld` (clear direction flag). Defender knows this byte pattern. `0x4A` is our encryption key, just a number we chose.

```csharp
        byte encrypted = (byte)(original ^ key);
```

The `^` symbol is XOR in C#. This takes `0xFC` and XORs it with `0x4A`. The result is `0xB6`, which is a completely different byte that does not match any shellcode signature. The `(byte)` at the beginning is needed because C# internally converts the result to a bigger number type, and we need to tell it we want a byte back.

```csharp
        byte decrypted = (byte)(encrypted ^ key);
```

Now XOR the encrypted value `0xB6` with the same key `0x4A` again. The result is `0xFC`, the original value. That is the whole point of XOR: apply it once to encrypt, apply it again with the same key to decrypt.

```csharp
        Console.WriteLine("Original:  0x" + original.ToString("X2"));
        Console.WriteLine("Encrypted: 0x" + encrypted.ToString("X2"));
        Console.WriteLine("Decrypted: 0x" + decrypted.ToString("X2"));
```

Output:
```
Original:  0xFC
Encrypted: 0xB6
Decrypted: 0xFC
```

Now apply this to an entire array of bytes, which is how the loaders encrypt and decrypt shellcode:

```csharp
        byte[] shellcode = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        byte xorKey = 0x4A;

        byte[] encrypted_data = new byte[shellcode.Length];
```

We have the shellcode bytes and a key. We create an empty array the same size as the shellcode to hold the encrypted version.

```csharp
        for (int i = 0; i < shellcode.Length; i++)
        {
            encrypted_data[i] = (byte)(shellcode[i] ^ xorKey);
        }
```

The loop goes through each byte in the shellcode array, XORs it with the key, and stores the result in the encrypted array. After this loop, `encrypted_data` contains bytes that look nothing like the original shellcode. Defender will not recognize them.

To decrypt, run the exact same loop on the encrypted data:

```csharp
        byte[] decrypted_data = new byte[encrypted_data.Length];
        for (int i = 0; i < encrypted_data.Length; i++)
        {
            decrypted_data[i] = (byte)(encrypted_data[i] ^ xorKey);
        }
```

Same operation, same key. The decrypted data matches the original shellcode.

Here is the complete program:

```csharp
using System;

class Program
{
    static void Main(string[] args)
    {
        byte[] shellcode = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        byte xorKey = 0x4A;

        Console.Write("Original:  ");
        for (int i = 0; i < shellcode.Length; i++)
            Console.Write(shellcode[i].ToString("X2") + " ");
        Console.WriteLine();

        byte[] encrypted_data = new byte[shellcode.Length];
        for (int i = 0; i < shellcode.Length; i++)
            encrypted_data[i] = (byte)(shellcode[i] ^ xorKey);

        Console.Write("Encrypted: ");
        for (int i = 0; i < encrypted_data.Length; i++)
            Console.Write(encrypted_data[i].ToString("X2") + " ");
        Console.WriteLine();

        byte[] decrypted_data = new byte[encrypted_data.Length];
        for (int i = 0; i < encrypted_data.Length; i++)
            decrypted_data[i] = (byte)(encrypted_data[i] ^ xorKey);

        Console.Write("Decrypted: ");
        for (int i = 0; i < decrypted_data.Length; i++)
            Console.Write(decrypted_data[i].ToString("X2") + " ");
        Console.WriteLine();
    }
}
```

Output:
```
Original:  FC 48 83 E4 F0
Encrypted: B6 02 C9 AE BA
Decrypted: FC 48 83 E4 F0
```

The encrypted bytes (B6 02 C9 AE BA) are completely different from the original (FC 48 83 E4 F0). Defender has no signature for B6 02 C9 AE BA because it is not real shellcode, it is encrypted data. When the loader runs, it decrypts the data in RAM and then executes it. Defender's file scanner only sees the encrypted version sitting on your hard drive, which matches nothing in its database.

### Part 8: Multi-Byte XOR Keys

Using a single byte as the key (like 0x4A) is simple but weak. If someone figures out the key, they can decrypt your shellcode. A multi-byte key (like 4 or 16 bytes) is much stronger and is what the loaders actually use.

With a multi-byte key, you cycle through the key bytes. The first byte of data is XORed with the first byte of the key, the second byte with the second key byte, and so on. When you reach the end of the key, you start over from the beginning.

```csharp
    static byte[] TransformData(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
```

The function takes two byte arrays: the data to encrypt/decrypt, and the key. It creates a result array the same size as the data.

```csharp
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
```

`i % key.Length` is the important part. The `%` operator gives you the remainder after division. If the key is 4 bytes long, then `0 % 4 = 0`, `1 % 4 = 1`, `2 % 4 = 2`, `3 % 4 = 3`, `4 % 4 = 0`, `5 % 4 = 1`, and so on. It cycles through positions 0, 1, 2, 3, 0, 1, 2, 3 forever. This means the key repeats over the entire data, no matter how long the data is.

```csharp
        return result;
    }
```

Return the encrypted (or decrypted) result.

This function is called `TransformData` in the loaders, not `XorEncrypt` or `XorDecrypt`. When you compile a C# program, every function name you write gets stored as readable text inside the .exe file on your hard drive. You can open the compiled .exe in Notepad right now and you will literally see `XorEncrypt` or `XorDecrypt` sitting there as readable text inside all the garbage characters. Defender opens that .exe file, reads the whole thing from start to end, and checks whether any text inside it matches strings in its database of known bad names. `XorDecrypt` is in that database because every offensive C# tool has used that name. Changing the name to `TransformData` means the .exe file on your hard drive contains `TransformData` instead, and Defender finds no match. The function works exactly the same regardless of what you name it.

Here is the complete program:

```csharp
using System;

class Program
{
    static byte[] TransformData(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }

    static void PrintHex(string label, byte[] data)
    {
        Console.Write(label);
        for (int i = 0; i < data.Length; i++)
            Console.Write(data[i].ToString("X2") + " ");
        Console.WriteLine();
    }

    static void Main(string[] args)
    {
        byte[] shellcode = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xCC, 0x00 };
        byte[] key = new byte[] { 0x4A, 0x7F, 0x2B, 0x1C };

        PrintHex("Original:  ", shellcode);

        byte[] encrypted = TransformData(shellcode, key);
        PrintHex("Encrypted: ", encrypted);

        byte[] decrypted = TransformData(encrypted, key);
        PrintHex("Decrypted: ", decrypted);
    }
}
```

Output:
```
Original:  FC 48 83 E4 F0 E8 CC 00
Encrypted: B6 37 A8 F8 BA 97 E7 1C
Decrypted: FC 48 83 E4 F0 E8 CC 00
```

The key `{0x4A, 0x7F, 0x2B, 0x1C}` is 4 bytes. It encrypts 8 bytes of shellcode by cycling through twice. The encrypted output is completely different from the original. Decrypting with the same key and same function gives back the original.

### Part 9: Reading and Writing Files

Every loader reads a file from your hard drive. The shellcode (encrypted or not) lives in a binary file, and the loader reads it into a byte array. C# makes this simple with two functions.

```csharp
using System.IO;
```

First, add `System.IO` at the top of your file. IO stands for Input/Output and contains file operations.

```csharp
        byte[] testData = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        File.WriteAllBytes("test.bin", testData);
```

`File.WriteAllBytes` takes a file path and a byte array, and writes the bytes to a file. If the file does not exist, it creates it. If it exists, it overwrites it. After this line, there is a file called test.bin on your hard drive containing those 5 bytes.

```csharp
        byte[] loaded = File.ReadAllBytes("test.bin");
```

`File.ReadAllBytes` reads the entire file into a byte array. After this line, `loaded` contains the same 5 bytes that were written to the file. This is the main way every loader gets shellcode from disk into RAM.

```csharp
        Console.WriteLine("Wrote " + testData.Length + " bytes to file.");
        Console.WriteLine("Read " + loaded.Length + " bytes from file.");
```

You can check that the number of bytes matches.

In the real loaders, the file path comes from the command line, not hardcoded:

```csharp
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: loader.exe <data.bin>");
            return;
        }

        string filePath = args[0];
```

`args` is the array of command-line arguments. `args[0]` is the first argument. When you run `loader.exe encrypted.bin`, `args[0]` is "encrypted.bin". The `if` check makes sure the user actually provided an argument before trying to use it.

You can also check if the file exists before trying to read it:

```csharp
        if (!File.Exists(filePath))
        {
            Console.WriteLine("[-] File not found: " + filePath);
            return;
        }

        byte[] fileData = File.ReadAllBytes(filePath);
        Console.WriteLine("[+] Loaded " + fileData.Length + " bytes from " + filePath);
```

`File.Exists` returns true if the file is there, false if it is not. The `!` before it means "not", so `!File.Exists(filePath)` means "if the file does NOT exist."

Here is the complete program:

```csharp
using System;
using System.IO;

class Program
{
    static void Main(string[] args)
    {
        byte[] testData = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        string testFile = "test.bin";

        File.WriteAllBytes(testFile, testData);
        Console.WriteLine("[+] Wrote " + testData.Length + " bytes to " + testFile);

        byte[] loaded = File.ReadAllBytes(testFile);
        Console.WriteLine("[+] Read " + loaded.Length + " bytes from " + testFile);

        Console.Write("[*] Contents: ");
        for (int i = 0; i < loaded.Length; i++)
            Console.Write(loaded[i].ToString("X2") + " ");
        Console.WriteLine();

        File.Delete(testFile);
        Console.WriteLine("[+] Test file cleaned up.");
    }
}
```

Output:
```
[+] Wrote 5 bytes to test.bin
[+] Read 5 bytes from test.bin
[*] Contents: FC 48 83 E4 F0
[+] Test file cleaned up.
```

### Part 10: Command-Line Arguments

Every loader accepts input from the command line: the shellcode file path, the encryption key, sometimes a target process name. This way, the same compiled binary works with any payload and any key without changing the source code.

```csharp
    static void Main(string[] args)
    {
```

`args` is an array of strings. Every word you type after the program name becomes one entry in this array:

```csharp
        Console.WriteLine("Number of arguments: " + args.Length);

        for (int i = 0; i < args.Length; i++)
        {
            Console.WriteLine("args[" + i + "] = " + args[i]);
        }
```

If you run: `dotnet run -- encrypted.bin 4A7F2B1C explorer`

Output:
```
Number of arguments: 3
args[0] = encrypted.bin
args[1] = 4A7F2B1C
args[2] = explorer
```

The `--` when using `dotnet run` separates dotnet's own arguments from your program's arguments. Everything after `--` goes into `args`.

The loaders check how many arguments were provided and show usage instructions if something is missing:

```csharp
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: loader.exe <data.bin> <key_hex> [target]");
            Console.WriteLine("  data.bin:  encrypted data file");
            Console.WriteLine("  key_hex:   decryption key in hex");
            Console.WriteLine("  target:    optional target process");
            return;
        }

        string filePath = args[0];
        string keyHex = args[1];
```

The third argument is optional. The loaders handle optional arguments with a conditional expression:

```csharp
        string target = args.Length >= 3 ? args[2] : "explorer";
```

This reads as: if args has at least 3 elements, use `args[2]` as the target, otherwise use "explorer" as the default. The `?` and `:` are the ternary operator, which is a compact if/else on a single line.

Since command-line arguments are always strings, you need to convert them when you need a different type. To convert a string to an integer:

```csharp
        int port = int.Parse(args[1]);
```

`int.Parse` converts the string "4444" to the number 4444. If the string is not a valid number, this crashes, but for our loaders the inputs are always correct because you control what you type.

Here is the complete program:

```csharp
using System;

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

    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: program.exe <file> <key_hex> [target]");
            return;
        }

        string filePath = args[0];
        string keyHex = args[1];
        string target = args.Length >= 3 ? args[2] : "explorer";

        Console.WriteLine("[*] File:   " + filePath);
        Console.WriteLine("[*] Key:    " + keyHex);
        Console.WriteLine("[*] Target: " + target);

        byte[] key = HexToBytes(keyHex);
        Console.Write("[+] Key bytes: ");
        for (int i = 0; i < key.Length; i++)
            Console.Write("0x" + key[i].ToString("X2") + " ");
        Console.WriteLine();
    }
}
```

Run: `dotnet run -- payload.bin 4A7F2B1C svchost`

Output:
```
[*] File:   payload.bin
[*] Key:    4A7F2B1C
[*] Target: svchost
[+] Key bytes: 0x4A 0x7F 0x2B 0x1C
```

### Part 11: The Marshal Class - Moving Data Between C# and Raw RAM

This is the last concept before we move to Windows API calls in Document 03. It is slightly more advanced but it is critical for understanding what the loaders do.

Your computer has RAM (Random Access Memory), which is a rectangular chip on your motherboard that stores data temporarily while programs run. When you run a C# program, C# manages a section of RAM for you automatically. It decides where your variables and arrays go, it cleans them up when you are done, and it can even move them around. This section of RAM that C# controls is called managed memory.

But Windows API functions do not work with C#'s managed memory. They work with raw RAM addresses directly. When you call VirtualAlloc (which you will learn in Document 03) to request RAM from Windows, Windows gives you a raw address in RAM. That address is not managed by C#. C# does not know what is stored there, cannot clean it up, and cannot move it. This section of RAM is called unmanaged memory.

The problem: your shellcode starts as a C# byte array (in managed memory), but it needs to end up at a raw RAM address (in unmanaged memory) where the CPU can execute it. You need a way to copy data from one to the other. That is what the `Marshal` class does.

```csharp
using System.Runtime.InteropServices;
```

Add this at the top. The `Marshal` class lives in this section of C#.

The most important Marshal function for the loaders is `Marshal.Copy`. It copies bytes from a C# byte array to a raw RAM address:

```csharp
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };

        IntPtr memory = Marshal.AllocHGlobal(data.Length);
```

`Marshal.AllocHGlobal` requests a block of raw (unmanaged) RAM and returns its address as an `IntPtr`. This is similar to what VirtualAlloc does in the loaders, but simpler. The address is a number that tells the CPU exactly where in RAM that block starts.

```csharp
        Marshal.Copy(data, 0, memory, data.Length);
```

`Marshal.Copy` takes 4 arguments: the source byte array, the starting position in the array (0 means start from the beginning), the destination RAM address, and how many bytes to copy. After this call, the raw RAM at address `memory` contains the same bytes as the `data` array.

This is the core operation in every loader. The loader reads shellcode into a byte array, requests RAM using a Windows function, and then copies the shellcode bytes into that RAM using Marshal.Copy. The shellcode is now in RAM and ready to execute.

After copying, you should clear the original byte array so the shellcode does not sit in two places at once:

```csharp
        Array.Clear(data, 0, data.Length);
```

`Array.Clear` sets every byte in the array to 0. This is a security practice. If Defender's memory scanner runs, the shellcode exists only in the requested RAM, not in the C# array.

```csharp
        byte firstByte = Marshal.ReadByte(memory);
        Console.WriteLine("First byte at address: 0x" + firstByte.ToString("X2"));
```

`Marshal.ReadByte` reads a single byte from a raw RAM address. This is useful for verifying that the copy worked.

```csharp
        Marshal.FreeHGlobal(memory);
```

`Marshal.FreeHGlobal` gives the RAM back to the system. In the loaders, you usually do not free RAM because the shellcode needs to keep running in it. But for a test like this, you clean up.

Here is the complete program:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    static void Main(string[] args)
    {
        byte[] data = new byte[] { 0xFC, 0x48, 0x83, 0xE4, 0xF0 };
        Console.WriteLine("[*] Data has " + data.Length + " bytes.");

        IntPtr memory = Marshal.AllocHGlobal(data.Length);
        Console.WriteLine("[+] Allocated memory at: 0x" + memory.ToString("X"));

        Marshal.Copy(data, 0, memory, data.Length);
        Console.WriteLine("[+] Copied " + data.Length + " bytes to memory.");

        Array.Clear(data, 0, data.Length);
        Console.WriteLine("[+] Cleared source array.");

        byte firstByte = Marshal.ReadByte(memory);
        Console.WriteLine("[*] Byte at memory address: 0x" + firstByte.ToString("X2"));

        Marshal.FreeHGlobal(memory);
        Console.WriteLine("[+] Memory freed.");
    }
}
```

Output:
```
[*] Data has 5 bytes.
[+] Allocated memory at: 0x<some_address>
[+] Copied 5 bytes to memory.
[+] Cleared source array.
[*] Byte at memory address: 0xFC
[+] Memory freed.
```

The address will be different every time you run it because the operating system assigns addresses dynamically.

### Part 12: Building Strings from Numbers (Avoiding Static Detection)

This last section connects directly to evasion. In Loaders 04, 07, and 08, the code needs to reference specific Windows function names like "AmsiScanBuffer" and "EtwEventWrite". If you write `string funcName = "AmsiScanBuffer";` in your code and compile it, that exact text gets written into the .exe file on your hard drive. You can open the compiled .exe in Notepad right now and you will literally see `AmsiScanBuffer` sitting there as readable text inside all the garbage characters. Defender opens that .exe file, reads the whole thing from start to end, and checks whether any text inside it matches strings in its database of known bad names. `AmsiScanBuffer` is in that database.

The solution: instead of storing the string, store the numbers that correspond to each character. Every character has a numeric value (its ASCII code). 'A' is 65, 'B' is 66, 'a' is 97, and so on. If you store the numbers and build the string at runtime, the string never appears in the compiled file.

The loaders use a function called `FromOffsets` that takes a base number and a list of offsets:

```csharp
    static string FromOffsets(int baseVal, params int[] offsets)
    {
        char[] c = new char[offsets.Length];
```

The function creates a character array the same size as the number of offsets.

```csharp
        for (int i = 0; i < offsets.Length; i++)
            c[i] = (char)(baseVal + offsets[i]);
```

For each offset, it adds the base value to the offset and converts the result to a character. If the base is 32 and the offset is 33, you get 32 + 33 = 65, which is 'A'. If the offset is 77, you get 32 + 77 = 109, which is 'm'.

```csharp
        return new string(c);
    }
```

Convert the character array to a string and return it.

The `params` keyword means you can pass any number of values and C# automatically collects them into an array. So you call it like:

```csharp
        string name = FromOffsets(32, 33, 77, 83, 73);
```

And C# treats `33, 77, 83, 73` as the array `{33, 77, 83, 73}`.

The compiled .exe on your hard drive contains only the numbers 32, 33, 77, 83, 73. You can open it in Notepad and you will NOT see "Amsi" anywhere. You will only see those integer values sitting in the file, which Defender's database has no entry for. The string "Amsi" is assembled character by character in RAM only when the program runs, and the file scanner never looks at RAM.

Here is the complete program:

```csharp
using System;

class Program
{
    static string FromOffsets(int baseVal, params int[] offsets)
    {
        char[] c = new char[offsets.Length];
        for (int i = 0; i < offsets.Length; i++)
            c[i] = (char)(baseVal + offsets[i]);
        return new string(c);
    }

    static void Main(string[] args)
    {
        string s1 = FromOffsets(32, 33,77,83,73,51,67,65,78,34,85,70,70,69,82);
        Console.WriteLine("Built: " + s1);

        string s2 = FromOffsets(32, 75,69,82,78,69,76,19,18,14,68,76,76);
        Console.WriteLine("Built: " + s2);

        string s3 = FromOffsets(32, 78,84,68,76,76);
        Console.WriteLine("Built: " + s3);
    }
}
```

Output:
```
Built: AmsiScanBuffer
Built: kernel32.dll
Built: ntdll
```

The strings "AmsiScanBuffer", "kernel32.dll", and "ntdll" exist only when the program runs, built in RAM from integer arithmetic. They are not stored anywhere in the .exe file on your hard drive. Defender opens that .exe, reads the whole thing from start to end, and finds only integer constants. The file scanner has nothing to match against. This is how the loaders reference sensitive Windows function and DLL names without triggering Defender's static scanner.

## Compilation and Execution

For every example in this document:

1. Open the Lesson folder on the dev box: `cd C:\Users\ammulu\Desktop\CSharpLab\Lesson`
2. Edit Program.cs with the example code
3. Run: `dotnet run`
4. For programs that use command-line arguments: `dotnet run -- arg1 arg2 arg3`

The `--` separates dotnet's arguments from your program's arguments.

## Confirming Success

After completing this document, verify you can do each of these:

- [ ] Write a C# program with the correct structure (using, class, Main)
- [ ] Create variables of different types (int, byte, string, bool, IntPtr)
- [ ] Use if/else to check conditions and handle errors
- [ ] Write a for loop that processes every element in an array
- [ ] Create byte arrays, access individual bytes, and print them as hex
- [ ] Write a function that takes parameters and returns a result
- [ ] XOR-encrypt a byte array with a single-byte key
- [ ] XOR-encrypt a byte array with a multi-byte key using the modulo cycle
- [ ] Read a binary file into a byte array with File.ReadAllBytes
- [ ] Parse command-line arguments from args
- [ ] Use Marshal.Copy to move bytes between a C# array and a RAM address
- [ ] Build a string from integer offsets using FromOffsets

## What Was Gained

You now know enough C# to understand every loader in this curriculum. Here is specifically what connects to the loaders:

**Variables and types** let you store process IDs, port numbers, RAM addresses, and the results of Windows function calls. The `IntPtr` type holds RAM addresses returned by functions like VirtualAlloc.

**If statements** are used after every Windows function call to check whether it succeeded or failed. If the RAM request fails, the loader stops. If a process cannot be opened, the loader stops. This error-checking pattern appears dozens of times across the 8 loaders.

**Loops** process shellcode byte by byte. XOR encryption, hex conversion, building strings from offsets, and printing diagnostic output all use loops to go through arrays.

**Byte arrays** are the core data structure. Shellcode is a byte array. XOR keys are byte arrays. The patch bytes that disable AMSI and ETW are byte arrays. Everything the loaders work with is bytes.

**Functions** organize code into reusable pieces. TransformData handles XOR. HexToBytes converts command-line keys. FromOffsets builds strings. PatchTelemetry disables ETW. PatchScanner disables AMSI. Each piece of functionality is a function.

**File reading** gets shellcode from your hard drive into RAM. Every loader starts by reading a .bin file with File.ReadAllBytes.

**Command-line arguments** make the loaders flexible. The same binary works with different payloads, different keys, and different target processes.

**Marshal.Copy** moves bytes from C# managed memory into raw RAM that Windows functions work with. This is the step between "shellcode in a byte array" and "shellcode in executable RAM."

**FromOffsets** hides sensitive strings from static scanners. Without it, every loader would contain strings like "AmsiScanBuffer" and "EtwEventWrite" that Defender immediately flags.

## Common Threats and Variations

### Variation 1: Top-Level Statements

.NET 6 and later lets you skip the class and Main wrapper:

```csharp
Console.WriteLine("Hello");
```

This works but the loaders use the explicit structure because it is clearer when you have multiple functions. Both produce the same compiled output.

### Variation 2: String Interpolation

Instead of joining strings with `+`:

```csharp
Console.WriteLine($"Target: {targetIP}:{port}");
```

The `$` before the quotes lets you put variables directly in the text inside `{}`. This is cleaner but does the same thing.

### Variation 3: LINQ and Modern C#

C# has powerful features like LINQ, async/await, generics, and lambda expressions. The loaders do not use any of these. You do not need them for evasion development. If you learn them later for other projects, great, but they are not part of this curriculum.

## Detection and Defense (Blue Team Perspective)

The C# concepts in this document create specific detection opportunities for defenders:

**String scanning.** Defenders can scan .NET binaries sitting on the hard drive for suspicious strings. If a compiled .exe contains "shellcode", "inject", "bypass", or Windows function names like "AmsiScanBuffer", that is a strong malware indicator. Tools like YARA with .NET-aware rules can automate this.

Blue team action: deploy YARA rules that match known offensive C# tool strings. Florian Roth's signature-base repository has rules for this.

**Method name analysis.** .NET metadata includes all function names. "XorDecrypt" or "InjectShellcode" are red flags. Tools like dnfile can extract .NET metadata for automated scanning.

Blue team action: scan .NET assemblies for method names matching offensive patterns. Create alerts for binaries with methods named after known attack techniques.

**Import table inspection.** When a C# program uses DllImport to call Windows functions, those names appear in the PE import table. Certain combinations (VirtualAlloc + WriteProcessMemory + CreateRemoteThread) are the classic injection pattern.

Blue team action: monitor for executables that import suspicious API combinations. Endpoint detection tools can flag these at load time.

## What Comes Next

Start Document 03 (lab/materials/03_windows_api.md). It teaches how C# talks to the Windows operating system. You will learn to call Windows functions that request RAM, change RAM permissions, and create threads. These are the building blocks that every loader uses to actually execute shellcode.
