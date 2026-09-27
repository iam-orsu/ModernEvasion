rule AMSI_Patch_Bytes_Classic {
    meta:
        description = "Detects classic AMSI bypass patch bytes B8 57 00 07 80 C3 (AmsiScanBuffer ret HRESULT_SUCCESS)"
        author = "ModernEvasion curriculum"
    strings:
        $patch = { B8 57 00 07 80 C3 }
    condition:
        $patch
}

rule AMSI_Patch_XOR_Variant {
    meta:
        description = "Detects XOR-based AMSI patch: xor eax,eax / ret (31 C0 C3)"
    strings:
        $patch = { 31 C0 C3 }
    condition:
        $patch
}

rule ETW_Patch_Classic {
    meta:
        description = "Detects ETW EtwEventWrite patch: xor eax,eax / ret (33 C0 C3)"
    strings:
        $patch = { 33 C0 C3 }
    condition:
        $patch
}

rule Indirect_Syscall_Stub {
    meta:
        description = "Detects indirect syscall stub: mov r10,rcx / mov eax,<SSN> / jmp qword ptr"
    strings:
        // mov r10,rcx (4C 8B D1) followed by mov eax,?? (B8) within 3 bytes
        $stub = { 4C 8B D1 B8 ?? 00 00 00 }
    condition:
        $stub
}

rule Reflective_DLL_MZ_Header_In_Binary {
    meta:
        description = "MZ header embedded in a non-PE section - reflective loader signal"
    strings:
        $mz = { 4D 5A 90 00 }
    condition:
        $mz at 0 and filesize > 1KB
}

rule Shellcode_GetProcAddress_Dynamic_Resolution {
    meta:
        description = "Detects dynamic API resolution pattern using GetProcAddress string"
    strings:
        $s1 = "GetProcAddress" ascii wide
        $s2 = "GetModuleHandle" ascii wide
        $s3 = "VirtualAlloc" ascii wide
        $s4 = "CreateThread" ascii wide
    condition:
        3 of them
}

rule Suspicious_NtAPI_Strings {
    meta:
        description = "NT-level function names that indicate syscall-level loader"
    strings:
        $n1 = "NtAllocateVirtualMemory" ascii wide
        $n2 = "NtProtectVirtualMemory" ascii wide
        $n3 = "NtCreateThreadEx" ascii wide
        $n4 = "NtWaitForSingleObject" ascii wide
    condition:
        2 of them
}

rule VirtualProtect_Code_Page_Write {
    meta:
        description = "VirtualProtect call on AMSI/ntdll code page - tamper signal"
    strings:
        $s1 = "amsi.dll" ascii wide nocase
        $s2 = "AmsiScanBuffer" ascii wide
        $s3 = "VirtualProtect" ascii wide
    condition:
        all of them
}
