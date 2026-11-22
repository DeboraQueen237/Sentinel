/*
 * MIT License
 * Copyright (c) SENTINEL Contributors
 *
 * Original demonstration YARA rules for suspicious Windows PE executables
 * (process injection API clusters and known packer section signatures).
 */

rule Sentinel_PE_Process_Injection_APIs : pe malware T1055
{
    meta:
        description = "Detects PE binaries referencing classic remote process injection API combinations"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 82
        date = "2026-01-01"
        mitre = "T1055"

    strings:
        $mz = { 4D 5A }
        $api_alloc = "VirtualAllocEx" ascii
        $api_write = "WriteProcessMemory" ascii
        $api_thread = "CreateRemoteThread" ascii
        $api_unmap = "NtUnmapViewOfSection" ascii
        $api_apc = "QueueUserAPC" ascii
        $api_open = "OpenProcess" ascii

    condition:
        $mz at 0 and
        ($api_alloc and $api_write and ($api_thread or $api_unmap or $api_apc)) or
        ($mz at 0 and $api_open and $api_unmap and $api_write)
}

rule Sentinel_PE_Known_Packer_Markers : pe packer T1027_002
{
    meta:
        description = "Detects PE binaries containing well-known software packer section markers"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "medium"
        score = 60
        date = "2026-01-01"
        mitre = "T1027.002"

    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "UPX!" ascii
        $aspack = ".aspack" ascii
        $themida = ".themida" ascii
        $vmp0 = ".vmp0" ascii
        $mpress = ".mpress1" ascii

    condition:
        uint16(0) == 0x5A4D and
        (($upx0 and $upx1) or $upx_sig or $aspack or $themida or $vmp0 or $mpress)
}
