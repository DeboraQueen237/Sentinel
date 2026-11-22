/*
 * MIT License
 * Copyright (c) SENTINEL Contributors
 *
 * Original demonstration YARA rules for suspicious PowerShell payloads
 * (obfuscated download cradles and AMSI/ETW logging bypass attempts).
 */

rule Sentinel_PowerShell_Encoded_Download : powershell T1059_001 T1027
{
    meta:
        description = "Detects encoded or obfuscated PowerShell download and execution cradles"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 85
        date = "2026-01-01"
        mitre = "T1059.001, T1027, T1105"

    strings:
        $enc1 = "-EncodedCommand" ascii wide nocase
        $enc2 = "-enc " ascii wide nocase
        $enc3 = "FromBase64String" ascii wide nocase
        $dl1 = "DownloadString" ascii wide nocase
        $dl2 = "DownloadFile" ascii wide nocase
        $dl3 = "Net.WebClient" ascii wide nocase
        $dl4 = "Invoke-WebRequest" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX(" ascii wide nocase
        $exec3 = "IEX (" ascii wide nocase
        $bypass = "ExecutionPolicy Bypass" ascii wide nocase

    condition:
        (any of ($enc*) and (any of ($dl*) or any of ($exec*))) or
        (any of ($dl*) and any of ($exec*) and $bypass)
}

rule Sentinel_PowerShell_Amsi_Etw_Bypass : powershell defense_evasion T1562_001
{
    meta:
        description = "Detects PowerShell scripts attempting to tamper with AMSI or ETW script inspection"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "critical"
        score = 92
        date = "2026-01-01"
        mitre = "T1562.001, T1562.006"

    strings:
        $amsi1 = "amsiInitFailed" ascii wide nocase
        $amsi2 = "AmsiScanBuffer" ascii wide nocase
        $amsi3 = "AmsiUtils" ascii wide nocase
        $etw1 = "EtwEventWrite" ascii wide nocase
        $etw2 = "SetValue($null,$true)" ascii wide nocase
        $ref1 = "GetField(" ascii wide nocase
        $ref2 = "NonPublic,Static" ascii wide nocase
        $patch = "VirtualProtect" ascii wide nocase

    condition:
        (any of ($amsi*) and ($ref1 or $ref2 or $etw2 or $patch)) or
        ($etw1 and $patch)
}
