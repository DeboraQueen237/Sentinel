/*
 * MIT License
 * Copyright (c) SENTINEL Contributors
 *
 * Original demonstration YARA rules targeting ransomware pre-encryption
 * recovery inhibition commands and ransom note indicators.
 */

rule Sentinel_Ransomware_Recovery_Inhibition : ransomware T1490
{
    meta:
        description = "Detects commands that delete Volume Shadow Copies or disable Windows recovery"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "critical"
        score = 95
        date = "2026-01-01"
        mitre = "T1490"

    strings:
        $vss1 = "vssadmin" ascii wide nocase
        $vss2 = "delete shadows" ascii wide nocase
        $wmic0 = "wmic" ascii wide nocase
        $wmic1 = "shadowcopy" ascii wide nocase
        $wmic2 = "delete" ascii wide nocase
        $bcd1 = "bcdedit" ascii wide nocase
        $bcd2 = "recoveryenabled no" ascii wide nocase
        $bcd3 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $wb1 = "wbadmin" ascii wide nocase
        $wb2 = "delete catalog" ascii wide nocase

    condition:
        ($vss1 and $vss2) or
        ($wmic0 and $wmic1 and $wmic2) or
        ($bcd1 and ($bcd2 or $bcd3)) or
        ($wb1 and $wb2)
}

rule Sentinel_Ransomware_Note_Heuristics : ransomware T1486
{
    meta:
        description = "Detects textual patterns commonly present in ransomware extortion notes"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 85
        date = "2026-01-01"
        mitre = "T1486"

    strings:
        $msg1 = "your files have been encrypted" ascii wide nocase
        $msg2 = "all your important files" ascii wide nocase
        $msg3 = "military-grade encryption" ascii wide nocase
        $msg4 = "decrypt your files" ascii wide nocase
        $pay1 = "bitcoin" ascii wide nocase
        $pay2 = "monero" ascii wide nocase
        $pay3 = "tor browser" ascii wide nocase
        $pay4 = "private decryption key" ascii wide nocase
        $warn = "do not rename" ascii wide nocase

    condition:
        (any of ($msg*) and any of ($pay*)) or
        (2 of ($msg*) and $warn)
}
