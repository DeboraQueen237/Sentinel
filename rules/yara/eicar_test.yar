/*
 * MIT License
 * Copyright (c) SENTINEL Contributors
 *
 * Original demonstration YARA rule for the standard EICAR antivirus test file.
 * The test string is split across two literals so endpoint AV products do not
 * quarantine this rule file itself while still matching the complete EICAR file.
 */

rule Sentinel_EICAR_Test_File : test eicar
{
    meta:
        description = "Detects the standard EICAR antivirus test signature"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 90
        date = "2026-01-01"
        mitre = "T1204.002"

    strings:
        $eicar_p1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" ascii
        $eicar_p2 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii

    condition:
        $eicar_p1 and $eicar_p2 and filesize <= 1024
}
