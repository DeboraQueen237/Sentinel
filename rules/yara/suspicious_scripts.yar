/*
 * MIT License
 * Copyright (c) SENTINEL Contributors
 *
 * Original demonstration YARA rules for suspicious Windows scripts
 * (.bat, .cmd, .vbs, .js, .hta) abusing LOLBins or establishing persistence.
 */

rule Sentinel_Script_Lolbin_Downloader : script lolbin T1218
{
    meta:
        description = "Detects script downloaders leveraging Windows LOLBins or COM scripting objects"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 80
        date = "2026-01-01"
        mitre = "T1218, T1105, T1059"

    strings:
        $lol1 = "certutil" ascii wide nocase
        $lol1_arg = "-urlcache" ascii wide nocase
        $lol2 = "bitsadmin" ascii wide nocase
        $lol2_arg = "/transfer" ascii wide nocase
        $lol3 = "mshta" ascii wide nocase
        $lol4 = "regsvr32" ascii wide nocase
        $lol4_arg = "scrobj.dll" ascii wide nocase
        $com1 = "WScript.Shell" ascii wide nocase
        $com2 = "ADODB.Stream" ascii wide nocase
        $com3 = "MSXML2.XMLHTTP" ascii wide nocase
        $com4 = "WinHttp.WinHttpRequest" ascii wide nocase
        $http = /https?:\/\/[^\s"'<>]{5,}/i

    condition:
        ($lol1 and $lol1_arg) or
        ($lol2 and $lol2_arg) or
        ($lol4 and $lol4_arg) or
        ($lol3 and $http) or
        (2 of ($com*) and $http)
}

rule Sentinel_Script_Persistence_And_Defender_Tamper : script persistence T1547_001
{
    meta:
        description = "Detects scripts creating autostart persistence or adding Microsoft Defender exclusions"
        author = "SENTINEL Project"
        license = "MIT"
        severity = "high"
        score = 82
        date = "2026-01-01"
        mitre = "T1547.001, T1053.005, T1562.001"

    strings:
        $run_key = "CurrentVersion\\Run" ascii wide nocase
        $reg_add = "reg add" ascii wide nocase
        $schtasks = "schtasks" ascii wide nocase
        $sch_create = "/create" ascii wide nocase
        $def1 = "Add-MpPreference" ascii wide nocase
        $def2 = "ExclusionPath" ascii wide nocase
        $def3 = "DisableRealtimeMonitoring" ascii wide nocase
        $hidden = "-WindowStyle Hidden" ascii wide nocase

    condition:
        ($def1 and ($def2 or $def3)) or
        ($def3 and $hidden) or
        ($reg_add and $run_key) or
        ($schtasks and $sch_create and $hidden)
}
