<#
.SYNOPSIS
    Downloads official Windows Sigma rules from the SigmaHQ repository on demand.
.DESCRIPTION
    Fetches the SigmaHQ Sigma rules archive from GitHub and extracts Windows rules
    into %ProgramData%\Sentinel\rules\sigma\sigmahq (or a custom -DestinationDir).

    LICENSE NOTICE (IMPORTANT):
    SENTINEL itself is licensed under the MIT License and does NOT bundle SigmaHQ rules.
    Rules downloaded by this script originate from SigmaHQ and are subject to the
    Detection Rule License (DRL) 1.1:
      https://github.com/SigmaHQ/Detection-Rule-License

    This script is compatible with Windows PowerShell 5.1 and PowerShell 7+.
.PARAMETER DestinationDir
    Target folder for extracted SigmaHQ Windows rules.
    Defaults to "%ProgramData%\Sentinel\rules\sigma\sigmahq".
.PARAMETER ArchiveUrl
    URL of the SigmaHQ zip archive to download.
    Defaults to "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip".
.PARAMETER Subfolders
    Optional list of subdirectories under "rules/windows/" to extract
    (e.g. "process_creation", "powershell", "registry", "file", "network_connection", "dns_query").
    When omitted or empty, all Windows rules under "rules/windows/" are extracted.
.PARAMETER Clean
    Removes existing .yml/.yaml files in DestinationDir before extracting the new set.
.PARAMETER AcceptDrlLicense
    Acknowledges the Detection Rule License (DRL) 1.1 non-interactively without prompting.
.PARAMETER DryRun
    Displays what would be downloaded and where rules would be extracted without making network requests.
.EXAMPLE
    .\scripts\update-sigma-rules.ps1
.EXAMPLE
    .\scripts\update-sigma-rules.ps1 -AcceptDrlLicense -Clean -Subfolders process_creation,powershell,registry
#>
[CmdletBinding()]
param(
    [string]$DestinationDir = "",
    [string]$ArchiveUrl = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
    [string[]]$Subfolders = @(),
    [switch]$Clean,
    [switch]$AcceptDrlLicense,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DestinationDir)) {
    $programData = $env:ProgramData
    if ([string]::IsNullOrWhiteSpace($programData)) {
        $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    }
    $DestinationDir = Join-Path $programData "Sentinel\rules\sigma\sigmahq"
}

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL v2 - SigmaHQ Windows Rules On-Demand Updater" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  Source archive : $ArchiveUrl"
Write-Host "  Destination    : $DestinationDir"
if ($Subfolders.Count -gt 0) {
    Write-Host "  Subfolders     : $($Subfolders -join ', ')"
}
else {
    Write-Host "  Subfolders     : all rules/windows/**"
}
Write-Host ""
Write-Host "  [LICENSE NOTICE - DRL 1.1]" -ForegroundColor Yellow
Write-Host "  SigmaHQ detection rules are NOT bundled with SENTINEL." -ForegroundColor Yellow
Write-Host "  They are governed by the Detection Rule License (DRL) 1.1:" -ForegroundColor Yellow
Write-Host "    https://github.com/SigmaHQ/Detection-Rule-License" -ForegroundColor White
Write-Host "  Please ensure your usage complies with DRL 1.1 attribution and terms." -ForegroundColor Yellow
Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY-RUN] No download or file modification performed." -ForegroundColor Cyan
    exit 0
}

if (-not $AcceptDrlLicense) {
    $answer = Read-Host "Do you acknowledge the SigmaHQ DRL 1.1 license and wish to continue? [y/N]"
    if ($answer -notmatch '^(y|yes|o|oui)$') {
        Write-Host "[ABORTED] Download cancelled by user." -ForegroundColor Yellow
        exit 0
    }
}

# Ensure TLS 1.2 on Windows PowerShell 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Warning "Could not explicitly enable TLS 1.2: $($_.Exception.Message)"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sentinel-sigmahq-" + [Guid]::NewGuid().ToString("N"))
$zipPath  = Join-Path $tempRoot "sigmahq.zip"

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null

    Write-Host "[1/3] Downloading SigmaHQ archive..." -ForegroundColor Cyan
    $iwrParams = @{
        Uri             = $ArchiveUrl
        OutFile         = $zipPath
        UseBasicParsing = $true
    }
    Invoke-WebRequest @iwrParams

    if (-not (Test-Path $zipPath)) {
        throw "Downloaded archive not found at '$zipPath'."
    }

    if ($Clean) {
        Write-Host "[2/3] Cleaning existing rules in '$DestinationDir'..." -ForegroundColor DarkGray
        Get-ChildItem -Path $DestinationDir -Recurse -File -Include *.yml, *.yaml -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }

    Write-Host "[2/3] Extracting Windows Sigma rules (rules/windows/**)..." -ForegroundColor Cyan
    $normalizedSubfolders = @()
    foreach ($sf in $Subfolders) {
        if (-not [string]::IsNullOrWhiteSpace($sf)) {
            $normalizedSubfolders += $sf.Trim().Trim('/', '\').ToLowerInvariant()
        }
    }

    $extractedCount = 0
    $archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $archive.Entries) {
            if ([string]::IsNullOrEmpty($entry.Name)) {
                continue
            }

            $entryPath = $entry.FullName.Replace('\', '/')
            if ($entryPath -notmatch '(?i)^[^/]+/rules/windows/(.+\.(?:yml|yaml))$') {
                continue
            }

            $relativePath = $Matches[1]
            if ($normalizedSubfolders.Count -gt 0) {
                $firstSegment = ($relativePath -split '/')[0].ToLowerInvariant()
                if ($normalizedSubfolders -notcontains $firstSegment) {
                    continue
                }
            }

            # Protect against path traversal inside zip entries
            $targetPath = [System.IO.Path]::GetFullPath((Join-Path $DestinationDir ($relativePath -replace '/', '\')))
            $destFullRoot = [System.IO.Path]::GetFullPath($DestinationDir).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
            if (-not $targetPath.StartsWith($destFullRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }

            $parentDir = [System.IO.Path]::GetDirectoryName($targetPath)
            if (-not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }

            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetPath, $true)
            $extractedCount++
        }
    }
    finally {
        $archive.Dispose()
    }

    Write-Host "[3/3] Writing DRL 1.1 attribution notice..." -ForegroundColor Cyan
    $noticePath = Join-Path $DestinationDir "LICENSE-DRL-1.1-NOTICE.txt"
    $timestampUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $noticeLines = @(
        "SigmaHQ Rules Attribution & License Notice",
        "==========================================",
        "Downloaded UTC : $timestampUtc",
        "Source Archive : $ArchiveUrl",
        "Rules Extracted: $extractedCount",
        "",
        "These rules are authored by the SigmaHQ community and are licensed under",
        "the Detection Rule License (DRL) 1.1:",
        "  https://github.com/SigmaHQ/Detection-Rule-License",
        "",
        "They are maintained separately from SENTINEL's MIT-licensed source code."
    )
    Set-Content -Path $noticePath -Value $noticeLines -Encoding ASCII

    Write-Host ""
    Write-Host "[OK] Extracted $extractedCount SigmaHQ Windows rule(s) into '$DestinationDir'." -ForegroundColor Green
    Write-Host "     SENTINEL's hot-reload watcher will automatically index the updated rules." -ForegroundColor DarkGray
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
