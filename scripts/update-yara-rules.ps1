<#
.SYNOPSIS
    Optional downloader for open-source community YARA rules into SENTINEL.
.DESCRIPTION
    Downloads selected open-source YARA rule files into
    %ProgramData%\Sentinel\rules\yara\community (or $env:SENTINEL_DATA_DIR\rules\yara\community).
    SENTINEL does NOT bundle third-party community rules in the repository; this script lets
    administrators opt in to curated public rule sources with full license attribution.
    Compatible with Windows PowerShell 5.1 (ASCII-only script).
.EXAMPLE
    .\scripts\update-yara-rules.ps1 -DryRun
.EXAMPLE
    .\scripts\update-yara-rules.ps1 -Sources yara-rules,elastic -Force
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("yara-rules", "elastic", "signature-base")]
    [string[]]$Sources = @("yara-rules", "elastic"),
    [string]$DestinationDir = "",
    [switch]$DryRun,
    [switch]$Force,
    [int]$TimeoutSeconds = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Enforce TLS 1.2 for Windows PowerShell 5.1
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
    Write-Warning "Unable to force TLS 1.2: $($_.Exception.Message)"
}

if ([string]::IsNullOrWhiteSpace($DestinationDir)) {
    if (-not [string]::IsNullOrWhiteSpace($env:SENTINEL_DATA_DIR)) {
        $baseDir = $env:SENTINEL_DATA_DIR
    }
    else {
        $baseDir = Join-Path $env:ProgramData "Sentinel"
    }
    $DestinationDir = Join-Path $baseDir "rules\yara\community"
}

# Curated open-source rule catalog (no third-party rules are embedded in SENTINEL)
$Catalog = @(
    @{
        Source      = "yara-rules"
        Name        = "yara-rules_capabilities.yar"
        License     = "GPL-2.0"
        Repository  = "https://github.com/Yara-Rules/rules"
        Url         = "https://raw.githubusercontent.com/Yara-Rules/rules/master/capabilities/capabilities.yar"
        Description = "Common PE and behavioral capability indicators (Yara-Rules community)"
    },
    @{
        Source      = "yara-rules"
        Name        = "yara-rules_packers.yar"
        License     = "GPL-2.0"
        Repository  = "https://github.com/Yara-Rules/rules"
        Url         = "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer.yar"
        Description = "Software packer signatures (Yara-Rules community)"
    },
    @{
        Source      = "elastic"
        Name        = "elastic_windows_trojan_generic.yar"
        License     = "Apache-2.0"
        Repository  = "https://github.com/elastic/protections-artifacts"
        Url         = "https://raw.githubusercontent.com/elastic/protections-artifacts/main/yara/rules/Windows_Generic_Threat.yar"
        Description = "Elastic open-source Windows generic YARA rules (Apache-2.0)"
    },
    @{
        Source      = "signature-base"
        Name        = "signature-base_gen_powershell.yar"
        License     = "Detection Rule License 1.1"
        Repository  = "https://github.com/Neo23x0/signature-base"
        Url         = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/gen_powershell_susp.yar"
        Description = "Suspicious PowerShell detection rules (Neo23x0 signature-base)"
    }
)

$selectedItems = @($Catalog | Where-Object { $Sources -contains $_.Source })

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL v2 - Community YARA Rules Updater (Opt-in)" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  Destination : $DestinationDir"
Write-Host "  Sources     : $($Sources -join ', ')"
Write-Host "  Mode        : $(if ($DryRun) { 'DRY-RUN (no download)' } else { 'DOWNLOAD' })"
Write-Host ""

if ($selectedItems.Count -eq 0) {
    Write-Warning "No rule entries matched the requested sources."
    exit 0
}

if (-not $DryRun -and -not (Test-Path $DestinationDir)) {
    New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
}

$manifestEntries = New-Object System.Collections.Generic.List[object]
$downloadedCount = 0
$skippedCount = 0
$failedCount = 0

foreach ($item in $selectedItems) {
    $targetFile = Join-Path $DestinationDir $item.Name
    Write-Host "  [SOURCE] $($item.Name) [$($item.License)]" -ForegroundColor White
    Write-Host "           Repo: $($item.Repository)" -ForegroundColor DarkGray
    Write-Host "           URL : $($item.Url)" -ForegroundColor DarkGray

    if ($DryRun) {
        Write-Host "           [DRY-RUN] Would save to $targetFile" -ForegroundColor Yellow
        $skippedCount++
        continue
    }

    if ((Test-Path $targetFile) -and -not $Force) {
        Write-Host "           [SKIP] Already exists (use -Force to overwrite)." -ForegroundColor DarkYellow
        $skippedCount++
        continue
    }

    if (-not $PSCmdlet.ShouldProcess($targetFile, "Download YARA rule from $($item.Url)")) {
        $skippedCount++
        continue
    }

    try {
        $response = Invoke-WebRequest -Uri $item.Url -TimeoutSec $TimeoutSeconds -UseBasicParsing -ErrorAction Stop
        $content = [string]$response.Content

        if ([string]::IsNullOrWhiteSpace($content) -or ($content -notmatch '(?m)^\s*(private\s+|global\s+)?rule\s+[A-Za-z0-9_]+')) {
            throw "Downloaded content does not appear to contain a valid YARA rule definition."
        }

        [System.IO.File]::WriteAllText($targetFile, $content, [System.Text.Encoding]::UTF8)
        $hashObj = Get-FileHash -Path $targetFile -Algorithm SHA256

        $manifestEntries.Add([PSCustomObject]@{
            file        = $item.Name
            source      = $item.Source
            license     = $item.License
            repository  = $item.Repository
            url         = $item.Url
            sha256      = $hashObj.Hash.ToLowerInvariant()
            downloadedAt = (Get-Date).ToUniversalTime().ToString("o")
        })

        Write-Host "           [OK] Saved ($($content.Length) chars, SHA256=$($hashObj.Hash.Substring(0, 12))...)" -ForegroundColor Green
        $downloadedCount++
    }
    catch {
        Write-Warning "Failed to download $($item.Name): $($_.Exception.Message)"
        $failedCount++
    }
}

if (-not $DryRun -and $manifestEntries.Count -gt 0) {
    $manifestPath = Join-Path $DestinationDir "SOURCES_MANIFEST.json"
    $manifestJson = $manifestEntries | ConvertTo-Json -Depth 4
    [System.IO.File]::WriteAllText($manifestPath, $manifestJson, [System.Text.Encoding]::UTF8)
    Write-Host ""
    Write-Host "  [MANIFEST] License attribution written to $manifestPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Summary: downloaded=$downloadedCount, skipped=$skippedCount, failed=$failedCount" -ForegroundColor Cyan

if ($failedCount -gt 0 -and $downloadedCount -eq 0 -and -not $DryRun) {
    Write-Warning "All downloads failed (host may be offline or source URL changed). Existing rules were left untouched."
}
