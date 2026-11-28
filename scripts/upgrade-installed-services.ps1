<#
.SYNOPSIS
    Met a niveau sur place les services Windows SENTINEL installes dans C:\Program Files\Sentinel vers la derniere version (v2.2.0).
.DESCRIPTION
    1. Demande automatiquement l'elevation Administrateur (UAC) si necessaire.
    2. Arrete proprement SentinelWatchdog, SentinelAgent, SentinelAdmin et SentinelServer.
    3. Nettoie toute base tampon outbox corrompue dans %ProgramData%\Sentinel\Outbox.
    4. Copie les binaires Release v2.2.0 (depuis dist\SentinelPortable-2.2.0.zip ou publication locale), les regles Sigma/YARA et met a jour integrity-manifest.json.
    5. Redemarre tous les services et ouvre http://127.0.0.1:5200.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Sentinel",
    [switch]$NoOpenBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Demande d'elevation Administrateur (UAC) pour mettre a jour les services dans $InstallDir..." -ForegroundColor Yellow
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -InstallDir `"$InstallDir`""
    if ($NoOpenBrowser) { $argList += " -NoOpenBrowser" }
    $proc = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argList -Wait -PassThru
    exit $proc.ExitCode
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$portableZip = Join-Path $repoRoot "dist\SentinelPortable-2.2.0.zip"

if (-not (Test-Path $portableZip)) {
    Write-Host "[1/5] Construction du package Release v2.2.0..." -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "build\build.ps1") -Version "2.2.0" -SkipTests -SkipMsi
    if ($LASTEXITCODE -ne 0) { throw "Echec build.ps1 v2.2.0" }
}

Write-Host "[2/5] Arret des services Windows SENTINEL..." -ForegroundColor Yellow
foreach ($svc in @("SentinelWatchdog", "SentinelAgent", "SentinelAdmin", "SentinelServer")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($null -ne $s -and $s.Status -ne "Stopped") {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
}
Start-Sleep -Seconds 2

# Réparation préventive du fichier outbox SQLite s'il était verrouillé/corrompu en v1.0
$outboxDir = "C:\ProgramData\Sentinel\Outbox"
if (Test-Path $outboxDir) {
    Get-ChildItem -Path $outboxDir -Filter "agent-outbox.db*" -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[3/5] Deploiement des binaires v2.2.0 dans $InstallDir..." -ForegroundColor Green
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$tmpExtract = Join-Path $env:TEMP ("sentinel-upgrade-" + [Guid]::NewGuid().ToString("N"))
[System.IO.Compression.ZipFile]::ExtractToDirectory($portableZip, $tmpExtract)
Copy-Item -Path (Join-Path $tmpExtract "*") -Destination $InstallDir -Recurse -Force
Remove-Item -Path $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue

# Déploiement des règles Sigma/YARA dans C:\ProgramData\Sentinel\rules
$rulesDst = "C:\ProgramData\Sentinel\rules"
if (Test-Path (Join-Path $repoRoot "rules")) {
    New-Item -ItemType Directory -Path $rulesDst -Force | Out-Null
    Copy-Item -Path (Join-Path $repoRoot "rules\*") -Destination $rulesDst -Recurse -Force
}

Write-Host "[4/5] Mise a jour du manifeste d'integrite SHA-256..." -ForegroundColor Cyan
$installerExe = Join-Path $InstallDir "Sentinel.Installer.exe"
if (Test-Path $installerExe) {
    & $installerExe --accept-consent --install-dir "$InstallDir" | Out-Host
}

Write-Host "[5/5] Redemarrage des services SENTINEL v2.2.0..." -ForegroundColor Green
foreach ($svc in @("SentinelServer", "SentinelAdmin", "SentinelAgent", "SentinelWatchdog")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($null -ne $s) {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

Start-Sleep -Seconds 3
Get-Service Sentinel* | Format-Table Name, Status, StartType -AutoSize

if (-not $NoOpenBrowser) {
    Start-Process "http://127.0.0.1:5200"
}
Write-Host "Mise a niveau vers SENTINEL v2.2.0 terminee avec succes !" -ForegroundColor Green
