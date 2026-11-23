<#
.SYNOPSIS
    Construit le package d'installation complet (Setup) de SENTINEL dans dist\.
.DESCRIPTION
    1. Publie en Release les 6 composants runtime : Sentinel.Server, Sentinel.Admin,
       Sentinel.Agent, Sentinel.Watchdog, Sentinel.Tray et Sentinel.BrowserHost.
    2. Fusionne les configurations appsettings.json, copie l'extension navigateur (extension/)
       et les metriques d'evaluation scientifique dans payload/.
    3. Compresse payload.zip puis genere :
       - dist/Sentinel-Setup-v<Version>/Sentinel.Installer.exe  (Setup graphique + CLI avec payload)
       - dist/Sentinel-Setup-v<Version>.zip                     (Archive portable prete a distribuer)
       - dist/SHA256SUMS.txt                                    (Empreintes SHA-256 des livrables)
    Passez -SelfContained (et -Runtime win-x64) pour generer un installeur autonome mono-fichier
    n'exigeant pas le runtime .NET 10 pre-installe sur le poste cible.
.EXAMPLE
    .\scripts\build-installer.ps1
.EXAMPLE
    .\scripts\build-installer.ps1 -SelfContained
#>
[CmdletBinding()]
param(
    [string]$Version = "2.0.0",
    [string]$Runtime = "win-x64",
    [switch]$SelfContained,
    [switch]$Restore,
    [string]$OutputDir = "dist"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$distRoot = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path $repoRoot $OutputDir }
$stagingRoot = Join-Path $distRoot "staging"
$payloadDir = Join-Path $stagingRoot "payload"
$payloadZip = Join-Path $stagingRoot "payload.zip"
$setupDir = Join-Path $distRoot "Sentinel-Setup-v$Version"

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL v$Version - Construction du Setup et de l'Installateur" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan

if (Test-Path $stagingRoot) { Remove-Item -Recurse -Force $stagingRoot }
if (Test-Path $setupDir) { Remove-Item -Recurse -Force $setupDir }
New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
New-Item -ItemType Directory -Path $setupDir -Force | Out-Null

$runtimeProjects = @(
    "src\Sentinel.Server\Sentinel.Server.csproj",
    "src\Sentinel.Admin\Sentinel.Admin.csproj",
    "src\Sentinel.Agent\Sentinel.Agent.csproj",
    "src\Sentinel.Watchdog\Sentinel.Watchdog.csproj",
    "src\Sentinel.Tray\Sentinel.Tray.csproj",
    "src\Sentinel.BrowserHost\Sentinel.BrowserHost.csproj"
)
$installerProj = Join-Path $repoRoot "src\Sentinel.Installer\Sentinel.Installer.csproj"

if ($SelfContained -or $Restore) {
    $scProp = if ($SelfContained) { "true" } else { "false" }
    foreach ($relProj in ($runtimeProjects + @("src\Sentinel.Installer\Sentinel.Installer.csproj"))) {
        $projPath = Join-Path $repoRoot $relProj
        $projName = [System.IO.Path]::GetFileNameWithoutExtension($projPath)
        Write-Host "  [RESTORE] $projName ($Runtime)..." -ForegroundColor DarkGray
        & dotnet restore $projPath -r $Runtime -p:SelfContained=$scProp --nologo -v minimal
        if ($LASTEXITCODE -ne 0) {
            throw "Echec de restauration pour $projName (code $LASTEXITCODE)."
        }
    }
}

foreach ($relProj in $runtimeProjects) {
    $projPath = Join-Path $repoRoot $relProj
    $projName = [System.IO.Path]::GetFileNameWithoutExtension($projPath)
    Write-Host "  [PUBLISH] $projName (Release)..." -ForegroundColor Green

    $pubArgs = @(
        "publish", $projPath,
        "-c", "Release",
        "--no-restore",
        "-nr:false",
        "-m:1",
        "-p:DebugType=None",
        "-p:DebugSymbols=false",
        "-o", $payloadDir,
        "--nologo", "-v", "minimal"
    )
    if ($SelfContained) {
        $pubArgs += @("-r", $Runtime, "--self-contained", "true")
    }
    & dotnet @pubArgs

    if ($LASTEXITCODE -ne 0) {
        throw "Echec de publication pour $projName (code $LASTEXITCODE)."
    }
}

# Fusion propre des appsettings.json des services dans payload/appsettings.json
Write-Host "  [CONFIG] Fusion des configurations appsettings.json..." -ForegroundColor Cyan
$serverCfg = Get-Content (Join-Path $repoRoot "src\Sentinel.Server\appsettings.json") -Raw | ConvertFrom-Json
$adminCfg  = Get-Content (Join-Path $repoRoot "src\Sentinel.Admin\appsettings.json") -Raw | ConvertFrom-Json
$agentCfg  = Get-Content (Join-Path $repoRoot "src\Sentinel.Agent\appsettings.json") -Raw | ConvertFrom-Json
$wdCfg     = Get-Content (Join-Path $repoRoot "src\Sentinel.Watchdog\appsettings.json") -Raw | ConvertFrom-Json

$mergedSettings = [ordered]@{
    Sentinel     = $serverCfg.Sentinel
    ServerUrl    = $adminCfg.ServerUrl
    Urls         = $adminCfg.Urls
    Agent        = $agentCfg.Agent
    Watchdog     = $wdCfg.Watchdog
    Serilog      = $serverCfg.Serilog
    Logging      = $adminCfg.Logging
    AllowedHosts = "*"
}
$mergedSettings | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $payloadDir "appsettings.json") -Encoding UTF8

# Copie de l'extension navigateur MV3 et des donnees d'evaluation si presentes
$extSrc = Join-Path $repoRoot "extension"
if (Test-Path $extSrc) {
    Copy-Item -Path $extSrc -Destination (Join-Path $payloadDir "extension") -Recurse -Force
}
$evalSrc = Join-Path $repoRoot "docs\evaluation-results.json"
if (Test-Path $evalSrc) {
    Copy-Item -Path $evalSrc -Destination (Join-Path $payloadDir "evaluation-results.json") -Force
}
Copy-Item -Path (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $payloadDir "LICENSE") -Force
Copy-Item -Path (Join-Path $repoRoot "README.md") -Destination (Join-Path $payloadDir "README.md") -Force

Write-Host "  [ZIP] Compression du payload applicatif..." -ForegroundColor Cyan
if (Test-Path $payloadZip) { Remove-Item $payloadZip -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($payloadDir, $payloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

# Publication de l'installateur (avec payload.zip integre dans Sentinel.Installer.dll)
Write-Host "  [SETUP] Publication de Sentinel.Installer..." -ForegroundColor Yellow
$instArgs = @(
    "publish", $installerProj,
    "-c", "Release",
    "--no-restore",
    "-nr:false",
    "-m:1",
    "-p:BundlePayloadZip=$payloadZip",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "-o", $setupDir,
    "--nologo", "-v", "minimal"
)
if ($SelfContained) {
    $instArgs += @(
        "-r", $Runtime,
        "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true"
    )
}
& dotnet @instArgs

if ($LASTEXITCODE -ne 0) {
    throw "Echec de generation de l'installateur (code $LASTEXITCODE)."
}

# Si mode non-single-file, copier aussi payload.zip a cote pour transparence et diagnostic
Copy-Item -Path (Join-Path $repoRoot "README.md") -Destination (Join-Path $setupDir "README.md") -Force
Copy-Item -Path (Join-Path $repoRoot "LICENSE") -Destination (Join-Path $setupDir "LICENSE") -Force

$setupZipPath = Join-Path $distRoot "Sentinel-Setup-v$Version.zip"
if (Test-Path $setupZipPath) { Remove-Item $setupZipPath -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($setupDir, $setupZipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

if ($SelfContained) {
    $singleExe = Join-Path $distRoot "Sentinel-Setup-v$Version-$Runtime.exe"
    Copy-Item -Path (Join-Path $setupDir "Sentinel.Installer.exe") -Destination $singleExe -Force
}

Remove-Item -Recurse -Force $stagingRoot

$checksumLines = [System.Collections.Generic.List[string]]::new()
$checksumLines.Add("$((Get-FileHash (Join-Path $setupDir 'Sentinel.Installer.exe') -Algorithm SHA256).Hash.ToLowerInvariant())  Sentinel-Setup-v$Version/Sentinel.Installer.exe")
$checksumLines.Add("$((Get-FileHash $setupZipPath -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $setupZipPath -Leaf)")
if ($SelfContained) {
    $singleExe = Join-Path $distRoot "Sentinel-Setup-v$Version-$Runtime.exe"
    $checksumLines.Add("$((Get-FileHash $singleExe -Algorithm SHA256).Hash.ToLowerInvariant())  $(Split-Path $singleExe -Leaf)")
}
$checksumPath = Join-Path $distRoot "SHA256SUMS.txt"
$checksumLines | Set-Content $checksumPath -Encoding UTF8

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor DarkGreen
Write-Host "  Setup SENTINEL genere avec succes !" -ForegroundColor Green
Write-Host "  - Dossier Setup     : $setupDir\Sentinel.Installer.exe"
Write-Host "  - Archive Setup ZIP : $setupZipPath ($('{0:0.0}' -f ((Get-Item $setupZipPath).Length / 1MB)) Mo)"
Write-Host "  - Empreintes SHA256 : $checksumPath"
Write-Host "==========================================================================" -ForegroundColor DarkGreen
