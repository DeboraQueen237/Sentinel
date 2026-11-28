<#
.SYNOPSIS
    Build reproductible complet de SENTINEL v2 : compilation Release, tests, publication win-x64,
    installateur MSI WiX v5, archive portable ZIP et empreintes SHA256SUMS.txt.
.EXAMPLE
    .\build\build.ps1
.EXAMPLE
    .\build\build.ps1 -Version 2.0.0 -SelfContained -SkipTests
#>
[CmdletBinding()]
param(
    [string]$Version = "2.2.0",
    [string]$Runtime = "win-x64",
    [switch]$SelfContained,
    [switch]$Restore,
    [switch]$SkipTests,
    [switch]$SkipMsi,
    [switch]$Sign,
    [switch]$SelfSignedDev,
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
$portableDir = Join-Path $stagingRoot "portable"
$slnPath = Join-Path $repoRoot "Sentinel.slnx"
$msiProj = Join-Path $repoRoot "src\Sentinel.Installer.Msi\Sentinel.Installer.Msi.wixproj"
$installerProj = Join-Path $repoRoot "src\Sentinel.Installer\Sentinel.Installer.csproj"

$runtimeProjects = @(
    "src\Sentinel.Server\Sentinel.Server.csproj",
    "src\Sentinel.Admin\Sentinel.Admin.csproj",
    "src\Sentinel.Agent\Sentinel.Agent.csproj",
    "src\Sentinel.Watchdog\Sentinel.Watchdog.csproj",
    "src\Sentinel.Tray\Sentinel.Tray.csproj",
    "src\Sentinel.BrowserHost\Sentinel.BrowserHost.csproj"
)

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL v$Version ($Runtime) - Pipeline de build reproductible" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan

New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
if (Test-Path $stagingRoot) { Remove-Item -Recurse -Force $stagingRoot }
New-Item -ItemType Directory -Path $payloadDir -Force | Out-Null
New-Item -ItemType Directory -Path $portableDir -Force | Out-Null

# 1. Restore (optionnel)
if ($Restore) {
    Write-Host "  [1/6] Restauration de la solution Sentinel.slnx..." -ForegroundColor Cyan
    & dotnet restore $slnPath --nologo -v minimal
    if ($LASTEXITCODE -ne 0) { throw "Echec dotnet restore (code $LASTEXITCODE)." }
}

# 2. Build Release
Write-Host "  [2/6] Compilation Release de Sentinel.slnx..." -ForegroundColor Cyan
& dotnet build $slnPath -c Release --no-restore -nr:false -m:1 --nologo -v minimal
if ($LASTEXITCODE -ne 0) { throw "Echec dotnet build Release (code $LASTEXITCODE)." }

# 3. Tests automatises
if (-not $SkipTests) {
    Write-Host "  [3/6] Execution des tests automatises (Release)..." -ForegroundColor Cyan
    & dotnet test $slnPath -c Release --no-build -nr:false -m:1 --nologo --verbosity minimal
    if ($LASTEXITCODE -ne 0) { throw "Echec dotnet test Release (code $LASTEXITCODE)." }
} else {
    Write-Host "  [3/6] Tests ignores (-SkipTests)." -ForegroundColor Yellow
}

# 4. Publication win-x64 des 6 composants runtime
Write-Host "  [4/6] Publication des composants runtime ($Runtime, SelfContained=$SelfContained)..." -ForegroundColor Green
if ($SelfContained) {
    foreach ($relProj in ($runtimeProjects + @("src\Sentinel.Installer\Sentinel.Installer.csproj"))) {
        $projPath = Join-Path $repoRoot $relProj
        & dotnet restore $projPath -r $Runtime -p:SelfContained=true --nologo -v minimal
        if ($LASTEXITCODE -ne 0) { throw "Echec restore $relProj ($Runtime)." }
    }
}

foreach ($relProj in $runtimeProjects) {
    $projPath = Join-Path $repoRoot $relProj
    $projName = [System.IO.Path]::GetFileNameWithoutExtension($projPath)
    Write-Host "        -> Publish $projName" -ForegroundColor DarkGreen

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
    if ($LASTEXITCODE -ne 0) { throw "Echec publication $projName (code $LASTEXITCODE)." }
}

# Fusion propre des appsettings.json
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

# Copie extension navigateur, regles par defaut, evaluation et licences
foreach ($folder in @("extension", "rules")) {
    $srcFolder = Join-Path $repoRoot $folder
    if (Test-Path $srcFolder) {
        Copy-Item -Path $srcFolder -Destination (Join-Path $payloadDir $folder) -Recurse -Force
    }
}
foreach ($file in @("LICENSE", "THIRD_PARTY_NOTICES.md", "README.md", "SECURITY.md")) {
    $srcFile = Join-Path $repoRoot $file
    if (Test-Path $srcFile) {
        Copy-Item -Path $srcFile -Destination (Join-Path $payloadDir $file) -Force
    }
}
$evalSrc = Join-Path $repoRoot "docs\evaluation-results.json"
if (Test-Path $evalSrc) {
    Copy-Item -Path $evalSrc -Destination (Join-Path $payloadDir "evaluation-results.json") -Force
}

# Creation de payload.zip + publication Sentinel.Installer.exe dans le dossier portable
[System.IO.Compression.ZipFile]::CreateFromDirectory($payloadDir, $payloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)

Copy-Item -Path (Join-Path $payloadDir "*") -Destination $portableDir -Recurse -Force

$instArgs = @(
    "publish", $installerProj,
    "-c", "Release",
    "--no-restore",
    "-nr:false",
    "-m:1",
    "-p:BundlePayloadZip=$payloadZip",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "-o", $portableDir,
    "--nologo", "-v", "minimal"
)
if ($SelfContained) {
    $instArgs += @("-r", $Runtime, "--self-contained", "true")
}
& dotnet @instArgs
if ($LASTEXITCODE -ne 0) { throw "Echec publication Sentinel.Installer (code $LASTEXITCODE)." }

# 5. Construction du package MSI WiX v5 + Archive Portable ZIP
$artifacts = [System.Collections.Generic.List[string]]::new()

if (-not $SkipMsi -and (Test-Path $msiProj)) {
    Write-Host "  [5/6] Construction de l'installateur Windows MSI (WiX v5)..." -ForegroundColor Yellow
    $msiOutDir = Join-Path $stagingRoot "msi"
    $msiPayloadDir = Join-Path $stagingRoot "msi-payload"
    New-Item -ItemType Directory -Path $msiOutDir -Force | Out-Null
    New-Item -ItemType Directory -Path $msiPayloadDir -Force | Out-Null
    Copy-Item -Path (Join-Path $payloadDir "*") -Destination $msiPayloadDir -Recurse -Force
    foreach ($svcExe in @("Sentinel.Server.exe", "Sentinel.Admin.exe", "Sentinel.Agent.exe", "Sentinel.Watchdog.exe")) {
        $dup = Join-Path $msiPayloadDir $svcExe
        if (Test-Path $dup) { Remove-Item $dup -Force }
    }

    & dotnet build $msiProj `
        -c Release `
        -p:ProductVersion=$Version `
        -p:PayloadDir=$msiPayloadDir `
        -p:ServiceExeDir=$payloadDir `
        -p:RulesDir="$(Join-Path $repoRoot 'rules')" `
        -o $msiOutDir `
        -nr:false -m:1 --nologo -v minimal
    if ($LASTEXITCODE -ne 0) { throw "Echec generation MSI WiX v5 (code $LASTEXITCODE)." }

    $builtMsi = Get-ChildItem -Path $msiOutDir -Filter "*.msi" -Recurse | Select-Object -First 1
    if (-not $builtMsi) { throw "Aucun fichier .msi genere dans $msiOutDir." }

    $targetMsi = Join-Path $distRoot "SentinelSetup-$Version.msi"
    Copy-Item -Path $builtMsi.FullName -Destination $targetMsi -Force
    $artifacts.Add($targetMsi)
    Write-Host "        -> MSI genere : $targetMsi" -ForegroundColor Green
}

$portableZip = Join-Path $distRoot "SentinelPortable-$Version.zip"
if (Test-Path $portableZip) { Remove-Item $portableZip -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($portableDir, $portableZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
$artifacts.Add($portableZip)
Write-Host "        -> Archive portable : $portableZip" -ForegroundColor Green

# Signature Authenticode optionnelle
if ($Sign -or $SelfSignedDev) {
    $signScript = Join-Path $PSScriptRoot "sign.ps1"
    $msiToSign = $artifacts | Where-Object { $_ -like "*.msi" }
    if ($msiToSign) {
        $signParams = @{ Path = $msiToSign }
        if ($SelfSignedDev) { $signParams["SelfSignedDev"] = $true }
        & $signScript @signParams
    }
}

# 6. Generation de SHA256SUMS.txt
Write-Host "  [6/6] Calcul des empreintes SHA-256 (SHA256SUMS.txt)..." -ForegroundColor Cyan
$checksumLines = [System.Collections.Generic.List[string]]::new()
foreach ($art in $artifacts) {
    $hash = (Get-FileHash $art -Algorithm SHA256).Hash.ToLowerInvariant()
    $leaf = Split-Path $art -Leaf
    $checksumLines.Add("$hash  $leaf")
}
$checksumPath = Join-Path $distRoot "SHA256SUMS.txt"
$checksumLines | Set-Content $checksumPath -Encoding UTF8

Remove-Item -Recurse -Force $stagingRoot

Write-Host ""
Write-Host "==========================================================================" -ForegroundColor DarkGreen
Write-Host "  Build SENTINEL v$Version termine avec succes !" -ForegroundColor Green
foreach ($art in $artifacts) {
    $sizeMb = "{0:0.0}" -f ((Get-Item $art).Length / 1MB)
    Write-Host "  - $(Split-Path $art -Leaf) ($sizeMb Mo)"
}
Write-Host "  - Empreintes : $checksumPath"
Write-Host "==========================================================================" -ForegroundColor DarkGreen
