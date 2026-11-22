<#
.SYNOPSIS
    Lance rapidement la pile de developpement SENTINEL (Serveur + Console Admin, et en option Agent, Tray et SeedDemo).
.DESCRIPTION
    Demarre Sentinel.Server (API REST http://127.0.0.1:5180 + gRPC 5181) et Sentinel.Admin (http://127.0.0.1:5200)
    avec un dossier de donnees isole via $env:SENTINEL_DATA_DIR, puis arrete proprement tous les processus enfants
    lorsque vous appuyez sur Ctrl+C ou fermez le script.
.EXAMPLE
    .\scripts\run-dev.ps1 -SeedDemo
.EXAMPLE
    .\scripts\run-dev.ps1 -WithAgent -WithTray -DataDir "C:\Temp\sentinel-dev"
#>
[CmdletBinding()]
param(
    [string]$DataDir = "",
    [switch]$UseSystemDataDir,
    [switch]$WithAgent,
    [switch]$WithTray,
    [switch]$SeedDemo,
    [switch]$NoBuild,
    [switch]$NoMtls,
    [int]$SeedDelayMs = 80,
    [int]$ServerApiPort = 5180,
    [int]$ServerGrpcPort = 5181,
    [int]$AdminPort = 5200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$serverProj = Join-Path $repoRoot "src\Sentinel.Server\Sentinel.Server.csproj"
$adminProj  = Join-Path $repoRoot "src\Sentinel.Admin\Sentinel.Admin.csproj"
$agentProj  = Join-Path $repoRoot "src\Sentinel.Agent\Sentinel.Agent.csproj"
$trayProj   = Join-Path $repoRoot "src\Sentinel.Tray\Sentinel.Tray.csproj"
$simProj    = Join-Path $repoRoot "tests\Sentinel.Simulation\Sentinel.Simulation.csproj"

$serverApiUrl  = "http://127.0.0.1:$ServerApiPort"
$serverGrpcUrl = if ($NoMtls) { "http://127.0.0.1:$ServerGrpcPort" } else { "https://localhost:$ServerGrpcPort" }
$adminUrl      = "http://127.0.0.1:$AdminPort"

if (-not $UseSystemDataDir) {
    if ([string]::IsNullOrWhiteSpace($DataDir)) {
        $DataDir = Join-Path $repoRoot ".sentinel-dev-data"
    }
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    $env:SENTINEL_DATA_DIR = (Resolve-Path $DataDir).Path
}

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL - Environnement de developpement local" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  Racine depot  : $repoRoot"
Write-Host "  Donnees       : $(if ($env:SENTINEL_DATA_DIR) { $env:SENTINEL_DATA_DIR } else { '%ProgramData%\Sentinel' })"
Write-Host "  Serveur API   : $serverApiUrl"
Write-Host "  Serveur gRPC  : $serverGrpcUrl"
Write-Host "  Console Admin : $adminUrl"
Write-Host ""

if (-not $NoBuild) {
    $projectsToBuild = @($serverProj, $adminProj)
    if ($WithAgent) { $projectsToBuild += $agentProj }
    if ($WithTray)  { $projectsToBuild += $trayProj }
    if ($SeedDemo)  { $projectsToBuild += $simProj }

    foreach ($proj in $projectsToBuild) {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($proj)
        Write-Host "  [BUILD] Compilation de $name..." -ForegroundColor DarkGray
        & dotnet build $proj --no-restore -nr:false -m:1 --nologo -v minimal
        if ($LASTEXITCODE -ne 0) {
            throw "Echec de compilation pour $name (code $LASTEXITCODE)."
        }
    }
    Write-Host ""
}

$children = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

function Start-SentinelProcess {
    param(
        [string]$Label,
        [string]$ProjectPath,
        [string[]]$ExtraArgs = @()
    )
    $argList = @("run", "--project", $ProjectPath, "--no-build") + $ExtraArgs
    Write-Host "  [START] $Label..." -ForegroundColor Green

    $quotedArgs = ($argList | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '

    $psi = [System.Diagnostics.ProcessStartInfo]::new("dotnet", $quotedArgs)
    $psi.WorkingDirectory = $repoRoot
    $psi.UseShellExecute = $false

    $proc = [System.Diagnostics.Process]::Start($psi)
    if ($null -eq $proc) {
        throw "Impossible de demarrer $Label."
    }
    $children.Add($proc)
    return $proc
}

function Stop-AllChildren {
    Write-Host ""
    Write-Host "  [STOP] Arret propre des processus SENTINEL..." -ForegroundColor Yellow
    foreach ($proc in $children) {
        try {
            if (-not $proc.HasExited) {
                & taskkill /PID $proc.Id /T /F 2>$null | Out-Null
                [void]$proc.WaitForExit(3000)
            }
        }
        catch {
            # Processus deja termine
        }
        finally {
            $proc.Dispose()
        }
    }
    $children.Clear()
    Write-Host "  [OK] Tous les processus enfants ont ete arretes." -ForegroundColor Green
}

function Wait-ForServerReady {
    param([string]$PingUrl, [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $PingUrl -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                return $true
            }
        }
        catch {
            Start-Sleep -Milliseconds 400
        }
    }
    return $false
}

try {
    $serverArgs = @(
        "--",
        "--Sentinel:ApiPort=$ServerApiPort",
        "--Sentinel:GrpcPort=$ServerGrpcPort"
    )
    if ($NoMtls) {
        $serverArgs += "--Sentinel:UseMtls=false"
    }
    $serverProc = Start-SentinelProcess -Label "Sentinel.Server ($serverApiUrl / gRPC $ServerGrpcPort)" -ProjectPath $serverProj -ExtraArgs $serverArgs

    Write-Host "  [WAIT] Attente de la disponibilite de Sentinel.Server ($serverApiUrl/api/system/ping)..." -ForegroundColor DarkGray
    $ready = Wait-ForServerReady -PingUrl "$serverApiUrl/api/system/ping" -TimeoutSeconds 35
    if (-not $ready) {
        Write-Warning "Sentinel.Server n'a pas repondu dans le delai imparti sur $serverApiUrl/api/system/ping."
    }
    else {
        Write-Host "  [OK] Sentinel.Server est pret." -ForegroundColor Green
    }

    $adminArgs = @(
        "--",
        "--Urls=$adminUrl",
        "--ServerUrl=$serverApiUrl"
    )
    $null = Start-SentinelProcess -Label "Sentinel.Admin ($adminUrl)" -ProjectPath $adminProj -ExtraArgs $adminArgs

    if ($WithAgent) {
        $agentArgs = @(
            "--",
            "--Agent:ServerGrpcUrl=$serverGrpcUrl",
            "--Agent:UseMtls=$(if ($NoMtls) { 'false' } else { 'true' })"
        )
        $null = Start-SentinelProcess -Label "Sentinel.Agent" -ProjectPath $agentProj -ExtraArgs $agentArgs
    }

    if ($WithTray) {
        $null = Start-SentinelProcess -Label "Sentinel.Tray" -ProjectPath $trayProj
    }

    if ($SeedDemo) {
        Write-Host ""
        Write-Host "  [SEED] Injection de scenarios realistes multi-postes via gRPC ($serverGrpcUrl)..." -ForegroundColor Cyan
        $seedArgs = @("run", "--project", $simProj, "--no-build", "--", "--push-grpc", $serverGrpcUrl, "--delay-ms", "$SeedDelayMs")
        if ($NoMtls) {
            $seedArgs += "--no-mtls"
        }
        & dotnet @seedArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Le rejeu de demonstration (-SeedDemo) a retourne le code $LASTEXITCODE."
        }
    }

    Write-Host ""
    Write-Host "==========================================================================" -ForegroundColor DarkGreen
    Write-Host "  SENTINEL est en cours d'execution !" -ForegroundColor Green
    Write-Host "  - Console d'administration : $adminUrl" -ForegroundColor White
    Write-Host "  - API Serveur (ping)       : $serverApiUrl/api/system/ping" -ForegroundColor White
    Write-Host "  Appuyez sur Ctrl+C pour tout arreter proprement." -ForegroundColor Yellow
    Write-Host "==========================================================================" -ForegroundColor DarkGreen

    while (-not $serverProc.HasExited) {
        Start-Sleep -Milliseconds 500
    }
    Write-Warning "Sentinel.Server s'est arrete (code $($serverProc.ExitCode))."
}
finally {
    Stop-AllChildren
}
