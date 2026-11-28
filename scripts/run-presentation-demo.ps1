<#
.SYNOPSIS
    Script de demonstration interactive pour la soutenance / presentation de SENTINEL v2.2.0.
.DESCRIPTION
    Permet de lancer une pile propre de demonstration ou de piloter un serveur deja actif
    et d'executer pas a pas devant le jury :
      1. Verification de sante du serveur + auto-selection Qwen IA locale (Ollama)
      2. Scan Systeme General en direct
      3. Audit de Posture & Integrite Cryptographique SHA-256
      4. Injection des 3 scenarios d'attaque multi-etapes (Phishing->C2, Ransomware Canary, BadUSB)
      5. Ouverture automatique de l'Arbre Causal et du Centre de Notifications
.EXAMPLE
    .\scripts\run-presentation-demo.ps1 -LaunchIsolatedStack
#>
[CmdletBinding()]
param(
    [string]$ServerUrl = "http://127.0.0.1:5180",
    [string]$AdminUrl = "http://127.0.0.1:5200",
    [switch]$LaunchIsolatedStack
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ($LaunchIsolatedStack) {
    Write-Host "Demarrage d'une pile de demonstration propre sur ports 5190 (API) et 5210 (Console Web)..." -ForegroundColor Cyan
    $demoData = Join-Path $repoRoot ".sentinel-presentation-demo"
    if (Test-Path $demoData) { Remove-Item -Recurse -Force $demoData }
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run-dev.ps1") `
        -DataDir $demoData -NoBuild -NoMtls -ServerApiPort 5190 -ServerGrpcPort 5191 -AdminPort 5210
    exit 0
}

Write-Host "==========================================================================" -ForegroundColor DarkCyan
Write-Host "  SENTINEL v2.2.0 - Verification pre-soutenance" -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor DarkCyan

try {
    $ping = Invoke-RestMethod -Uri "$ServerUrl/api/system/ping" -TimeoutSec 4
    Write-Host "  [OK] Serveur SENTINEL joignable sur $ServerUrl ($ping)" -ForegroundColor Green
} catch {
    Write-Warning "Serveur non joignable sur $ServerUrl. Lancez .\scripts\upgrade-installed-services.ps1 ou .\scripts\run-dev.ps1 -NoBuild."
    exit 1
}

try {
    $tags = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 3
    $names = ($tags.models | ForEach-Object { $_.name }) -join ", "
    Write-Host "  [OK] Ollama local actif — Modeles detectes : $names" -ForegroundColor Green
} catch {
    Write-Host "  [INFO] Ollama hors ligne — SENTINEL fonctionnera en mode deterministe + Playbooks SOC." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Ouvrez $AdminUrl/scan-audit pour piloter en 1 clic devant le jury :" -ForegroundColor White
Write-Host "    1) Scenario 'Chaine Phishing -> PowerShell -> C2' -> cliquez 'Voir l'Arbre Causal'"
Write-Host "    2) Scenario 'Rancongiciel & Fichier Canari'       -> observez la cloche temps reel + action reversible"
Write-Host "    3) Bouton 'Lancer un Scan Systeme General'        -> inspection live processus/reseau/persistance"
Write-Host "    4) Bouton 'Executer l'Audit de Securite'          -> score /100 + verification SHA-256 + synthese IA"
Write-Host "==========================================================================" -ForegroundColor DarkCyan
Start-Process "$AdminUrl/scan-audit"
