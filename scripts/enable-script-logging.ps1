<#
.SYNOPSIS
    Active ou desactive PowerShell Script Block Logging (Event ID 4104) pour SENTINEL v2 (Mission 7).
.DESCRIPTION
    Configure la cle de strategie locale HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging.
    Necessite une elevation Administrateur et le consentement explicite de l'utilisateur.
    SENTINEL ne stocke par defaut aucun contenu brut de script (uniquement hash, taille et indicateurs).
.PARAMETER Disable
    Desactive Script Block Logging et restaure l'etat initial.
.PARAMETER Force
    Accepte sans invite interactive (uniquement apres consentement documente).
#>
[CmdletBinding()]
param(
    [switch]$Disable,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Droits Administrateur requis pour modifier la strategie PowerShell Script Block Logging."
    exit 1
}

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if ($Disable) {
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord
        Write-Host "[OK] PowerShell Script Block Logging (Event ID 4104) desactive."
    } else {
        Write-Host "[INFO] Aucune strategie Script Block Logging active."
    }
    exit 0
}

if (-not $Force) {
    Write-Host "=== SENTINEL v2 : Activation PowerShell Script Block Logging (Event ID 4104) ==="
    Write-Host "Cette option active le journal Windows 'Microsoft-Windows-PowerShell/Operational'."
    Write-Host "SENTINEL inspecte les blocs de script en memoire et ne conserve par defaut que"
    Write-Host "le hash SHA-256, la longueur et les indicateurs d'obfuscation/contournement."
    $answer = Read-Host "Confirmez-vous l'activation ? (O/N)"
    if ($answer -notmatch '^(O|OUI|Y|YES)$') {
        Write-Host "[ANNULE] Aucune modification appliquee."
        exit 0
    }
}

New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Write-Host "[OK] PowerShell Script Block Logging (Event ID 4104) active avec succes."
Write-Host "Pour annuler : .\scripts\enable-script-logging.ps1 -Disable"
