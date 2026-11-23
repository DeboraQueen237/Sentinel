<#
.SYNOPSIS
    Script d'evaluation Atomic Red Team STRICTEMENT RESERVE A UNE VM ISOLEE (SENTINEL v2 Mission 10).
.DESCRIPTION
    NE JAMAIS EXECUTER SUR UNE MACHINE DE DEVELOPPEMENT OU DE PRODUCTION.
    Ce script verifie qu'il s'execute dans une machine virtuelle isolee (Hyper-V, VMware, VirtualBox, QEMU),
    exige le drapeau explicite -ConfirmIsolatedVm, execute uniquement une liste fermee de tests
    Atomic Red Team defensifs (Invoke-AtomicTest) mappes sur les regles SENTINEL, puis rappelle la
    restauration immediate du snapshot VM.
.PARAMETER ConfirmIsolatedVm
    Obligatoire pour confirmer que l'environnement est une VM isolee sans acces reseau production.
.PARAMETER DryRun
    Affiche les tests prevus sans rien executer (mode par defaut recommande pour revue).
#>
[CmdletBinding()]
param(
    [switch]$ConfirmIsolatedVm,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

# Liste fermee de techniques MITRE ATT&CK testables en VM isolee (aucun malware reel)
$PlannedAtomicTests = @(
    @{ Technique = "T1059.001"; TestNumber = 1; Name = "PowerShell Encoded Command (benign echo)" },
    @{ Technique = "T1547.001"; TestNumber = 1; Name = "Registry Run Key creation (cleanup inclus)" },
    @{ Technique = "T1053.005"; TestNumber = 1; Name = "Scheduled Task creation via schtasks" },
    @{ Technique = "T1218.005"; TestNumber = 1; Name = "Mshta local benign execution" },
    @{ Technique = "T1036.007"; TestNumber = 1; Name = "Double file extension masquerading (benign copy)" }
)

Write-Host "=== SENTINEL v2 - Evaluation reproductible Atomic Red Team (VM ISOLEE UNIQUEMENT) ==="

# 1. Verification environnement virtuel
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$model = if ($cs) { "$($cs.Manufacturer) $($cs.Model)" } else { "Unknown" }
$isVirtual = $model -match "(Virtual|VMware|VirtualBox|Hyper-V|KVM|QEMU|Bochs|Xen)"

Write-Host "Materiel detecte : $model (VM detectee = $isVirtual)"

if ($DryRun -or -not $ConfirmIsolatedVm) {
    Write-Host ""
    Write-Host "[MODE DRY-RUN / SECURITE] Aucun test execute."
    Write-Host "Tests prevus en VM isolee (Invoke-AtomicRedTeam) :"
    foreach ($t in $PlannedAtomicTests) {
        Write-Host "  - $($t.Technique) #$($t.TestNumber) : $($t.Name)"
    }
    Write-Host ""
    Write-Host "Procedure VM recommandee :"
    Write-Host "  1. Creer un snapshot propre : Checkpoint-VM -Name 'SentinelEvalVM' -SnapshotName 'PreEvalClean'"
    Write-Host "  2. Couper la carte reseau externe de la VM (switch interne uniquement)."
    Write-Host "  3. Installer Invoke-AtomicRedTeam (MIT) dans la VM."
    Write-Host "  4. Lancer : .\scripts\run-atomic-red-team-vm.ps1 -ConfirmIsolatedVm"
    Write-Host "  5. Exporter le rapport SENTINEL puis restaurer le snapshot :"
    Write-Host "     Restore-VMSnapshot -VMName 'SentinelEvalVM' -Name 'PreEvalClean' -Confirm:`$false"
    exit 0
}

if (-not $isVirtual) {
    Write-Error "BLOCAGE SECURITE : Cet hote ne semble pas etre une VM isolee ($model). Abandon immediat."
    exit 2
}

if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
    Write-Error "Module PowerShell 'invoke-atomicredteam' absent. Installez-le uniquement dans la VM isolee."
    exit 3
}

Import-Module invoke-atomicredteam
$results = @()

foreach ($t in $PlannedAtomicTests) {
    $start = Get-Date
    Write-Host "[EXEC] $($t.Technique) #$($t.TestNumber) - $($t.Name)"
    try {
        Invoke-AtomicTest $t.Technique -TestNumbers $t.TestNumber -TimeoutSeconds 30
        Invoke-AtomicTest $t.Technique -TestNumbers $t.TestNumber -Cleanup
        $results += [pscustomobject]@{
            Technique = $t.Technique
            TestNumber = $t.TestNumber
            ExecutedAtUtc = $start.ToUniversalTime().ToString("o")
            Status = "ExecutedAndCleaned"
        }
    } catch {
        $results += [pscustomobject]@{
            Technique = $t.Technique
            TestNumber = $t.TestNumber
            ExecutedAtUtc = $start.ToUniversalTime().ToString("o")
            Status = "Error: $($_.Exception.Message)"
        }
    }
}

$outFile = Join-Path $env:TEMP "sentinel-atomic-vm-results.json"
$results | ConvertTo-Json -Depth 4 | Set-Content -Path $outFile -Encoding UTF8
Write-Host "[OK] Execution VM terminee. Resultats : $outFile"
Write-Host "[RAPPEL] Restaurez maintenant le snapshot propre de la VM !"
