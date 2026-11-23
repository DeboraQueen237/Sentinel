<#
.SYNOPSIS
    Signe un binaire ou un package MSI SENTINEL via Authenticode (signtool.exe).
.DESCRIPTION
    Supporte :
    - Certificat PFX fourni par parametre ou variable d'environnement ($env:SENTINEL_SIGN_PFX / $env:SENTINEL_SIGN_PASSWORD)
    - Empreinte de certificat dans le magasin Windows (-CertThumbprint)
    - Mode -SelfSignedDev creant un certificat auto-signe STRICTEMENT reserve au developpement / tests VM
      (JAMAIS pour une distribution en production).
.EXAMPLE
    .\build\sign.ps1 -Path dist\SentinelSetup-2.0.0.msi -PfxPath C:\certs\codesign.pfx -PfxPassword $env:SIGN_PWD
.EXAMPLE
    .\build\sign.ps1 -Path dist\SentinelSetup-2.0.0.msi -SelfSignedDev
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,
    [string]$PfxPath = $env:SENTINEL_SIGN_PFX,
    [string]$PfxPassword = $env:SENTINEL_SIGN_PASSWORD,
    [string]$CertThumbprint = $env:SENTINEL_SIGN_THUMBPRINT,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SelfSignedDev
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $kitRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin",
        "${env:ProgramFiles}\Windows Kits\10\bin"
    )
    foreach ($root in $kitRoots) {
        if (Test-Path $root) {
            $found = Get-ChildItem -Path $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -match '\\x64\\' } |
                     Sort-Object FullName -Descending |
                     Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    return $null
}

$signtool = Find-SignTool
if (-not $signtool) {
    throw "signtool.exe introuvable. Installez le Windows 10/11 SDK ou ajoutez signtool.exe au PATH."
}

$resolvedFiles = @()
foreach ($p in $Path) {
    if (-not (Test-Path $p)) { throw "Fichier a signer introuvable : $p" }
    $resolvedFiles += (Resolve-Path $p).Path
}

if ($SelfSignedDev) {
    Write-Warning "========================================================================"
    Write-Warning "  MODE -SelfSignedDev : CERTIFICAT AUTO-SIGNE RESERVE AU DEV / VM !"
    Write-Warning "  Ne distribuez JAMAIS un MSI auto-signe en production."
    Write-Warning "========================================================================"

    $existing = Get-ChildItem Cert:\CurrentUser\My |
                Where-Object { $_.Subject -eq "CN=SENTINEL Dev Code Signing (NOT FOR PRODUCTION)" -and $_.NotAfter -gt (Get-Date).AddDays(7) } |
                Select-Object -First 1

    if (-not $existing) {
        $existing = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=SENTINEL Dev Code Signing (NOT FOR PRODUCTION)" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears(1)
        Write-Host "  [CERT] Certificat auto-signe dev cree : $($existing.Thumbprint)" -ForegroundColor Yellow
    }
    $CertThumbprint = $existing.Thumbprint
    $TimestampUrl = ""
}

foreach ($file in $resolvedFiles) {
    $signArgs = @("sign", "/fd", "SHA256", "/v")

    if (-not [string]::IsNullOrWhiteSpace($PfxPath)) {
        if (-not (Test-Path $PfxPath)) { throw "Certificat PFX introuvable : $PfxPath" }
        $signArgs += @("/f", $PfxPath)
        if (-not [string]::IsNullOrWhiteSpace($PfxPassword)) {
            $signArgs += @("/p", $PfxPassword)
        }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertThumbprint)) {
        $signArgs += @("/sha1", $CertThumbprint)
    }
    else {
        throw "Specifiez -PfxPath, -CertThumbprint ou -SelfSignedDev."
    }

    if (-not [string]::IsNullOrWhiteSpace($TimestampUrl)) {
        $signArgs += @("/tr", $TimestampUrl, "/td", "SHA256")
    }

    $signArgs += $file

    Write-Host "  [SIGN] Signature Authenticode : $file" -ForegroundColor Cyan
    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Echec de signature Authenticode pour $file (code $LASTEXITCODE)."
    }
}

Write-Host "  [OK] Signature Authenticode terminee pour $($resolvedFiles.Count) fichier(s)." -ForegroundColor Green
