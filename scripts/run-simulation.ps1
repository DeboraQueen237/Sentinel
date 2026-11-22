<#
.SYNOPSIS
    Execute le benchmark scientifique A vs B vs C de SENTINEL et exporte les resultats (Markdown + JSON).
.DESCRIPTION
    Compile (si necessaire) tests/Sentinel.Simulation puis lance l'evaluation complete sur les 8 scenarios
    d'attaque MITRE ATT&CK et le corpus benin (219 evenements). Exporte le rapport scientifique dans
    docs/evaluation-results.md et le jeu ScenarioMetricDto[] dans docs/evaluation-results.json.
.EXAMPLE
    .\scripts\run-simulation.ps1
.EXAMPLE
    .\scripts\run-simulation.ps1 -Ollama -OllamaModel "qwen2.5:7b" -PushEvalUrl "http://127.0.0.1:5180" -Token "<jwt>"
#>
[CmdletBinding()]
param(
    [string]$OutputMd = "docs/evaluation-results.md",
    [string]$OutputJson = "docs/evaluation-results.json",
    [switch]$Ollama,
    [string]$OllamaUrl = "http://localhost:11434",
    [string]$OllamaModel = "qwen2.5:7b",
    [string]$PushEvalUrl = "",
    [string]$Token = "",
    [switch]$NoBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$simProj  = Join-Path $repoRoot "tests\Sentinel.Simulation\Sentinel.Simulation.csproj"

$resolvedMd   = if ([System.IO.Path]::IsPathRooted($OutputMd))   { $OutputMd }   else { Join-Path $repoRoot $OutputMd }
$resolvedJson = if ([System.IO.Path]::IsPathRooted($OutputJson)) { $OutputJson } else { Join-Path $repoRoot $OutputJson }

if (-not $NoBuild) {
    Write-Host "[BUILD] Compilation de Sentinel.Simulation..." -ForegroundColor Cyan
    & dotnet build $simProj --no-restore -nr:false -m:1 --nologo -v minimal
    if ($LASTEXITCODE -ne 0) {
        throw "Echec de compilation de Sentinel.Simulation (code $LASTEXITCODE)."
    }
}

$simArgs = @(
    "run", "--project", $simProj, "--no-build", "--",
    "--output-md", $resolvedMd,
    "--output-json", $resolvedJson
)

if ($Ollama) {
    $simArgs += @("--ollama", "--ollama-url", $OllamaUrl, "--ollama-model", $OllamaModel)
}

if (-not [string]::IsNullOrWhiteSpace($PushEvalUrl)) {
    $simArgs += @("--push-eval", $PushEvalUrl)
    if (-not [string]::IsNullOrWhiteSpace($Token)) {
        $simArgs += @("--token", $Token)
    }
}

Write-Host "[RUN] Execution du benchmark scientifique SENTINEL (A vs B vs C)..." -ForegroundColor Green
& dotnet @simArgs
exit $LASTEXITCODE
