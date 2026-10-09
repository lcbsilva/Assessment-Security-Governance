param(
    [Parameter(Mandatory=$true)]
    [string]$Subscriptions,
    [Parameter(Mandatory=$true)]
    [string]$ExpectedTenantId,
    [switch]$Fresh
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Piloto de Segurança: menor superfície, menor paralelismo e retomada segura.
$env:ASSESSMENT_MAX_WORKERS = "1"
$env:ASSESSMENT_RESUME = if ($Fresh) { "0" } else { "1" }

& "$PSScriptRoot/run-assessment.ps1" -Subscriptions $Subscriptions -Profile security -ExpectedTenantId $ExpectedTenantId
if ($LASTEXITCODE -ne 0) { throw "O piloto não foi concluído." }

$pythonPath = Join-Path $root ".assessment-venv/Scripts/python.exe"
if (-not (Test-Path $pythonPath -PathType Leaf)) {
    throw "Ambiente isolado do assessment não encontrado. Execute novamente run-assessment.ps1."
}
& $pythonPath src/release_gate.py --data runtime/assessment.json --output runtime/release-gate.json
if ($LASTEXITCODE -ne 0) {
    $gate = Get-Content .\runtime\release-gate.json | ConvertFrom-Json
    $failed = $gate.checks | Where-Object { $_.status -ne "pass" }
    $failed | Select-Object name,status,detail | Format-List
    throw "O Release Gate bloqueou a saída. Consulte runtime/release-gate.json."
}

Write-Host "Piloto de Segurança concluído. Abra dist/assessment.html"
