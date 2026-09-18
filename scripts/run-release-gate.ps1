param(
    [string]$Data = "mock/assessment.json",
    [string]$Output = "runtime/release-gate.json"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python src/release_gate.py --data $Data --output $Output
if ($LASTEXITCODE -ne 0) { throw "Release Gate bloqueou o fechamento da Beta. Consulte $Output." }
