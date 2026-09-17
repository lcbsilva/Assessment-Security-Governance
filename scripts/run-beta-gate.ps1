param(
    [string]$Data = "mock/assessment.json",
    [string]$Output = "runtime/beta-gate.json"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python src/beta_gate.py --data $Data --output $Output
if ($LASTEXITCODE -ne 0) {
    throw "Beta Gate bloqueou a distribuição. Consulte $Output."
}

