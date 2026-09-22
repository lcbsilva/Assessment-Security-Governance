param(
    [string]$Preflight = "runtime/preflight.json",
    [string]$Assessment = "runtime/assessment.json",
    [string]$PilotValidation = "runtime/pilot-validation.json",
    [string]$Approval = "config/pilot-approval.json",
    [string]$Output = "runtime/pilot-evidence.json"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python src/pilot_evidence.py `
  --preflight $Preflight `
  --assessment $Assessment `
  --pilot-validation $PilotValidation `
  --approval $Approval `
  --output $Output
