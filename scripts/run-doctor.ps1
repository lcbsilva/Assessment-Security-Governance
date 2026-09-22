param(
    [Parameter(Mandatory=$true)][string]$Subscriptions,
    [ValidateSet("security", "governance", "full")][string]$Profile = "full"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python src/doctor.py --subscriptions $Subscriptions --profile $Profile --output runtime/doctor.json
if ($LASTEXITCODE -ne 0) { throw "Diagnóstico bloqueado. Consulte runtime/doctor.json." }
Write-Host "Diagnóstico concluído. Consulte runtime/doctor.json antes da coleta."
