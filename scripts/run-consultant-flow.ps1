param(
    [Parameter(Mandatory=$true)][string]$Subscriptions,
    [Parameter(Mandatory=$true)][string]$ExpectedTenantId,
    [ValidateSet("security","governance","full")][string]$Profile = "full",
    [string]$OutputRoot = "runtime"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$account = az account show --output json | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $account) { throw "Sessão Azure não encontrada. Execute az login." }
if ($account.tenantId -ne $ExpectedTenantId) {
    throw "Tenant bloqueado pelo guardrail. Atual: $($account.tenantId); esperado: $ExpectedTenantId."
}
$requested = @($Subscriptions.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($requested.Count -eq 0) { throw "Informe ao menos uma subscription." }
$visible = @(az account list --query "[?tenantId=='$ExpectedTenantId'].id" -o tsv)
foreach ($id in $requested) {
    if ($visible -notcontains $id) { throw "Subscription $id não pertence ao escopo visível do tenant esperado." }
}

Write-Host "1/4 Guardrail de tenant e subscriptions aprovado."
& "$PSScriptRoot/run-assessment.ps1" -Subscriptions ($requested -join ",") -OutputRoot $OutputRoot -Profile $Profile -ExpectedTenantId $ExpectedTenantId
if ($LASTEXITCODE -ne 0) { throw "Assessment bloqueado. Consulte os diagnósticos em $OutputRoot." }

Write-Host "2/4 Assessment e artefatos concluídos."
python src/delivery_gate.py --data (Join-Path $OutputRoot "assessment.json") --artifact-validation (Join-Path $OutputRoot "artifact-validation.json") --output (Join-Path $OutputRoot "delivery-gate.json")
if ($LASTEXITCODE -ne 0) { throw "Delivery Gate bloqueou a entrega. Consulte delivery-gate.json." }

Write-Host "3/4 Delivery Gate aprovado."
python src/release_gate.py --data (Join-Path $OutputRoot "assessment.json") --output (Join-Path $OutputRoot "release-gate.json")
if ($LASTEXITCODE -ne 0) { throw "Release Gate bloqueou a execução." }
Write-Host "4/4 Fluxo consultivo concluído. Revise dist/assessment.html e os artefatos antes da entrega ao cliente."
