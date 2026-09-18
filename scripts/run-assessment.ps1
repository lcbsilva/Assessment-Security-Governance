param(
    [Parameter(Mandatory=$true)]
    [string]$Subscriptions,
    [string]$OutputRoot = "runtime",
    [ValidateSet("security", "governance", "full")]
    [string]$Profile = "full"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python 3 não encontrado. Instale Python 3.11 ou superior."
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI não encontrado. Instale o Azure CLI antes de executar."
}

az account show | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Nenhuma sessão Azure encontrada. Execute 'az login' e tente novamente."
}

if ($env:VIRTUAL_ENV) {
    python -m pip install -r requirements.txt
} else {
    python -m pip install --user -r requirements.txt
}
New-Item -ItemType Directory -Force -Path $OutputRoot, "dist" | Out-Null
$json = Join-Path $OutputRoot "assessment.json"

python src/preflight.py --subscriptions $Subscriptions --profile $Profile --output (Join-Path $OutputRoot "preflight.json")
if ($LASTEXITCODE -ne 0) {
    throw "Readiness Gate bloqueou a execução. Consulte $(Join-Path $OutputRoot 'preflight.json') e corrija somente os pré-requisitos essenciais. Nenhuma alteração foi feita no tenant."
}
python src/run_assessment.py --subscriptions $Subscriptions --profile $Profile --output $json
python src/generate_report.py --data $json --output "dist/assessment.html"
python src/export_artifacts.py --data $json --output-dir dist
python src/validate_pilot.py --data $json --output (Join-Path $OutputRoot "pilot-validation.json")
python src/ai_payload.py --data $json --output (Join-Path $OutputRoot "ai-payload.json")
python src/validate_artifacts.py --output-dir dist --ai-payload (Join-Path $OutputRoot "ai-payload.json") --output (Join-Path $OutputRoot "artifact-validation.json")
if ($LASTEXITCODE -ne 0) {
    throw "Validação dos artefatos falhou. Consulte $(Join-Path $OutputRoot 'artifact-validation.json')."
}

Write-Host "Assessment concluído. Abra dist/assessment.html"
