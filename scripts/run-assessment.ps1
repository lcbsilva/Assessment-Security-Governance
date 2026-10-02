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
$runTimer = [System.Diagnostics.Stopwatch]::StartNew()
function Write-ProgressStage([string]$Message) {
    $minutes = [int][Math]::Floor($runTimer.Elapsed.TotalSeconds / 60)
    $seconds = [int]$runTimer.Elapsed.TotalSeconds % 60
    Write-Host ("[{0:D2}:{1:D2}] {2}" -f $minutes, $seconds, $Message)
}

$pythonCommand = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } elseif (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { $null }
if (-not $pythonCommand) {
    throw "Python 3 não encontrado. Instale Python 3.11 ou superior, ou habilite o launcher 'py'."
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI não encontrado. Instale o Azure CLI antes de executar."
}

az account show | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Nenhuma sessão Azure encontrada. Execute 'az login' e tente novamente."
}

if ($env:VIRTUAL_ENV) {
  & $pythonCommand -m pip install -r requirements.txt
} else {
  & $pythonCommand -m pip install --user -r requirements.txt
}
if ($LASTEXITCODE -ne 0) { throw "Falha ao instalar as dependências Python." }
New-Item -ItemType Directory -Force -Path $OutputRoot, "dist" | Out-Null
$json = Join-Path $OutputRoot "assessment.json"

Write-ProgressStage "Etapa 1/6 · Readiness Gate · verificando pré-requisitos"
& $pythonCommand src/preflight.py --subscriptions $Subscriptions --profile $Profile --output (Join-Path $OutputRoot "preflight.json")
if ($LASTEXITCODE -ne 0) {
    throw "Readiness Gate bloqueou a execução. Consulte $(Join-Path $OutputRoot 'preflight.json') e corrija somente os pré-requisitos essenciais. Nenhuma alteração foi feita no tenant."
}
Write-ProgressStage "Etapa 1/6 concluída · Readiness finalizado sem bloqueios"
Write-ProgressStage "Etapa 2/6 · coleta · checkpoints e progresso por módulo aparecem abaixo"
& $pythonCommand src/run_assessment.py --subscriptions $Subscriptions --profile $Profile --output $json
if ($LASTEXITCODE -ne 0) { throw "A coleta do assessment falhou; os artefatos não serão publicados." }
Write-ProgressStage "Etapa 2/6 concluída · assessment consolidado"
$reportJson = $json
if ($env:ASSESSMENT_ZERO_TRUST_REPORT) {
    Write-ProgressStage "Etapa 3/6 · importação local do Microsoft Zero Trust"
    $reportJson = Join-Path $OutputRoot "assessment-combined.json"
    & $pythonCommand src/import_zt_assessment.py --source $env:ASSESSMENT_ZERO_TRUST_REPORT --data $json --output $reportJson
    if ($LASTEXITCODE -ne 0) { throw "A importação local do relatório Microsoft Zero Trust falhou." }
    Write-ProgressStage "Etapa 3/6 concluída · resultados externos minimizados; score separado"
} else {
    Write-ProgressStage "Etapa 3/6 · sem relatório Microsoft configurado; etapa ignorada"
}
Write-ProgressStage "Etapa 4/6 · gerando HTML, PDF, PPTX e XLSX"
& $pythonCommand src/generate_report.py --data $reportJson --output "dist/assessment.html"
if ($LASTEXITCODE -ne 0) { throw "A geração do HTML falhou." }
& $pythonCommand src/export_artifacts.py --data $reportJson --output-dir dist
if ($LASTEXITCODE -ne 0) { throw "A exportação dos artefatos falhou." }
Write-ProgressStage "Etapa 4/6 concluída · artefatos gerados"
Write-ProgressStage "Etapa 5/6 · preparando payload de IA agregado e validando artefatos"
& $pythonCommand src/ai_payload.py --data $json --output (Join-Path $OutputRoot "ai-payload.json")
if ($LASTEXITCODE -ne 0) { throw "A geração do payload de IA falhou." }
& $pythonCommand src/validate_artifacts.py --output-dir dist --ai-payload (Join-Path $OutputRoot "ai-payload.json") --assessment $reportJson --output (Join-Path $OutputRoot "artifact-validation.json")
if ($LASTEXITCODE -ne 0) {
    throw "Validação dos artefatos falhou. Consulte $(Join-Path $OutputRoot 'artifact-validation.json')."
}
Write-ProgressStage "Etapa 5/6 concluída · validação de artefatos finalizada"
Write-ProgressStage "Etapa 6/6 · gerando manifesto e validando piloto"
& $pythonCommand src/artifact_manifest.py --output-dir dist --assessment $reportJson --input (Join-Path $OutputRoot "ai-payload.json") --output (Join-Path $OutputRoot "artifact-manifest.json")
if ($LASTEXITCODE -ne 0) { throw "A geração do manifesto falhou." }
& $pythonCommand src/validate_manifest.py --manifest (Join-Path $OutputRoot "artifact-manifest.json") --output-dir dist --input-dir $OutputRoot --output (Join-Path $OutputRoot "manifest-validation.json")
if ($LASTEXITCODE -ne 0) { throw "A validação de integridade falhou." }
& $pythonCommand src/validate_pilot.py --data $json --manifest-validation (Join-Path $OutputRoot "manifest-validation.json") --output (Join-Path $OutputRoot "pilot-validation.json")
if ($LASTEXITCODE -ne 0) { throw "A validação do piloto falhou." }

Write-ProgressStage "Etapa 6/6 concluída · execução completa"
$html = Join-Path $root "dist\assessment.html"
Write-Host "Assessment concluído. Artefatos gerados:"
Get-ChildItem (Join-Path $root "dist") -File | Sort-Object Name | ForEach-Object { Write-Host (" - " + $_.FullName) }
if ($env:OS -eq "Windows_NT" -and (Test-Path $html)) {
    Start-Process -FilePath $html
}

