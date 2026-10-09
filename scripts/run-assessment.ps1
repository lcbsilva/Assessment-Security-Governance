param(
    [Parameter(Mandatory=$true)]
    [string]$Subscriptions,
    [Parameter(Mandatory=$true)]
    [string]$ExpectedTenantId,
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

$azCommand = Get-Command az -ErrorAction SilentlyContinue
if (-not $azCommand) {
    throw "Azure CLI não encontrado. Instale o Azure CLI antes de executar."
}

$accountJson = az account show --output json
if ($LASTEXITCODE -ne 0 -or -not $accountJson) {
    throw "Nenhuma sessão Azure encontrada. Execute 'az login --tenant $ExpectedTenantId' e tente novamente."
}
try {
    $account = $accountJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Não foi possível identificar com segurança o tenant da sessão Azure."
}
if ([string]::IsNullOrWhiteSpace([string]$account.tenantId)) {
    throw "A sessão Azure não retornou um tenant ID."
}
if ([string]$account.tenantId -ne $ExpectedTenantId) {
    throw "Tenant bloqueado pelo guardrail. A sessão atual não corresponde ao tenant esperado."
}

$requestedSubscriptions = @(
    $Subscriptions.Split(",") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)
if ($requestedSubscriptions.Count -eq 0) {
    throw "Informe ao menos uma subscription aprovada."
}
$accountsJson = az account list --output json
if ($LASTEXITCODE -ne 0 -or -not $accountsJson) {
    throw "Não foi possível validar as subscriptions visíveis no tenant esperado."
}
try {
    $visibleSubscriptions = @(
        $accountsJson |
            ConvertFrom-Json -ErrorAction Stop |
            Where-Object { [string]$_.tenantId -eq $ExpectedTenantId } |
            ForEach-Object { [string]$_.id }
    )
} catch {
    throw "A lista de subscriptions retornada pelo Azure CLI não pôde ser validada."
}
$notVisible = @(
    $requestedSubscriptions |
        Where-Object { $visibleSubscriptions -notcontains $_ }
)
if ($notVisible.Count -gt 0) {
    throw "Escopo bloqueado. Uma ou mais subscriptions não pertencem ao tenant esperado ou não estão visíveis: $($notVisible -join ', ')."
}
Write-Host "Tenant esperado e escopo de subscriptions conferidos."

$systemPython = Get-Command python -CommandType Application -ErrorAction SilentlyContinue
if (-not $systemPython) {
    throw "Python 3 não encontrado. Instale Python 3.11 ou superior."
}
$pythonVersionText = & $systemPython.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) {
    throw "Não foi possível consultar a versão do Python."
}
try {
    $pythonVersion = [version]$pythonVersionText.Trim()
} catch {
    throw "A versão do Python não pôde ser interpretada."
}
if ($pythonVersion -lt [version]"3.11") {
    throw "Python 3.11 ou superior é necessário; versão encontrada: $pythonVersion."
}

$venvRoot = Join-Path $root ".assessment-venv"
$pythonPath = Join-Path $venvRoot "Scripts/python.exe"
if (-not (Test-Path $pythonPath -PathType Leaf)) {
    Write-ProgressStage "Criando ambiente Python isolado do assessment"
    & $systemPython.Source -m venv $venvRoot
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $pythonPath -PathType Leaf)) {
        throw "Não foi possível criar o ambiente Python isolado."
    }
}
Write-ProgressStage "Instalando dependências no ambiente isolado do projeto"
& $pythonPath -m pip install --disable-pip-version-check -r (Join-Path $root "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Falha ao instalar dependências Python no ambiente isolado."
}

New-Item -ItemType Directory -Force -Path $OutputRoot, "dist" | Out-Null
$json = Join-Path $OutputRoot "assessment.json"

Write-ProgressStage "Etapa 1/6 · Readiness Gate · verificando pré-requisitos"
& $pythonPath src/preflight.py --subscriptions $Subscriptions --profile $Profile --output (Join-Path $OutputRoot "preflight.json")
if ($LASTEXITCODE -ne 0) {
    throw "Readiness Gate bloqueou a execução. Consulte $(Join-Path $OutputRoot 'preflight.json') e corrija somente os pré-requisitos essenciais. Nenhuma alteração foi feita no tenant."
}
Write-ProgressStage "Etapa 1/6 concluída · Readiness finalizado sem bloqueios"
Write-ProgressStage "Etapa 2/6 · coleta · checkpoints e progresso por módulo aparecem abaixo"
& $pythonPath src/run_assessment.py --subscriptions $Subscriptions --profile $Profile --output $json
if ($LASTEXITCODE -ne 0) {
    throw "A coleta do assessment falhou; os artefatos não serão publicados."
}
Write-ProgressStage "Etapa 2/6 concluída · assessment consolidado"
$reportJson = $json
if ($env:ASSESSMENT_ZERO_TRUST_REPORT) {
    Write-ProgressStage "Etapa 3/6 · importação local do Microsoft Zero Trust"
    $reportJson = Join-Path $OutputRoot "assessment-combined.json"
    & $pythonPath src/import_zt_assessment.py --source $env:ASSESSMENT_ZERO_TRUST_REPORT --data $json --output $reportJson
    if ($LASTEXITCODE -ne 0) {
        throw "A importação local do relatório Microsoft Zero Trust falhou."
    }
    Write-ProgressStage "Etapa 3/6 concluída · resultados externos minimizados; score separado"
} else {
    Write-ProgressStage "Etapa 3/6 · sem relatório Microsoft configurado; etapa ignorada"
}
Write-ProgressStage "Etapa 4/6 · gerando HTML, PDF, PPTX e XLSX"
& $pythonPath src/generate_report.py --data $reportJson --output "dist/assessment.html"
if ($LASTEXITCODE -ne 0) {
    throw "A geração do HTML falhou."
}
& $pythonPath src/export_artifacts.py --data $reportJson --output-dir dist
if ($LASTEXITCODE -ne 0) {
    throw "A exportação dos artefatos falhou."
}
Write-ProgressStage "Etapa 4/6 concluída · artefatos gerados"
Write-ProgressStage "Etapa 5/6 · preparando payload de IA agregado e validando artefatos"
& $pythonPath src/ai_payload.py --data $json --output (Join-Path $OutputRoot "ai-payload.json")
if ($LASTEXITCODE -ne 0) {
    throw "A geração do payload de IA falhou."
}
& $pythonPath src/validate_artifacts.py --output-dir dist --ai-payload (Join-Path $OutputRoot "ai-payload.json") --assessment $reportJson --output (Join-Path $OutputRoot "artifact-validation.json")
if ($LASTEXITCODE -ne 0) {
    throw "Validação dos artefatos falhou. Consulte $(Join-Path $OutputRoot 'artifact-validation.json')."
}
Write-ProgressStage "Etapa 5/6 concluída · validação de artefatos finalizada"
Write-ProgressStage "Etapa 6/6 · gerando manifesto e validando piloto"
& $pythonPath src/artifact_manifest.py --output-dir dist --assessment $reportJson --input (Join-Path $OutputRoot "ai-payload.json") --output (Join-Path $OutputRoot "artifact-manifest.json")
if ($LASTEXITCODE -ne 0) {
    throw "A geração do manifesto falhou."
}
& $pythonPath src/validate_manifest.py --manifest (Join-Path $OutputRoot "artifact-manifest.json") --output-dir dist --input-dir $OutputRoot --output (Join-Path $OutputRoot "manifest-validation.json")
if ($LASTEXITCODE -ne 0) {
    throw "A validação de integridade falhou."
}
& $pythonPath src/validate_pilot.py --data $json --manifest-validation (Join-Path $OutputRoot "manifest-validation.json") --output (Join-Path $OutputRoot "pilot-validation.json")
if ($LASTEXITCODE -ne 0) {
    throw "A validação do piloto falhou."
}

Write-ProgressStage "Etapa 6/6 concluída · execução completa"
Write-Host "Assessment concluído. Abra $(Join-Path $root 'dist/assessment.html')"
Write-Host "Arquivos técnicos e evidências detalhadas ficam em: $(Join-Path $root $OutputRoot)"
