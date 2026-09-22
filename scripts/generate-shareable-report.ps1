param(
    [string]$InputPath = "runtime/assessment.json",
    [string]$Output = "dist-shareable"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
New-Item -ItemType Directory -Force -Path "runtime", $Output | Out-Null
$data = "runtime/assessment-shareable.json"
python src/pseudonymize.py --input $InputPath --output $data
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar a cópia pseudonimizada." }
python src/generate_report.py --data $data --output (Join-Path $Output "assessment.html")
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar o HTML compartilhável." }
python src/export_artifacts.py --data $data --output-dir $Output
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar os artefatos compartilháveis." }
python src/artifact_manifest.py --output-dir $Output --assessment $data --output "runtime/artifact-manifest-shareable.json"
if ($LASTEXITCODE -ne 0) { throw "Falha ao gerar o manifesto compartilhável." }
python src/validate_manifest.py --manifest "runtime/artifact-manifest-shareable.json" --output-dir $Output --input-dir "runtime" --output "runtime/manifest-validation-shareable.json"
if ($LASTEXITCODE -ne 0) { throw "A validação do pacote compartilhável falhou." }
Write-Host "Relatório pseudonimizado: $root/$Output/assessment.html"
