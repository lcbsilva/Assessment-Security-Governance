param(
    [Parameter(Mandatory=$true)]
    [string]$Subscriptions
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3 não encontrado." }
if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw "Azure CLI não encontrado." }
az account show | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Execute 'az login' antes de continuar." }

New-Item -ItemType Directory -Force -Path "runtime/lab-validation", "dist/lab-validation" | Out-Null
foreach ($Profile in @("security", "governance", "full")) {
    $out = Join-Path "runtime/lab-validation" $Profile
    $dist = Join-Path "dist/lab-validation" $Profile
    New-Item -ItemType Directory -Force -Path $out, $dist | Out-Null
    python src/preflight.py --subscriptions $Subscriptions --profile $Profile --output (Join-Path $out "preflight.json")
    python src/run_assessment.py --subscriptions $Subscriptions --profile $Profile --output (Join-Path $out "assessment.json")
    python src/generate_report.py --data (Join-Path $out "assessment.json") --output (Join-Path $dist "assessment.html")
    python src/export_artifacts.py --data (Join-Path $out "assessment.json") --output-dir $dist
    python src/ai_payload.py --data (Join-Path $out "assessment.json") --output (Join-Path $out "ai-payload.json")
    python src/validate_artifacts.py --output-dir $dist --ai-payload (Join-Path $out "ai-payload.json") --output (Join-Path $out "artifact-validation.json")
    python src/artifact_manifest.py --output-dir $dist --assessment (Join-Path $out "assessment.json") --input (Join-Path $out "ai-payload.json") --output (Join-Path $out "artifact-manifest.json")
    python src/validate_manifest.py --manifest (Join-Path $out "artifact-manifest.json") --output-dir $dist --input-dir $out --output (Join-Path $out "manifest-validation.json")
    python src/validate_pilot.py --data (Join-Path $out "assessment.json") --manifest-validation (Join-Path $out "manifest-validation.json") --output (Join-Path $out "pilot-validation.json")
}

python src/summarize_lab_validation.py --root "runtime/lab-validation" --output "runtime/lab-validation/summary.json"
Write-Host "Validação de laboratório concluída. Consulte runtime/lab-validation/summary.json"
