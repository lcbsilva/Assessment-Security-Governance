param(
    [string]$Scenario = "full",
    [int]$Scale = 1
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
python src/build_demo_package.py --output-root runtime/demo-package --scenario $Scenario --scale $Scale
if ($LASTEXITCODE -ne 0) {
    throw "A geração do pacote demo falhou. Nenhum artefato será copiado."
}
New-Item -ItemType Directory -Force -Path "dist/demo-package" | Out-Null
Copy-Item "runtime/demo-package/dist/*" "dist/demo-package" -Force
Copy-Item "runtime/demo-package/runtime/demo-summary.json" "dist/demo-package" -Force
Write-Host "Pacote demonstrável gerado em dist/demo-package; dados sintéticos, sem acesso a tenant."
