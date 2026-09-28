$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
foreach ($scenario in @("small", "medium", "limited", "full", "large")) {
    New-Item -ItemType Directory -Force -Path "runtime/tour/$scenario", "dist/tour/$scenario" | Out-Null
    python src/simulate_tenant.py --scenario $scenario --output "runtime/tour/$scenario/assessment.json"
    python src/generate_report.py --data "runtime/tour/$scenario/assessment.json" --output "dist/tour/$scenario/assessment.html"
}
Write-Host "Tour gerado em dist/tour; dados sintéticos, sem acesso a tenant."
