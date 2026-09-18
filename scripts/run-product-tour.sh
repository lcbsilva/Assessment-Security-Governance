#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
for scenario in small limited full; do
  mkdir -p "runtime/tour/$scenario" "dist/tour/$scenario"
  python3 src/simulate_tenant.py --scenario "$scenario" --output "runtime/tour/$scenario/assessment.json"
  python3 src/generate_report.py --data "runtime/tour/$scenario/assessment.json" --output "dist/tour/$scenario/assessment.html"
done
echo "Tour gerado em dist/tour; dados sintéticos, sem acesso a tenant."
