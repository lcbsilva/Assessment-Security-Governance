#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Uso: ./scripts/run-assessment.sh <subscription-id-1,subscription-id-2> [security|governance|full]"
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v python3 >/dev/null || { echo "Python 3 não encontrado."; exit 1; }
command -v az >/dev/null || { echo "Azure CLI não encontrado."; exit 1; }
az account show >/dev/null || { echo "Execute 'az login' antes de continuar."; exit 1; }

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  python3 -m pip install -r requirements.txt
else
  python3 -m pip install --user -r requirements.txt
fi
mkdir -p runtime dist
JSON="runtime/assessment.json"

PROFILE="${2:-full}"
python3 src/preflight.py --subscriptions "$1" --profile "$PROFILE" --output runtime/preflight.json
python3 src/run_assessment.py --subscriptions "$1" --profile "$PROFILE" --output "$JSON"
python3 src/generate_report.py --data "$JSON" --output dist/assessment.html
python3 src/export_artifacts.py --data "$JSON" --output-dir dist
python3 src/validate_pilot.py --data "$JSON" --output runtime/pilot-validation.json
python3 src/ai_payload.py --data "$JSON" --output runtime/ai-payload.json

echo "Assessment concluído. Abra dist/assessment.html"
