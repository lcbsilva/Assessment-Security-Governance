#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Uso: ./scripts/run-lab-validation.sh <subscription-id-1,subscription-id-2>"
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v python3 >/dev/null || { echo "Python 3 não encontrado."; exit 1; }
command -v az >/dev/null || { echo "Azure CLI não encontrado."; exit 1; }
az account show >/dev/null || { echo "Execute 'az login' antes de continuar."; exit 1; }

SUBSCRIPTIONS="$1"
mkdir -p runtime/lab-validation dist/lab-validation

for PROFILE in security governance full; do
  OUT="runtime/lab-validation/$PROFILE"
  DIST="dist/lab-validation/$PROFILE"
  mkdir -p "$OUT" "$DIST"
  python3 src/preflight.py --subscriptions "$SUBSCRIPTIONS" --profile "$PROFILE" --output "$OUT/preflight.json"
  python3 src/run_assessment.py --subscriptions "$SUBSCRIPTIONS" --profile "$PROFILE" --output "$OUT/assessment.json"
  python3 src/generate_report.py --data "$OUT/assessment.json" --output "$DIST/assessment.html"
  python3 src/export_artifacts.py --data "$OUT/assessment.json" --output-dir "$DIST"
  python3 src/ai_payload.py --data "$OUT/assessment.json" --output "$OUT/ai-payload.json"
  python3 src/validate_artifacts.py --output-dir "$DIST" --ai-payload "$OUT/ai-payload.json" --output "$OUT/artifact-validation.json"
  python3 src/artifact_manifest.py --output-dir "$DIST" --assessment "$OUT/assessment.json" --input "$OUT/ai-payload.json" --output "$OUT/artifact-manifest.json"
  python3 src/validate_manifest.py --manifest "$OUT/artifact-manifest.json" --output-dir "$DIST" --input-dir "$OUT" --output "$OUT/manifest-validation.json"
  python3 src/validate_pilot.py --data "$OUT/assessment.json" --manifest-validation "$OUT/manifest-validation.json" --output "$OUT/pilot-validation.json"
done

python3 src/summarize_lab_validation.py --root runtime/lab-validation --output runtime/lab-validation/summary.json
echo "Validação de laboratório concluída. Consulte runtime/lab-validation/summary.json"
