#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -lt 1 ]]; then
  echo "Uso: ./scripts/run-assessment.sh <subscription-id-1,subscription-id-2> [security|governance|full]"
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RUN_START_EPOCH="$(date +%s)"
progress() {
  local current_epoch elapsed_seconds
  current_epoch="$(date +%s)"
  elapsed_seconds=$((current_epoch - RUN_START_EPOCH))
  printf '[%02d:%02d] %s\n' "$((elapsed_seconds / 60))" "$((elapsed_seconds % 60))" "$1"
}

command -v python3 >/dev/null || { echo "Python 3 não encontrado."; exit 1; }
command -v az >/dev/null || { echo "Azure CLI não encontrado."; exit 1; }
az account show >/dev/null || { echo "Execute 'az login' antes de continuar."; exit 1; }

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  python3 -m pip install -r requirements.txt || { echo "Falha ao instalar dependências Python." >&2; exit 1; }
else
  python3 -m pip install --user -r requirements.txt || { echo "Falha ao instalar dependências Python." >&2; exit 1; }
fi
mkdir -p runtime dist
JSON="runtime/assessment.json"

PROFILE="${2:-full}"
progress "Etapa 1/6 · Readiness Gate · verificando pré-requisitos"
if ! python3 src/preflight.py --subscriptions "$1" --profile "$PROFILE" --output runtime/preflight.json; then
  echo "Readiness Gate bloqueou a execução. Consulte runtime/preflight.json; nenhuma alteração foi feita no tenant." >&2
  exit 1
fi
progress "Etapa 1/6 concluída · Readiness finalizado sem bloqueios"
progress "Etapa 2/6 · coleta · checkpoints e progresso por módulo aparecem abaixo"
python3 src/run_assessment.py --subscriptions "$1" --profile "$PROFILE" --output "$JSON" || { echo "A coleta falhou; artefatos não publicados." >&2; exit 1; }
progress "Etapa 2/6 concluída · assessment consolidado"
# A importação opcional é local; não autentica nem faz chamadas ao tenant.
REPORT_JSON="$JSON"
if [[ -n "${ASSESSMENT_ZERO_TRUST_REPORT:-}" ]]; then
  progress "Etapa 3/6 · importação local do Microsoft Zero Trust"
  REPORT_JSON="runtime/assessment-combined.json"
  python3 src/import_zt_assessment.py --source "$ASSESSMENT_ZERO_TRUST_REPORT" --data "$JSON" --output "$REPORT_JSON" || exit 1
  progress "Etapa 3/6 concluída · resultados externos minimizados; score separado"
else
  progress "Etapa 3/6 · sem relatório Microsoft configurado; etapa ignorada"
fi
progress "Etapa 4/6 · gerando HTML, PDF, PPTX e XLSX"
python3 src/generate_report.py --data "$REPORT_JSON" --output dist/assessment.html || exit 1
python3 src/export_artifacts.py --data "$REPORT_JSON" --output-dir dist || exit 1
progress "Etapa 4/6 concluída · artefatos gerados"
progress "Etapa 5/6 · preparando payload de IA agregado e validando artefatos"
python3 src/ai_payload.py --data "$JSON" --output runtime/ai-payload.json || exit 1
python3 src/validate_artifacts.py --output-dir dist --ai-payload runtime/ai-payload.json --output runtime/artifact-validation.json
progress "Etapa 5/6 concluída · validação de artefatos finalizada"
progress "Etapa 6/6 · gerando manifesto e validando piloto"
python3 src/artifact_manifest.py --output-dir dist --assessment "$REPORT_JSON" --input runtime/ai-payload.json --output runtime/artifact-manifest.json || exit 1
python3 src/validate_manifest.py --manifest runtime/artifact-manifest.json --output-dir dist --input-dir runtime --output runtime/manifest-validation.json || exit 1
python3 src/validate_pilot.py --data "$JSON" --manifest-validation runtime/manifest-validation.json --output runtime/pilot-validation.json || exit 1

progress "Etapa 6/6 concluída · execução completa"
echo "Assessment concluído. Abra dist/assessment.html"
