#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
INPUT="${1:-runtime/assessment.json}"
DATA="runtime/assessment-shareable.json"
OUTPUT="dist-shareable"
mkdir -p runtime "$OUTPUT"
python3 src/pseudonymize.py --input "$INPUT" --output "$DATA" || exit 1
python3 src/generate_report.py --data "$DATA" --output "$OUTPUT/assessment.html" || exit 1
python3 src/export_artifacts.py --data "$DATA" --output-dir "$OUTPUT" || exit 1
python3 src/artifact_manifest.py --output-dir "$OUTPUT" --assessment "$DATA" --output runtime/artifact-manifest-shareable.json || exit 1
python3 src/validate_manifest.py --manifest runtime/artifact-manifest-shareable.json --output-dir "$OUTPUT" --input-dir runtime --output runtime/manifest-validation-shareable.json || exit 1
echo "Relatório pseudonimizado: $ROOT/$OUTPUT/assessment.html"
