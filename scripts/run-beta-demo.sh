#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
python3 src/build_demo_package.py --output-root runtime/demo-package --scenario full
mkdir -p dist/demo-package
cp -R runtime/demo-package/dist/. dist/demo-package/
cp runtime/demo-package/runtime/demo-summary.json dist/demo-package/
echo "Pacote demonstrável gerado em dist/demo-package; dados sintéticos, sem acesso a tenant."
