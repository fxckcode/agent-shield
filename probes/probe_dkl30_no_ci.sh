#!/usr/bin/env bash
# Probe DKL-30: demuestra que NO existe el workflow de CI.
# Exit 1 (fail) = el problema existe (no hay CI) → el issue es válido.
set -euo pipefail
if [ -f ".github/workflows/ci.yml" ]; then
  echo "OK: .github/workflows/ci.yml existe"
  exit 0
fi
echo "PROBE FAIL: no existe .github/workflows/ci.yml en agent-guard-proxy"
exit 1
