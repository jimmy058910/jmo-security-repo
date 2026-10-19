#!/usr/bin/env bash
# Weekly metrics entry point. Results, status and recovery: docs/METRICS.md.
# Usage: bash scripts/dev/collect_metrics.sh [--date YYYY-MM-DD]
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PY="${JMO_METRICS_PYTHON:-}"
if [[ -z $PY ]]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 &&
      "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 12))' >/dev/null 2>&1; then
      PY="$candidate"
      break
    fi
  done
fi
if [[ -z $PY ]] || ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 12))' >/dev/null 2>&1; then
  printf '%s\n' '{"status":"failed","error":"Python 3.12+ is required"}' >&2
  exit 1
fi
exec "$PY" -B "$SCRIPT_DIR/collect_metrics.py" "$@"
