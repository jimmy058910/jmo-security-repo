#!/usr/bin/env bash
# ci-local.sh - Terminal-first local verification pipeline
# Runs: format checks, lint, unit tests, snapshot tests, and minimal security scans

set -Eeuo pipefail
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[verify]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
fail() { echo -e "${RED}[fail]${NC} $*"; exit 2; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

# Ensure local package imports resolve when running under system Python
if [ -z "${PYTHONPATH:-}" ]; then
  export PYTHONPATH="$PROJECT_ROOT"
else
  export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
fi

log "Project root: $PROJECT_ROOT"

# 1) Pre-commit hooks (if present)
if command -v pre-commit >/dev/null 2>&1 && [ -f ".pre-commit-config.yaml" ]; then
  log "Running pre-commit on all files"
  pre-commit run --all-files || true
else
  log "pre-commit not configured; skipping"
fi

# 2) Shell lint
if command -v shellcheck >/dev/null 2>&1; then
  log "shellcheck scripts/**/*.sh"
  find scripts -type f -name "*.sh" -print0 | xargs -0 -I{} shellcheck {}
else
  log "shellcheck not found; skipping"
fi

# 3) Python lint/format
if command -v ruff >/dev/null 2>&1; then
  log "ruff check"
  ruff check || true
fi
if command -v black >/dev/null 2>&1; then
  log "black --check"
  black --check . || true
fi

# 4) Unit + snapshot tests (Python)
if [ -d "tests" ]; then
  if python3 -c "import pytest" >/dev/null 2>&1; then
    log "pytest with coverage"
    pytest -q --maxfail=1 --disable-warnings --cov --cov-report=term-missing || fail "pytest failed"
  else
    log "pytest not installed; skipping Python tests"
  fi
else
  log "No tests/ directory; skipping Python tests"
fi

# 5) Minimal security scans on repo (fast and local)
if command -v semgrep >/dev/null 2>&1; then
  log "semgrep scan (p/ci)"
  semgrep ci --no-git-ignore --config p/ci || true
else
  log "semgrep not installed; skipping"
fi
if command -v gitleaks >/dev/null 2>&1; then
  log "gitleaks detect --redact"
  gitleaks detect --no-git --redact --report-path /tmp/gitleaks-local.sarif --report-format sarif || true
fi

ok "Local verification complete"
