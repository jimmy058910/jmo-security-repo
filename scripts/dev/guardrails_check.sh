#!/usr/bin/env bash
set -euo pipefail

# Guardrails: fail CI if forbidden paths are tracked in git.
# Forbidden examples: virtualenvs, build artifacts, egg-info, coverage outputs, large caches.

FORBIDDEN_PATTERNS=(
  "^\.venv/"
  "^\.post-release-venv/"
  "^env/"
  "^venv/"
  "^build/"
  "^dist/"
  "^[^/]+\.egg-info/"
  "^htmlcov/"
  "^coverage\.xml$"
  "^\.coverage(\..*)?$"
)

# Collect tracked files and check against patterns
tracked=$(git ls-files)
violations=()

while IFS= read -r file; do
  for pat in "${FORBIDDEN_PATTERNS[@]}"; do
    if [[ "$file" =~ $pat ]]; then
      violations+=("$file")
      break
    fi
  done
done <<< "$tracked"

if (( ${#violations[@]} > 0 )); then
  echo "::error::Guardrail violation: the following paths are tracked in git but should be ignored:" >&2
  for v in "${violations[@]}"; do
    echo "  - $v" >&2
  done
  echo "\nPlease add to .gitignore and remove from git history (git rm --cached <path>)." >&2
  exit 1
fi

echo "[guardrails] OK: no forbidden tracked files detected."
