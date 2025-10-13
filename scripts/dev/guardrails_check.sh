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
  # Common caches and virtualenv managers
  "^\.pytest_cache/"
  "^\.mypy_cache/"
  "^\.ruff_cache/"
  "^\.tox/"
  "^\.nox/"
  "^\.cache/"
  # Anywhere in the tree
  "(^|/)__pycache__/"
  "(^|/)\.DS_Store$"
  "(^|/)Thumbs\.db$"
)

# Allowlist: paths or regexes to exempt from checks. Two mechanisms:
# - Environment variable GUARDRAILS_ALLOW_REGEX: a single regex applied to paths
# - File .guardrails-allowlist at repo root: one regex glob/regex per non-comment line

ALLOWLIST_REGEX="${GUARDRAILS_ALLOW_REGEX-}"
if [ -f .guardrails-allowlist ]; then
  # Build a combined regex from lines (ignore comments and blanks)
  mapfile -t allow_lines < <(grep -vE '^(#|\s*$)' .guardrails-allowlist || true)
  if ((${#allow_lines[@]} > 0)); then
    joined=$(printf "|%s" "${allow_lines[@]}")
    joined=${joined:1}
    if [ -n "$ALLOWLIST_REGEX" ]; then
      ALLOWLIST_REGEX="(${ALLOWLIST_REGEX})|(${joined})"
    else
      ALLOWLIST_REGEX="(${joined})"
    fi
  fi
fi

matches_allowlist() {
  local path="$1"
  if [ -n "$ALLOWLIST_REGEX" ] && [[ $path =~ $ALLOWLIST_REGEX ]]; then
    return 0
  fi
  return 1
}

# Collect tracked files and check against patterns
tracked=$(git ls-files)
violations=()

while IFS= read -r file; do
  # Skip allowlisted paths entirely
  if matches_allowlist "$file"; then
    continue
  fi
  for pat in "${FORBIDDEN_PATTERNS[@]}"; do
    if [[ $file =~ $pat ]]; then
      violations+=("$file")
      break
    fi
  done
done <<<"$tracked"

if ((${#violations[@]} > 0)); then
  echo "::error::Guardrail violation: the following paths are tracked in git but should be ignored:" >&2
  for v in "${violations[@]}"; do
    echo "  - $v" >&2
  done
  printf "\nPlease add to .gitignore and remove from git history (git rm --cached <path>).\n" >&2
  exit 1
fi

echo "[guardrails] OK: no forbidden tracked files detected."

# Additional guardrail: prevent accidentally committing large binary files.
# Threshold defaults to 10 MB; can be overridden via GUARDRAILS_MAX_MB env.
MAX_MB=${GUARDRAILS_MAX_MB:-10}
MAX_BYTES=$((MAX_MB * 1024 * 1024))

# Exclusions: allow large artifacts under well-known paths if ever present in the tree,
# and anything allowlisted above
EXCLUDE_REGEX='^(results/|build/|dist/|\.git/|\.venv/|\.mypy_cache/|\.ruff_cache/|\.pytest_cache/|__pycache__/|docs/screenshots/)'

large_violations=()

# Iterate through tracked files; skip exclusions; check size and basic binary heuristic
while IFS= read -r file; do
  if [[ $file =~ $EXCLUDE_REGEX ]] || matches_allowlist "$file"; then
    continue
  fi
  # Skip symlinks
  if [ -L "$file" ]; then
    continue
  fi
  if [ -f "$file" ]; then
    size=$(wc -c <"$file" | tr -d ' ')
    if [ "$size" -ge "$MAX_BYTES" ]; then
      # Heuristic: consider file binary if it contains NUL bytes or fails 'file --mime-type' as text/*
      if command -v file >/dev/null 2>&1; then
        mime=$(file --mime-type -b "$file" || echo "")
        case "$mime" in
        text/*) is_binary=0 ;;
        */json | */xml | application/x-yaml | application/yaml) is_binary=0 ;;
        *) is_binary=1 ;;
        esac
      else
        # Fallback: search for NUL bytes
        if LC_ALL=C grep -q $'\x00' "$file" >/dev/null 2>&1; then
          is_binary=1
        else
          is_binary=0
        fi
      fi
      if [ "$is_binary" -eq 1 ]; then
        large_violations+=("$file ($((size / 1024 / 1024)) MB)")
      fi
    fi
  fi
done <<<"$tracked"

if ((${#large_violations[@]} > 0)); then
  echo "::error::Guardrail violation: large binary files tracked in git (>${MAX_MB}MB):" >&2
  for v in "${large_violations[@]}"; do
    echo "  - $v" >&2
  done
  printf "\nRemediation:\n" >&2
  printf "- Use Git LFS for required binaries, or compress and host externally.\n" >&2
  printf "- Remove from history: git rm --cached <file> && add to .gitignore\n" >&2
  printf "- To adjust threshold, set GUARDRAILS_MAX_MB (current: %sMB).\n" "$MAX_MB" >&2
  exit 1
fi

echo "[guardrails] OK: no large binary files detected (> ${MAX_MB}MB)."
