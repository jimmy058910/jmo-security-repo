#!/usr/bin/env bash
# Audit the project's locked dependencies for known CVEs (OSV database).
#
# Single implementation shared by .github/workflows/ci.yml and
# .pre-commit-config.yaml. Previously each inlined its own `pip-audit -r
# requirements-dev.txt` call, and their explanatory comments had already
# drifted apart. Keep it that way: one script, two callers.
#
# pip-audit needs a requirements file, and uv.lock is not one, so we export an
# ephemeral requirements.txt to a temp path. It is deliberately NOT committed --
# any tracked requirements*.txt is a file Dependabot would try to manage, which
# is the exact second-writer problem this migration removed.
#
# Ignored advisories -- verify before removing either:
#
#   PYSEC-2025-183 (CVE-2025-45768) "pyjwt weak encryption" -- DISPUTED by the
#     maintainer ("key length is chosen by the application that uses the
#     library"). No fix version exists. pyjwt is a transitive dev-only dep via
#     `mcp`, not used in production paths.
#     https://api.osv.dev/v1/vulns/PYSEC-2025-183
#
#   GHSA-qp9x-wp8f-qgjj "tuf platform-dependent delegation path matching"
#     (CVSS 4.0 medium) -- fixed in tuf 7.0.0. Adopted when every sigstore
#     release capped tuf<7.0.0, making the fix unreachable. As of the uv.lock
#     migration the lock resolves tuf 7.0.0 (sigstore 4.5.0 lifted the cap), so
#     this ignore is likely inert and #539 may be closeable. Kept for now
#     because dropping it is a security-posture change that deserves its own
#     review, not a rider on a dependency migration.
#     https://github.com/advisories/GHSA-qp9x-wp8f-qgjj
#
# Usage: scripts/dev/audit_deps.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

REQ_FILE="$(mktemp -t jmo-audit-XXXXXX.txt)"
trap 'rm -f "$REQ_FILE"' EXIT

# --frozen: audit the lock as committed. Lock freshness is a separate gate
#           (`uv lock --check`), so this never double-reports a stale lock.
# --no-emit-project: the project itself is not a PyPI dependency to audit.
# --no-hashes: pip-audit resolves names/versions; hashes add nothing here.
# --quiet: uv export echoes the requirements to stdout even with an output
#          file, which buries pip-audit's actual findings in ~250 lines of noise.
#
# The export is universal, so the audited set includes platform-conditional
# entries such as `pywin32==312 ; sys_platform == 'win32'` regardless of which
# OS the audit runs on. A Linux-only audit would silently skip Windows deps.
uv export \
  --frozen \
  --quiet \
  --format requirements.txt \
  --no-emit-project \
  --no-hashes \
  --output-file "$REQ_FILE"

pip-audit -r "$REQ_FILE" --progress-spinner=off \
  --ignore-vuln PYSEC-2025-183 \
  --ignore-vuln GHSA-qp9x-wp8f-qgjj
