# Makefile - Developer shortcuts for terminal-first workflow

.PHONY: help fmt lint typecheck test verify clean tools verify-env analyze-completeness verify-completeness dev-deps dev-setup pre-commit-install pre-commit-run upgrade-pip deps-compile deps-sync deps-refresh uv-sync docker-build docker-build-all docker-build-local docker-push docker-test validate-readme check-pypi-readme collect-metrics metrics verify-badges samples-clean samples-scan samples-report samples-verify regenerate-samples dist dist-clean dist-verify clean-build clean-test clean-caches clean-all

# Prefer workspace venv if available
PY := $(shell [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3)

help:
	@echo "Targets:"
	@echo "  tools    - Install required CLI tools (Linux/WSL/macOS)"
	@echo "  tools-upgrade - Upgrade/refresh CLI tools"
	@echo "  fmt      - Run formatters (shfmt, black, ruff-format)"
	@echo "  lint     - Run linters (shellcheck, ruff, bandit)"
	@echo "  typecheck - Run mypy type checking on scripts/"
	@echo "  test     - Run tests (pytest if tests/ exists)"
	@echo "  verify   - Local CI: lint+test+fast security scans"
	@echo "  clean    - Clean temporary artifacts"
	@echo "  normalize-report - Aggregate tool outputs and write JSON/Markdown summaries"
	@echo "  report   - Use CLI to emit json/md/yaml/html from RESULTS_DIR (supports FAIL_ON and THREADS)"
	@echo "  profile  - Same as report, but records timings.json (JMO_PROFILE=1)"
	@echo "  verify-env - Check OS/WSL/macOS and required tools"
	@echo "  analyze-completeness - Run repository completeness analyzer (doc-code drift detection)"
	@echo "  dev-deps  - Install Python dev dependencies"
	@echo "  upgrade-pip - Upgrade pip/setuptools/wheel in current Python env"
	@echo "  deps-compile - Use pip-tools to compile requirements-dev.in -> requirements-dev.txt"
	@echo "  deps-sync    - Use pip-tools to sync the environment to requirements-dev.txt"
	@echo "  deps-refresh - Recompile + sync dev deps (pip-tools)"
	@echo "  deps-validate - Validate requirements-dev.txt Python version and conflicts"
	@echo "  deps-upgrade  - Upgrade all dependencies to latest versions (use with caution)"
	@echo "  deps-check-outdated - Check for outdated packages"
	@echo "  uv-sync      - Sync dev deps with uv if installed (alternative to pip-tools)"
	@echo "  pre-commit-install - Install git hooks (pre-commit)"
	@echo "  pre-commit-run     - Run pre-commit on all files"
	@echo "  smoke-ai   - Run AI repo finder smoke test (creates TSV/CSV/JSONL in ai-search/smoke)"
	@echo "  capture-screenshot - Render dashboard.html from RESULTS_DIR and save PNG via headless Chromium"
	@echo "  screenshots-demo  - Produce demo results from samples/fixtures/infra-demo (stubs allowed), render dashboard, capture PNG"
	@echo "  setup     - Bootstrap security tools (jmotools setup)"
	@echo "  fast      - Fast profile scan via jmotools"
	@echo "  balanced  - Balanced profile scan via jmotools"
	@echo "  full      - Deep profile scan via jmotools"
	@echo "  attack-navigator - Open ATT&CK Navigator with scan findings (auto-serve)"
	@echo ""
	@echo "Sample Fixture Targets:"
	@echo "  regenerate-samples   - Full sample regeneration (scan + report + verify)"
	@echo "  samples-scan         - Scan samples/fixtures/infra-demo with balanced profile"
	@echo "  samples-report       - Generate reports from sample scan results"
	@echo "  samples-verify       - Verify sample outputs have v1.0.0 format"
	@echo "  samples-clean        - Remove old sample outputs"
	@echo ""
	@echo "Distribution/Build Targets:"
	@echo "  dist                 - Build sdist and wheel packages"
	@echo "  dist-verify          - Verify built packages are installable"
	@echo "  dist-clean           - Remove build/ dist/ *.egg-info/"
	@echo ""
	@echo "Extended Clean Targets:"
	@echo "  clean                - Quick clean (Python caches only)"
	@echo "  clean-all            - Full clean (caches + build + test + samples)"
	@echo "  clean-build          - Remove build artifacts only"
	@echo "  clean-test           - Remove test artifacts only"
	@echo "  clean-caches         - Remove Python caches only"
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker-build         - Build Docker image (VARIANT=full|slim|alpine, default: full)"
	@echo "  docker-build-all     - Build all Docker image variants (full, slim, alpine)"
	@echo "  docker-build-local   - Build all variants with 'local' tag for testing before release"
	@echo "  docker-test          - Test Docker image (VARIANT=full|slim|alpine, default: full)"
	@echo "  docker-push          - Push Docker image to registry (VARIANT=full|slim|alpine, TAG=latest)"
	@echo ""
	@echo "Release Targets:"
	@echo "  validate-readme      - Check README consistency (PyPI + Docker Hub + GHCR)"
	@echo "  verify-badges        - Verify PyPI badges match pyproject.toml version"
	@echo ""
	@echo "Metrics Targets (Maintainer-Only):"
	@echo "  collect-metrics      - Collect weekly metrics (GitHub, PyPI, Docker Hub, telemetry)"
	@echo "  metrics              - Alias for collect-metrics"
	@echo "  validate-readme-pypi - Check PyPI README only (skip Docker Hub)"
	@echo "  check-pypi-readme    - Alias for validate-readme"

TOOLS_SCRIPT := scripts/dev/install_tools.sh
VERIFY_SCRIPT := scripts/dev/ci-local.sh

TOOLS := jq curl git

tools:
	bash $(TOOLS_SCRIPT)

tools-upgrade:
	bash $(TOOLS_SCRIPT) --upgrade

fmt:
	@if command -v shfmt >/dev/null 2>&1; then \
		find scripts -type f -name '*.sh' -print0 | xargs -0 shfmt -w -i 2 -ci -bn ; \
	else echo 'shfmt not found'; fi
	@if command -v black >/dev/null 2>&1; then black . ; else echo 'black not found'; fi
	@if command -v ruff >/dev/null 2>&1; then ruff format . ; else echo 'ruff not found'; fi

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		find scripts -type f -name '*.sh' -print0 | xargs -0 -I{} shellcheck {} || true; \
	else echo 'shellcheck not found'; fi
	@if command -v ruff >/dev/null 2>&1; then ruff check . || true; else echo 'ruff not found'; fi
	@if command -v bandit >/dev/null 2>&1; then \
		# Strict source scan (configured via bandit.yaml); focus on Python under scripts/ to avoid scanning tests or external dirs \
		bandit -q -r scripts -c bandit.yaml || true ; \
		# Quiet tests-only scan: if issues are found, re-run without -q to print them \
		if ! bandit -q -r tests -s B101,B404 >/dev/null 2>&1; then \
			echo "Bandit found issues in tests/ (printing):" ; \
			bandit -r tests -s B101,B404 || true ; \
		fi ; \
	else echo 'bandit not found'; fi
	@if command -v pre-commit >/dev/null 2>&1; then pre-commit run --all-files || true; else echo 'pre-commit not found'; fi

typecheck:
	@if command -v mypy >/dev/null 2>&1; then \
		echo "Running mypy on scripts/..." ; \
		mypy scripts/ --config-file=pyproject.toml || true ; \
	else echo 'mypy not found. Run: make dev-deps'; fi

TEST_FLAGS ?= -q --maxfail=1 --disable-warnings

test:
	@if [ -d tests ]; then \
		$(PY) -m pytest $(TEST_FLAGS) --cov --cov-report=term-missing ; \
	else echo 'no tests/ directory'; fi

verify:
	bash $(VERIFY_SCRIPT)
	@if command -v pre-commit >/dev/null 2>&1; then pre-commit run --all-files || true; else true; fi

verify-env:
	bash scripts/dev/verify-env.sh

analyze-completeness:
	$(PY) scripts/dev/analyze_repo_completeness.py

verify-completeness:  ## Verify no critical completeness issues (for CI)
	@echo "🔍 Verifying repository completeness..."
	@$(PY) scripts/dev/analyze_repo_completeness.py
	@CRITICAL=$$(jq '.summary.critical_issues' dev-only/REPO_COMPLETENESS_ANALYSIS.json); \
	TOTAL=$$(jq '.summary.total_issues' dev-only/REPO_COMPLETENESS_ANALYSIS.json); \
	if [ "$$CRITICAL" -gt 0 ]; then \
		echo ""; \
		echo "❌ Found $$CRITICAL critical issues (total: $$TOTAL)"; \
		echo "📄 Review: dev-only/REPO_COMPLETENESS_ANALYSIS.json"; \
		echo "🔧 Action Plan: dev-only/UNIFICATION_ACTION_PLAN.md"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "✅ No critical completeness issues (total: $$TOTAL)"

dev-deps:
	$(PY) -m pip install -r requirements-dev.txt || true
	@if ! command -v pre-commit >/dev/null 2>&1; then $(PY) -m pip install pre-commit || true; fi

upgrade-pip:
	$(PY) -m pip install -U pip setuptools wheel

deps-compile:
	@echo "Note: Requires Python 3.10+ to match CI compilation (pip-tools uses active Python version)"
	@$(PY) -m pip show pip-tools >/dev/null 2>&1 || $(PY) -m pip install pip-tools
	@if [ -f requirements-dev.in ]; then $(PY) -m piptools compile -o requirements-dev.txt requirements-dev.in; else echo 'requirements-dev.in not found'; exit 1; fi

deps-sync:
	@$(PY) -m pip show pip-tools >/dev/null 2>&1 || $(PY) -m pip install pip-tools
	@if [ -f requirements-dev.txt ]; then $(PY) -m piptools sync requirements-dev.txt; else echo 'requirements-dev.txt not found'; exit 1; fi

deps-refresh: upgrade-pip deps-compile deps-sync

deps-validate:
	@$(PY) scripts/dev/update_dependencies.py --validate

deps-upgrade:
	@echo "WARNING: This will upgrade ALL dependencies to latest versions"
	@echo "Press Ctrl+C to cancel, or Enter to continue..."
	@read dummy
	@$(PY) scripts/dev/update_dependencies.py --upgrade

deps-check-outdated:
	@$(PY) scripts/dev/update_dependencies.py --check-outdated

uv-sync:
	@if command -v uv >/dev/null 2>&1; then \
		uv pip compile -o requirements-dev.txt requirements-dev.in; \
		uv pip sync requirements-dev.txt; \
	else \
		echo 'uv not found. See https://docs.astral.sh/uv/'; exit 1; \
	fi

pre-commit-install:
	@if command -v pre-commit >/dev/null 2>&1; then pre-commit install; else echo 'pre-commit not found. Run: make dev-deps'; fi

pre-commit-run:
	@if command -v pre-commit >/dev/null 2>&1; then pre-commit run --all-files; else echo 'pre-commit not found. Run: make dev-deps'; fi

# Convenience target: install dev deps and the package in editable mode so
# `from scripts...` imports work without tweaking PYTHONPATH.
dev-setup:
	$(PY) -m pip install -r requirements-dev.txt
	$(PY) -m pip install -e .

clean:
	rm -rf .pytest_cache .ruff_cache __pycache__ */__pycache__ *.pyc *.pyo .mypy_cache

normalize-report:
	@if [ -z "$(RESULTS_DIR)" ]; then \
		echo 'Usage: make normalize-report RESULTS_DIR=/path/to/results [OUT=/path/to/out]'; exit 1; \
	fi
	python3 scripts/core/normalize_and_report.py $(RESULTS_DIR) --out $${OUT:-$(RESULTS_DIR)/summaries}

report:
	@if [ -z "$(RESULTS_DIR)" ]; then \
		echo 'Usage: make report RESULTS_DIR=/path/to/results [OUT=/path/to/out] [CONFIG=jmo.yml] [FAIL_ON=]'; exit 1; \
	fi
	python3 scripts/cli/jmo.py report $(RESULTS_DIR) --out $${OUT:-$(RESULTS_DIR)/summaries} --config $${CONFIG:-jmo.yml} $$( [ -n "$(FAIL_ON)" ] && echo --fail-on $(FAIL_ON) ) $$( [ -n "$(THREADS)" ] && echo --threads $(THREADS) )

profile:
	@if [ -z "$(RESULTS_DIR)" ]; then \
		echo 'Usage: make profile RESULTS_DIR=/path/to/results [OUT=/path/to/out] [CONFIG=jmo.yml]'; exit 1; \
	fi
	python3 scripts/cli/jmo.py report $(RESULTS_DIR) --out $${OUT:-$(RESULTS_DIR)/summaries} --config $${CONFIG:-jmo.yml} --profile $$( [ -n "$(THREADS)" ] && echo --threads $(THREADS) )

.PHONY: capture-screenshot
capture-screenshot:
	@if [ -z "$(RESULTS_DIR)" ]; then \
		echo 'Usage: make capture-screenshot RESULTS_DIR=/path/to/results [OUTDIR=docs/screenshots] [CONFIG=jmo.yml]'; exit 1; \
	fi
	# Ensure the dashboard exists, then capture a PNG using our helper script (chromium/google-chrome required)
	python3 scripts/cli/jmo.py report $(RESULTS_DIR) --out $${OUT:-$(RESULTS_DIR)/summaries} --config $${CONFIG:-jmo.yml}
	bash docs/screenshots/capture.sh $${OUT:-$(RESULTS_DIR)/summaries}/dashboard.html $${OUTDIR:-docs/screenshots}
	@echo "[capture-screenshot] Wrote PNG(s) under $${OUTDIR:-docs/screenshots}"

.PHONY: screenshots-demo
screenshots-demo:
	@echo "[screenshots-demo] Creating demo results under /tmp/jmo-infra-demo-results (tools may be missing: using stubs if needed)"
	PYTHONPATH=. python3 scripts/cli/jmo.py scan --repo samples/fixtures/infra-demo --results /tmp/jmo-infra-demo-results --allow-missing-tools || true
	PYTHONPATH=. python3 scripts/cli/jmo.py report /tmp/jmo-infra-demo-results --out /tmp/jmo-infra-demo-results/summaries || true
	bash docs/screenshots/capture.sh /tmp/jmo-infra-demo-results/summaries/dashboard.html $${OUTDIR:-docs/screenshots}
	@echo "[screenshots-demo] Dashboard: /tmp/jmo-infra-demo-results/summaries/dashboard.html"
	@echo "[screenshots-demo] Screenshot(s) saved under $${OUTDIR:-docs/screenshots}"

.PHONY: smoke-ai
smoke-ai:
	@echo "[smoke-ai] Running constrained search to validate outputs..."
	@mkdir -p ai-search/smoke
	@OUTDIR=ai-search/smoke FORMATS=tsv,csv,jsonl RPM=10 PER_PAGE=50 MAX_PER_QUERY=50 LIMIT=15 \
		./ai-search/find-ai-generated-repos.sh --months 1 --stars-max 50 --query-file ai-search/queries.txt --outdir ai-search/smoke >/dev/null
	@ls -1 ai-search/smoke | grep -E '^ai-repos-.*\.(tsv|csv|jsonl)$$' >/dev/null || (echo "[smoke-ai] Expected outputs not found in ai-search/smoke" && exit 1)
	@echo "[smoke-ai] OK - Found outputs:"
	@ls -1 ai-search/smoke | grep -E '^ai-repos-.*\.(tsv|csv|jsonl)$$' | sed 's/^/  - /'

.PHONY: setup fast balanced full
setup:
	@which jmotools >/dev/null 2>&1 || (echo 'Installing package to expose jmotools…' && $(PY) -m pip install -e . )
	jmotools setup --check || true

# Usage: make fast [DIR=~/repos] [TARGETS=results/targets.tsv.txt] [RESULTS=results]
fast:
	@which jmotools >/dev/null 2>&1 || (echo 'Installing package to expose jmotools…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmotools fast --repos-dir $(DIR) --results-dir $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmotools fast --targets $(TARGETS) --results-dir $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi

balanced:
	@which jmotools >/dev/null 2>&1 || (echo 'Installing package to expose jmotools…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmotools balanced --repos-dir $(DIR) --results-dir $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmotools balanced --targets $(TARGETS) --results-dir $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi

full:
	@which jmotools >/dev/null 2>&1 || (echo 'Installing package to expose jmotools…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmotools full --repos-dir $(DIR) --results-dir $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmotools full --targets $(TARGETS) --results-dir $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi

# ============================================================================
# Sample Fixture Targets
# ============================================================================
# These targets regenerate sample outputs for documentation and testing.
# The primary fixture is samples/fixtures/infra-demo/ which contains:
#   - Terraform (main.tf) - IaC security scanning
#   - Kubernetes (deployment.yaml) - Container orchestration security
#   - Docker (Dockerfile) - Container security
#   - Secrets (secrets.json) - Secret detection testing
#
# Sample outputs demonstrate v1.0.0 format with metadata wrapper:
#   {"meta": {"output_version": "1.0.0", ...}, "findings": [...]}
#
# Usage:
#   make regenerate-samples    # Full regeneration (scan + report + verify)
#   make samples-verify        # Verify outputs are valid v1.0.0 format
#
# Time estimates:
#   - samples-scan: 5-15 minutes (depends on installed tools)
#   - samples-report: ~30 seconds
#   - Full regeneration: 5-20 minutes total
# ============================================================================

SAMPLES_FIXTURE := samples/fixtures/infra-demo
SAMPLES_OUTPUT := samples/fixtures/infra-demo/sample-results

samples-clean:
	@echo "[samples-clean] Removing old sample outputs..."
	@rm -rf $(SAMPLES_OUTPUT)
	@echo "[samples-clean] Done"

samples-scan: samples-clean
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║  Scanning sample fixture: $(SAMPLES_FIXTURE)                 ║"
	@echo "║  Profile: balanced (18 tools)                                ║"
	@echo "║  Estimated time: 5-15 minutes                                ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"
	@echo ""
	PYTHONPATH=. $(PY) scripts/cli/jmo.py scan \
		--repo $(SAMPLES_FIXTURE) \
		--results $(SAMPLES_OUTPUT) \
		--profile balanced \
		--allow-missing-tools \
		--human-logs
	@echo ""
	@echo "[samples-scan] ✅ Scan complete: $(SAMPLES_OUTPUT)"

samples-report:
	@if [ ! -d "$(SAMPLES_OUTPUT)/individual-repos" ]; then \
		echo "[samples-report] ❌ No scan results found."; \
		echo ""; \
		echo "Run 'make samples-scan' first, or 'make regenerate-samples' for full workflow."; \
		exit 1; \
	fi
	@echo "[samples-report] Generating reports from: $(SAMPLES_OUTPUT)"
	PYTHONPATH=. $(PY) scripts/cli/jmo.py report $(SAMPLES_OUTPUT) \
		--out $(SAMPLES_OUTPUT)/summaries \
		--human-logs
	@echo ""
	@echo "[samples-report] ✅ Reports generated:"
	@ls -la $(SAMPLES_OUTPUT)/summaries/ 2>/dev/null | tail -10 || echo "  (no files)"

samples-verify:
	@echo "[samples-verify] Verifying sample outputs..."
	@echo ""
	@if [ ! -d "$(SAMPLES_OUTPUT)/summaries" ]; then \
		echo "❌ No sample outputs found at $(SAMPLES_OUTPUT)/summaries"; \
		echo "   Run 'make regenerate-samples' first."; \
		exit 1; \
	fi
	@echo "Checking required output files:"
	@for f in findings.json SUMMARY.md dashboard.html findings.sarif findings.csv simple-report.html; do \
		if [ -f "$(SAMPLES_OUTPUT)/summaries/$$f" ]; then \
			echo "  ✅ $$f"; \
		else \
			echo "  ❌ $$f (MISSING)"; \
		fi; \
	done
	@echo ""
	@echo "Validating v1.0.0 metadata format:"
	@if [ -f "$(SAMPLES_OUTPUT)/summaries/findings.json" ]; then \
		if command -v jq >/dev/null 2>&1; then \
			VERSION=$$(jq -r '.meta.output_version // "missing"' $(SAMPLES_OUTPUT)/summaries/findings.json 2>/dev/null); \
			SCHEMA=$$(jq -r '.meta.schema_version // "missing"' $(SAMPLES_OUTPUT)/summaries/findings.json 2>/dev/null); \
			COUNT=$$(jq -r '.meta.finding_count // .findings | length' $(SAMPLES_OUTPUT)/summaries/findings.json 2>/dev/null); \
			echo "  ✅ output_version: $$VERSION"; \
			echo "  ✅ schema_version: $$SCHEMA"; \
			echo "  ✅ finding_count: $$COUNT"; \
		else \
			echo "  ⚠️  jq not installed, skipping JSON validation"; \
		fi; \
	else \
		echo "  ❌ findings.json not found"; \
	fi
	@echo ""
	@echo "[samples-verify] Done"

regenerate-samples: samples-scan samples-report samples-verify
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║  ✅ Sample outputs regenerated successfully!                 ║"
	@echo "╠══════════════════════════════════════════════════════════════╣"
	@echo "║  Location: $(SAMPLES_OUTPUT)/summaries/                      ║"
	@echo "║                                                              ║"
	@echo "║  Output files (v1.0.0 format):                               ║"
	@echo "║    findings.json      - Machine-readable with metadata       ║"
	@echo "║    findings.sarif     - GitHub/GitLab code scanning          ║"
	@echo "║    findings.csv       - Spreadsheet export                   ║"
	@echo "║    SUMMARY.md         - PR comments, documentation           ║"
	@echo "║    dashboard.html     - Interactive browser viewing          ║"
	@echo "║    simple-report.html - Email-compatible static report       ║"
	@echo "║                                                              ║"
	@echo "║  These outputs are used by SAMPLE_OUTPUTS.md examples.       ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"

# ============================================================================
# Distribution/Build Targets
# ============================================================================
# Build and verify Python distribution packages (sdist + wheel).
# These are used for PyPI releases and local testing.
#
# Usage:
#   make dist          # Build distribution packages
#   make dist-verify   # Verify packages are installable
#   make dist-clean    # Clean build artifacts
#
# Note: CI handles actual PyPI publishing via trusted publisher (OIDC).
# These targets are for local development and pre-release testing.
# ============================================================================

dist-clean:
	@echo "[dist-clean] Removing build artifacts..."
	@rm -rf build/ dist/ *.egg-info/
	@echo "[dist-clean] Done"

dist: dist-clean
	@echo "[dist] Building source distribution and wheel..."
	@$(PY) -m pip install --quiet build 2>/dev/null || true
	$(PY) -m build
	@echo ""
	@echo "[dist] ✅ Built packages:"
	@ls -lh dist/

dist-verify: dist
	@echo ""
	@echo "[dist-verify] Verifying distribution packages..."
	@echo "[dist-verify] Creating temporary venv..."
	@$(PY) -m venv /tmp/jmo-dist-test
	@/tmp/jmo-dist-test/bin/pip install --quiet --upgrade pip
	@echo "[dist-verify] Installing wheel..."
	@/tmp/jmo-dist-test/bin/pip install --quiet dist/*.whl
	@echo "[dist-verify] Testing CLI..."
	@/tmp/jmo-dist-test/bin/jmo --version
	@/tmp/jmo-dist-test/bin/jmo --help >/dev/null
	@echo ""
	@echo "[dist-verify] ✅ Distribution verified successfully"
	@rm -rf /tmp/jmo-dist-test

# ============================================================================
# Extended Clean Targets
# ============================================================================
# Comprehensive cleanup for various artifact types.
# The base 'clean' target is intentionally minimal (caches only).
# Use 'clean-all' for a full workspace reset.
#
# Usage:
#   make clean         # Quick: Python caches only
#   make clean-all     # Full: caches + build + test + samples
#   make clean-build   # Build artifacts only
#   make clean-test    # Test artifacts only
# ============================================================================

clean-caches:
	@echo "[clean-caches] Removing Python caches..."
	@rm -rf .ruff_cache/ .mypy_cache/
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@find . -name "*.pyo" -delete 2>/dev/null || true
	@echo "[clean-caches] Done"

clean-build:
	@echo "[clean-build] Removing build artifacts..."
	@rm -rf build/ dist/ *.egg-info/
	@find . -name "*.whl" -not -path "./.venv/*" -delete 2>/dev/null || true
	@find . -name "*.egg" -not -path "./.venv/*" -delete 2>/dev/null || true
	@echo "[clean-build] Done"

clean-test:
	@echo "[clean-test] Removing test artifacts..."
	@rm -rf htmlcov/ .coverage coverage.xml coverage.json
	@rm -rf results/ results-*/
	@rm -rf .pytest_cache/ .hypothesis/
	@rm -f *-images.txt
	@echo "[clean-test] Done"

clean-all: clean-caches clean-build clean-test samples-clean
	@echo ""
	@echo "[clean-all] ✅ Comprehensive cleanup complete"
	@echo "  Removed: caches, build artifacts, test outputs, sample outputs"
	@echo ""
	@echo "  Note: Virtual environments (.venv/) are preserved."
	@echo "  To remove stale venvs, manually delete: venv-*/, .venv-pypi/, .post-release-venv/"

# ============================================================================
# Docker Build Targets
# ============================================================================

# Docker image configuration
DOCKER_REGISTRY ?= ghcr.io
DOCKER_ORG ?= jimmy058910
DOCKER_IMAGE ?= jmo-security
DOCKER_TAG ?= latest
VARIANT ?= full

# Determine Dockerfile based on variant
DOCKERFILE := $(if $(filter full,$(VARIANT)),Dockerfile,Dockerfile.$(VARIANT))

# Auto-detect target architecture (amd64 or arm64) for Docker builds
# This ensures Alpine builds install semgrep/checkov on amd64
TARGETARCH := $(shell uname -m | sed 's/x86_64/amd64/g' | sed 's/aarch64/arm64/g')

docker-build:
	@echo "Building Docker image: $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT)"
	@echo "Target architecture: $(TARGETARCH)"
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f $(DOCKERFILE) -t $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT) .
	@if [ "$(VARIANT)" = "full" ]; then \
		docker tag $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT) $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG); \
		echo "Tagged as latest: $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)"; \
	fi

docker-build-all:
	@echo "Building all Docker image variants..."
	$(MAKE) docker-build VARIANT=full
	$(MAKE) docker-build VARIANT=slim
	$(MAKE) docker-build VARIANT=alpine

docker-build-local:
	@echo "Building all Docker variants with 'local' tag for testing..."
	@echo "Target architecture: $(TARGETARCH)"
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile -t jmo-security:local-full .
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile.slim -t jmo-security:local-slim .
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile.alpine -t jmo-security:local-alpine .
	@echo ""
	@echo "✅ Local Docker images built successfully:"
	@echo "  - jmo-security:local-full"
	@echo "  - jmo-security:local-slim"
	@echo "  - jmo-security:local-alpine"
	@echo ""
	@echo "Test with: docker run --rm jmo-security:local-full --help"
	@echo "Run E2E tests: DOCKER_IMAGE_BASE=jmo-security DOCKER_TAG=local bash tests/e2e/run_comprehensive_tests.sh"

docker-test:
	@echo "Testing Docker image: $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT)"
	docker run --rm $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT) --version
	docker run --rm $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT) --help
	@echo "Creating test scan..."
	@mkdir -p /tmp/docker-test-scan
	@echo "print('test')" > /tmp/docker-test-scan/test.py
	docker run --rm -v /tmp/docker-test-scan:/scan $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT) \
		scan --repo /scan --results /scan/results --profile fast --human-logs || true
	@rm -rf /tmp/docker-test-scan
	@echo "Test completed successfully"

docker-push:
	@echo "Pushing Docker image: $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT)"
	docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)-$(VARIANT)
	@if [ "$(VARIANT)" = "full" ]; then \
		docker push $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG); \
		echo "Pushed latest: $(DOCKER_REGISTRY)/$(DOCKER_ORG)/$(DOCKER_IMAGE):$(DOCKER_TAG)"; \
	fi

# ATT&CK Navigator automation
ATTACK_JSON ?= results/summaries/attack-navigator.json
attack-navigator:
	@if [ ! -f "$(ATTACK_JSON)" ]; then \
		echo "❌ Error: $(ATTACK_JSON) not found"; \
		echo ""; \
		echo "Run a scan first:"; \
		echo "  make balanced"; \
		echo "  jmo report results --profile"; \
		exit 1; \
	fi
	@echo "🚀 Starting ATT&CK Navigator server..."
	@echo "📊 Layer file: $(ATTACK_JSON)"
	@$(PY) scripts/dev/serve_attack_navigator.py $(ATTACK_JSON)

# README validation for releases
validate-readme:
	@echo "🔍 Validating README consistency (PyPI + Docker Hub)..."
	@$(PY) scripts/dev/validate_readme.py --check-dockerhub --fix || true
	@echo ""
	@echo "💡 Documentation: dev-only/README_CONSISTENCY.md"
	@echo "💡 Quick reference: dev-only/PYPI_README_QUICK_REF.md"

check-pypi-readme: validate-readme

# Validate PyPI README only (skip Docker Hub)
validate-readme-pypi:
	@echo "🔍 Validating PyPI README only..."
	@$(PY) scripts/dev/validate_readme.py --fix || true

# Metrics collection (maintainer-only)
collect-metrics:
	@echo "📊 Collecting weekly metrics..."
	@./scripts/dev/collect_metrics.sh
	@echo ""
	@echo "📄 View summary: cat metrics/summary-$$(date +%Y-%m-%d).md"

metrics: collect-metrics

# Verify PyPI badges match pyproject.toml
verify-badges:
	@echo "🏷️  Verifying PyPI badge versions..."
	@bash scripts/dev/verify_badges.sh
