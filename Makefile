# Makefile - Developer shortcuts for terminal-first workflow

.PHONY: help fmt lint typecheck test verify clean tools verify-env dev-deps dev-setup pre-commit-install pre-commit-run upgrade-pip deps-compile deps-sync deps-refresh uv-sync docker-build docker-build-all docker-build-local docker-push docker-test

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
	@echo "  dev-deps  - Install Python dev dependencies"
	@echo "  upgrade-pip - Upgrade pip/setuptools/wheel in current Python env"
	@echo "  deps-compile - Use pip-tools to compile requirements-dev.in -> requirements-dev.txt"
	@echo "  deps-sync    - Use pip-tools to sync the environment to requirements-dev.txt"
	@echo "  deps-refresh - Recompile + sync dev deps (pip-tools)"
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
	@echo ""
	@echo "Docker Targets:"
	@echo "  docker-build         - Build Docker image (VARIANT=full|slim|alpine, default: full)"
	@echo "  docker-build-all     - Build all Docker image variants (full, slim, alpine)"
	@echo "  docker-build-local   - Build all variants with 'local' tag for testing before release"
	@echo "  docker-test          - Test Docker image (VARIANT=full|slim|alpine, default: full)"
	@echo "  docker-push          - Push Docker image to registry (VARIANT=full|slim|alpine, TAG=latest)"

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

dev-deps:
	$(PY) -m pip install -r requirements-dev.txt || true
	@if ! command -v pre-commit >/dev/null 2>&1; then $(PY) -m pip install pre-commit || true; fi

upgrade-pip:
	$(PY) -m pip install -U pip setuptools wheel

deps-compile:
	@$(PY) -m pip show pip-tools >/dev/null 2>&1 || $(PY) -m pip install pip-tools
	@if [ -f requirements-dev.in ]; then $(PY) -m piptools compile -o requirements-dev.txt requirements-dev.in; else echo 'requirements-dev.in not found'; exit 1; fi

deps-sync:
	@$(PY) -m pip show pip-tools >/dev/null 2>&1 || $(PY) -m pip install pip-tools
	@if [ -f requirements-dev.txt ]; then $(PY) -m piptools sync requirements-dev.txt; else echo 'requirements-dev.txt not found'; exit 1; fi

deps-refresh: upgrade-pip deps-compile deps-sync

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
