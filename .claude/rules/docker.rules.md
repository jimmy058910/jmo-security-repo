---
title: Docker & Container Rules
paths:
  - Dockerfile*
  - docker-compose.yml
  - .dockerignore
references:
  - docs/DOCKER_README.md (registry selection guidance)
  - release.rules.md (Docker build pipeline)
---

# Docker & Container Rules

**What this covers:** Volume persistence, multi-architecture builds, registry selection, arm64 limitations, and container execution best practices.

## Volume Mounts (CRITICAL for Persistence)

**MUST mount `.jmo/history.db` for scan persistence:**

```bash
docker run \
  -v $PWD/.jmo:/scan/.jmo \
  -v $PWD:/scan \
  ghcr.io/jimmy058910/jmo-security:balanced scan
```

**Why:** The SQLite database stores scan history and enables trend analysis. Without the mount, every container starts with empty history.

## Container Registries

| Registry | Image | Purpose | Access |
|----------|-------|---------|--------|
| **GHCR** (Primary) | `ghcr.io/jimmy058910/jmo-security` | CI/CD, unlimited pulls | Public, auth-optional |
| **Docker Hub** | `jmogaming/jmo-security` | Discoverability | Public (replicated via `crane copy`) |
| **ECR Public** | `public.ecr.aws/m2d8u2k1/jmo-security` | AWS users | Public (replicated via `crane copy`) |

## Docker Image Variants

| Variant | File | Tools (PROFILE_TOOLS) | Tools in image | Use Case |
|---------|------|----------------------|----------------|----------|
| `deep` | `Dockerfile.deep` | 28 | 24 (-4 manual-only) | Compliance audits, pentests |
| `balanced` | `Dockerfile.balanced` | 17 | 17 | Production scans, CI/CD |
| `fast` | `Dockerfile.fast` | 9 | 9 | Pre-commit, PR validation |
| `slim` | `Dockerfile.slim` | 13 | 13 | Cloud/IaC focus |

**Note:** The heavyweight image lives at `Dockerfile.deep` (also pulled via `:latest` and `:deep` bare tags).

`MANUAL_INSTALL_TOOLS` (4 tools, intentionally NOT in any image): `akto`, `afl++`, `mobsf`, `falco`. These appear in `PROFILE_TOOLS["deep"]` so users can opt into them via `jmo tools install`, but Docker images skip them (Java/Go runtime weight, license restrictions, or upstream packaging issues). When auditing tool counts, always subtract these 4 from the deep variant's PROFILE_TOOLS count.

## Published Tag Schema (CRITICAL)

GHCR publishes these tag patterns per release:

| Tag pattern | Variants | Example |
|------------|----------|---------|
| `:latest` | deep ONLY | `ghcr.io/jimmy058910/jmo-security:latest` |
| `:<variant>` | all 4 | `:deep`, `:balanced`, `:slim`, `:fast` |
| `:<X>.<Y>.<Z>` (bare semver) | deep ONLY | `:1.0.3`, `:1.0`, `:1` |
| `:<X>.<Y>.<Z>-<variant>` | all 4 | `:1.0.3-deep`, `:1.0.3-balanced`, etc. |
| `:full` (legacy alias for deep) | deep ONLY | One-cycle backward-compat from v1.0.2 rename |

**There is NO `:latest-deep`, `:latest-balanced`, `:latest-slim`, or `:latest-fast`.** The `latest` tag is bare (no suffix) and only attaches to the deep variant per `release.yml`'s metadata-action `flavor: ... onlatest=${{ matrix.variant != 'deep' }}` setting plus the `enable=` condition for bare-`:latest`.

When tests or scripts need a fixed reference to the deep variant, use `:latest` or `:deep`. Never `:latest-deep` — it doesn't exist and pulls will fail with "manifest unknown".

**Verifying actual published tags:**
```bash
gh api users/jimmy058910/packages/container/jmo-security/versions \
  --jq '.[0:3] | .[] | .metadata.container.tags'
```

## Download Hardening Convention (CRITICAL)

Every binary download in `Dockerfile.*` builder stages MUST use these flags. A single missing flag produces the "tar: not in gzip format" cycle that broke v1.0.3 nightly Docker Smoke Tests repeatedly.

**curl** (every invocation):

```dockerfile
curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "$URL" -o /path
```

| Flag | Purpose |
|------|---------|
| `-f` (`--fail`) | **Root-cause fix.** Without this, curl exits 0 on HTTP 4xx/5xx with HTML body, handing garbage to `tar -xzf`. |
| `--retry 3 --retry-delay 5` | Bounded backoff for transient flakes. |
| `--retry-all-errors` | Retry on any error (including timeout / connection-reset), not just HTTP 5xx. Requires curl 7.71+ (ubuntu 24.04 ships 8.5+). |
| `--connect-timeout 30` | Bound DNS / TCP-handshake hangs. |
| `--max-time 600` | Hard ceiling on total request time (10 min for slow CDNs). |

**wget** (every invocation):

```dockerfile
wget -q --tries=3 --waitretry=5 --timeout=600 "$URL" -O /path
```

wget already exits non-zero on HTTP errors, so no `--fail` equivalent is needed.

**Integrity check** (mandatory before extracting an archive — belt-and-suspenders for "200 with corrupt body" that even `--fail` can miss):

```dockerfile
gzip -t /tmp/foo.tar.gz && \      # before tar -xzf
xz -t /tmp/foo.tar.xz && \         # before tar -xJf
unzip -t /tmp/foo.zip > /dev/null  # before unzip
```

Binary-only downloads (no extraction step) don't need an integrity check — `--fail` plus the runtime version-check (`<tool> --version` in the verify stage) catches HTTP errors and serving-the-wrong-file mistakes.

**Why this matters**: With ~50 binaries downloaded per release across 4 Dockerfile variants × 2 architectures, single-attempt downloads at even 0.5% CDN flake rate cause one transient failure most release cycles. The v1.0.3 cycle saw multiple Docker Smoke Test failures from this exact pattern (trufflehog, trivy, others — each different binary on different runs). Hardening landed in PR #349.

## Image Size Measurement Dimension

Two different "size" dimensions exist for Docker images:

| Dimension | What it measures | Example value (v1.0.3 deep) |
|-----------|------------------|------------------------------|
| Compressed pull | Bytes downloaded from registry | ~2.0 GB |
| Uncompressed | Total layer size on disk after extraction | ~6.2 GB |

`docker image inspect --format={{.Size}}` returns the UNCOMPRESSED size. The `release.yml` "Benchmark Docker Image Sizes" step emits compressed numbers (different scale).

When setting size thresholds in tests (`tests/e2e/test_docker_workflows.py::IMAGE_SIZE_RANGES`), confirm which dimension `docker image inspect` uses for that test, then set thresholds accordingly. The compressed-vs-uncompressed mismatch silently broke `test_image_size_within_range` for several releases until exposed in the post-v1.0.3 archeology.

## Docker arm64 (Linux/ARM64)

### Known Limitations

- **scancode-toolkit:** Skipped on arm64 (`extractcode-7z` has no `linux/aarch64` wheel on PyPI).
- **Expected behavior:** Scan runs, scancode layer skipped, no error.

### arm64 Build Checklist

- `TARGETARCH` ARG must be **re-declared** in the runtime stage:

  ```dockerfile
  FROM base AS runtime
  ARG TARGETARCH
  RUN if [ "$TARGETARCH" = "amd64" ]; then ...; fi
  ```
- arm64 builds use **native** `ubuntu-24.04-arm` runners (not QEMU).
- If the arm64 build fails, the merge job creates an **amd64-only manifest** (graceful degradation).

### Testing arm64 Locally

```bash
# Build for arm64 on an amd64 machine (requires qemu-user-static)
docker buildx build --platform linux/arm64 -f Dockerfile.balanced .

# Or run an existing arm64 image
docker run --platform linux/arm64 ghcr.io/jimmy058910/jmo-security:balanced --version
```

**Reference:** [docs/DOCKER_README.md](../../docs/DOCKER_README.md) for detailed registry and image selection guidance.
