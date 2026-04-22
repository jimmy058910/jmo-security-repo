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

| Variant | File | Tools | Use Case |
|---------|------|-------|----------|
| `deep` | `Dockerfile.deep` | 29 (full) | Compliance audits, pentests |
| `balanced` | `Dockerfile.balanced` | 18 | Production scans, CI/CD |
| `fast` | `Dockerfile.fast` | 9 | Pre-commit, PR validation |
| `slim` | `Dockerfile.slim` | 14 | Cloud/IaC focus |

**Note:** The heavyweight image lives at `Dockerfile.deep` (also pulled via `:latest` and `:deep` bare tags).

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
