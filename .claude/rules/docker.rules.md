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

**What this covers:** Volume persistence, multi-architecture builds, registry selection, the published tag schema, and container execution best practices.

## Volume Mounts (CRITICAL for Persistence)

**MUST mount `.jmo/history.db` for scan persistence:**

```bash
docker run \
  -v $PWD/.jmo:/scan/.jmo \
  -v $PWD:/scan \
  ghcr.io/jimmy058910/jmo-security:latest scan
```

**Why:** The SQLite database stores scan history and enables trend analysis. Without the mount, every container starts with empty history.

## Container Registries

| Registry | Image | Purpose | Access |
|----------|-------|---------|--------|
| **GHCR** (Primary) | `ghcr.io/jimmy058910/jmo-security` | CI/CD, unlimited pulls | Public, auth-optional |
| **Docker Hub** | `jmogaming/jmo-security` | Discoverability | Public (replicated via `crane copy`) |
| **ECR Public** | `public.ecr.aws/m2d8u2k1/jmo-security` | AWS users | Public (replicated via `crane copy`) |

## Published Tag Schema (CRITICAL)

There is **one image**, built from `Dockerfile`. It carries the whole tool matrix
(`TOOL_MATRIX` in `scripts/core/tool_registry.py`) plus opa, the policy engine. Each
release publishes it under:

| Tag pattern | Example |
|------------|---------|
| `:latest` | `ghcr.io/jimmy058910/jmo-security:latest` |
| `:<X>.<Y>.<Z>` (semver) | `ghcr.io/jimmy058910/jmo-security:2.0.0` |

Any shorter semver aliases are whatever `release.yml`'s `docker/metadata-action` `tags:`
block says; read it there rather than trusting a copy here.

**No variant tag is built any more.** `:fast`, `:slim`, `:balanced`, `:deep`, `:full`
and every `-<variant>` suffix stopped with v2.0.0. Tags that v1.x releases pushed still
exist on the registries, frozen, so an old pull keeps working and silently stays on
v1.x. The `latest` tag is bare and has never taken a suffix: a suffixed `latest` fails
to pull with "manifest unknown". When tests or scripts need a fixed reference, use
`:latest` or a semver tag.

**Verifying actual published tags:**
```bash
gh api users/jimmy058910/packages/container/jmo-security/versions \
  --jq '.[0:3] | .[] | .metadata.container.tags'
```

## Download Hardening Convention (CRITICAL)

Every binary download in `Dockerfile`'s builder stages MUST use these flags. A single missing flag produces the "tar: not in gzip format" cycle that broke v1.0.3 nightly Docker Smoke Tests repeatedly.

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

**Do not use wget for new downloads.** wget exits non-zero on HTTP errors but **does NOT retry on them by default** — `--tries=N` only covers connection failures. To get curl-equivalent behavior with wget, you'd need `--retry-on-http-error=429,500,502,503,504`, which is easy to forget. The post-v1.0.5 nightly cycle hit this when nuclei's release URL returned a transient HTTP error: `wget --tries=3` did not retry, the build failed, and curl with `--retry-all-errors` would have recovered. PR #350 hardened all `curl` calls but missed 9 `wget` invocations spanning nuclei, ZAP and others across the Dockerfiles of the time; the follow-up PR converts every download to the curl pattern above and adds `tests/unit/test_dockerfile_download_hardening.py` as a drift guard against re-introducing wget in builder stages.

**Integrity check** (mandatory before extracting an archive — belt-and-suspenders for "200 with corrupt body" that even `--fail` can miss):

```dockerfile
gzip -t /tmp/foo.tar.gz && \      # before tar -xzf
xz -t /tmp/foo.tar.xz && \         # before tar -xJf
unzip -t /tmp/foo.zip > /dev/null  # before unzip
```

Binary-only downloads (no extraction step) don't need an integrity check — `--fail` plus the runtime version-check (`<tool> --version` in the verify stage) catches HTTP errors and serving-the-wrong-file mistakes.

**Checksum verification: keep the canonical asset filename.** When a project publishes a `*_checksums.txt`, `sha256sum -c` resolves the path written *inside* that line and opens it from the working directory — it does not check whatever you piped in. So renaming the download breaks verification permanently, and the failure is easy to misread as a corrupt file:

```dockerfile
# WRONG - can never verify: the checksums line names the original asset
curl -fsSL "$URL/actionlint_1.7.12_linux_amd64.tar.gz" -o actionlint.tar.gz
grep " actionlint_1.7.12_linux_amd64.tar.gz$" checksums.txt | sha256sum -c -
#   -> sha256sum: actionlint_1.7.12_linux_amd64.tar.gz: No such file or directory
#      FAILED open or read

# RIGHT - save under the name the checksums file uses
archive="actionlint_1.7.12_linux_amd64.tar.gz"
curl -fsSL "$URL/$archive" -o "$archive"
grep " ${archive}$" checksums.txt | sha256sum -c -
```

Found in a documented recipe that had never been run (#749). It fails loudly rather than silently, but it fails on *every* invocation, so a recipe carrying it has provably never been executed. Run any download recipe you write.

**Why this matters**: Every binary is downloaded once per architecture per release, so single-attempt downloads at even a 0.5% CDN flake rate turn into a transient failure in many release cycles. The v1.0.3 cycle saw multiple Docker Smoke Test failures from this exact pattern (trufflehog, trivy, others — each different binary on different runs). Hardening landed in PR #349.

## A Later `pip install` Pass Can Silently Downgrade an Earlier Tool

`Dockerfile` installs its Python tools in separate `pip install` passes, and **a later
pass cannot see the constraints of an earlier one**: it re-resolves shared transitive
dependencies from scratch, and whatever it picks wins. The first `v1.1.0` tag attempt
failed 6 of 8 Docker builds this way: a later pass (prowler's, since removed) lifted
`opentelemetry-sdk` past semgrep's `~=1.37.0` pin, and `semgrep --version` died with
`ImportError: cannot import name 'LogData'`. So pin the shared dependency on the later
pass (reordering only changes which tool loses), re-run the earlier tool's `--version`
after it, and read pip's "dependency resolver does not currently take into account"
block rather than the exit code. `mcp` 2.0.0 requires `opentelemetry-api`, so adding the
`[mcp]` extra to the image would reopen this against semgrep's pin.

## `.dockerignore` Patterns Are Root-Anchored (`.gitignore` Is Not)

The two files look alike and match differently. Git treats a pattern with no
leading slash as matching **at any depth**; Docker anchors at the context root
unless the pattern is prefixed with `**/`.

So `node_modules/` in `.dockerignore` excluded `./node_modules` and nothing
else. `scripts/dashboard/node_modules` (237MB) and `scripts/api/node_modules`
(23MB) were shipped into every locally-built image via `COPY . /opt/jmo-security/`,
while `git check-ignore` cheerfully reported them ignored.

**Release images were never affected** — both directories are gitignored, so the
bare `actions/checkout@v7` in `release.yml`'s `docker-build-*` jobs never had
them, and no `npm install` runs before the build. This is a local-build defect
only, and worth stating that way: an image-size or context finding must name
which artifact it is about.

Symptom: `docker build` sits on `transferring context: NNNMB` for minutes.
Measured before the fix: **632MB and climbing**; `graphify-out/` (411MB, also
unlisted) plus the two `node_modules` accounted for it. After adding `**/node_modules/`
and `graphify-out/`, a build of the smallest image of the time completed in 4m19s.

When adding an ignore rule for something that can appear in a subdirectory, write
`**/name/`, and check the transferred context size rather than assuming the rule
took.

## Image Size Measurement Dimension

Two different "size" dimensions exist for Docker images:

| Dimension | What it measures | Example value (v1.0.3 all-tools image) |
|-----------|------------------|------------------------------|
| Compressed pull | Bytes downloaded from registry | ~2.0 GB |
| Uncompressed | Total layer size on disk after extraction | ~6.2 GB |

`docker image inspect --format={{.Size}}` returns the UNCOMPRESSED size. The `release.yml` "Benchmark Docker Image Sizes" step emits compressed numbers (different scale).

When setting size thresholds in tests (`tests/e2e/test_docker_workflows.py::IMAGE_SIZE_RANGE`), confirm which dimension `docker image inspect` uses for that test, then set thresholds accordingly. The compressed-vs-uncompressed mismatch silently broke `test_image_size_within_range` for several releases until exposed in the post-v1.0.3 archeology.

## Docker arm64 (Linux/ARM64)

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
docker buildx build --platform linux/arm64 -f Dockerfile .

# Or run an existing arm64 image
docker run --platform linux/arm64 ghcr.io/jimmy058910/jmo-security:latest --version
```

**Reference:** [docs/DOCKER_README.md](../../docs/DOCKER_README.md) for detailed registry and image selection guidance.
