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

**Do not use wget for new downloads.** wget exits non-zero on HTTP errors but **does NOT retry on them by default** — `--tries=N` only covers connection failures. To get curl-equivalent behavior with wget, you'd need `--retry-on-http-error=429,500,502,503,504`, which is easy to forget. The post-v1.0.5 nightly cycle hit this when nuclei's release URL returned a transient HTTP error: `wget --tries=3` did not retry, the build failed, and curl with `--retry-all-errors` would have recovered. PR #350 hardened all `curl` calls but missed 9 `wget` invocations spanning nuclei / ZAP / dependency-check across all 4 Dockerfiles; the follow-up PR converts every download to the curl pattern above and adds `tests/unit/test_dockerfile_download_hardening.py` as a drift guard against re-introducing wget in builder stages.

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

**Why this matters**: With ~50 binaries downloaded per release across 4 Dockerfile variants × 2 architectures, single-attempt downloads at even 0.5% CDN flake rate cause one transient failure most release cycles. The v1.0.3 cycle saw multiple Docker Smoke Test failures from this exact pattern (trufflehog, trivy, others — each different binary on different runs). Hardening landed in PR #349.

## A Later `pip install` Pass Can Silently Downgrade an Earlier Tool

`checkov` and `prowler` genuinely conflict on `boto3`, so `Dockerfile.{slim,balanced,deep}`
install prowler in its **own** `pip install`. That split is deliberate and must stay — but
it has a consequence that is not obvious: **a separate pip invocation cannot see the
constraints of the previous one.** It re-resolves shared transitive dependencies from
scratch, and whatever it picks wins.

Measured on the first `v1.1.0` tag attempt (release run `33944824134`), which failed
**6 of 8** Docker builds:

```text
ImportError: cannot import name 'LogData' from 'opentelemetry.sdk._logs'
  -- raised by `semgrep --version` in the tool-verification RUN
```

`semgrep==1.175.0` pins `opentelemetry-{api,sdk,exporter-otlp-proto-http}~=1.37.0`.
prowler's `microsoft-kiota-abstractions` requires `opentelemetry-sdk>=1.27.0` with **no
upper bound**, so its pass resolved the SDK to **1.44.0**, which had removed
`opentelemetry.sdk._logs.LogData`. semgrep's 1.37.0 exporter imports that name.

| Variant | prowler | `pip install` passes | Result |
|---|---|---|---|
| `fast` | no | 2 | PASS both arches |
| `slim` | yes | 3 | FAIL both |
| `balanced` | yes | 5 | FAIL both |
| `deep` | yes | 9 | FAIL both |

**`fast` survived with the identical semgrep pin.** A single pip pass *backtracks* — its
log shows it trying `opentelemetry-instrumentation-requests` 0.65b0, falling back to
0.64b0, and landing consistent. Multi-pass installs cannot backtrack across invocations.

### Rules

1. **Pin the shared dependency on the later pass**, not the earlier one. The fix is
   `pip install prowler==5.40.0 "opentelemetry-sdk~=1.37.0" "opentelemetry-api~=1.37.0"`.
   Reordering the passes only changes which tool loses.
2. **Verify the earlier tool again after the later pass.** All three Dockerfiles now run
   `semgrep --version` immediately after the prowler install, so a future prowler bump
   fails at the install site. `Dockerfile.deep` showed why this matters: its own
   post-install `semgrep --version` at line ~247 **passed**, and only the final
   verification RUN caught the breakage — a hundred lines from the cause.
3. **Read the pip conflict block, not just the exit code.** `pip` prints
   `ERROR: pip's dependency resolver does not currently take into account all the
   packages that are installed` and then lists each conflict. Before the fix there were
   **five** opentelemetry lines; after, **zero**, with the two pre-existing non-otel ones
   (`checkov`/`boto3`, `semgrep`/`jsonschema`) unchanged. That delta is the check —
   a passing `--version` alone only proves this image, not a consistent resolution.
4. **Nothing that installs after prowler may pull opentelemetry.** Verified for the
   current set: `scancode-toolkit` declares none, and `jmo-security`'s base deps and its
   `[reporting]` extra declare none. **`mcp` 2.0.0 DOES require `opentelemetry-api`** —
   it is an optional extra and no Dockerfile installs it. Adding `[mcp]` to an image
   would reintroduce this bug.
5. **This class is upstream drift, not a repo regression.** No JMo pin changed;
   `opentelemetry-sdk` 1.44.0 simply became resolvable. It can recur at any time from a
   new upstream release, which is what rule 2's guard is for.

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
and `graphify-out/`, a `fast` build completed in 4m19s.

When adding an ignore rule for something that can appear in a subdirectory, write
`**/name/`, and check the transferred context size rather than assuming the rule
took.

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
