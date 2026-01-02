# Build Time Optimization Guide

**Status:** Planned Enhancement (post-v1.0.0)
**Priority:** Medium - Performance improvement for development workflow
**Estimated Effort:** 8-12 hours implementation + testing

---

## Overview

This document outlines planned optimizations to reduce Docker build times and CLI tool installation times. Current full build takes ~12 minutes on typical hardware; these optimizations target a 40-60% reduction.

### Current Performance Baseline

| Variant | Tools | Docker Build | CLI Install |
|---------|-------|--------------|-------------|
| fast | 8 | 5-10 min | 5-10 min |
| slim | 14 | 12-18 min | 12-18 min |
| balanced | 18 | 18-25 min | 18-25 min |
| deep | 28 | 40-70 min | 40-70 min |

### Target Performance

| Variant | Docker Build | CLI Install | Improvement |
|---------|--------------|-------------|-------------|
| fast | 3-5 min | 2-4 min | ~40% |
| slim | 5-8 min | 4-7 min | ~50% |
| balanced | 8-12 min | 6-10 min | ~50% |
| deep | 15-25 min | 15-25 min | ~60% |

---

## Part 1: Docker Build Optimization

### 1.1 Parallel Binary Downloads with BuildKit Heredocs

**Problem:**
The builder stage contains 17 sequential RUN commands for downloading binaries. Each download waits for the previous to complete, even though they are completely independent.

**Current Pattern (Sequential):**

```dockerfile
# Each RUN creates a layer and blocks until complete
RUN TRUFFLEHOG_VERSION="3.91.1" && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/..." \
    -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog

RUN SYFT_VERSION="1.38.0" && \
    curl -sSL "https://github.com/anchore/syft/releases/..." \
    -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft

# ... 15 more sequential downloads
```

**Optimized Pattern (Parallel with BuildKit Heredocs):**

```dockerfile
# syntax=docker/dockerfile:1.4
FROM ubuntu:22.04 AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget unzip ca-certificates && rm -rf /var/lib/apt/lists/*

# Download ALL binaries in parallel using background jobs
RUN <<'EOF'
#!/bin/bash
set -e

# Architecture detection
ARCH_AMD64_ARM64=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64")
ARCH_X86_ARM64=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64")
ARCH_AARCH64_X86=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64")
TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit")

mkdir -p /downloads

# Start all downloads in parallel (background jobs)
(
  echo "Downloading TruffleHog..."
  curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v3.91.1/trufflehog_3.91.1_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/trufflehog.tar.gz
) &

(
  echo "Downloading Syft..."
  curl -sSL "https://github.com/anchore/syft/releases/download/v1.38.0/syft_1.38.0_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/syft.tar.gz
) &

(
  echo "Downloading Trivy..."
  curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v0.67.2/trivy_0.67.2_Linux-${TRIVY_ARCH}.tar.gz" \
    -o /downloads/trivy.tar.gz
) &

(
  echo "Downloading Hadolint..."
  curl -sSL "https://github.com/hadolint/hadolint/releases/download/v2.14.0/hadolint-Linux-${ARCH_X86_ARM64}" \
    -o /downloads/hadolint
) &

(
  echo "Downloading Nuclei..."
  wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.5.1/nuclei_3.5.1_linux_${ARCH_AMD64_ARM64}.zip" \
    -O /downloads/nuclei.zip
) &

(
  echo "Downloading Kubescape..."
  curl -sSL "https://github.com/kubescape/kubescape/releases/download/v3.0.47/kubescape_3.0.47_linux_${ARCH_AMD64_ARM64}" \
    -o /downloads/kubescape
) &

(
  echo "Downloading Gosec..."
  curl -sSL "https://github.com/securego/gosec/releases/download/v2.22.10/gosec_2.22.10_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/gosec.tar.gz
) &

(
  echo "Downloading Grype..."
  curl -sSL "https://github.com/anchore/grype/releases/download/v0.104.0/grype_0.104.0_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/grype.tar.gz
) &

(
  echo "Downloading Bearer..."
  curl -sSL "https://github.com/bearer/bearer/releases/download/v1.51.1/bearer_1.51.1_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/bearer.tar.gz
) &

(
  echo "Downloading Horusec..."
  curl -sSL "https://github.com/ZupIT/horusec/releases/download/v2.8.0/horusec_linux_${ARCH_AMD64_ARM64}" \
    -o /downloads/horusec
) &

(
  echo "Downloading ZAP..."
  wget -q "https://github.com/zaproxy/zaproxy/releases/download/v2.16.1/ZAP_2.16.1_Linux.tar.gz" \
    -O /downloads/zap.tar.gz
) &

(
  echo "Downloading Dependency-Check..."
  wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/v11.1.1/dependency-check-11.1.1-release.zip" \
    -O /downloads/dependency-check.zip
) &

(
  echo "Downloading shfmt..."
  curl -sSL "https://github.com/mvdan/sh/releases/download/v3.12.0/shfmt_v3.12.0_linux_${ARCH_AMD64_ARM64}" \
    -o /downloads/shfmt
) &

(
  echo "Downloading Falcoctl..."
  curl -sSL "https://github.com/falcosecurity/falcoctl/releases/download/v0.11.4/falcoctl_${FALCOCTL_VERSION}_linux_${ARCH_AMD64_ARM64}.tar.gz" \
    -o /downloads/falcoctl.tar.gz
) &

(
  echo "Downloading Nosey Parker..."
  curl -sSL "https://github.com/praetorian-inc/noseyparker/releases/download/v0.24.0/noseyparker-v0.24.0-${ARCH_AARCH64_X86}-unknown-linux-musl.tar.gz" \
    -o /downloads/noseyparker.tar.gz
) &

(
  echo "Downloading Lynis..."
  curl -sSL "https://github.com/CISOfy/lynis/archive/refs/tags/3.1.3.tar.gz" \
    -o /downloads/lynis.tar.gz
) &

# Wait for ALL downloads to complete
wait

echo "All downloads completed successfully"
ls -la /downloads/
EOF

# Extract all archives in a single layer (sequential but fast - local I/O)
RUN <<'EOF'
#!/bin/bash
set -e

# Tarballs to /usr/local/bin
tar -xzf /downloads/trufflehog.tar.gz -C /tmp && mv /tmp/trufflehog /usr/local/bin/
tar -xzf /downloads/syft.tar.gz -C /usr/local/bin syft
tar -xzf /downloads/trivy.tar.gz -C /usr/local/bin trivy
tar -xzf /downloads/gosec.tar.gz -C /usr/local/bin gosec
tar -xzf /downloads/grype.tar.gz -C /usr/local/bin grype
tar -xzf /downloads/bearer.tar.gz -C /usr/local/bin bearer
tar -xzf /downloads/falcoctl.tar.gz -C /usr/local/bin falcoctl
tar -xzf /downloads/noseyparker.tar.gz -C /tmp && mv /tmp/bin/noseyparker /usr/local/bin/

# Large archives to /opt
tar -xzf /downloads/zap.tar.gz -C /opt && mv /opt/ZAP_* /opt/zaproxy
tar -xzf /downloads/lynis.tar.gz -C /opt && mv /opt/lynis-* /opt/lynis
unzip -q /downloads/nuclei.zip -d /usr/local/bin
unzip -q /downloads/dependency-check.zip -d /opt

# Direct binaries
mv /downloads/hadolint /usr/local/bin/
mv /downloads/shfmt /usr/local/bin/
mv /downloads/kubescape /usr/local/bin/
mv /downloads/horusec /usr/local/bin/

# Set permissions
chmod +x /usr/local/bin/*

# Cleanup
rm -rf /downloads

echo "All tools extracted successfully"
EOF
```

**Time Savings:** 10-15 minutes (17 sequential downloads run in parallel in ~2-3 min)

**Risk Assessment:** LOW

- BuildKit heredocs are stable since Docker BuildKit 1.4
- Background jobs with `wait` ensure all complete before proceeding
- If any download fails, entire RUN fails (maintains atomicity)

---

### 1.2 Batch pip Installs

**Problem:**
8 separate pip install commands in the runtime stage, each with its own dependency resolution.

**Current Pattern:**

```dockerfile
RUN python3 -m pip install --no-cache-dir bandit==1.9.2 && echo "done"
RUN python3 -m pip install --no-cache-dir semgrep==1.144.0 && semgrep --version
RUN python3 -m pip install --no-cache-dir checkov==3.2.495 && checkov --version
RUN python3 -m pip install --no-cache-dir ruff==0.14.6 && echo "done"
RUN python3 -m pip install --no-cache-dir yara-python==4.5.2 && echo "done"
RUN python3 -m pip install --no-cache-dir scancode-toolkit==32.4.1 && scancode --version
RUN python3 -m pip install --no-cache-dir prowler==5.13.1 && prowler --version
```

**Optimized Pattern:**

```dockerfile
# Install all Python packages in a single pip invocation
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
    bandit==1.9.2 \
    semgrep==1.144.0 \
    checkov==3.2.495 \
    ruff==0.14.6 \
    yara-python==4.5.2 \
    scancode-toolkit==32.4.1 \
    prowler==5.13.1 && \
    # Verify critical tools
    semgrep --version && \
    checkov --version && \
    prowler --version && \
    scancode --version && \
    # Cleanup bytecode in same layer
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true
```

**Time Savings:** 3-5 minutes (single dependency resolution instead of 8)

**Risk Assessment:** LOW

- pip resolves dependencies once instead of 8 times
- Single layer reduces image size slightly
- Verification commands ensure tools work

---

### 1.3 Nuclei Template Optimization

**Problem:**
Nuclei template update downloads ~400MB of templates on every build (3-8 minutes).

**Current Pattern (all variants):**

```dockerfile
RUN nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities,apis -silent
```

**Optimized Pattern (variant-specific):**

```dockerfile
# Fast variant: minimal templates (~50MB, ~1 min)
RUN nuclei -update-templates -tl cves,exposures -silent

# Slim variant: moderate templates (~100MB, ~2 min)
RUN nuclei -update-templates -tl cves,misconfigurations,exposures -silent

# Balanced variant: broader templates (~150MB, ~3 min)
RUN nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities -silent

# Deep variant: full templates (current - 400MB, 3-8 min)
RUN nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities,apis -silent
```

**Time Savings:** 2-5 minutes for fast/slim/balanced variants

**Risk Assessment:** MEDIUM

- Reduces scanning coverage for faster variants
- Users needing full templates should use deep variant
- Document the template differences per variant

---

### 1.4 BuildKit Cache Mounts

**Problem:**
apt and pip caches are cleared after each build, requiring full re-download on rebuilds.

**Optimized Pattern:**

```dockerfile
# syntax=docker/dockerfile:1.4

# Apt with cache mount (persists between builds on same host)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip git ca-certificates jq shellcheck openjdk-17-jre-headless curl

# Pip with cache mount
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install \
    bandit==1.9.2 \
    semgrep==1.144.0 \
    checkov==3.2.495 \
    # ...
```

**Time Savings:** 1-2 minutes on rebuilds (apt/pip caches persist)

**Risk Assessment:** LOW

- Cache mounts are stable BuildKit feature
- Requires `DOCKER_BUILDKIT=1` (recommended anyway)
- Cache is local to build host (not in image)

---

### 1.5 Layer Consolidation

**Problem:**
Build dependencies installed and removed in separate layers.

**Optimized Pattern:**

```dockerfile
# Single layer for Python compilation dependencies + pip install + cleanup
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ python3-dev libffi-dev libssl-dev pkg-config libicu-dev && \
    python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
    bandit==1.9.2 semgrep==1.144.0 checkov==3.2.495 ruff==0.14.6 \
    yara-python==4.5.2 scancode-toolkit==32.4.1 prowler==5.13.1 && \
    npm install -g @cyclonedx/cdxgen@12.0.0 && npm cache clean --force && \
    apt-get purge -y gcc g++ python3-dev libffi-dev libssl-dev pkg-config libicu-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
```

**Time Savings:** 30s-1 min (fewer layers, better cache utilization)

---

## Part 2: CLI Parallel Installation

### 2.1 Current Implementation Analysis

**File:** `scripts/cli/tool_installer.py`

The `parallel` parameter exists but is not implemented:

```python
def install_profile(
    self,
    profile: str,
    skip_installed: bool = True,
    parallel: bool = False,  # NOT IMPLEMENTED
) -> InstallProgress:
    # Sequential loop
    for i, tool_name in enumerate(tools):
        result = self.install_tool(tool_name)  # BLOCKING
        progress.add_result(result)
```

### 2.2 Parallel Installation Implementation

**Add to `scripts/cli/tool_installer.py`:**

```python
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


@dataclass
class ParallelInstallProgress:
    """Thread-safe installation progress tracker."""

    total: int
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    current_tools: list[str] = field(default_factory=list)
    results: list[InstallResult] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def on_start(self, tool_name: str) -> None:
        """Called when a tool installation begins."""
        with self._lock:
            self.current_tools.append(tool_name)

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        """Called when a tool installation completes."""
        with self._lock:
            if tool_name in self.current_tools:
                self.current_tools.remove(tool_name)
            self.results.append(result)
            if result.success:
                self.completed += 1
            elif getattr(result, 'skipped', False):
                self.skipped += 1
            else:
                self.failed += 1

    def get_status_line(self) -> str:
        """Get current progress status for display."""
        with self._lock:
            done = self.completed + self.failed + self.skipped
            running = ", ".join(self.current_tools[:3])
            if len(self.current_tools) > 3:
                running += f" +{len(self.current_tools) - 3}"
            return f"[{done}/{self.total}] Installing: {running}"


def install_profile_parallel(
    self,
    profile: str,
    skip_installed: bool = True,
    max_workers: int = 4,
    progress_callback: Callable[[str, str], None] | None = None,
) -> InstallProgress:
    """
    Install tools for a profile in parallel.

    Args:
        profile: Profile name ('fast', 'slim', 'balanced', 'deep')
        skip_installed: Skip already-installed tools (default: True)
        max_workers: Maximum concurrent installations (default: 4)
        progress_callback: Optional callback(tool_name, status) for progress

    Returns:
        InstallProgress with results for all tools
    """
    from scripts.core.tool_registry import PROFILE_TOOLS

    tools = PROFILE_TOOLS.get(profile, [])

    # Separate tools by installation strategy
    pip_tools = []
    other_tools = []

    for tool_name in tools:
        if skip_installed and self._is_installed(tool_name):
            continue

        tool_info = self.registry.get_tool(tool_name)
        if tool_info and tool_info.pypi_package:
            pip_tools.append(tool_name)
        else:
            other_tools.append(tool_name)

    results = []
    progress = ParallelInstallProgress(total=len(pip_tools) + len(other_tools))

    # Strategy 1: Batch pip installs (single subprocess, thread-safe)
    if pip_tools:
        pip_results = self._batch_pip_install(pip_tools, progress_callback)
        results.extend(pip_results)

    # Strategy 2: Parallel download/install for other tools
    if other_tools:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {}
            for tool_name in other_tools:
                future = executor.submit(
                    self._install_tool_threadsafe,
                    tool_name,
                    progress,
                    progress_callback,
                )
                future_to_tool[future] = tool_name

            for future in as_completed(future_to_tool):
                tool_name = future_to_tool[future]
                try:
                    result = future.result(timeout=600)
                    results.append(result)
                except TimeoutError:
                    results.append(InstallResult(
                        tool_name=tool_name,
                        success=False,
                        message="Installation timed out after 10 minutes",
                    ))
                except Exception as e:
                    logger.error(f"Installation failed for {tool_name}: {e}")
                    results.append(InstallResult(
                        tool_name=tool_name,
                        success=False,
                        message=str(e),
                    ))

    return InstallProgress(total=len(tools), results=results)


def _install_tool_threadsafe(
    self,
    tool_name: str,
    progress: ParallelInstallProgress,
    callback: Callable[[str, str], None] | None = None,
) -> InstallResult:
    """Thread-safe wrapper around install_tool()."""
    progress.on_start(tool_name)
    if callback:
        callback(tool_name, "start")

    try:
        result = self.install_tool(tool_name)
        progress.on_complete(tool_name, result)
        if callback:
            status = "success" if result.success else "failed"
            callback(tool_name, status)
        return result
    except Exception as e:
        result = InstallResult(tool_name=tool_name, success=False, message=str(e))
        progress.on_complete(tool_name, result)
        if callback:
            callback(tool_name, "failed")
        return result


def _batch_pip_install(
    self,
    pip_tools: list[str],
    callback: Callable[[str, str], None] | None = None,
) -> list[InstallResult]:
    """
    Install multiple pip packages in a single subprocess call.

    More efficient than individual pip install commands because:
    1. Single dependency resolution pass
    2. Shared network connections
    3. Reduced subprocess overhead
    """
    results = []

    # Get package names from tool registry
    packages = []
    for tool_name in pip_tools:
        tool_info = self.registry.get_tool(tool_name)
        if tool_info and tool_info.pypi_package:
            package_spec = f"{tool_info.pypi_package}=={tool_info.version}"
            packages.append(package_spec)

    if not packages:
        return results

    # Notify start for all pip tools
    for tool_name in pip_tools:
        if callback:
            callback(tool_name, "start")

    # Single pip install command for all packages
    cmd = [sys.executable, "-m", "pip", "install", "--quiet"] + packages

    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)

        # All succeeded
        for tool_name in pip_tools:
            results.append(InstallResult(
                tool_name=tool_name,
                success=True,
                method="pip_batch",
            ))
            if callback:
                callback(tool_name, "success")

    except subprocess.CalledProcessError as e:
        # Batch failed - fall back to individual installs
        logger.warning(f"Batch pip install failed: {e.stderr}")
        for tool_name in pip_tools:
            result = self._install_pip(tool_name)
            results.append(result)
            if callback:
                status = "success" if result.success else "failed"
                callback(tool_name, status)

    return results
```

### 2.3 CLI Flag Integration

**File:** `scripts/cli/jmo.py`

Add to install subparser (around line 510):

```python
install_parser.add_argument(
    "--parallel",
    action="store_true",
    help="Install tools in parallel (faster, uses more system resources)",
)
install_parser.add_argument(
    "--jobs", "-j",
    type=int,
    default=4,
    metavar="N",
    help="Number of parallel installation jobs (default: 4, max: 8)",
)
```

**File:** `scripts/cli/tool_commands.py`

Update `cmd_tools_install()`:

```python
def cmd_tools_install(args) -> int:
    """Handle 'jmo tools install' command."""
    installer = ToolInstaller()

    # Determine parallelism
    parallel = getattr(args, 'parallel', False)
    max_workers = min(getattr(args, 'jobs', 4), 8)  # Cap at 8

    if parallel:
        console.print(f"[cyan]Installing tools in parallel (max {max_workers} workers)...[/]")
        results = installer.install_profile_parallel(
            profile=args.profile,
            skip_installed=not args.force,
            max_workers=max_workers,
        )
    else:
        results = installer.install_profile(
            profile=args.profile,
            skip_installed=not args.force,
        )

    return _report_install_results(results)
```

---

## Thread Safety Considerations

### Shared Resources

| Resource | Strategy |
|----------|----------|
| Progress counters | Use `threading.Lock` |
| Console output | Lock around print or use queue |
| File downloads | Use unique temp files per thread |
| pip installs | Batch or serialize with lock |
| Tool registry | Read-only (thread-safe) |

### File Download Safety

Each download must use a unique temp file path:

```python
def _download_binary(self, url: str, tool_name: str) -> Path:
    """Download binary with thread-safe temp file naming."""
    thread_id = threading.current_thread().ident
    timestamp = int(time.time() * 1000)
    temp_name = f".{tool_name}_{thread_id}_{timestamp}.download"
    temp_path = self.bin_dir / temp_name

    response = requests.get(url, stream=True)
    with open(temp_path, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    # Atomic rename to final location
    final_path = self.bin_dir / tool_name
    temp_path.rename(final_path)
    return final_path
```

---

## Testing Strategy

### Build Time Benchmarks

```bash
#!/bin/bash
# benchmark-builds.sh

echo "=== Docker Build Time Benchmark ==="

for variant in "" ".fast" ".slim" ".balanced"; do
    dockerfile="Dockerfile${variant}"
    name="${variant:-deep}"

    echo ""
    echo "Building $name variant..."

    # Clear cache
    docker builder prune -f 2>/dev/null

    # Time the build
    start=$(date +%s)
    DOCKER_BUILDKIT=1 docker build \
        -f "$dockerfile" \
        -t "jmo-test:${name}" \
        --no-cache \
        --progress=plain \
        . 2>&1 | tee "build-${name}.log"
    end=$(date +%s)

    echo "$name: $((end - start)) seconds"
done
```

### Tool Verification

```bash
#!/bin/bash
# verify-tools.sh

for tag in deep balanced slim fast; do
    echo "=== Verifying jmo-test:$tag ==="

    docker run --rm "jmo-test:$tag" jmo --help > /dev/null && echo "  jmo: OK"
    docker run --rm --entrypoint bash "jmo-test:$tag" -c "trufflehog --version" && echo "  trufflehog: OK"
    docker run --rm --entrypoint bash "jmo-test:$tag" -c "semgrep --version" && echo "  semgrep: OK"
    docker run --rm --entrypoint bash "jmo-test:$tag" -c "trivy --version" && echo "  trivy: OK"
    docker run --rm --entrypoint bash "jmo-test:$tag" -c "nuclei --version" && echo "  nuclei: OK"
done
```

### Parallel Installation Tests

```python
# tests/unit/test_tool_installer_parallel.py

import threading
from concurrent.futures import ThreadPoolExecutor
import pytest

from scripts.cli.tool_installer import ParallelInstallProgress, InstallResult


class TestParallelInstallProgress:
    """Test thread-safe progress tracking."""

    def test_concurrent_updates(self):
        """Verify progress tracks correctly under concurrent updates."""
        progress = ParallelInstallProgress(total=100)

        def update_progress(i: int):
            progress.on_start(f"tool_{i}")
            progress.on_complete(f"tool_{i}", InstallResult(
                tool_name=f"tool_{i}", success=True
            ))

        with ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(update_progress, range(100)))

        assert progress.completed == 100
        assert len(progress.current_tools) == 0

    def test_no_race_conditions(self):
        """Stress test for race conditions."""
        progress = ParallelInstallProgress(total=50)
        errors = []

        def stress_test(i: int):
            try:
                for _ in range(100):
                    progress.on_start(f"t{i}")
                    progress.on_complete(f"t{i}", InstallResult(
                        tool_name=f"t{i}", success=True
                    ))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=stress_test, args=(i,))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
```

---

## Implementation Checklist

### Phase 1: Quick Wins (1-2 hours)

- [ ] Add `# syntax=docker/dockerfile:1.4` to all Dockerfiles
- [ ] Consolidate pip installs into single RUN command
- [ ] Reduce Nuclei templates for fast/slim variants
- [ ] Test builds still work

### Phase 2: Docker Parallel Downloads (2-3 hours)

- [ ] Convert builder stage to heredoc parallel pattern
- [ ] Separate download and extraction steps
- [ ] Test on amd64 architecture
- [ ] Test on arm64 architecture
- [ ] Verify all 4 variants build successfully

### Phase 3: CLI Parallel Installation (3-4 hours)

- [ ] Add `ParallelInstallProgress` dataclass
- [ ] Implement `install_profile_parallel()` method
- [ ] Implement `_install_tool_threadsafe()` wrapper
- [ ] Implement `_batch_pip_install()` method
- [ ] Add `--parallel` and `--jobs` CLI flags
- [ ] Update `cmd_tools_install()` handler
- [ ] Add thread safety tests

### Phase 4: Testing & Documentation (2-3 hours)

- [ ] Run build time benchmarks (before/after)
- [ ] Verify all tools work in built images
- [ ] Update CLAUDE.md with new CLI flags
- [ ] Update docs/USER_GUIDE.md

---

## Files to Modify

| File | Changes |
|------|---------|
| `Dockerfile` | BuildKit syntax, parallel downloads, batch pip |
| `Dockerfile.fast` | Same optimizations (fewer tools) |
| `Dockerfile.slim` | Same optimizations |
| `Dockerfile.balanced` | Same optimizations |
| `scripts/cli/tool_installer.py` | Parallel install methods, progress tracking |
| `scripts/cli/tool_commands.py` | Handle --parallel flag |
| `scripts/cli/jmo.py` | Add --parallel, --jobs arguments |
| `tests/unit/test_tool_installer_parallel.py` | New test file |
| `CLAUDE.md` | Document new CLI flags |
| `docs/USER_GUIDE.md` | Document parallel installation |

---

## Notes

### GPU Acceleration

GPU acceleration is **not applicable** to build optimization:

- Bottlenecks are network I/O (downloads) and pip dependency resolution
- No compute-bound operations during builds
- GPU would help only for runtime operations like AFL++ fuzzing

### Alternative Approaches Not Recommended

1. **Docker BuildKit parallel stages**: Not suitable because downloads are in same stage
2. **Multi-Dockerfile pattern**: Would increase maintenance burden
3. **Pre-built binary caching in registry**: Complex infrastructure requirement
4. **Aria2 for parallel downloads**: Adds dependency, curl with `&` is simpler

---

## References

- [Docker BuildKit Documentation](https://docs.docker.com/build/buildkit/)
- [BuildKit Heredocs](https://www.docker.com/blog/introduction-to-heredocs-in-dockerfiles/)
- [Python ThreadPoolExecutor](https://docs.python.org/3/library/concurrent.futures.html)
- [JMo Security Tool Registry](../scripts/core/tool_registry.py)
