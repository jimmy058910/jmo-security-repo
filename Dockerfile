# JMo Security Suite - All-in-One Docker Image (Full/Deep - v1.0.0)
# Base: Ubuntu 22.04 with 26 security tools pre-installed + OPA
# Size: ~1.9 GB (optimized) | Tools: 26 Docker-ready scanners | Multi-arch: amd64, arm64
# Note: 3 tools require manual install outside Docker: MobSF, Akto, AFL++ (see docs/MANUAL_INSTALLATION.md)

#
# Stage 1: Builder - Download and extract tools
#
FROM ubuntu:22.04 AS builder

ARG TARGETARCH

# Install build dependencies (curl, tar, wget for downloads + build tools for AFL++)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    unzip \
    ca-certificates \
    build-essential \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

# Download TruffleHog (Secrets - Verified)
RUN TRUFFLEHOG_VERSION="3.91.1" && \
    TRUFFLEHOG_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Download Syft (SBOM)
RUN SYFT_VERSION="1.38.0" && \
    SYFT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz" \
    -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft

# Download Trivy (SCA + Vuln)
RUN TRIVY_VERSION="0.67.2" && \
    TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy

# Download Hadolint (Dockerfile)
RUN HADOLINT_VERSION="2.14.0" && \
    HADOLINT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -sSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HADOLINT_ARCH}" \
    -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Download shfmt (Shell formatting)
RUN SHFMT_VERSION="3.12.0" && \
    SHFMT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/mvdan/sh/releases/download/v${SHFMT_VERSION}/shfmt_v${SHFMT_VERSION}_linux_${SHFMT_ARCH}" \
    -o /usr/local/bin/shfmt && \
    chmod +x /usr/local/bin/shfmt

# Download Falcoctl (Runtime Security)
RUN FALCOCTL_VERSION="0.11.4" && \
    FALCOCTL_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_linux_${FALCOCTL_ARCH}.tar.gz" \
    -o /tmp/falcoctl.tar.gz && \
    tar -xzf /tmp/falcoctl.tar.gz -C /usr/local/bin falcoctl && \
    chmod +x /usr/local/bin/falcoctl

# Download Nosey Parker (Secrets - Backup)
RUN NP_VERSION="0.24.0" && \
    NP_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -sSL "https://github.com/praetorian-inc/noseyparker/releases/download/v${NP_VERSION}/noseyparker-v${NP_VERSION}-${NP_ARCH}-unknown-linux-musl.tar.gz" \
    -o /tmp/noseyparker.tar.gz && \
    tar -xzf /tmp/noseyparker.tar.gz -C /tmp && \
    mv /tmp/bin/noseyparker /usr/local/bin/noseyparker && \
    chmod +x /usr/local/bin/noseyparker

# Download OWASP ZAP (DAST)
RUN ZAP_VERSION="2.16.1" && \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    -O /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy

# Download Nuclei (DAST + API Security)
RUN NUCLEI_VERSION="3.5.1" && \
    TARGETARCH=$(dpkg --print-architecture) && \
    NUCLEI_ARCH=$(case ${TARGETARCH} in amd64) echo "amd64";; arm64) echo "arm64";; *) echo "amd64";; esac) && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities,apis -silent

# NOTE: Prowler 5.x is Python-based (pip install), no binary download needed
# Prowler is installed via pip in the runtime stage

# Download Kubescape (Kubernetes Security)
# Note: Release naming changed from kubescape-ubuntu-{arch} to kubescape_{version}_linux_{arch}
RUN KUBESCAPE_VERSION="3.0.47" && \
    KUBESCAPE_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape_${KUBESCAPE_VERSION}_linux_${KUBESCAPE_ARCH}" \
    -o /usr/local/bin/kubescape && \
    chmod +x /usr/local/bin/kubescape

# Download Gosec (Go SAST)
RUN GOSEC_VERSION="2.22.10" && \
    GOSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz" \
    -o /tmp/gosec.tar.gz && \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec && \
    chmod +x /usr/local/bin/gosec

# Download Grype (SCA + Vuln - Anchore)
RUN GRYPE_VERSION="0.104.0" && \
    GRYPE_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GRYPE_ARCH}.tar.gz" \
    -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype

# Download OSV-Scanner (SCA + Vuln - Google)
RUN OSV_VERSION="2.3.1" && \
    OSV_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_${OSV_ARCH}" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Download Bearer (Data Privacy + SAST)
RUN BEARER_VERSION="1.51.1" && \
    BEARER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz" \
    -o /tmp/bearer.tar.gz && \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer && \
    chmod +x /usr/local/bin/bearer

# Download Lynis (System Hardening)
RUN LYNIS_VERSION="3.1.3" && \
    curl -sSL "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_VERSION}.tar.gz" \
    -o /tmp/lynis.tar.gz && \
    tar -xzf /tmp/lynis.tar.gz -C /opt && \
    mv /opt/lynis-${LYNIS_VERSION} /opt/lynis

# Download OWASP Dependency-Check (SCA + License)
RUN DC_VERSION="12.1.0" && \
    wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip" \
    -O /tmp/dependency-check.zip && \
    unzip -q /tmp/dependency-check.zip -d /opt && \
    mv /opt/dependency-check /opt/dependency-check-cli && \
    rm /tmp/dependency-check.zip

# Download Horusec (Multi-language SAST)
RUN HORUSEC_VERSION="2.8.0" && \
    HORUSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/ZupIT/horusec/releases/download/v${HORUSEC_VERSION}/horusec_linux_${HORUSEC_ARCH}" \
    -o /usr/local/bin/horusec && \
    chmod +x /usr/local/bin/horusec

# Download OPA (Policy-as-Code engine)
RUN OPA_VERSION="1.12.0" && \
    OPA_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${OPA_ARCH}_static" \
    -o /usr/local/bin/opa && \
    chmod +x /usr/local/bin/opa

# NOTE: AFL++ removed from Docker image - requires LLVM/GCC dev headers for full build
# AFL++ is a specialized fuzzing tool; install manually if needed: https://github.com/AFLplusplus/AFLplusplus

#
# Stage 2: Runtime - Complete runtime environment with ALL tools
#
FROM ubuntu:22.04 AS runtime

LABEL org.opencontainers.image.title="JMo Security Suite (Full)"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 27 pre-installed scanners + OPA policy engine + plugin system (v1.0.0)"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="James Moceri <general@jmogaming.com>"
LABEL org.opencontainers.image.url="https://jmotools.com"
LABEL org.opencontainers.image.source="https://github.com/jimmy058910/jmo-security-repo"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent interactive prompts during apt installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}" \
    DOCKER_CONTAINER=1

# Install ONLY runtime dependencies (no curl, wget, tar, build-essential)
# Combined in single RUN to reduce layers, with aggressive cache cleanup
# Note: nodejs/npm installed separately below (need Node 18+ for cdxgen)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    jq \
    shellcheck \
    yara \
    openjdk-17-jre-headless \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Node.js 20 LTS from NodeSource (Ubuntu 22.04 default is v12, too old for cdxgen)
# cdxgen 12.x requires Node.js 18+ for optional chaining (?.) syntax
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    node --version && npm --version

# Clean Java runtime (Phase 1 optimization: 30 MB savings)
RUN rm -rf /usr/lib/jvm/java-17-openjdk-*/man \
    /usr/lib/jvm/java-17-openjdk-*/legal \
    /usr/share/doc \
    /usr/share/man \
    /usr/share/locale

# Install Python security tools (pip)
# Note: horusec is a Go binary (from builder stage), not a pip package
# Install build deps temporarily for packages that may need compilation
# pkg-config + libicu-dev needed for pyicu (scancode-toolkit dependency)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libssl-dev \
    pkg-config \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip first
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python security tools one by one for better error visibility
RUN python3 -m pip install --no-cache-dir bandit==1.9.2 && \
    echo "✓ bandit installed"

RUN python3 -m pip install --no-cache-dir semgrep==1.146.0 && \
    semgrep --version && \
    echo "✓ semgrep installed"

RUN python3 -m pip install --no-cache-dir checkov==3.2.495 && \
    checkov --version && \
    echo "✓ checkov installed"

RUN python3 -m pip install --no-cache-dir ruff==0.14.6 && \
    echo "✓ ruff installed"

RUN python3 -m pip install --no-cache-dir yara-python==4.5.2 && \
    echo "✓ yara-python installed"

RUN python3 -m pip install --no-cache-dir scancode-toolkit==32.4.1 && \
    scancode --version && \
    echo "✓ scancode-toolkit installed"

RUN python3 -m pip install --no-cache-dir prowler==5.13.1 && \
    prowler --version && \
    echo "✓ prowler installed"

# Install Node.js tools (cdxgen) - MUST be before apt cleanup
RUN npm install -g @cyclonedx/cdxgen@12.0.0 && \
    npm cache clean --force && \
    echo "✓ cdxgen installed"

# Clean up build dependencies to reduce image size
# Note: keep libicu70 runtime lib, only remove dev packages
# Don't use autoremove as it may remove nodejs/npm
RUN apt-get update && apt-get purge -y gcc g++ python3-dev libffi-dev libssl-dev pkg-config libicu-dev \
    && rm -rf /var/lib/apt/lists/* \
    && find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Copy compiled binaries from builder stage
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/shfmt /usr/local/bin/shfmt
COPY --from=builder /usr/local/bin/falcoctl /usr/local/bin/falcoctl
COPY --from=builder /usr/local/bin/noseyparker /usr/local/bin/noseyparker
# NOTE: Prowler 5.x is installed via pip, no binary to copy
COPY --from=builder /usr/local/bin/kubescape /usr/local/bin/kubescape
COPY --from=builder /usr/local/bin/gosec /usr/local/bin/gosec
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /usr/local/bin/bearer /usr/local/bin/bearer
COPY --from=builder /usr/local/bin/horusec /usr/local/bin/horusec
COPY --from=builder /usr/local/bin/opa /usr/local/bin/opa
COPY --from=builder /opt/zaproxy /opt/zaproxy
COPY --from=builder /opt/lynis /opt/lynis
COPY --from=builder /opt/dependency-check-cli /opt/dependency-check-cli

# NOTE: AFL++ removed - see comment in builder stage

# Binary stripping (Phase 1 optimization: 15 MB savings)
RUN strip /usr/local/bin/trufflehog \
    /usr/local/bin/syft \
    /usr/local/bin/trivy \
    /usr/local/bin/hadolint \
    /usr/local/bin/nuclei \
    /usr/local/bin/gosec \
    /usr/local/bin/grype \
    /usr/local/bin/bearer \
    /usr/local/bin/horusec \
    /usr/local/bin/opa \
    2>/dev/null || true

# Create symlinks and wrapper scripts for easier invocation
# ZAP and Dependency-Check work fine as symlinks
RUN ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap && \
    chmod +x /usr/local/bin/zap && \
    ln -s /opt/dependency-check-cli/bin/dependency-check.sh /usr/local/bin/dependency-check && \
    chmod +x /usr/local/bin/dependency-check

# Lynis requires its include/db/plugins directories in specific locations.
# It searches: /usr/local/include/lynis, /usr/local/lynis/include, /usr/share/lynis/include
# We install to /usr/local/lynis (one of the expected paths) and symlink the binary.
RUN mkdir -p /usr/local/lynis && \
    cp -r /opt/lynis/* /usr/local/lynis/ && \
    ln -sf /usr/local/lynis/lynis /usr/local/bin/lynis && \
    chmod +x /usr/local/bin/lynis /usr/local/lynis/lynis

# Mark cache directories as volumes for persistence
VOLUME ["/root/.cache/trivy", "/root/.cache/grype"]

# Create working directory
WORKDIR /scan

# =============================================================================
# CACHE OPTIMIZATION: Use .dockerignore to minimize context (Phase 2)
# This reduces context transfer time and improves cache efficiency
# Combined with GitHub Actions cache-from/cache-to for layer caching
# =============================================================================
COPY . /opt/jmo-security/

# Copy default config to WORKDIR for profile loading
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo Security Suite with optional reporting dependencies
# Clean up pip cache and bytecode immediately after install (Phase 1: 40 MB savings)
RUN cd /opt/jmo-security && \
    python3 -m pip install --no-cache-dir -e ".[reporting]" && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Verify all 27 tools are installed and accessible
RUN echo "=== Verifying all 27 tools ===" && \
    python3 --version && \
    jmo --help > /dev/null && \
    jmo tools --help > /dev/null && \
    trufflehog --version && \
    noseyparker --version && \
    semgrep --version && \
    bandit --version && \
    syft version && \
    trivy --version && \
    osv-scanner --version && \
    checkov --version && \
    hadolint --version && \
    zap -version && \
    nuclei -version && \
    yara --version && \
    falcoctl version && \
    shellcheck --version && \
    shfmt --version && \
    prowler --version && \
    kubescape version && \
    gosec --version && \
    grype version && \
    bearer version && \
    lynis --version && \
    dependency-check --version && \
    horusec version && \
    scancode --version && \
    cdxgen --version && \
    opa version && \
    echo "=== All 27 tools verified ==="

# Create non-root user and set ownership (Security best practice)
# Note: /root/.local may not exist if pip installed to /usr/local instead
RUN useradd -m -u 1000 -s /bin/bash jmo && \
    mkdir -p /root/.local /home/jmo/.cache /home/jmo/.local && \
    chown -R jmo:jmo /opt/jmo-security /scan /root/.cache /root/.local /home/jmo && \
    chmod -R 755 /opt/jmo-security

# Update PATH environment variable for non-root user
# Set DOCKER_CONTAINER=1 to enable Docker-specific behaviors (skip first-run prompts)
ENV PATH="/home/jmo/.local/bin:${PATH}" \
    DOCKER_CONTAINER=1

# Switch to non-root user
USER jmo

# Set default entrypoint to jmo CLI
ENTRYPOINT ["jmo"]

# Default command: show help
CMD ["--help"]

# Health check: verify jmo command works
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD jmo --help > /dev/null || exit 1

# Usage examples (documented in metadata):
# Basic scan (deep profile, all 27 tools):
# docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:1.0.0-full scan --repo /scan --results /scan/results --profile deep
#
# CI mode with caching (30s faster on subsequent runs):
# docker run --rm -v $(pwd):/scan -v trivy-cache:/root/.cache/trivy -v grype-cache:/root/.cache/grype \
#   ghcr.io/jimmy058910/jmo-security:1.0.0-full ci --repo /scan --fail-on HIGH --profile
#
# v1.0.0 Optimizations:
# - Multi-stage builds: Reduced image size by 21% (2.49 GB → 1.97 GB)
# - Phase 1 optimizations: Nuclei template filtering (65 MB), Python bytecode cleanup (40 MB), binary stripping (15 MB), Java cleanup (30 MB), Git metadata exclusion (5 MB)
# - Volume mounting: Use -v trivy-cache:/root/.cache/trivy for persistent caching
# - Tool count: 12 → 27 tools (26 Docker-ready, 2 manual install)
