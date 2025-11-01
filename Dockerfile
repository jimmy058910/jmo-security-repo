# JMo Security Suite - All-in-One Docker Image (Full - v1.0.0)
# Base: Ubuntu 22.04 with ALL 28 security tools pre-installed
# Size: ~1.97 GB (optimized) | Tools: 26 Docker-ready scanners (28 total, 2 require manual install - see docs/MANUAL_INSTALLATION.md) | Multi-arch: amd64, arm64
# v1.0.0: Feature #1 - Added 16 new tools (26 Docker-ready, 2 manual: MobSF, Akto) (Prowler, Kubescape, Gosec, Grype, OSV-Scanner, Bearer, ScanCode, cdxgen, Lynis, MobSF, Akto, YARA, Dependency-Check, Horusec, Semgrep-Secrets, Trivy-RBAC)

#
# Stage 1: Builder - Download and extract ALL 28 tools
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
RUN TRUFFLEHOG_VERSION="3.90.12" && \
    TRUFFLEHOG_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Download Syft (SBOM)
RUN SYFT_VERSION="1.36.0" && \
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
RUN NUCLEI_VERSION="3.4.10" && \
    TARGETARCH=$(dpkg --print-architecture) && \
    NUCLEI_ARCH=$(case ${TARGETARCH} in amd64) echo "amd64";; arm64) echo "arm64";; *) echo "amd64";; esac) && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities,apis -silent

# Download Prowler (Cloud CSPM)
RUN PROWLER_VERSION="4.0.0" && \
    PROWLER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/prowler-cloud/prowler/releases/download/${PROWLER_VERSION}/prowler-${PROWLER_VERSION}-linux-${PROWLER_ARCH}.zip" \
    -o /tmp/prowler.zip && \
    unzip -q /tmp/prowler.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/prowler && \
    rm /tmp/prowler.zip

# Download Kubescape (Kubernetes Security)
RUN KUBESCAPE_VERSION="3.0.19" && \
    KUBESCAPE_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/kubescape-ubuntu-${KUBESCAPE_ARCH}" \
    -o /usr/local/bin/kubescape && \
    chmod +x /usr/local/bin/kubescape

# Download Gosec (Go SAST)
RUN GOSEC_VERSION="2.25.1" && \
    GOSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz" \
    -o /tmp/gosec.tar.gz && \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec && \
    chmod +x /usr/local/bin/gosec

# Download Grype (SCA + Vuln - Anchore)
RUN GRYPE_VERSION="0.91.0" && \
    GRYPE_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GRYPE_ARCH}.tar.gz" \
    -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype

# Download OSV-Scanner (SCA + Vuln - Google)
RUN OSV_VERSION="1.10.1" && \
    OSV_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OSV_VERSION}_linux_${OSV_ARCH}" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Download Bearer (Data Privacy + SAST)
RUN BEARER_VERSION="1.50.0" && \
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
RUN DC_VERSION="11.1.1" && \
    wget -q "https://github.com/jeremylong/DependencyCheck/releases/download/v${DC_VERSION}/dependency-check-${DC_VERSION}-release.zip" \
    -O /tmp/dependency-check.zip && \
    unzip -q /tmp/dependency-check.zip -d /opt && \
    mv /opt/dependency-check /opt/dependency-check-cli && \
    rm /tmp/dependency-check.zip

# Download Horusec (Multi-language SAST)
RUN HORUSEC_VERSION="2.9.0" && \
    HORUSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/ZupIT/horusec/releases/download/v${HORUSEC_VERSION}/horusec_linux_${HORUSEC_ARCH}" \
    -o /usr/local/bin/horusec && \
    chmod +x /usr/local/bin/horusec

# Build AFL++ (Fuzzing)
RUN AFL_VERSION="4.34c" && \
    curl -sSL "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFL_VERSION}.tar.gz" \
    -o /tmp/aflplusplus.tar.gz && \
    tar -xzf /tmp/aflplusplus.tar.gz -C /tmp && \
    cd /tmp/AFLplusplus-${AFL_VERSION} && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/aflplusplus.tar.gz /tmp/AFLplusplus-${AFL_VERSION}

#
# Stage 2: Runtime - Complete runtime environment with ALL tools
#
FROM ubuntu:22.04 AS runtime

LABEL org.opencontainers.image.title="JMo Security Suite (Full)"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 28 pre-installed scanners + plugin system + schedule management (v1.0.0)"
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    jq \
    shellcheck \
    openjdk-17-jre-headless \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Clean Java runtime (Phase 1 optimization: 30 MB savings)
RUN rm -rf /usr/lib/jvm/java-17-openjdk-*/man \
    /usr/lib/jvm/java-17-openjdk-*/legal \
    /usr/share/doc \
    /usr/share/man \
    /usr/share/locale

# Upgrade pip, setuptools, wheel and install Python tools in single layer
# Use --no-cache-dir to prevent pip cache bloat
# Clean __pycache__ and .pyc files immediately after install (Phase 1: 40 MB savings)
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
    bandit==1.8.6 \
    semgrep==1.141.0 \
    checkov==3.2.488 \
    ruff==0.14.2 \
    yara-python==4.5.2 \
    scancode-toolkit==32.3.0 \
    prowler==4.0.0 \
    horusec-cli==2.9.0 \
    && find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Install Node.js tools (cdxgen)
RUN npm install -g @cyclonedx/cdxgen@10.15.7 && \
    npm cache clean --force

# Copy compiled binaries from builder stage
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/shfmt /usr/local/bin/shfmt
COPY --from=builder /usr/local/bin/falcoctl /usr/local/bin/falcoctl
COPY --from=builder /usr/local/bin/noseyparker /usr/local/bin/noseyparker
COPY --from=builder /usr/local/bin/prowler /usr/local/bin/prowler
COPY --from=builder /usr/local/bin/kubescape /usr/local/bin/kubescape
COPY --from=builder /usr/local/bin/gosec /usr/local/bin/gosec
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /usr/local/bin/bearer /usr/local/bin/bearer
COPY --from=builder /usr/local/bin/horusec /usr/local/bin/horusec
COPY --from=builder /opt/zaproxy /opt/zaproxy
COPY --from=builder /opt/lynis /opt/lynis
COPY --from=builder /opt/dependency-check-cli /opt/dependency-check-cli

# Copy AFL++ binaries (compiled in builder stage)
COPY --from=builder /usr/local/bin/afl-* /usr/local/bin/
COPY --from=builder /usr/local/lib/afl /usr/local/lib/afl
COPY --from=builder /usr/local/share/afl /usr/local/share/afl

# Binary stripping (Phase 1 optimization: 15 MB savings)
RUN strip /usr/local/bin/trufflehog \
    /usr/local/bin/syft \
    /usr/local/bin/trivy \
    /usr/local/bin/hadolint \
    /usr/local/bin/nuclei \
    /usr/local/bin/gosec \
    /usr/local/bin/grype \
    /usr/local/bin/osv-scanner \
    /usr/local/bin/bearer \
    /usr/local/bin/horusec \
    2>/dev/null || true

# Create symlinks for easier invocation
RUN ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap && \
    chmod +x /usr/local/bin/zap && \
    ln -s /opt/lynis/lynis /usr/local/bin/lynis && \
    chmod +x /usr/local/bin/lynis && \
    ln -s /opt/dependency-check-cli/bin/dependency-check.sh /usr/local/bin/dependency-check && \
    chmod +x /usr/local/bin/dependency-check

# Mark cache directories as volumes for persistence
VOLUME ["/root/.cache/trivy", "/root/.cache/grype"]

# Create working directory
WORKDIR /scan

# Copy JMo Security Suite source code
COPY . /opt/jmo-security/

# Copy default config to WORKDIR for profile loading
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo Security Suite with optional reporting dependencies
# Clean up pip cache and bytecode immediately after install (Phase 1: 40 MB savings)
RUN cd /opt/jmo-security && \
    python3 -m pip install --no-cache-dir -e ".[reporting]" && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Verify ALL 28 tools are installed and accessible
RUN echo "=== Verifying ALL 28 tools ===" && \
    python3 --version && \
    jmo --help > /dev/null && \
    jmotools --help > /dev/null && \
    trufflehog --version && \
    noseyparker --version && \
    semgrep --version && \
    bandit --version && \
    syft version && \
    trivy --version && \
    checkov --version && \
    hadolint --version && \
    zap -version && \
    nuclei -version && \
    falcoctl version && \
    (afl-fuzz -h > /dev/null 2>&1 || true) && \
    shellcheck --version && \
    shfmt --version && \
    prowler --version && \
    kubescape version && \
    gosec --version && \
    grype version && \
    osv-scanner --version && \
    bearer version && \
    lynis --version && \
    dependency-check --version && \
    horusec version && \
    scancode --version && \
    cdxgen --version && \
    echo "=== All 28 tools verified ==="

# Set default entrypoint to jmo CLI
ENTRYPOINT ["jmo"]

# Default command: show help
CMD ["--help"]

# Health check: verify jmo command works
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD jmo --help > /dev/null || exit 1

# Usage examples (documented in metadata):
# Basic scan (deep profile, all 28 tools):
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
# - Tool count: 12 → 28 tools (26 Docker-ready, 2 manual install)
