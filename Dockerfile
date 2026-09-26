# JMo Security Suite - Docker Image
# Base: Ubuntu 24.04 with every scanner in scripts/core/tool_registry.py TOOL_MATRIX
# pre-installed, plus the OPA policy engine | Multi-arch: amd64, arm64

#
# Stage 1: Builder - Download and extract tools
#
FROM ubuntu:26.04 AS builder

ARG TARGETARCH

# Install download dependencies (curl for downloads, unzip for nuclei, xz for shellcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    xz-utils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download TruffleHog (Secrets - working tree and git history)
RUN TRUFFLEHOG_VERSION="3.97.1" && \
    TRUFFLEHOG_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz && \
    gzip -t /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Download Gitleaks (Secrets - working tree and git history); amd64 is "x64"
RUN GITLEAKS_VERSION="8.30.1" && \
    GITLEAKS_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    -o /tmp/gitleaks.tar.gz && \
    gzip -t /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Download Syft (SBOM)
RUN SYFT_VERSION="1.51.1" && \
    SYFT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz" \
    -o /tmp/syft.tar.gz && \
    gzip -t /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft

# Download Trivy (SCA + Vuln)
RUN TRIVY_VERSION="0.74.0" && \
    TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    -o /tmp/trivy.tar.gz && \
    gzip -t /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy

# Download Hadolint (Dockerfile)
RUN HADOLINT_VERSION="2.15.1" && \
    HADOLINT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HADOLINT_ARCH}" \
    -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Download shfmt (Shell formatting)
RUN SHFMT_VERSION="3.14.0" && \
    SHFMT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/mvdan/sh/releases/download/v${SHFMT_VERSION}/shfmt_v${SHFMT_VERSION}_linux_${SHFMT_ARCH}" \
    -o /usr/local/bin/shfmt && \
    chmod +x /usr/local/bin/shfmt

# Download OWASP ZAP (DAST)
RUN ZAP_VERSION="2.17.0" && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    -o /tmp/zap.tar.gz && \
    gzip -t /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy

# Download Nuclei (DAST + API Security)
RUN NUCLEI_VERSION="3.11.1" && \
    TARGETARCH=$(dpkg --print-architecture) && \
    NUCLEI_ARCH=$(case ${TARGETARCH} in amd64) echo "amd64";; arm64) echo "arm64";; *) echo "amd64";; esac) && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    -o /tmp/nuclei.zip && \
    unzip -t /tmp/nuclei.zip > /dev/null && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -tl cves,misconfigurations,exposures,vulnerabilities,apis -silent

# Download Gosec (Go SAST)
RUN GOSEC_VERSION="2.29.0" && \
    GOSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${GOSEC_ARCH}.tar.gz" \
    -o /tmp/gosec.tar.gz && \
    gzip -t /tmp/gosec.tar.gz && \
    tar -xzf /tmp/gosec.tar.gz -C /usr/local/bin gosec && \
    chmod +x /usr/local/bin/gosec

# Download Grype (SCA + Vuln - Anchore)
RUN GRYPE_VERSION="0.118.0" && \
    GRYPE_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${GRYPE_ARCH}.tar.gz" \
    -o /tmp/grype.tar.gz && \
    gzip -t /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    chmod +x /usr/local/bin/grype

# Download OPA (Policy-as-Code engine)
RUN OPA_VERSION="1.20.1" && \
    OPA_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_${OPA_ARCH}_static" \
    -o /usr/local/bin/opa && \
    chmod +x /usr/local/bin/opa

# Download ShellCheck (pinned version instead of apt)
RUN SHELLCHECK_VERSION="0.11.0" && \
    SHELLCHECK_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600 "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.${SHELLCHECK_ARCH}.tar.xz" \
    -o /tmp/shellcheck.tar.xz && \
    xz -t /tmp/shellcheck.tar.xz && \
    tar -xJf /tmp/shellcheck.tar.xz -C /tmp && \
    mv /tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck /usr/local/bin/shellcheck && \
    chmod +x /usr/local/bin/shellcheck

#
# Stage 2: Runtime - Complete runtime environment with ALL tools
#
FROM ubuntu:26.04 AS runtime

LABEL org.opencontainers.image.title="JMo Security Suite"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit: every TOOL_MATRIX scanner plus the OPA policy engine"
LABEL org.opencontainers.image.version="1.0.2"
LABEL org.opencontainers.image.authors="James Moceri <general@jmogaming.com>"
LABEL org.opencontainers.image.url="https://jmotools.com"
LABEL org.opencontainers.image.source="https://github.com/jimmy058910/jmo-security-repo"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent interactive prompts during apt installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}" \
    DOCKER_CONTAINER=1

# Install ONLY runtime dependencies (no wget, tar, build-essential)
# Combined in single RUN to reduce layers, with aggressive cache cleanup
# Java is for ZAP.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    jq \
    yara \
    openjdk-17-jre-headless \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Git history (G1): a mounted repository belongs to another UID (a CI runner's
# 1001; this image runs as 1000), and git refuses it as "dubious ownership", so
# every scan here skipped the secrets in its history. Trust every directory:
# the image reads what it is handed, and git then honours that repository's
# own .git/config (decided 2026-09-26; docs/KNOWN_LIMITATIONS.md).
RUN git config --system --add safe.directory '*'

# Clean Java runtime (Phase 1 optimization: 30 MB savings)
RUN rm -rf /usr/lib/jvm/java-17-openjdk-*/man \
    /usr/lib/jvm/java-17-openjdk-*/legal \
    /usr/share/doc \
    /usr/share/man \
    /usr/share/locale

# Install Python security tools (pip)
# Install build deps temporarily for packages that may need compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python security tools one by one for better error visibility
# Note: Ubuntu 24.04 ships pip 24.0/setuptools 68.1/wheel 0.42 (sufficient, skip upgrade)
RUN python3 -m pip install --no-cache-dir --break-system-packages semgrep==1.175.0 && \
    semgrep --version && \
    echo "✓ semgrep installed"

RUN python3 -m pip install --no-cache-dir --break-system-packages checkov==3.3.16 && \
    checkov --version && \
    echo "✓ checkov installed"

RUN python3 -m pip install --no-cache-dir --break-system-packages ruff==0.16.5 && \
    echo "✓ ruff installed"

RUN python3 -m pip install --no-cache-dir --break-system-packages yara-python==4.5.4 && \
    echo "✓ yara-python installed"

# Clean up build dependencies to reduce image size
RUN apt-get update && apt-get purge -y gcc g++ python3-dev libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Copy compiled binaries from builder stage
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/shfmt /usr/local/bin/shfmt
COPY --from=builder /usr/local/bin/gosec /usr/local/bin/gosec
COPY --from=builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=builder /usr/local/bin/opa /usr/local/bin/opa
COPY --from=builder /usr/local/bin/shellcheck /usr/local/bin/shellcheck
COPY --from=builder /opt/zaproxy /opt/zaproxy

# Binary stripping (Phase 1 optimization: 15 MB savings)
RUN strip /usr/local/bin/trufflehog \
    /usr/local/bin/syft \
    /usr/local/bin/trivy \
    /usr/local/bin/hadolint \
    /usr/local/bin/nuclei \
    /usr/local/bin/gosec \
    /usr/local/bin/grype \
    /usr/local/bin/opa \
    2>/dev/null || true

# Create a symlink for easier invocation
RUN ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap && \
    chmod +x /usr/local/bin/zap

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

# Copy default config to WORKDIR
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo Security Suite with optional reporting dependencies
# Clean up pip cache and bytecode immediately after install (Phase 1: 40 MB savings)
RUN python3 -m pip install --no-cache-dir --break-system-packages -e "/opt/jmo-security[reporting]" && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Verify every scanner and the policy engine are installed and accessible
RUN echo "=== Verifying tools ===" && \
    python3 --version && \
    jmo --help > /dev/null && \
    jmo tools --help > /dev/null && \
    trufflehog --version && \
    semgrep --version && \
    syft version && \
    trivy --version && \
    checkov --version && \
    hadolint --version && \
    zap -version && \
    nuclei -version && \
    yara --version && \
    shellcheck --version && \
    shfmt --version && \
    gosec --version && \
    grype version && \
    opa version && \
    echo "=== All tools verified ==="

# Create non-root user and set ownership (Security best practice)
# Note: Ubuntu 24.04 pre-creates 'ubuntu' user with UID 1000, must remove first
RUN userdel -r ubuntu 2>/dev/null || true && \
    useradd -m -u 1000 -s /bin/bash jmo && \
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
# Exec form with an explicit shell. hadolint 2.15.0 extended DL3025 to cover
# HEALTHCHECK, and this probe genuinely needs a shell for the redirect and the
# `||`. Naming /bin/sh keeps the behaviour identical to the shell form Docker
# would otherwise have wrapped it in.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/bin/sh", "-c", "jmo --help > /dev/null || exit 1"]

# Usage examples (documented in metadata):
# Basic scan:
# docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results-dir /scan/results
#
# Usage: docker run --rm -v "$(pwd)/.jmo:/scan/.jmo" -v "$(pwd):/scan" \
#   ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --fail-on HIGH
# The .jmo mount persists the SQLite history DB between runs so `jmo history`, `jmo diff`, and `jmo trends` work.
#
# CI mode with caching (30s faster on subsequent runs):
# docker run --rm -v $(pwd):/scan -v trivy-cache:/root/.cache/trivy -v grype-cache:/root/.cache/grype \
#   ghcr.io/jimmy058910/jmo-security:latest ci --repo /scan --fail-on HIGH
#
# Size optimizations:
# - Multi-stage builds: download tooling stays in the builder stage
# - Nuclei template filtering, Python bytecode cleanup, binary stripping, Java cleanup, Git metadata exclusion
# - Volume mounting: Use -v trivy-cache:/root/.cache/trivy for persistent caching
