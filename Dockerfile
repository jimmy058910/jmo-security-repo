# JMo Security Suite - All-in-One Docker Image (Full)
# Base: Ubuntu 22.04 with all security tools pre-installed
# Size: ~1.5GB | Tools: 11 security scanners (v0.6.0) | Multi-arch: amd64, arm64
# v0.6.0: Multi-target unified scanning (repos, images, IaC, URLs, GitLab, K8s)

FROM ubuntu:22.04 AS base

LABEL org.opencontainers.image.title="JMo Security Suite"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 11 pre-installed scanners + multi-target scanning (v0.6.0)"
LABEL org.opencontainers.image.version="0.6.0"
LABEL org.opencontainers.image.authors="James Moceri <general@jmogaming.com>"
LABEL org.opencontainers.image.url="https://jmotools.com"
LABEL org.opencontainers.image.source="https://github.com/jimmy058910/jmo-security-repo"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent interactive prompts during apt installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}"

# Install core dependencies and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    ca-certificates \
    jq \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip, setuptools, wheel
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python-based tools (bandit, semgrep, checkov)
RUN python3 -m pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.94.0 \
    checkov==3.2.255 \
    ruff==0.14.0

# Install shfmt
ARG TARGETARCH
RUN SHFMT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/mvdan/sh/releases/download/v3.8.0/shfmt_v3.8.0_linux_${SHFMT_ARCH}" \
    -o /usr/local/bin/shfmt && \
    chmod +x /usr/local/bin/shfmt

# Install OWASP ZAP (DAST)
RUN ZAP_VERSION="2.15.0" && \
    apt-get update && apt-get install -y --no-install-recommends \
    wget \
    openjdk-11-jre-headless \
    && rm -rf /var/lib/apt/lists/* && \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    -O /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy && \
    ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap && \
    chmod +x /usr/local/bin/zap && \
    rm /tmp/zap.tar.gz

# Install TruffleHog
RUN TRUFFLEHOG_VERSION="3.84.2" && \
    TRUFFLEHOG_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog && \
    rm /tmp/trufflehog.tar.gz

# Install Syft (SBOM generator)
RUN SYFT_VERSION="1.18.1" && \
    SYFT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz" \
    -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    rm /tmp/syft.tar.gz

# Install Trivy (vulnerability scanner)
# Updated to latest version for current CVE database
RUN TRIVY_VERSION="0.67.2" && \
    TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz

# Install Hadolint (Dockerfile linter)
RUN HADOLINT_VERSION="2.12.0" && \
    HADOLINT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -sSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HADOLINT_ARCH}" \
    -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Install Falcoctl (Falco CLI tool for static analysis)
# Note: Full Falco runtime requires kernel modules; for deep scans we use falcoctl
# Users running on K8s can use full Falco with kernel driver
RUN FALCOCTL_VERSION="0.11.0" && \
    FALCOCTL_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_linux_${FALCOCTL_ARCH}.tar.gz" \
    -o /tmp/falcoctl.tar.gz && \
    tar -xzf /tmp/falcoctl.tar.gz -C /usr/local/bin falcoctl && \
    chmod +x /usr/local/bin/falcoctl && \
    rm /tmp/falcoctl.tar.gz

# Install AFL++ (Fuzzing)
RUN AFL_VERSION="4.21c" && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/* && \
    curl -sSL "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFL_VERSION}.tar.gz" \
    -o /tmp/aflplusplus.tar.gz && \
    tar -xzf /tmp/aflplusplus.tar.gz -C /tmp && \
    cd /tmp/AFLplusplus-${AFL_VERSION} && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/aflplusplus.tar.gz /tmp/AFLplusplus-${AFL_VERSION}

# Install Nosey Parker (secrets scanner)
# Uses musl builds for better compatibility with Alpine-based base images
RUN NP_VERSION="0.24.0" && \
    NP_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -sSL "https://github.com/praetorian-inc/noseyparker/releases/download/v${NP_VERSION}/noseyparker-v${NP_VERSION}-${NP_ARCH}-unknown-linux-musl.tar.gz" \
    -o /tmp/noseyparker.tar.gz && \
    tar -xzf /tmp/noseyparker.tar.gz -C /tmp && \
    mv /tmp/bin/noseyparker /usr/local/bin/noseyparker && \
    chmod +x /usr/local/bin/noseyparker && \
    rm -rf /tmp/noseyparker.tar.gz /tmp/bin

# Create working directory
WORKDIR /scan

# Copy JMo Security Suite source code
COPY . /opt/jmo-security/

# Copy default config to WORKDIR for profile loading
# This ensures jmo.yml is found when running without --config flag
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo Security Suite with optional reporting dependencies
RUN cd /opt/jmo-security && \
    python3 -m pip install --no-cache-dir -e ".[reporting]"

# Verify all tools are installed and accessible
RUN echo "=== Verifying installed tools ===" && \
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
    falcoctl version && \
    (afl-fuzz -h > /dev/null 2>&1 || true) && \
    shellcheck --version && \
    shfmt --version && \
    echo "=== All tools verified ==="

# Set default entrypoint to jmo CLI
ENTRYPOINT ["jmo"]

# Default command: show help
CMD ["--help"]

# Health check: verify jmo command works
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD jmo --help > /dev/null || exit 1

# Usage examples (documented in metadata):
# docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced
# docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest ci --repo /scan --fail-on HIGH --profile
