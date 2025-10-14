# JMo Security Suite - All-in-One Docker Image (Full)
# Base: Ubuntu 22.04 with all security tools pre-installed
# Size: ~500MB | Tools: 11+ security scanners | Multi-arch: amd64, arm64

FROM ubuntu:22.04 AS base

LABEL org.opencontainers.image.title="JMo Security Suite"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 11+ pre-installed scanners"
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

# Install gitleaks
RUN GITLEAKS_VERSION="8.21.2" && \
    GITLEAKS_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x64") && \
    curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
    -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz

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
RUN TRIVY_VERSION="0.58.1" && \
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

# Install tfsec (Terraform security scanner)
RUN TFSEC_VERSION="1.28.11" && \
    TFSEC_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/aquasecurity/tfsec/releases/download/v${TFSEC_VERSION}/tfsec_${TFSEC_VERSION}_linux_${TFSEC_ARCH}.tar.gz" \
    -o /tmp/tfsec.tar.gz && \
    tar -xzf /tmp/tfsec.tar.gz -C /usr/local/bin tfsec && \
    rm /tmp/tfsec.tar.gz

# Install osv-scanner (Google OSV vulnerability scanner)
RUN OSV_VERSION="1.9.2" && \
    OSV_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_${OSV_VERSION}_linux_${OSV_ARCH}" \
    -o /usr/local/bin/osv-scanner && \
    chmod +x /usr/local/bin/osv-scanner

# Create working directory
WORKDIR /scan

# Copy JMo Security Suite source code
COPY . /opt/jmo-security/

# Install JMo Security Suite with optional reporting dependencies
RUN cd /opt/jmo-security && \
    python3 -m pip install --no-cache-dir -e ".[reporting]"

# Verify all tools are installed and accessible
RUN echo "=== Verifying installed tools ===" && \
    python3 --version && \
    jmo --help > /dev/null && \
    jmotools --help > /dev/null && \
    gitleaks version && \
    trufflehog --version && \
    semgrep --version && \
    syft version && \
    trivy --version && \
    hadolint --version && \
    tfsec --version && \
    checkov --version && \
    osv-scanner --version && \
    bandit --version && \
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
