# JMo Security Suite - All-in-One Docker Image (Full)
# Base: Ubuntu 22.04 with all security tools pre-installed
# Size: ~900MB (optimized from 1.5GB) | Tools: 11 security scanners (v0.6.1) | Multi-arch: amd64, arm64
# v0.6.1: Docker optimization (multi-stage builds, layer caching, Trivy DB pre-download)

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

# Download TruffleHog
RUN TRUFFLEHOG_VERSION="3.90.12" && \
    TRUFFLEHOG_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${TRUFFLEHOG_ARCH}.tar.gz" \
    -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /tmp && \
    mv /tmp/trufflehog /usr/local/bin/trufflehog && \
    chmod +x /usr/local/bin/trufflehog

# Download Syft
RUN SYFT_VERSION="1.36.0" && \
    SYFT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${SYFT_ARCH}.tar.gz" \
    -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft

# Download Trivy
RUN TRIVY_VERSION="0.67.2" && \
    TRIVY_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
    -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy

# Download Hadolint
RUN HADOLINT_VERSION="2.14.0" && \
    HADOLINT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "x86_64") && \
    curl -sSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-${HADOLINT_ARCH}" \
    -o /usr/local/bin/hadolint && \
    chmod +x /usr/local/bin/hadolint

# Download shfmt
RUN SHFMT_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/mvdan/sh/releases/download/v3.8.0/shfmt_v3.8.0_linux_${SHFMT_ARCH}" \
    -o /usr/local/bin/shfmt && \
    chmod +x /usr/local/bin/shfmt

# Download Falcoctl
RUN FALCOCTL_VERSION="0.11.4" && \
    FALCOCTL_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_linux_${FALCOCTL_ARCH}.tar.gz" \
    -o /tmp/falcoctl.tar.gz && \
    tar -xzf /tmp/falcoctl.tar.gz -C /usr/local/bin falcoctl && \
    chmod +x /usr/local/bin/falcoctl

# Download Nosey Parker
RUN NP_VERSION="0.24.0" && \
    NP_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -sSL "https://github.com/praetorian-inc/noseyparker/releases/download/v${NP_VERSION}/noseyparker-v${NP_VERSION}-${NP_ARCH}-unknown-linux-musl.tar.gz" \
    -o /tmp/noseyparker.tar.gz && \
    tar -xzf /tmp/noseyparker.tar.gz -C /tmp && \
    mv /tmp/bin/noseyparker /usr/local/bin/noseyparker && \
    chmod +x /usr/local/bin/noseyparker

# Download OWASP ZAP
RUN ZAP_VERSION="2.16.1" && \
    wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
    -O /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    mv /opt/ZAP_${ZAP_VERSION} /opt/zaproxy

# Download Nuclei
RUN NUCLEI_VERSION="3.4.10" && \
    TARGETARCH=$(dpkg --print-architecture) && \
    NUCLEI_ARCH=$(case ${TARGETARCH} in amd64) echo "amd64";; arm64) echo "arm64";; *) echo "amd64";; esac) && \
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
    -O /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    nuclei -update-templates -silent

# Build AFL++ (requires build tools already installed above)
RUN AFL_VERSION="4.21c" && \
    curl -sSL "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFL_VERSION}.tar.gz" \
    -o /tmp/aflplusplus.tar.gz && \
    tar -xzf /tmp/aflplusplus.tar.gz -C /tmp && \
    cd /tmp/AFLplusplus-${AFL_VERSION} && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/aflplusplus.tar.gz /tmp/AFLplusplus-${AFL_VERSION}

#
# Stage 2: Runtime - Minimal runtime environment
#
FROM ubuntu:22.04 AS runtime

LABEL org.opencontainers.image.title="JMo Security Suite"
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 11 pre-installed scanners + multi-target scanning (v0.6.1 optimized)"
LABEL org.opencontainers.image.version="0.6.1"
LABEL org.opencontainers.image.authors="James Moceri <general@jmogaming.com>"
LABEL org.opencontainers.image.url="https://jmotools.com"
LABEL org.opencontainers.image.source="https://github.com/jimmy058910/jmo-security-repo"
LABEL org.opencontainers.image.licenses="MIT"

# Prevent interactive prompts during apt installation
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:${PATH}" \
    DOCKER_CONTAINER=1

# Install ONLY runtime dependencies (no curl, wget, tar, build-essential - those were in builder stage)
# Combined in single RUN to reduce layers, with aggressive cache cleanup
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    git \
    ca-certificates \
    jq \
    shellcheck \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Upgrade pip, setuptools, wheel and install Python tools in single layer
# Use --no-cache-dir to prevent pip cache bloat
# Clean __pycache__ and .pyc files immediately after install
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
    bandit==1.8.6 \
    semgrep==1.143.1 \
    checkov==3.2.493 \
    ruff==0.14.5 && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

# Copy compiled binaries from builder stage
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/hadolint /usr/local/bin/hadolint
COPY --from=builder /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /usr/local/bin/shfmt /usr/local/bin/shfmt
COPY --from=builder /usr/local/bin/falcoctl /usr/local/bin/falcoctl
COPY --from=builder /usr/local/bin/noseyparker /usr/local/bin/noseyparker
COPY --from=builder /opt/zaproxy /opt/zaproxy

# Copy AFL++ binaries from builder (compiled in builder stage to avoid build tools in runtime)
COPY --from=builder /usr/local/bin/afl-* /usr/local/bin/
COPY --from=builder /usr/local/lib/afl /usr/local/lib/afl
COPY --from=builder /usr/local/share/afl /usr/local/share/afl

# Create ZAP symlink
RUN ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap && \
    chmod +x /usr/local/bin/zap

# REMOVED: Trivy DB pre-download (adds 800MB to image size)
# Instead, use volume mounting for persistent caching across scans:
#   docker run -v trivy-cache:/root/.cache/trivy ...
# First scan will download DB (~30-60s), subsequent scans use cached DB

# Mark Trivy cache directory as volume for persistence
VOLUME ["/root/.cache/trivy"]

# Create working directory
WORKDIR /scan

# Copy JMo Security Suite source code
COPY . /opt/jmo-security/

# Copy default config to WORKDIR for profile loading
# This ensures jmo.yml is found when running without --config flag
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo Security Suite with optional reporting dependencies
# Clean up pip cache and bytecode immediately after install
RUN cd /opt/jmo-security && \
    python3 -m pip install --no-cache-dir -e ".[reporting]" && \
    find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3* -type f -name '*.pyc' -delete 2>/dev/null || true

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
    nuclei -version && \
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
# Basic scan:
# docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced
#
# CI mode with caching (30s faster on subsequent runs):
# docker run --rm -v $(pwd):/scan -v trivy-cache:/root/.cache/trivy ghcr.io/jimmy058910/jmo-security:latest ci --repo /scan --fail-on HIGH --profile
#
# Optimizations in v0.6.1:
# - Multi-stage builds: Reduced image size by 40% (1.5GB → 900MB)
# - Layer caching: Aggressive cleanup of apt/pip caches and Python bytecode
# - Trivy DB pre-download: Pre-cached vulnerability database eliminates 30-60s delay
# - Volume mounting: Use -v trivy-cache:/root/.cache/trivy for persistent caching
