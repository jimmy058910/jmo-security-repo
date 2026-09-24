"""
Configuration constants for JMo Security tool installation.

Contains URL templates, installation priorities, isolated tool configurations,
and dependency management settings. Extracted from tool_installer.py for
better modularity and reuse.
"""

from __future__ import annotations

from scripts.core.tool_registry import Platform

# ============================================================================
# TIMEOUT AND LIMIT CONSTANTS
# ============================================================================
# Replace magic numbers with named constants for clarity and easy adjustment

DOWNLOAD_TIMEOUT_SECONDS = 300
PIP_INSTALL_TIMEOUT_SECONDS = 600
SUBPROCESS_DEFAULT_TIMEOUT = 120
DOWNLOAD_CHUNK_SIZE = 8192
MAX_PARALLEL_WORKERS = 8
CLEANUP_RETRY_BACKOFF_FACTOR = 0.5
MAX_CLEANUP_RETRIES = 3


# ============================================================================
# INSTALLATION METHOD PRIORITIES
# ============================================================================
# Installation method priorities per platform
# "install_script" uses official install scripts from tool maintainers (most reliable)
# "binary" downloads pre-built binaries from GitHub releases
#
# npm and brew are gone (v2.0.0). npm served only cdxgen; brew was the first
# macOS choice and never honoured the pinned version (PINNED_INSTALL_METHODS
# excludes it), so macOS now installs the same pinned binary as everyone else.

INSTALL_PRIORITIES: dict[Platform, list[str]] = {
    "linux": ["apt", "pip", "install_script", "binary"],
    "macos": ["pip", "install_script", "binary"],
    "windows": ["pip", "binary", "manual"],
}


# ============================================================================
# SPECIAL INSTALLATION HANDLING
# ============================================================================
# Tools that require special installation handling

SPECIAL_INSTALL: dict[str, str] = {
    "zap": "extract_app",  # Extract zip to directory (cross-platform)
}


# ============================================================================
# EXTRACT APP URLS
# ============================================================================
# App archives that extract to a directory (not single binary)
# These are downloaded, extracted, and the main script is linked/used
#
# Type can be str (universal) or dict (platform-specific)
# For platform-specific URLs, use keys: "windows", "linux", "macos", "default"
#
# Available placeholders:
#   {version}    - Tool version from versions.yaml

EXTRACT_APP_URLS: dict[str, str | dict[str, str]] = {
    # ZAP: Use cross-platform release that works on all platforms
    # Changed from Linux-only tarball to universal Crossplatform.zip
    "zap": "https://github.com/zaproxy/zaproxy/releases/download/v{version}/ZAP_{version}_Crossplatform.zip",
}


# ============================================================================
# YARA RULE BUNDLE
# ============================================================================
# yara is the one scanner whose package carries no detection content: the
# yara-python wheel is the libyara engine and nothing else. Without rules it
# examines every file and matches nothing, which is byte-for-byte the same
# result as a clean repository - so the rules are part of the install, not an
# optional extra.
#
# Why this bundle:
#   - MIT (verified verbatim in its LICENSE), so it can be redistributed and
#     used commercially. The set the yara adapter's docstring names,
#     Neo23x0/signature-base, reports its licence as NOASSERTION and is 42 MB,
#     which also exceeds the repo's 10 MB check-added-large-files hook.
#   - 615 KB across 310 rule files, organised by category (backdoor,
#     ransomware, trojan, exploit, ...). Those directory names become the
#     namespace, and the adapter infers severity from exactly such tags.
#   - Fetched at install time into ~/.jmo/yara-rules/, matching how zap
#     already lives under ~/.jmo/. Nothing is vendored.
#
# Pinned to a commit because the repository publishes no releases or tags. Bump
# deliberately - a rule set that changes under you changes your findings.
YARA_RULES_BUNDLE: dict[str, str] = {
    "repo": "reversinglabs/reversinglabs-yara-rules",
    "ref": "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84",  # 2025-11-03
    "url": (
        "https://github.com/reversinglabs/reversinglabs-yara-rules/"
        "archive/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84.tar.gz"
    ),
    # Directory inside the archive holding the rules; everything else (README,
    # LICENSE) is dropped so the namespace stays category-relative.
    "subdir": "yara",
    "license": "MIT",
}


# ============================================================================
# BINARY DOWNLOAD URLS
# ============================================================================
# Binary download URLs (GitHub releases)
# v1.0.0: Changed from /latest/download/ to /download/v{version}/ for reproducible installs
# v1.0.1: Fixed asset naming to match actual GitHub release filenames
# v1.0.2: Added platform-specific URL support (dict format) for Windows compatibility
#
# Type can be str (universal) or dict (platform-specific)
# For platform-specific URLs, use keys: "windows", "linux", "macos", "default"
#
# IMPORTANT: Asset naming varies significantly by tool AND platform:
# - Windows typically uses .zip extension, Linux uses .tar.gz
# - Windows uses "windows" (lowercase), Linux uses "Linux" or "linux"
#
# Available placeholders:
#   {version}    - Tool version from versions.yaml
#   {os}         - "Linux", "Darwin", "Windows"
#   {os_lower}   - "linux", "darwin", "windows"
#   {arch}       - "x86_64", "arm64"
#   {arch_amd}   - "amd64", "arm64" (for Go tools)
#   {arch_aarch} - "x86_64", "aarch64" (for shellcheck)
#   {trivy_arch} - "64bit", "ARM64" (trivy's unique format)

BINARY_URLS: dict[str, str | dict[str, str]] = {
    # trivy: Windows uses lowercase "windows-64bit.zip", Linux uses "Linux-64bit.tar.gz"
    "trivy": {
        "windows": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-{trivy_arch}.zip",
        "default": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os}-{trivy_arch}.tar.gz",
    },
    # Anchore grype: Windows uses .zip, Linux uses .tar.gz
    "grype": {
        "windows": "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # Anchore syft: Windows uses .zip, Linux uses .tar.gz
    "syft": {
        "windows": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # hadolint: "Linux-x86_64" (capital L, hyphen, lowercase arch)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "hadolint": {
        "windows": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-Windows-x86_64.exe",
        "default": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-{os}-{arch}",
    },
    # shellcheck: lowercase "linux.x86_64" with dots
    # Windows is a single arch-less .zip - the {os_lower}.{arch_aarch} scheme
    # has no Windows asset, so the generic template 404s (verified upstream).
    "shellcheck": {
        "windows": "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.zip",
        "default": "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{os_lower}.{arch_aarch}.tar.xz",
    },
    # Go tools using lowercase "linux_amd64" format
    # trufflehog: ships .tar.gz on every platform including Windows
    "trufflehog": {
        "windows": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_windows_{arch_amd}.tar.gz",
        "default": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_lower}_{arch_amd}.zip",
    "gosec": "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_{os_lower}_{arch_amd}.tar.gz",
    # OPA (Open Policy Agent): "opa_linux_amd64" (no version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "opa": {
        "windows": "https://github.com/open-policy-agent/opa/releases/download/v{version}/opa_windows_{arch_amd}.exe",
        "default": "https://github.com/open-policy-agent/opa/releases/download/v{version}/opa_{os_lower}_{arch_amd}",
    },
}


# ============================================================================
# OFFICIAL INSTALL SCRIPTS
# ============================================================================
# Official install scripts (preferred over direct binary downloads)
# These are maintained by tool authors and handle platform detection correctly

INSTALL_SCRIPTS: dict[str, str] = {
    "trivy": "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
    "grype": "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
    "syft": "https://raw.githubusercontent.com/anchore/syft/main/install.sh",
}


# ============================================================================
# ISOLATED VENV CONFIGURATION
# ============================================================================
# Python-packaged scanners that install into their own virtualenv under
# ~/.jmo/tools/venvs/<tool_name>/ instead of JMo's own Python environment.
#
# Isolation began as a pydantic conflict: prowler pinned pydantic<2 while
# semgrep and checkov need pydantic>=2, so no single environment could hold all
# three. prowler left in v2.0.0 and took its venv with it. The two that remain
# still pin heavily enough that sharing JMo's environment would let either one
# downgrade a package JMo itself depends on (semgrep pins mcp, see
# tool_installer), so each keeps its own.
#
# Format: {tool_name: {package, reason}}

ISOLATED_TOOLS: dict[str, dict[str, str | list[str]]] = {
    "semgrep": {
        "package": "semgrep",
        "reason": "Pins its own dependency set (including mcp) that must not reach JMo's environment",
    },
    "checkov": {
        "package": "checkov",
        "reason": "Pins its own dependency set (pydantic>=2 among it) that must not reach JMo's environment",
    },
}


# ============================================================================
# DEPENDENCY AUTO-INSTALL CONFIGURATION
# ============================================================================
# Runtime dependencies (Java, for zap) can be auto-installed via package managers.
# The wizard will detect missing deps and offer to install them automatically.
#
# Structure: {dep_name: {platform: {package_manager: [command_args]}}}
# - Deps: "java"
# - Platforms: "windows", "linux", "macos"
# - Package managers: chocolatey, winget, apt, dnf, brew

DEPENDENCY_INSTALL_COMMANDS: dict[str, dict[str, dict[str, list[str] | str]]] = {
    "java": {
        "windows": {
            "chocolatey": ["choco", "install", "openjdk17", "-y"],
            "winget": [
                "winget",
                "install",
                "--id",
                "Microsoft.OpenJDK.17",
                "-e",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
        },
        "linux": {
            # Use default-jre-headless for broader compatibility across Debian/Ubuntu versions
            # openjdk-17-jre may not be available in slim images without extra repos
            "apt": ["sudo", "apt-get", "install", "-y", "default-jre-headless"],
            "dnf": ["sudo", "dnf", "install", "-y", "java-17-openjdk-headless"],
        },
        "macos": {
            "brew": ["brew", "install", "openjdk@17"],
        },
    },
}

# Commands to verify dependency installation succeeded
DEPENDENCY_VERIFY_COMMANDS: dict[str, list[str]] = {
    "java": ["java", "-version"],
}

# Human-readable display names for dependencies
DEPENDENCY_DISPLAY_NAMES: dict[str, str] = {
    "java": "Java 17+",
}

# Manual installation commands (fallback if auto-install fails)
DEPENDENCY_MANUAL_COMMANDS: dict[str, dict[str, str]] = {
    "java": {
        "windows": "choco install openjdk17 -y  OR  winget install Microsoft.OpenJDK.17",
        "linux": "sudo apt-get install default-jre-headless -y  OR  sudo dnf install java-17-openjdk-headless -y",
        "macos": "brew install openjdk@17",
    },
}
