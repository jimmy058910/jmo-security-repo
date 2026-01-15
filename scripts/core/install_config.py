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
NPM_INSTALL_TIMEOUT_SECONDS = 600
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

INSTALL_PRIORITIES: dict[Platform, list[str]] = {
    "linux": ["apt", "pip", "npm", "install_script", "binary", "brew"],
    "macos": ["brew", "pip", "npm", "install_script", "binary"],
    "windows": ["pip", "npm", "binary", "manual"],
}


# ============================================================================
# SPECIAL INSTALLATION HANDLING
# ============================================================================
# Tools that require special installation handling
# NOTE: kubescape moved to BINARY_URLS (v1.0.0) - direct binary download is more reliable

SPECIAL_INSTALL: dict[str, str] = {
    "zap": "extract_app",  # Extract zip to directory (cross-platform)
    "dependency-check": "extract_app",  # Extract zip to directory (Java CLI)
    "scancode": "extract_app",  # Platform-specific pre-built releases (bypasses pip bug)
    "falco": "manual",  # Kernel module
    "afl++": "manual",  # Build from source
    "mobsf": "docker",  # Docker-only
    "akto": "docker",  # Docker-only
    "lynis": "clone",  # Git clone
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
#   {py_version} - Python version (e.g., "3.11") for tools requiring specific Python builds

EXTRACT_APP_URLS: dict[str, str | dict[str, str]] = {
    # ZAP: Use cross-platform release that works on all platforms
    # Changed from Linux-only tarball to universal Crossplatform.zip
    "zap": "https://github.com/zaproxy/zaproxy/releases/download/v{version}/ZAP_{version}_Crossplatform.zip",
    # Dependency-check: Universal zip works on all platforms (Java-based)
    "dependency-check": "https://github.com/jeremylong/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip",
    # ScanCode: Platform-specific pre-built releases (bypasses pip upstream bug)
    # The pip install fails due to invalid PEP 440 specifier in extractcode dependency
    # See: https://github.com/aboutcode-org/scancode-toolkit/issues/3944
    "scancode": {
        "windows": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-windows.zip",
        "linux": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-linux.tar.gz",
        "macos": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-macos.tar.gz",
    },
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
#   {rust_arch}  - "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", etc.
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
    "shellcheck": "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{os_lower}.{arch_aarch}.tar.xz",
    # Go tools using lowercase "linux_amd64" format
    # trufflehog: Windows uses .zip, Linux/macOS use .tar.gz
    "trufflehog": {
        "windows": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_lower}_{arch_amd}.zip",
    "gosec": "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_{os_lower}_{arch_amd}.tar.gz",
    # bearer: Windows uses .zip, Linux/macOS use .tar.gz
    "bearer": {
        "windows": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # horusec: lowercase "linux_amd64" (no version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    # Note: Windows uses "win" not "windows" in asset name (horusec_win_amd64.exe)
    "horusec": {
        "windows": "https://github.com/ZupIT/horusec/releases/download/v{version}/horusec_win_{arch_amd}.exe",
        "default": "https://github.com/ZupIT/horusec/releases/download/v{version}/horusec_{os_lower}_{arch_amd}",
    },
    # noseyparker: Rust target triple format with 'v' prefix
    "noseyparker": "https://github.com/praetorian-inc/noseyparker/releases/download/v{version}/noseyparker-v{version}-{rust_arch}.tar.gz",
    # kubescape: "kubescape_{version}_linux_amd64" (underscores, version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "kubescape": {
        "windows": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_windows_{arch_amd}.exe",
        "default": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_{os_lower}_{arch_amd}",
    },
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
    "kubescape": "https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh",
}


# ============================================================================
# ISOLATED VENV CONFIGURATION
# ============================================================================
# Known pip package conflicts - these tools need isolated virtual environments
# to avoid dependency conflicts (e.g., pydantic version incompatibilities).
#
# Tools in this dict will be installed in ~/.jmo/tools/venvs/<tool_name>/
# instead of the system Python environment.
#
# Pydantic version matrix:
#   - prowler: requires pydantic<2 (v1.x)
#   - semgrep: requires pydantic>=2 (TypeAdapter)
#   - checkov: requires pydantic>=2 (model_serializer)
#
# These tools CANNOT coexist in the same Python environment!
#
# Format: {tool_name: {package, conflicts_with, reason}}

ISOLATED_TOOLS: dict[str, dict[str, str | list[str]]] = {
    "prowler": {
        "package": "prowler",
        "conflicts_with": ["semgrep", "checkov"],
        "reason": "Requires pydantic<2 (v1.x), conflicts with semgrep/checkov which need pydantic>=2",
    },
    "semgrep": {
        "package": "semgrep",
        "conflicts_with": ["prowler"],
        "reason": "Requires pydantic>=2 (TypeAdapter), conflicts with prowler which needs pydantic<2",
    },
    "checkov": {
        "package": "checkov",
        "conflicts_with": ["prowler"],
        "reason": "Requires pydantic>=2 (model_serializer), conflicts with prowler which needs pydantic<2",
    },
    # NOTE: scancode removed from ISOLATED_TOOLS (v1.0.1) - now uses pre-built
    # binary download via SPECIAL_INSTALL["scancode"] = "extract_app" due to
    # upstream extractcode dependency bug (invalid PEP 440 specifier).
    # See: https://github.com/aboutcode-org/scancode-toolkit/issues/3944
}


# ============================================================================
# DEPENDENCY AUTO-INSTALL CONFIGURATION
# ============================================================================
# Runtime dependencies (Java, Node.js) can be auto-installed via package managers.
# The wizard will detect missing deps and offer to install them automatically.
#
# Structure: {dep_name: {platform: {package_manager: [command_args]}}}
# - Deps: "java", "node"
# - Platforms: "windows", "linux", "macos"
# - Package managers: chocolatey, winget, apt, dnf, brew

DEPENDENCY_INSTALL_COMMANDS: dict[str, dict[str, dict[str, list[str]]]] = {
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
            "apt": ["sudo", "apt", "install", "-y", "openjdk-17-jre"],
            "dnf": ["sudo", "dnf", "install", "-y", "java-17-openjdk"],
        },
        "macos": {
            "brew": ["brew", "install", "openjdk@17"],
        },
    },
    "node": {
        "windows": {
            "chocolatey": ["choco", "install", "nodejs-lts", "-y"],
            "winget": [
                "winget",
                "install",
                "--id",
                "OpenJS.NodeJS.LTS",
                "-e",
                "--accept-source-agreements",
                "--accept-package-agreements",
            ],
        },
        "linux": {
            "apt": ["sudo", "apt", "install", "-y", "nodejs"],
            "dnf": ["sudo", "dnf", "install", "-y", "nodejs"],
        },
        "macos": {
            "brew": ["brew", "install", "node@20"],
        },
    },
}

# Commands to verify dependency installation succeeded
DEPENDENCY_VERIFY_COMMANDS: dict[str, list[str]] = {
    "java": ["java", "-version"],
    "node": ["node", "--version"],
}

# Human-readable display names for dependencies
DEPENDENCY_DISPLAY_NAMES: dict[str, str] = {
    "java": "Java 17+",
    "node": "Node.js 20+",
}

# Manual installation commands (fallback if auto-install fails)
DEPENDENCY_MANUAL_COMMANDS: dict[str, dict[str, str]] = {
    "java": {
        "windows": "choco install openjdk17 -y  OR  winget install Microsoft.OpenJDK.17",
        "linux": "sudo apt install openjdk-17-jre -y  OR  sudo dnf install java-17-openjdk -y",
        "macos": "brew install openjdk@17",
    },
    "node": {
        "windows": "choco install nodejs-lts -y  OR  winget install OpenJS.NodeJS.LTS",
        "linux": "sudo apt install nodejs -y  OR  sudo dnf install nodejs -y",
        "macos": "brew install node@20",
    },
}
