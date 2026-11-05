"""
Configuration constants for JMo Security tool installation.

Contains URL templates, installation priorities, isolated tool configurations,
and dependency management settings. Extracted from tool_installer.py for
better modularity and reuse.
"""

from __future__ import annotations

from scripts.core.tool_registry import Platform
from scripts.core.yara_rules import Review

# ============================================================================
# TIMEOUT AND LIMIT CONSTANTS
# ============================================================================
# Replace magic numbers with named constants for clarity and easy adjustment

DOWNLOAD_TIMEOUT_SECONDS = 300
# A download is tried this many times, this far apart, as every Dockerfile
# download is (`curl --retry 3 --retry-delay 5`): GitHub's transient errors
# failed image builds until then (#1573).
DOWNLOAD_ATTEMPTS = 4
DOWNLOAD_RETRY_DELAY_SECONDS = 5
PIP_INSTALL_TIMEOUT_SECONDS = 600
SUBPROCESS_DEFAULT_TIMEOUT = 120
DOWNLOAD_CHUNK_SIZE = 8192
MAX_PARALLEL_WORKERS = 8
CLEANUP_RETRY_BACKOFF_FACTOR = 0.5
MAX_CLEANUP_RETRIES = 3


# ============================================================================
# INSTALLATION METHOD PRIORITIES
# ============================================================================
# Installation method priorities per platform: pip for the Python tool
# (checkov, in its own venv), then the pinned release binary, checked against
# its release's sha256 where the project publishes one.
#
# npm and brew are gone (v2.0.0). npm served only cdxgen; brew was the first
# macOS choice and never honoured the pinned version (PINNED_INSTALL_METHODS
# excludes it), so macOS now installs the same pinned binary as everyone else.
# apt and the official install scripts went in #1374: apt installed the
# distribution's shellcheck, not the pin, and the scripts (trivy, syft) were
# fetched from `main` and run before the checked binary.

INSTALL_PRIORITIES: dict[Platform, list[str]] = {
    "linux": ["pip", "binary"],
    "macos": ["pip", "binary"],
    "windows": ["pip", "binary"],
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
# yara-x is the one scanner whose package carries no detection content: the
# engine holds no rules. Without rules it examines every file and matches
# nothing, which is byte-for-byte the same result as a clean repository - so
# the rules are part of the install, not an optional extra.
#
# Why signature-base (v2.0.0 Phase 6, decision 3): ReversingLabs' bundle, the
# previous choice, matched nothing on nine targets and a 24,942-file
# node_modules, and its categories are PE/ELF malware; signature-base carries
# webshell, hack-tool and npm supply-chain rules. The two reasons once given
# against it were both false: 42 MB is GitHub's size of the repository with its
# history (the tarball is 1.9 MB), and NOASSERTION is GitHub not recognising
# the Detection Rule License 1.1 it is under. Nothing is vendored: the rules are
# fetched at install time into ~/.jmo/yara-rules/, and by the Docker image's
# build into /opt/jmo/yara-rules/ (scripts/core/paths.py).
#
# DRL 1.1 binds whoever shares the rules to keep each rule's author, and every
# message from a match to name it. Not every rule is DRL:
# scripts/core/yara_rules.py drops the others during the fetch (decision 6),
# and YARA_RULES_REVIEWED lists the files it cannot decide alone.
#
# Pinned by commit, and by git's ids for what it holds, checked before
# extraction: the repository publishes no releases, and a rule set that changes
# under you changes your findings. Not by the archive's sha256: GitHub builds
# `/archive/` tarballs on request and does not promise their bytes stay the same
# (#1573). The ids are what the commit holds, recomputed from the archive by
# scripts/core/git_archive.py; read them for a new pin with
#   gh api repos/Neo23x0/signature-base/git/trees/<ref> \
#     --jq '.tree[] | select(.path=="yara" or .path=="LICENSE") | "\(.path) \(.sha)"'
# A bump re-reads every file the fetch then refuses.
YARA_RULES_BUNDLE: dict[str, str] = {
    "repo": "Neo23x0/signature-base",
    "ref": "36ab70428fc5b52701b7ee6107c853ff019ed759",  # 2026-10-29
    "url": (
        "https://github.com/Neo23x0/signature-base/"
        "archive/36ab70428fc5b52701b7ee6107c853ff019ed759.tar.gz"
    ),
    "tree": "9266045ebadb60de83fc00d6421413043aa4e6a8",  # git id of yara/ at ref
    "license_blob": "a2486e663132108cffe118790d6195a662a39ab2",  # of LICENSE
    # Directory inside the archive holding the rules; everything else (IOCs,
    # scripts) is dropped, and the LICENSE is copied beside them.
    "subdir": "yara",
    "license": "DRL 1.1",
}

# signature-base's ambiguous files, read at the pin above (decided 2026-11-03).
# "drop": a header names a license other than DRL, which wins over any DRL
# metadata in its rules; or third-party rules licensed otherwise sit beside
# rules with no license line. "keep": read, and its rules with no license line
# are DRL (a rule naming another license is still dropped).
YARA_RULES_REVIEWED: dict[str, Review] = {
    "apt_apt37_bluelight.yar": ("drop", "Volexity, BSD-2-Clause header"),
    "apt_apt41.yar": ("drop", "CC BY-NC 4.0 header"),
    "apt_carbon_paper_turla.yar": ("drop", "ESET, BSD-2-Clause header"),
    "apt_cobaltstrike.yar": ("drop", "JPCERT copyright header"),
    "apt_lnx_kobalos.yar": ("drop", "ESET, BSD-2-Clause header"),
    "apt_nk_inkysquid.yar": ("drop", "Volexity, BSD-2-Clause header"),
    "apt_prikormka.yar": ("drop", "ESET, BSD-2-Clause header"),
    "apt_pulsesecure.yar": ("drop", "FireEye, BSD-2-Clause header"),
    "apt_royalroad.yar": ("drop", "MIT header"),
    "apt_solarwinds_sunburst.yar": ("drop", "FireEye license header"),
    "apt_triton_mal_sshdoor.yar": ("drop", "ESET, BSD-2-Clause header"),
    "crime_malware_generic.yar": ("drop", "CC BY-NC-SA 4.0 header"),
    "crime_nansh0u.yar": ("drop", "CC BY-NC 4.0 header"),
    "crime_xbash.yar": ("drop", "CC BY-NC 4.0 header"),
    "gen_gcti_cobaltstrike.yar": ("drop", "Apache-2.0 header"),
    "gen_gcti_sliver.yar": ("drop", "Apache-2.0 header"),
    "gen_loaders.yar": ("drop", "GPL header"),
    "gen_rtf_malver_objects.yar": ("drop", "ditekSHen, BSD-2-Clause header"),
    "apt_apt27_hyperbro.yar": ("drop", "CC BY-NC 4.0 rules beside unlabelled ones"),
    "apt_cisco_asa_lineviper_rayinitiator_sep25.yar": (
        "drop",
        "UK OGL v3 rules beside an unlabelled one",
    ),
    "apt_mal_ru_snake_may23.yar": ("drop", "an MIT rule beside an unlabelled one"),
    "apt_apt10.yar": ("keep", "'license' is a C2 domain in a disabled rule"),
    "gen_github_net_redteam_tools_names.yar": (
        "keep",
        "its one CC BY-NC rule is commented out upstream",
    ),
    "generic_anomalies.yar": ("keep", "the author's own; one rule is CC BY-NC"),
    "thor-hacktools.yar": ("keep", "the author's own; one rule is CC BY-NC"),
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
#   {arch_x64}   - "x64", "arm64" (gitleaks)
#   {arch_x86}   - "x86", then the machine name as the platform reports it:
#                  "aarch64" on Linux, "arm64" on macOS (opengrep)

BINARY_URLS: dict[str, str | dict[str, str]] = {
    # trivy: Windows uses lowercase "windows-64bit.zip", Linux uses "Linux-64bit.tar.gz"
    "trivy": {
        "windows": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-{trivy_arch}.zip",
        "default": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os}-{trivy_arch}.tar.gz",
    },
    # Anchore syft: Windows uses .zip, Linux uses .tar.gz
    "syft": {
        "windows": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # hadolint: "hadolint-linux-x86_64", "hadolint-macos-arm64",
    # "hadolint-windows-x86_64.exe" (v2.15.1's assets, listed 2026-11-05). The
    # checksum file names them so, and is matched by name (#1374).
    "hadolint": {
        "windows": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-windows-x86_64.exe",
        "macos": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-macos-{arch}",
        "default": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-linux-{arch}",
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
    # gitleaks: amd64 is "x64"; .zip on Windows, .tar.gz elsewhere (v8.30.1's
    # assets, listed 2026-09-26)
    "gitleaks": {
        "windows": "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_windows_{arch_x64}.zip",
        "default": "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{os_lower}_{arch_x64}.tar.gz",
    },
    # zizmor: named by target triple, no version in the name (v1.30.1's
    # assets, listed 2026-09-27). No Windows arm64 build, so Windows is the
    # x86_64 one on every architecture, as for hadolint and shellcheck.
    "zizmor": {
        "windows": "https://github.com/zizmorcore/zizmor/releases/download/v{version}/zizmor-x86_64-pc-windows-msvc.zip",
        "macos": "https://github.com/zizmorcore/zizmor/releases/download/v{version}/zizmor-{arch_aarch}-apple-darwin.tar.gz",
        "default": "https://github.com/zizmorcore/zizmor/releases/download/v{version}/zizmor-{arch_aarch}-unknown-linux-gnu.tar.gz",
    },
    # opengrep: a static binary, no archive, no version in the name (v1.32.0's
    # assets, listed 2026-10-29). ARM is "aarch64" on Linux but "arm64" on
    # macOS, so {arch_x86} reads the platform's own name. No Windows arm64
    # build, so Windows is the x86 one on every architecture, as for zizmor.
    "opengrep": {
        "windows": "https://github.com/opengrep/opengrep/releases/download/v{version}/opengrep_windows_x86.exe",
        "macos": "https://github.com/opengrep/opengrep/releases/download/v{version}/opengrep_osx_{arch_x86}",
        "default": "https://github.com/opengrep/opengrep/releases/download/v{version}/opengrep_manylinux_{arch_x86}",
    },
    # osv-scanner: raw binaries, no archive, no version in the name (v2.6.0's
    # assets, listed 2026-09-28); Windows has an arm64 build.
    "osv-scanner": {
        "windows": "https://github.com/google/osv-scanner/releases/download/v{version}/osv-scanner_windows_{arch_amd}.exe",
        "default": "https://github.com/google/osv-scanner/releases/download/v{version}/osv-scanner_{os_lower}_{arch_amd}",
    },
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_lower}_{arch_amd}.zip",
    # OPA (Open Policy Agent): "opa_linux_amd64" (no version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "opa": {
        "windows": "https://github.com/open-policy-agent/opa/releases/download/v{version}/opa_windows_{arch_amd}.exe",
        "default": "https://github.com/open-policy-agent/opa/releases/download/v{version}/opa_{os_lower}_{arch_amd}",
    },
}


# ============================================================================
# RELEASE CHECKSUMS (#1374)
# ============================================================================
# Where each tool's release publishes the sha256 of its assets, in `sha256sum`
# form (scripts/core/checksums.py). A download is checked against it before it
# is extracted or installed; a mismatch, or an asset the file does not list,
# fails the install and leaves the installed binary alone. {asset} is the
# downloaded file's name, for a project that writes one file per asset.
# Read at each pinned tag on 2026-11-05.
CHECKSUM_URLS: dict[str, str] = {
    "trivy": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_checksums.txt",
    "syft": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_checksums.txt",
    "trufflehog": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_checksums.txt",
    "gitleaks": "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_checksums.txt",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_checksums.txt",
    "hadolint": "https://github.com/hadolint/hadolint/releases/download/v{version}/checksums.sha256",
    "osv-scanner": "https://github.com/google/osv-scanner/releases/download/v{version}/osv-scanner_SHA256SUMS",
    "opa": "https://github.com/open-policy-agent/opa/releases/download/v{version}/{asset}.sha256",
}

# The tools whose project publishes no checksum file, and what it publishes
# instead: `jmo tools install` installs them and says they were not verified.
UNCHECKSUMMED: dict[str, str] = {
    "zizmor": "zizmor publishes no checksums",
    "shellcheck": "shellcheck publishes no checksums",
    "opengrep": "opengrep publishes signatures (.sig), no checksums",
    "zap": "ZAP publishes its checksums only in its release notes",
}


# ============================================================================
# ISOLATED VENV CONFIGURATION
# ============================================================================
# Python-packaged scanners that install into their own virtualenv under
# ~/.jmo/tools/venvs/<tool_name>/ instead of JMo's own Python environment.
#
# Isolation began as a pydantic conflict: prowler pinned pydantic<2 while
# semgrep and checkov need pydantic>=2, so no single environment could hold all
# three. prowler left in v2.0.0 and took its venv with it, and semgrep followed
# when opengrep's static binary replaced it. checkov still pins heavily enough
# that sharing JMo's environment would let it downgrade a package JMo itself
# depends on, so it keeps its own.
#
# Format: {tool_name: {package, reason}}

ISOLATED_TOOLS: dict[str, dict[str, str | list[str]]] = {
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
