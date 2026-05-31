#!/usr/bin/env python3
"""
Update tool versions across Dockerfile, install_tools.sh, and versions.yaml.

This script provides automated version management for all external security tools
used by JMo Security Suite. It serves as Layer 4 of the 5-layer version management
system described in ROADMAP.md #14.

Usage:
  # Validate all versions exist upstream BEFORE building (RECOMMENDED)
  python3 scripts/dev/update_versions.py --validate

  # Check for latest versions of all tools (informational; exits 0 even if outdated)
  python3 scripts/dev/update_versions.py --check-latest

  # Opt into strict gating: exit 1 if outdated tools are found
  python3 scripts/dev/update_versions.py --check-latest --fail-if-outdated

  # Emit JSON manifest with semver bump classification (for auto-PR automation)
  python3 scripts/dev/update_versions.py --classify

  # Update specific tool
  python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

  # Sync all Dockerfiles AND .github/workflows/*.yml env: blocks from versions.yaml
  python3 scripts/dev/update_versions.py --sync

  # Generate version consistency report
  python3 scripts/dev/update_versions.py --report

  # Check for outdated tools and create GitHub issues
  python3 scripts/dev/update_versions.py --check-outdated --create-issues

Requirements:
  - PyYAML: pip install pyyaml
  - packaging: pip install packaging (for semver bump classification)
  - GitHub CLI (gh) for --create-issues
  - Internet connection for GitHub API access

Exit codes:
  0: Success (outdated tools are informational, not an error — use
     --fail-if-outdated for strict CI gating)
  1: Validation errors OR strict-gating triggered OR real operational failure
  2: Missing dependencies
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

try:
    from packaging.version import InvalidVersion, Version
except ImportError:
    print("ERROR: packaging not installed. Run: pip install packaging", file=sys.stderr)
    sys.exit(2)

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent
VERSIONS_YAML = REPO_ROOT / "versions.yaml"
DOCKERFILE = REPO_ROOT / "Dockerfile.deep"
DOCKERFILE_BALANCED = REPO_ROOT / "Dockerfile.balanced"
DOCKERFILE_SLIM = REPO_ROOT / "Dockerfile.slim"
DOCKERFILE_FAST = REPO_ROOT / "Dockerfile.fast"
INSTALL_TOOLS = REPO_ROOT / "scripts" / "dev" / "install_tools.sh"
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Tools that require manual installation (platform limitations) and are
# intentionally NOT baked into any Docker image. They carry synthetic versions
# in versions.yaml (e.g. falco 0.0.0), so they ALWAYS read as "outdated" and
# would otherwise spawn a fresh "Update <tool>" issue every weekly check-versions
# cron run. We skip GitHub issue creation for them (the version delta is still
# surfaced in --check-latest / --report output) to stop the recurring churn.
#
# Source of truth: scripts/core/tool_registry.py MANUAL_INSTALL_TOOLS. This is a
# deliberate local mirror because scripts/dev/update_versions.py runs in CI
# (maintenance.yml check-versions) WITHOUT `pip install -e .`, so importing the
# scripts.core package is not reliably available there. A drift-guard unit test
# (tests/unit/test_update_versions_manual_tools.py) asserts the two stay in sync.
MANUAL_INSTALL_TOOLS: frozenset[str] = frozenset({"falco", "afl++", "mobsf", "akto"})

# ANSI colors
BLUE = "\033[0;34m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
NC = "\033[0m"  # No Color


def log(msg: str) -> None:
    """Print info message."""
    print(f"{BLUE}[update]{NC} {msg}")


def ok(msg: str) -> None:
    """Print success message."""
    print(f"{GREEN}[ok]{NC} {msg}")


def warn(msg: str) -> None:
    """Print warning message."""
    print(f"{YELLOW}[warn]{NC} {msg}")


def err(msg: str) -> None:
    """Print error message."""
    print(f"{RED}[err]{NC} {msg}", file=sys.stderr)


def _normalize_version(v: str) -> str:
    """Strip leading `v`, trailing `-stable`/`-static`, and similar decorations."""
    v = v.strip()
    if v.lower().startswith("v"):
        v = v[1:]
    # akto uses "mini-testing-1.53.7" — take the last numeric-looking chunk.
    parts = re.split(r"[-_/]", v)
    for part in reversed(parts):
        if re.match(r"^\d+(\.\d+)*", part):
            return part
    return v


def classify_bump(current: str, latest: str) -> str:
    """
    Classify the semver bump level between two versions.

    Returns one of: "patch", "minor", "major", "unknown".

    Rules:
    - No change → "patch" (safe default).
    - Unparseable version → "unknown" (e.g. non-semver tags).
    - 0.x → anything (or anything → 0.x): "major". Per semver, 0.x is
      pre-release and any bump may be breaking, so auto-merge is unsafe.
    - Prefix loss during normalization (e.g. akto `mini-testing-1.53.7` → `1.98.0`)
      is treated as "unknown" — the rebranding context is lost.
    - Else: compare major/minor/patch triples.

    Callers should treat "unknown" and "major" as risky (require human review);
    "patch" and "minor" are auto-merge candidates (with contract-test gating).
    """
    if current == latest:
        return "patch"
    normalized_current = _normalize_version(current)
    normalized_latest = _normalize_version(latest)
    # Detect lossy normalization (prefix/suffix discarded).
    if normalized_current != current.strip().lstrip("v").lstrip("V"):
        return "unknown"
    if normalized_latest != latest.strip().lstrip("v").lstrip("V"):
        return "unknown"
    try:
        cur = Version(normalized_current)
        new = Version(normalized_latest)
    except InvalidVersion:
        return "unknown"
    # 0.x is pre-1.0 territory where any change may be breaking.
    if cur.major == 0 or new.major == 0:
        return "major"
    if new.major != cur.major:
        return "major"
    if new.minor != cur.minor:
        return "minor"
    return "patch"


# Cumulative bump-level inclusion. --level=minor means "include patch and minor".
# "unknown" is only included under the explicit --level=all opt-in, because
# synthetic version transitions (falco 0.0.0 -> 0.43.1, akto mini-testing-X -> 1.Y)
# are the riskiest class and must not auto-merge.
_LEVEL_INCLUDES: dict[str, frozenset[str]] = {
    "patch": frozenset({"patch"}),
    "minor": frozenset({"patch", "minor"}),
    "major": frozenset({"patch", "minor", "major"}),
    "all": frozenset({"patch", "minor", "major", "unknown"}),
}


def _lookup_critical(tool: str, versions: dict) -> bool:
    """Return the critical flag for a tool from versions.yaml."""
    for category in ("python_tools", "binary_tools", "special_tools"):
        if tool in versions.get(category, {}):
            return bool(versions[category][tool].get("critical", False))
    return False


def _select_tools_for_update(
    results: dict[str, tuple[str, str, bool]],
    versions: dict,
    critical_only: bool,
    level: str,
) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str, str]]]:
    """
    Pick which outdated tools to update based on critical_only + bump level.

    Args:
        results: mapping from tool name to (current, latest, is_outdated)
                 as emitted by check_latest_versions().
        versions: parsed versions.yaml (for critical-flag lookup).
        critical_only: if True, skip tools where critical is False.
        level: one of _LEVEL_INCLUDES keys ("patch", "minor", "major", "all").

    Returns:
        (to_update, skipped) where
          to_update = [(tool, current, latest), ...]
          skipped   = [(tool, current, latest, reason), ...]
    """
    if level not in _LEVEL_INCLUDES:
        raise ValueError(
            f"Unknown bump level {level!r}; expected one of {sorted(_LEVEL_INCLUDES)}"
        )
    allowed_levels = _LEVEL_INCLUDES[level]

    to_update: list[tuple[str, str, str]] = []
    skipped: list[tuple[str, str, str, str]] = []

    for tool, (current, latest, is_outdated) in results.items():
        if not is_outdated:
            continue
        if critical_only and not _lookup_critical(tool, versions):
            skipped.append((tool, current, latest, "non-critical"))
            continue
        bump_level = classify_bump(current, latest)
        if bump_level not in allowed_levels:
            skipped.append((tool, current, latest, f"level={bump_level}"))
            continue
        to_update.append((tool, current, latest))

    return to_update, skipped


def load_versions() -> dict:
    """Load versions.yaml."""
    if not VERSIONS_YAML.exists():
        err(f"versions.yaml not found at {VERSIONS_YAML}")
        sys.exit(1)

    with open(VERSIONS_YAML, encoding="utf-8") as f:
        data: dict[Any, Any] = yaml.safe_load(f) or {}
        return data


def save_versions(data: dict) -> None:
    """Save versions.yaml with updated timestamp."""
    # Update version history
    if "version_history" not in data:
        data["version_history"] = []

    data["version_history"].insert(
        0,
        {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "action": "Automated version update",
            "tools_updated": [],
            "updated_by": "update_versions.py",
            "notes": "",
        },
    )

    # newline="\n" forces LF on all platforms; without it Windows text-mode
    # writes emit CRLF for every line, producing a full-file false diff (#555).
    with open(VERSIONS_YAML, "w", encoding="utf-8", newline="\n") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def get_latest_github_release(repo: str) -> str | None:
    """Get latest release version from GitHub using gh CLI."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases/latest"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        tag = data.get("tag_name", "")
        # Strip 'v' prefix if present
        version: str = str(tag).lstrip("v") if tag else ""
        return version if version else None
    except (subprocess.CalledProcessError, json.JSONDecodeError, FileNotFoundError):
        return None


def get_latest_pypi_version(package: str) -> str | None:
    """Get latest version from PyPI."""
    try:
        result = subprocess.run(
            ["pip", "index", "versions", package],
            capture_output=True,
            text=True,
            check=True,
        )
        # Parse output: "package (X.Y.Z)"
        match = re.search(r"\(([0-9.]+)\)", result.stdout.split("\n")[0])
        return match.group(1) if match else None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_npm_version_exists(package: str, version: str) -> bool:
    """Check if a specific npm package version exists."""
    try:
        result = subprocess.run(
            ["npm", "view", f"{package}@{version}", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0 and version in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_github_release_exists(repo: str, version: str) -> bool:
    """Check if a specific GitHub release version exists."""
    try:
        # Try both with and without 'v' prefix
        for tag in [f"v{version}", version]:
            result = subprocess.run(
                ["gh", "api", f"repos/{repo}/releases/tags/{tag}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_pypi_version_exists(package: str, version: str) -> bool:
    """Check if a specific PyPI package version exists."""
    try:
        result = subprocess.run(
            ["pip", "index", "versions", package],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False
        # Check if version appears in available versions
        return version in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def check_npm_version_exists(package: str, version: str) -> bool:
    """Check if a specific npm package version exists."""
    try:
        result = subprocess.run(
            ["npm", "view", f"{package}@{version}", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0 and version in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def validate_all_versions() -> tuple[list[str], list[str]]:
    """
    Validate that all versions in versions.yaml exist upstream.

    Returns:
        Tuple of (passed_tools, failed_tools)
    """
    versions = load_versions()
    passed = []
    failed = []

    log("Validating Python tool versions on PyPI...")
    for tool, info in versions.get("python_tools", {}).items():
        version = info["version"]
        pypi_package = info.get("pypi_package")
        if not pypi_package:
            # Skip tools without PyPI package
            ok(f"{tool}: {version} (skipped - no PyPI package)")
            passed.append(tool)
            continue

        if check_pypi_version_exists(pypi_package, version):
            ok(f"{tool}: {version} (exists on PyPI)")
            passed.append(tool)
        else:
            err(f"{tool}: {version} NOT FOUND on PyPI ({pypi_package})")
            failed.append(tool)

    log("Validating binary tool versions on GitHub...")
    for tool, info in versions.get("binary_tools", {}).items():
        version = info["version"]
        github_repo = info.get("github_repo")
        if not github_repo:
            ok(f"{tool}: {version} (skipped - no GitHub repo)")
            passed.append(tool)
            continue

        if check_github_release_exists(github_repo, version):
            ok(f"{tool}: {version} (exists on GitHub)")
            passed.append(tool)
        else:
            err(f"{tool}: {version} NOT FOUND on GitHub ({github_repo})")
            failed.append(tool)

    log("Validating special tool versions...")
    for tool, info in versions.get("special_tools", {}).items():
        version = info["version"]
        github_repo = info.get("github_repo")
        npm_package = info.get("npm_package")

        if npm_package:
            if check_npm_version_exists(npm_package, version):
                ok(f"{tool}: {version} (exists on npm)")
                passed.append(tool)
            else:
                err(f"{tool}: {version} NOT FOUND on npm ({npm_package})")
                failed.append(tool)
        elif github_repo:
            if check_github_release_exists(github_repo, version):
                ok(f"{tool}: {version} (exists on GitHub)")
                passed.append(tool)
            else:
                err(f"{tool}: {version} NOT FOUND on GitHub ({github_repo})")
                failed.append(tool)
        else:
            ok(f"{tool}: {version} (skipped - manual validation required)")
            passed.append(tool)

    # Check npm tools specifically (cdxgen is in special_tools but uses npm)
    log("Validating npm tool versions...")
    npm_tools = {
        "cdxgen": (
            "@cyclonedx/cdxgen",
            versions.get("python_tools", {}).get("cdxgen", {}).get("version"),
        ),
    }
    # Also check from special_tools if cdxgen is there
    if "cdxgen" in versions.get("special_tools", {}):
        npm_tools["cdxgen"] = (
            "@cyclonedx/cdxgen",
            versions["special_tools"]["cdxgen"]["version"],
        )

    for tool, (package, version) in npm_tools.items():
        if not version:
            continue
        if tool in passed or tool in failed:
            continue  # Already validated
        if check_npm_version_exists(package, version):
            ok(f"{tool}: {version} (exists on npm)")
            passed.append(tool)
        else:
            err(f"{tool}: {version} NOT FOUND on npm ({package})")
            failed.append(tool)

    return passed, failed


def check_latest_versions() -> dict[str, tuple[str, str, bool]]:
    """
    Check for latest versions of all tools.

    Returns:
        Dict mapping tool name to (current_version, latest_version, is_outdated)
    """
    versions = load_versions()
    results = {}

    log("Checking latest versions for Python tools...")
    for tool, info in versions.get("python_tools", {}).items():
        current = info["version"]
        pypi_package = info.get("pypi_package")
        if not pypi_package:
            # Skip tools without PyPI package (e.g., lynis)
            continue
        latest = get_latest_pypi_version(pypi_package)
        if latest:
            is_outdated = current != latest
            results[tool] = (current, latest, is_outdated)
            if is_outdated:
                warn(f"{tool}: {current} → {latest} (UPDATE AVAILABLE)")
            else:
                ok(f"{tool}: {current} (latest)")
        else:
            warn(f"{tool}: Failed to check latest version")

    log("Checking latest versions for binary tools...")
    for tool, info in versions.get("binary_tools", {}).items():
        current = info["version"]
        latest = get_latest_github_release(info["github_repo"])
        if latest:
            is_outdated = current != latest
            results[tool] = (current, latest, is_outdated)
            if is_outdated:
                warn(f"{tool}: {current} → {latest} (UPDATE AVAILABLE)")
            else:
                ok(f"{tool}: {current} (latest)")
        else:
            warn(f"{tool}: Failed to check latest version")

    log("Checking latest versions for special tools...")
    for tool, info in versions.get("special_tools", {}).items():
        current = info["version"]
        latest = get_latest_github_release(info["github_repo"])
        if latest:
            is_outdated = current != latest
            results[tool] = (current, latest, is_outdated)
            if is_outdated:
                warn(f"{tool}: {current} → {latest} (UPDATE AVAILABLE)")
            else:
                ok(f"{tool}: {current} (latest)")
        else:
            warn(f"{tool}: Failed to check latest version")

    return results


def _print_classification_json() -> int:
    """
    Emit a JSON manifest of all tools with their semver bump classification.

    Output shape (to stdout, one blob — machine-readable for auto-PR workflows):

        {
          "bandit":   {"current": "1.9.3",    "latest": "1.9.4",  "level": "patch",   "critical": false},
          "semgrep":  {"current": "1.151.0",  "latest": "1.159.0","level": "minor",   "critical": true},
          "kubescape":{"current": "3.0.47",   "latest": "4.0.5",  "level": "major",   "critical": true},
          "falco":    {"current": "0.0.0",    "latest": "0.43.1", "level": "unknown", "critical": false}
        }

    Bump levels "patch" and "minor" are typically safe to auto-merge (with
    contract-test gating). "major" and "unknown" should open a tracking issue
    for human review — adapter output schemas frequently break across majors.

    Returns exit code 0 on success, non-zero only on genuine errors (missing
    deps, unreadable versions.yaml). Outdated-ness is not an error.
    """
    versions = load_versions()
    results = check_latest_versions()
    manifest: dict[str, dict[str, Any]] = {}

    for tool, (current, latest, _is_outdated) in results.items():
        critical = False
        for category in ("python_tools", "binary_tools", "special_tools"):
            if tool in versions.get(category, {}):
                critical = bool(versions[category][tool].get("critical", False))
                break
        manifest[tool] = {
            "current": current,
            "latest": latest,
            "level": classify_bump(current, latest),
            "critical": critical,
        }

    # Stable key order for deterministic diffing / testing.
    ordered = {k: manifest[k] for k in sorted(manifest)}
    print(json.dumps(ordered, indent=2))
    return 0


def update_tool_version(tool: str, new_version: str) -> bool:
    """Update a specific tool's version in versions.yaml."""
    versions = load_versions()
    updated = False

    # Check all tool categories
    for category in ["python_tools", "binary_tools", "special_tools"]:
        if tool in versions.get(category, {}):
            old_version = versions[category][tool]["version"]
            versions[category][tool]["version"] = new_version

            # Update version history
            if "version_history" not in versions:
                versions["version_history"] = []

            versions["version_history"].insert(
                0,
                {
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "action": f"Updated {tool}",
                    "tools_updated": [
                        {
                            "tool": tool,
                            "old_version": old_version,
                            "new_version": new_version,
                        }
                    ],
                    "updated_by": "update_versions.py",
                    "notes": "Manual update via --tool flag",
                },
            )

            save_versions(versions)
            ok(f"Updated {tool}: {old_version} → {new_version}")
            updated = True
            break

    if not updated:
        err(f"Tool '{tool}' not found in versions.yaml")
        return False

    return True


def sync_dockerfiles(dry_run: bool = False) -> bool:
    """Sync Dockerfiles AND .github/workflows/*.yml `env:` blocks with versions.yaml.

    Two file families are kept in sync:

    1. Dockerfiles (`Dockerfile.{deep,balanced,slim,fast}`) — shell-style
       `TOOL_VERSION="X.Y.Z"` (no whitespace around `=`).
    2. GitHub Actions workflows (`.github/workflows/*.yml`) — YAML mapping form
       `TOOL_VERSION: "X.Y.Z"` (colon + single space). Pinned env: blocks were
       added in PR #358 to harden tool installs against upstream `install.sh`
       GitHub-API "latest" lookup flakes; both files must move together when
       `versions.yaml` is bumped.

    The two regex patterns are kept distinct because a single permissive
    pattern that matched both forms would risk corrupting YAML structure.
    """
    versions = load_versions()
    all_success = True
    changes_needed = False

    log(
        "Syncing Dockerfiles + workflows with versions.yaml..."
        + (" (dry-run)" if dry_run else "")
    )

    # Build version mapping
    version_map = {}

    for tool, info in versions.get("python_tools", {}).items():
        version_map[tool] = info["version"]

    for tool, info in versions.get("binary_tools", {}).items():
        version_map[tool.upper()] = info["version"]

    for tool, info in versions.get("special_tools", {}).items():
        version_map[tool.upper()] = info["version"]

    # Update each Dockerfile
    for dockerfile_path in [
        DOCKERFILE,
        DOCKERFILE_BALANCED,
        DOCKERFILE_SLIM,
        DOCKERFILE_FAST,
    ]:
        if not dockerfile_path.exists():
            warn(f"{dockerfile_path.name} not found, skipping")
            continue

        content = dockerfile_path.read_text(encoding="utf-8")
        original_content = content

        # Replace version variables
        for tool, version in version_map.items():
            # Pattern: TOOL_VERSION="X.Y.Z"
            pattern = rf'{tool}_VERSION="[0-9.]+"'
            replacement = f'{tool}_VERSION="{version}"'
            content = re.sub(pattern, replacement, content)

            # Pattern: tool==X.Y.Z (Python packages)
            if tool.lower() in ["bandit", "semgrep", "checkov", "ruff"]:
                pattern = rf"{tool.lower()}==[0-9.]+"
                replacement = f"{tool.lower()}=={version}"
                content = re.sub(pattern, replacement, content)

        if content != original_content:
            changes_needed = True
            if dry_run:
                warn(f"{dockerfile_path.name} needs updates (dry-run, not writing)")
            else:
                # newline="\n": keep LF on Windows (see #555).
                dockerfile_path.write_text(content, encoding="utf-8", newline="\n")
                ok(f"Updated {dockerfile_path.name}")
        else:
            ok(f"{dockerfile_path.name} already in sync")

    # Update workflow env: blocks (e.g., TRIVY_VERSION: "0.70.0")
    workflow_files = (
        sorted(WORKFLOWS_DIR.glob("*.yml")) if WORKFLOWS_DIR.exists() else []
    )
    for workflow_path in workflow_files:
        content = workflow_path.read_text(encoding="utf-8")
        original_content = content

        for tool, version in version_map.items():
            # Pattern: `<indent>TOOL_VERSION: "X.Y.Z"` (canonical YAML — single
            # space after colon, double-quoted value). yamllint enforces the
            # canonical spacing so we normalize on replace.
            pattern = rf'{tool}_VERSION:\s+"[0-9.]+"'
            replacement = f'{tool}_VERSION: "{version}"'
            content = re.sub(pattern, replacement, content)

        if content != original_content:
            changes_needed = True
            if dry_run:
                warn(
                    f".github/workflows/{workflow_path.name} needs updates (dry-run, not writing)"
                )
            else:
                # newline="\n": keep LF on Windows (see #555).
                workflow_path.write_text(content, encoding="utf-8", newline="\n")
                ok(f"Updated .github/workflows/{workflow_path.name}")
        else:
            ok(f".github/workflows/{workflow_path.name} already in sync")

    if dry_run and changes_needed:
        err("Dockerfiles or workflows are out of sync with versions.yaml")
        return False

    return all_success


def generate_report() -> None:
    """Generate version consistency report."""
    versions = load_versions()

    print("\n" + "=" * 80)
    print("JMo Security Suite - Version Consistency Report")
    print("=" * 80 + "\n")

    print("Python Tools:")
    print("-" * 80)
    for tool, info in versions.get("python_tools", {}).items():
        critical = "🔴 CRITICAL" if info.get("critical") else "⚪ Normal"
        print(f"  {tool:15s} v{info['version']:12s} {critical}")
        print(f"                → {info['description']}")

    print("\nBinary Tools:")
    print("-" * 80)
    for tool, info in versions.get("binary_tools", {}).items():
        critical = "🔴 CRITICAL" if info.get("critical") else "⚪ Normal"
        print(f"  {tool:15s} v{info['version']:12s} {critical}")
        print(f"                → {info['description']}")

    print("\nSpecial Tools:")
    print("-" * 80)
    for tool, info in versions.get("special_tools", {}).items():
        critical = "🔴 CRITICAL" if info.get("critical") else "⚪ Normal"
        print(f"  {tool:15s} v{info['version']:12s} {critical}")
        print(f"                → {info['description']}")

    print("\nDocker Base Images:")
    print("-" * 80)
    for img, info in versions.get("docker_images", {}).items():
        print(f"  {img:15s} v{info['version']:12s}")
        print(f"                → {info['description']}")

    print("\n" + "=" * 80 + "\n")


def _close_superseded_version_issues(tool_names: list[str]) -> None:
    """
    Close existing open version update issues for the given tools.

    Prevents weekly duplicate accumulation by closing old issues before
    creating new ones. Matches issues by title pattern and 'dependencies' label.
    """
    import json as _json

    try:
        result = subprocess.run(
            [
                "gh",
                "issue",
                "list",
                "--state",
                "open",
                "--label",
                "dependencies",
                "--limit",
                "200",
                "--json",
                "number,title",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        existing_issues = _json.loads(result.stdout)
    except (subprocess.CalledProcessError, _json.JSONDecodeError):
        warn("Could not query existing issues; skipping dedup")
        return

    for tool in tool_names:
        # Match both "Update <tool> to v..." and "[CRITICAL] Update <tool> to v..."
        matching = [
            issue for issue in existing_issues if f"Update {tool} to " in issue["title"]
        ]
        if not matching:
            continue

        for issue in matching:
            try:
                subprocess.run(
                    [
                        "gh",
                        "issue",
                        "close",
                        str(issue["number"]),
                        "--comment",
                        "Superseded by newer version check. Closing stale issue.",
                    ],
                    check=True,
                    capture_output=True,
                )
                log(f"  Closed superseded issue #{issue['number']}: {issue['title']}")
            except subprocess.CalledProcessError:
                warn(f"  Failed to close issue #{issue['number']}")


def check_outdated_and_create_issues(create_issues: bool = False) -> int:
    """
    Check for outdated tools and optionally create GitHub issues.

    Returns:
        Number of outdated tools found
    """
    versions = load_versions()
    results = check_latest_versions()

    outdated_critical = []
    outdated_normal = []
    outdated_manual = []

    # Categorize outdated tools
    for tool, (current, latest, is_outdated) in results.items():
        if not is_outdated:
            continue

        # Manual-install tools are never baked into images and can't be
        # auto-updated; filing a weekly issue for them is pure noise (they
        # always read as outdated). Surface the version delta in the log but
        # don't create an issue. See MANUAL_INSTALL_TOOLS comment above.
        if tool in MANUAL_INSTALL_TOOLS:
            outdated_manual.append((tool, current, latest))
            continue

        # Check if tool is critical
        is_critical = False
        for category in ["python_tools", "binary_tools", "special_tools"]:
            if tool in versions.get(category, {}):
                is_critical = versions[category][tool].get("critical", False)
                break

        if is_critical:
            outdated_critical.append((tool, current, latest))
        else:
            outdated_normal.append((tool, current, latest))

    # Print summary
    if outdated_critical:
        warn(f"Found {len(outdated_critical)} outdated CRITICAL tools:")
        for tool, current, latest in outdated_critical:
            warn(f"  - {tool}: {current} → {latest}")

    if outdated_normal:
        log(f"Found {len(outdated_normal)} outdated non-critical tools:")
        for tool, current, latest in outdated_normal:
            log(f"  - {tool}: {current} → {latest}")

    if outdated_manual:
        log(
            f"Found {len(outdated_manual)} outdated MANUAL-install tools "
            "(no issue filed; install manually):"
        )
        for tool, current, latest in outdated_manual:
            log(f"  - MANUAL: {tool}: {current} → {latest}")

    # Create GitHub issues if requested
    if create_issues and (outdated_critical or outdated_normal or outdated_manual):
        log("Closing superseded version update issues before creating new ones...")
        # Include manual tools in the sweep so any lingering "Update <manual-tool>"
        # issues (filed before we stopped creating them) get auto-closed and are
        # never re-filed — keeps the fix self-healing without manual cleanup.
        _close_superseded_version_issues(
            [t for t, _, _ in outdated_critical]
            + [t for t, _, _ in outdated_normal]
            + [t for t, _, _ in outdated_manual]
        )
        log("Creating GitHub issues for outdated tools...")

        for tool, current, latest in outdated_critical:
            title = f"[CRITICAL] Update {tool} to v{latest}"
            body = f"""## Summary

Critical security tool **{tool}** is outdated and should be updated immediately.

- **Current version:** {current}
- **Latest version:** {latest}
- **Priority:** 🔴 CRITICAL
- **Update window:** 7 days (per update policy)

## Action Required

```bash
python3 scripts/dev/update_versions.py --tool {tool} --version {latest}
python3 scripts/dev/update_versions.py --sync
```

## Related

- ROADMAP.md #14: Tool Version Consistency
- Issue #46: Automated Dependency Management

---
*Automated issue created by version checker (scripts/dev/update_versions.py)*
"""
            try:
                subprocess.run(
                    [
                        "gh",
                        "issue",
                        "create",
                        "--title",
                        title,
                        "--body",
                        body,
                        "--label",
                        "dependencies,critical",
                    ],
                    check=True,
                    capture_output=True,
                )
                ok(f"Created issue: {title}")
            except subprocess.CalledProcessError:
                warn(f"Failed to create issue for {tool}")

        for tool, current, latest in outdated_normal:
            title = f"Update {tool} to v{latest}"
            body = f"""## Summary

Security tool **{tool}** has a newer version available.

- **Current version:** {current}
- **Latest version:** {latest}
- **Priority:** ⚪ Normal
- **Update window:** Monthly (per update policy)

## Action Required

```bash
python3 scripts/dev/update_versions.py --tool {tool} --version {latest}
python3 scripts/dev/update_versions.py --sync
```

## Related

- ROADMAP.md #14: Tool Version Consistency
- Issue #46: Automated Dependency Management

---
*Automated issue created by version checker (scripts/dev/update_versions.py)*
"""
            try:
                subprocess.run(
                    [
                        "gh",
                        "issue",
                        "create",
                        "--title",
                        title,
                        "--body",
                        body,
                        "--label",
                        "dependencies",
                    ],
                    check=True,
                    capture_output=True,
                )
                ok(f"Created issue: {title}")
            except subprocess.CalledProcessError:
                warn(f"Failed to create issue for {tool}")

    # Manual tools are counted as outdated (messaging/`--fail-if-outdated`
    # stay honest) even though no issue is filed for them.
    return len(outdated_critical) + len(outdated_normal) + len(outdated_manual)


def update_all_tools(
    critical_only: bool = False,
    level: str = "all",
    dry_run: bool = False,
) -> int:
    """
    Update tools to their latest versions, optionally filtered by bump level.

    Args:
        critical_only: If True, only update tools marked as critical.
        level: Cumulative bump-level filter — "patch", "minor", "major", or
               "all". "minor" includes patch+minor; "major" includes
               patch+minor+major; "all" includes everything including
               "unknown" (synthetic version transitions). Default "all"
               preserves the pre-existing behaviour of this script.
        dry_run: If True, report what would change without writing
                 versions.yaml. Useful for verification and maintainer preview.

    Returns:
        Number of tools updated (0 if all already up-to-date).
    """
    log("Checking for tool updates...")
    results = check_latest_versions()
    versions = load_versions()

    to_update, skipped_tools = _select_tools_for_update(
        results, versions, critical_only=critical_only, level=level
    )

    updated_tools: list[tuple[str, str, str]] = []
    failed_tools: list[tuple[str, str, str]] = []

    action_verb = "Would update" if dry_run else "Updating"
    for tool, current, latest in to_update:
        log(f"{action_verb} {tool}: {current} → {latest}")
        if dry_run:
            updated_tools.append((tool, current, latest))
            continue
        if update_tool_version(tool, latest):
            updated_tools.append((tool, current, latest))
            ok(f"✓ {tool} updated successfully")
        else:
            failed_tools.append((tool, current, latest))
            warn(f"✗ {tool} update failed")

    # Print summary
    print("")
    if updated_tools:
        summary_verb = "Would update" if dry_run else "Successfully updated"
        ok(f"{summary_verb} {len(updated_tools)} tool(s):")
        for tool, old, new in updated_tools:
            print(f"  • {tool}: {old} → {new}")

    if failed_tools:
        warn(f"Failed to update {len(failed_tools)} tool(s):")
        for tool, old, new in failed_tools:
            print(f"  • {tool}: {old} → {new}")

    if skipped_tools:
        log(f"Skipped {len(skipped_tools)} tool(s):")
        for tool, old, new, reason in skipped_tools:
            print(f"  • {tool}: {old} → {new} ({reason})")

    print("")
    if updated_tools:
        if dry_run:
            log(
                "Dry run — versions.yaml was NOT modified. Re-run without --dry-run to apply."
            )
            return 0
        log("Next steps:")
        print("  1. Run: python3 scripts/dev/update_versions.py --sync")
        print("  2. Test: make docker-build")
        print("  3. Commit: git add versions.yaml Dockerfile*")
        print('  4. Commit: git commit -m "deps(tools): update all to latest"')
        return len(updated_tools)
    elif failed_tools:
        err("Some tool updates failed. Fix errors and retry.")
        return 1
    else:
        ok("All tools are already up-to-date!")
        return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Manage tool versions for JMo Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check-latest",
        action="store_true",
        help="Check for latest versions of all tools",
    )
    group.add_argument(
        "--tool", type=str, help="Tool name to update (requires --version)"
    )
    group.add_argument(
        "--sync",
        action="store_true",
        help="Sync Dockerfiles AND .github/workflows/*.yml env: blocks with versions.yaml",
    )
    group.add_argument(
        "--report", action="store_true", help="Generate version consistency report"
    )
    group.add_argument(
        "--check-outdated",
        action="store_true",
        help="Check for outdated tools (use with --create-issues)",
    )
    group.add_argument(
        "--update-all",
        action="store_true",
        help="Update ALL tools to latest versions automatically",
    )
    group.add_argument(
        "--validate",
        action="store_true",
        help="Validate all versions exist upstream (GitHub, PyPI, npm) before Docker build",
    )
    group.add_argument(
        "--classify",
        action="store_true",
        help="Emit JSON manifest of all tools with current, latest, semver bump level, and critical flag",
    )

    parser.add_argument("--version", type=str, help="Version to set (used with --tool)")
    parser.add_argument(
        "--create-issues",
        action="store_true",
        help="Create GitHub issues for outdated tools (used with --check-outdated)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Check for changes without writing files (used with --sync or "
            "--update-all). With --update-all, prints which bumps would be "
            "applied without modifying versions.yaml."
        ),
    )
    parser.add_argument(
        "--critical-only",
        action="store_true",
        help="Only update critical tools (used with --update-all)",
    )
    parser.add_argument(
        "--level",
        choices=["patch", "minor", "major", "all"],
        default="all",
        help=(
            "Cumulative bump-level filter for --update-all. 'patch' updates "
            "patch bumps only; 'minor' includes patch+minor; 'major' includes "
            "patch+minor+major (still excludes 'unknown'); 'all' includes "
            "everything. Default: all. Used with --update-all."
        ),
    )
    parser.add_argument(
        "--fail-if-outdated",
        action="store_true",
        help=(
            "Exit 1 when outdated tools are found (used with --check-latest or "
            "--check-outdated). Default: exit 0 — outdated is informational, not "
            "an error. Opt into strict gating with this flag."
        ),
    )

    args = parser.parse_args()

    # Validate arguments
    if args.tool and not args.version:
        err("--tool requires --version")
        return 1

    if args.create_issues and not args.check_outdated:
        err("--create-issues requires --check-outdated")
        return 1

    if args.level != "all" and not args.update_all:
        err("--level requires --update-all")
        return 1

    # Execute commands
    try:
        if args.check_latest:
            results = check_latest_versions()
            outdated = sum(1 for _, _, is_outdated in results.values() if is_outdated)
            if outdated > 0:
                warn(f"{outdated} tool(s) have updates available")
                if args.fail_if_outdated:
                    return 1
                return 0
            else:
                ok("All tools are up to date")
                return 0

        elif args.classify:
            return _print_classification_json()

        elif args.tool:
            if update_tool_version(args.tool, args.version):
                log("Run --sync to apply changes to Dockerfiles")
                return 0
            return 1

        elif args.sync:
            if sync_dockerfiles(dry_run=args.dry_run):
                if args.dry_run:
                    ok("All Dockerfiles in sync (dry-run check passed)")
                else:
                    ok("All Dockerfiles synced")
                return 0
            return 1

        elif args.report:
            generate_report()
            return 0

        elif args.check_outdated:
            count = check_outdated_and_create_issues(args.create_issues)
            if count > 0:
                warn(f"{count} outdated tool(s) found")
                if args.fail_if_outdated:
                    return 1
                return 0
            else:
                ok("All tools are up to date")
                return 0

        elif args.update_all:
            updated_count = update_all_tools(
                critical_only=args.critical_only,
                level=args.level,
                dry_run=args.dry_run,
            )
            if updated_count > 0 and not args.dry_run:
                log(
                    "Don't forget to run: python3 scripts/dev/update_versions.py --sync"
                )
            return 0

        elif args.validate:
            log("Validating all tool versions exist upstream...")
            passed, failed = validate_all_versions()
            print()
            log(f"Validation complete: {len(passed)} passed, {len(failed)} failed")
            if failed:
                err(f"Failed tools: {', '.join(failed)}")
                err("Fix these versions before building Docker images")
                return 1
            else:
                ok("All versions validated successfully - safe to build")
                return 0

    except Exception as e:
        err(f"Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
