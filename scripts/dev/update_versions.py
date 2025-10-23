#!/usr/bin/env python3
"""
Update tool versions across Dockerfile, install_tools.sh, and versions.yaml.

This script provides automated version management for all external security tools
used by JMo Security Suite. It serves as Layer 4 of the 5-layer version management
system described in ROADMAP.md #14.

Usage:
  # Check for latest versions of all tools
  python3 scripts/dev/update_versions.py --check-latest

  # Update specific tool
  python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

  # Sync all Dockerfiles and install_tools.sh from versions.yaml
  python3 scripts/dev/update_versions.py --sync

  # Generate version consistency report
  python3 scripts/dev/update_versions.py --report

  # Check for outdated tools and create GitHub issues
  python3 scripts/dev/update_versions.py --check-outdated --create-issues

Requirements:
  - PyYAML: pip install pyyaml
  - GitHub CLI (gh) for --check-latest and --create-issues
  - Internet connection for GitHub API access

Exit codes:
  0: Success
  1: Validation errors or version mismatch detected
  2: Missing dependencies
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent
VERSIONS_YAML = REPO_ROOT / "versions.yaml"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERFILE_SLIM = REPO_ROOT / "Dockerfile.slim"
DOCKERFILE_ALPINE = REPO_ROOT / "Dockerfile.alpine"
INSTALL_TOOLS = REPO_ROOT / "scripts" / "dev" / "install_tools.sh"

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


def load_versions() -> Dict:
    """Load versions.yaml."""
    if not VERSIONS_YAML.exists():
        err(f"versions.yaml not found at {VERSIONS_YAML}")
        sys.exit(1)

    with open(VERSIONS_YAML) as f:
        data: Dict[Any, Any] = yaml.safe_load(f) or {}
        return data


def save_versions(data: Dict) -> None:
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

    with open(VERSIONS_YAML, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def get_latest_github_release(repo: str) -> Optional[str]:
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


def get_latest_pypi_version(package: str) -> Optional[str]:
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


def check_latest_versions() -> Dict[str, Tuple[str, str, bool]]:
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
        latest = get_latest_pypi_version(info["pypi_package"])
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
    """Sync all Dockerfiles with versions from versions.yaml."""
    versions = load_versions()
    all_success = True
    changes_needed = False

    log("Syncing Dockerfiles with versions.yaml..." + (" (dry-run)" if dry_run else ""))

    # Build version mapping
    version_map = {}

    for tool, info in versions.get("python_tools", {}).items():
        version_map[tool] = info["version"]

    for tool, info in versions.get("binary_tools", {}).items():
        version_map[tool.upper()] = info["version"]

    for tool, info in versions.get("special_tools", {}).items():
        version_map[tool.upper()] = info["version"]

    # Update each Dockerfile
    for dockerfile_path in [DOCKERFILE, DOCKERFILE_SLIM, DOCKERFILE_ALPINE]:
        if not dockerfile_path.exists():
            warn(f"{dockerfile_path.name} not found, skipping")
            continue

        content = dockerfile_path.read_text()
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
                dockerfile_path.write_text(content)
                ok(f"Updated {dockerfile_path.name}")
        else:
            ok(f"{dockerfile_path.name} already in sync")

    if dry_run and changes_needed:
        err("Dockerfiles are out of sync with versions.yaml")
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

    # Categorize outdated tools
    for tool, (current, latest, is_outdated) in results.items():
        if not is_outdated:
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

    # Create GitHub issues if requested
    if create_issues and (outdated_critical or outdated_normal):
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

    return len(outdated_critical) + len(outdated_normal)


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
        "--sync", action="store_true", help="Sync Dockerfiles with versions.yaml"
    )
    group.add_argument(
        "--report", action="store_true", help="Generate version consistency report"
    )
    group.add_argument(
        "--check-outdated",
        action="store_true",
        help="Check for outdated tools (use with --create-issues)",
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
        help="Check for changes without writing files (used with --sync)",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.tool and not args.version:
        err("--tool requires --version")
        return 1

    if args.create_issues and not args.check_outdated:
        err("--create-issues requires --check-outdated")
        return 1

    # Execute commands
    try:
        if args.check_latest:
            results = check_latest_versions()
            outdated = sum(1 for _, _, is_outdated in results.values() if is_outdated)
            if outdated > 0:
                warn(f"{outdated} tool(s) have updates available")
                return 1
            else:
                ok("All tools are up to date")
                return 0

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
                return 1
            else:
                ok("All tools are up to date")
                return 0

    except Exception as e:
        err(f"Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
