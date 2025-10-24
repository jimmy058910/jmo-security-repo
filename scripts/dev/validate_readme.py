#!/usr/bin/env python3
"""
Validate README consistency across PyPI, Docker Hub, and GHCR.

This script helps maintain consistency between GitHub README and what's
published to PyPI and Docker Hub. GHCR auto-syncs from GitHub (no check needed).

Usage:
    python3 scripts/dev/validate_readme.py [--fix] [--check-dockerhub]

Exit codes:
    0 - All READMEs are consistent
    1 - Differences found (use --fix to update)
    2 - Network/API error
"""

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ============================================================================
# PyPI Validation
# ============================================================================

def get_pypi_readme(package_name: str = "jmo-security") -> str:
    """Fetch README content from PyPI JSON API."""
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data["info"]["description"]
    except Exception as e:
        print(f"❌ Error fetching PyPI README: {e}", file=sys.stderr)
        sys.exit(2)


def get_local_readme(readme_path: Path = Path("README.md")) -> str:
    """Read local README.md content."""
    if not readme_path.exists():
        print(f"❌ README not found: {readme_path}", file=sys.stderr)
        sys.exit(2)
    return readme_path.read_text(encoding="utf-8")


def extract_badges(content: str) -> List[str]:
    """Extract badge lines from README content."""
    lines = content.splitlines()
    badges = []
    for line in lines:
        # Match lines containing badge markdown: [![...](...)
        if line.strip().startswith("[![") or "](https://img.shields.io/" in line:
            badges.append(line.strip())
    return badges


def compare_badges(local_badges: List[str], remote_badges: List[str]) -> Tuple[List[str], List[str]]:
    """Compare local and remote badges, return differences."""
    local_set = set(local_badges)
    remote_set = set(remote_badges)

    missing_on_remote = local_set - remote_set
    extra_on_remote = remote_set - local_set

    return sorted(missing_on_remote), sorted(extra_on_remote)


def check_pypi_issues(local_content: str, pypi_content: str) -> List[Dict[str, str]]:
    """Check for known PyPI-specific consistency issues."""
    issues = []

    # Issue 1: Docker Hub namespace inconsistency
    if "docker/pulls/jimmy058910/jmo-security" in pypi_content and \
       "docker/pulls/jmogaming/jmo-security" in local_content:
        issues.append({
            "type": "Docker Hub namespace mismatch",
            "remote": "jimmy058910/jmo-security (old)",
            "local": "jmogaming/jmo-security (current)",
            "fix": "Update PyPI README to use jmogaming namespace (publish new release)"
        })

    # Issue 2: Version string mismatch
    pypi_version_match = re.search(r"v(\d+\.\d+\.\d+)", pypi_content)
    local_version_match = re.search(r"v(\d+\.\d+\.\d+)", local_content)

    if pypi_version_match and local_version_match:
        pypi_ver = pypi_version_match.group(1)
        local_ver = local_version_match.group(1)
        if pypi_ver != local_ver:
            issues.append({
                "type": "Version mismatch in content",
                "remote": f"v{pypi_ver}",
                "local": f"v{local_ver}",
                "fix": "Republish to PyPI after version bump"
            })

    return issues


# ============================================================================
# Docker Hub Validation
# ============================================================================

def get_dockerhub_readme(repo: str = "jmogaming/jmo-security") -> Optional[str]:
    """
    Fetch README from Docker Hub API.

    Note: Docker Hub API requires authentication for most endpoints.
    This function attempts to fetch public repository data.
    """
    url = f"https://hub.docker.com/v2/repositories/{repo}/"
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "jmo-security-validator/1.0")

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            # Docker Hub full_description field contains the README
            return data.get("full_description", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"⚠️  Docker Hub repository not found: {repo}")
            print(f"    This is normal if you haven't pushed to Docker Hub yet.")
            return None
        print(f"⚠️  Error fetching Docker Hub README (HTTP {e.code})")
        print(f"    Docker Hub API may require authentication for this repo.")
        return None
    except Exception as e:
        print(f"⚠️  Could not fetch Docker Hub README: {e}")
        return None


def check_dockerhub_local_consistency(local_dockerhub_readme: str) -> List[Dict[str, str]]:
    """Check Docker Hub README for common issues."""
    issues = []

    # Issue 1: Old Docker Hub namespace in DOCKER_HUB_README.md
    if "jimmy058910/jmo-security" in local_dockerhub_readme:
        issues.append({
            "type": "Docker Hub namespace in local file",
            "file": "DOCKER_HUB_README.md",
            "found": "jimmy058910/jmo-security (old)",
            "expected": "jmogaming/jmo-security (current)",
            "fix": "Update DOCKER_HUB_README.md to use jmogaming namespace"
        })

    # Issue 2: Version mentions (check if version is recent)
    version_matches = re.findall(r"v?(\d+\.\d+\.\d+)", local_dockerhub_readme)
    if version_matches:
        # Get version from pyproject.toml
        pyproject_path = Path("pyproject.toml")
        if pyproject_path.exists():
            pyproject_content = pyproject_path.read_text()
            current_version_match = re.search(r'version\s*=\s*"(\d+\.\d+\.\d+)"', pyproject_content)
            if current_version_match:
                current_version = current_version_match.group(1)
                # Check if Docker Hub README mentions current version
                if current_version not in local_dockerhub_readme:
                    issues.append({
                        "type": "Outdated version in Docker Hub README",
                        "file": "DOCKER_HUB_README.md",
                        "found": f"Versions mentioned: {', '.join(set(version_matches))}",
                        "expected": f"Should include v{current_version}",
                        "fix": "Update DOCKER_HUB_README.md with current version, then sync to Docker Hub"
                    })

    return issues


def check_dockerhub_sync_config() -> List[Dict[str, str]]:
    """Check if Docker Hub sync is configured in GitHub Actions."""
    issues = []

    release_yml = Path(".github/workflows/release.yml")
    if not release_yml.exists():
        issues.append({
            "type": "Missing release workflow",
            "file": ".github/workflows/release.yml",
            "found": "File not found",
            "expected": "Release workflow with docker-hub-readme job",
            "fix": "Create release workflow with Docker Hub sync"
        })
        return issues

    content = release_yml.read_text()

    # Check for docker-hub-readme job
    if "docker-hub-readme:" not in content:
        issues.append({
            "type": "Missing Docker Hub sync job",
            "file": ".github/workflows/release.yml",
            "found": "No docker-hub-readme job",
            "expected": "Job to sync DOCKER_HUB_README.md",
            "fix": "Add docker-hub-readme job to release.yml"
        })

    # Check for DOCKERHUB_ENABLED gate
    if "vars.DOCKERHUB_ENABLED" not in content:
        issues.append({
            "type": "Missing DOCKERHUB_ENABLED variable",
            "file": ".github/workflows/release.yml",
            "found": "No DOCKERHUB_ENABLED check",
            "expected": "if: vars.DOCKERHUB_ENABLED == 'true'",
            "fix": "Add repository variable DOCKERHUB_ENABLED=true in GitHub settings"
        })

    # Check for dockerhub-description action
    if "dockerhub-description" not in content:
        issues.append({
            "type": "Missing Docker Hub description action",
            "file": ".github/workflows/release.yml",
            "found": "No dockerhub-description action",
            "expected": "uses: peter-evans/dockerhub-description@v5",
            "fix": "Add dockerhub-description action to sync README"
        })

    return issues


# ============================================================================
# Main Validation Flow
# ============================================================================

def validate_pypi(args) -> Tuple[bool, List[Dict]]:
    """Validate PyPI README consistency."""
    print("\n" + "="*60)
    print("📦 PyPI README Validation")
    print("="*60)

    local_readme = get_local_readme()
    pypi_readme = get_pypi_readme(args.package)

    local_badges = extract_badges(local_readme)
    pypi_badges = extract_badges(pypi_readme)

    print(f"\n📊 Badge Summary:")
    print(f"  Local (GitHub):  {len(local_badges)} badges")
    print(f"  PyPI:            {len(pypi_badges)} badges")

    missing, extra = compare_badges(local_badges, pypi_badges)
    pypi_issues = check_pypi_issues(local_readme, pypi_readme)

    has_issues = bool(missing or extra or pypi_issues)

    if not has_issues:
        print("\n✅ PyPI README is consistent with GitHub!")
        return True, []

    all_issues = []

    if missing:
        print(f"\n❌ Badges missing on PyPI ({len(missing)}):")
        for badge in missing:
            display = badge[:100] + "..." if len(badge) > 100 else badge
            print(f"  - {display}")
            all_issues.append({
                "platform": "PyPI",
                "type": "Missing badge",
                "details": display
            })

    if extra:
        print(f"\n❌ Extra badges on PyPI not in local ({len(extra)}):")
        for badge in extra:
            display = badge[:100] + "..." if len(badge) > 100 else badge
            print(f"  - {display}")
            all_issues.append({
                "platform": "PyPI",
                "type": "Extra badge",
                "details": display
            })

    if pypi_issues:
        print(f"\n❌ Known PyPI issues ({len(pypi_issues)}):")
        for issue in pypi_issues:
            print(f"  • {issue['type']}")
            print(f"    Remote: {issue['remote']}")
            print(f"    Local:  {issue['local']}")
            if args.fix:
                print(f"    Fix:    {issue['fix']}")
            all_issues.append({
                "platform": "PyPI",
                "type": issue["type"],
                "details": issue
            })

    return False, all_issues


def validate_dockerhub(args) -> Tuple[bool, List[Dict]]:
    """Validate Docker Hub README consistency and configuration."""
    if not args.check_dockerhub:
        return True, []  # Skip if not requested

    print("\n" + "="*60)
    print("🐳 Docker Hub README Validation")
    print("="*60)

    all_issues = []

    # Check local Docker Hub README file
    dockerhub_readme_path = Path("DOCKER_HUB_README.md")
    if not dockerhub_readme_path.exists():
        print("\n❌ DOCKER_HUB_README.md not found")
        all_issues.append({
            "platform": "Docker Hub",
            "type": "Missing file",
            "details": "DOCKER_HUB_README.md does not exist"
        })
        return False, all_issues

    local_dockerhub_readme = dockerhub_readme_path.read_text()
    print(f"\n📄 Local Docker Hub README: {len(local_dockerhub_readme)} bytes")

    # Check local file consistency
    local_issues = check_dockerhub_local_consistency(local_dockerhub_readme)
    if local_issues:
        print(f"\n❌ Issues in DOCKER_HUB_README.md ({len(local_issues)}):")
        for issue in local_issues:
            print(f"  • {issue['type']}")
            print(f"    File:     {issue['file']}")
            print(f"    Found:    {issue['found']}")
            print(f"    Expected: {issue['expected']}")
            if args.fix:
                print(f"    Fix:      {issue['fix']}")
            all_issues.append({
                "platform": "Docker Hub",
                "type": issue["type"],
                "details": issue
            })

    # Check GitHub Actions sync configuration
    sync_issues = check_dockerhub_sync_config()
    if sync_issues:
        print(f"\n❌ Docker Hub sync configuration issues ({len(sync_issues)}):")
        for issue in sync_issues:
            print(f"  • {issue['type']}")
            print(f"    File:     {issue['file']}")
            print(f"    Found:    {issue['found']}")
            print(f"    Expected: {issue['expected']}")
            if args.fix:
                print(f"    Fix:      {issue['fix']}")
            all_issues.append({
                "platform": "Docker Hub",
                "type": issue["type"],
                "details": issue
            })

    # Optional: Check remote Docker Hub (may fail without auth)
    dockerhub_readme = get_dockerhub_readme(args.dockerhub_repo)
    if dockerhub_readme is not None:
        print(f"\n📄 Remote Docker Hub README: {len(dockerhub_readme)} bytes")
        # Basic comparison (exact match not expected, Docker Hub may modify formatting)
        if len(local_dockerhub_readme.strip()) == 0:
            print("⚠️  Local DOCKER_HUB_README.md is empty!")
            all_issues.append({
                "platform": "Docker Hub",
                "type": "Empty local file",
                "details": "DOCKER_HUB_README.md has no content"
            })

    has_issues = bool(all_issues)
    if not has_issues:
        print("\n✅ Docker Hub README is properly configured!")

    return not has_issues, all_issues


def main():
    parser = argparse.ArgumentParser(
        description="Validate README consistency across PyPI and Docker Hub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check PyPI only (default)
  python3 scripts/dev/validate_readme.py

  # Check PyPI and Docker Hub
  python3 scripts/dev/validate_readme.py --check-dockerhub --fix

  # Check different PyPI package
  python3 scripts/dev/validate_readme.py --package my-package
"""
    )
    parser.add_argument("--fix", action="store_true",
                       help="Show detailed fix recommendations")
    parser.add_argument("--package", default="jmo-security",
                       help="PyPI package name (default: jmo-security)")
    parser.add_argument("--check-dockerhub", action="store_true",
                       help="Also validate Docker Hub README and sync configuration")
    parser.add_argument("--dockerhub-repo", default="jmogaming/jmo-security",
                       help="Docker Hub repository (default: jmogaming/jmo-security)")
    args = parser.parse_args()

    print(f"🔍 Validating README consistency for {args.package}...")
    if args.check_dockerhub:
        print(f"🐳 Also checking Docker Hub: {args.dockerhub_repo}")

    # Run validations
    pypi_ok, pypi_issues = validate_pypi(args)
    dockerhub_ok, dockerhub_issues = validate_dockerhub(args)

    all_issues = pypi_issues + dockerhub_issues
    all_ok = pypi_ok and dockerhub_ok

    # Summary
    print("\n" + "="*60)
    print("📊 Validation Summary")
    print("="*60)
    print(f"PyPI:       {'✅ OK' if pypi_ok else f'❌ {len(pypi_issues)} issues'}")
    if args.check_dockerhub:
        print(f"Docker Hub: {'✅ OK' if dockerhub_ok else f'❌ {len(dockerhub_issues)} issues'}")
    print(f"GHCR:       ✅ Auto-synced from GitHub (no check needed)")

    if all_ok:
        print("\n✅ All README files are consistent!")
        return 0

    # Show fix instructions
    if args.fix:
        print("\n" + "="*60)
        print("📋 How to Fix Issues")
        print("="*60)

        if pypi_issues:
            print("\n🔧 PyPI Issues:")
            print("  1. Bump version in pyproject.toml (if not already done)")
            print("  2. Update CHANGELOG.md with changes")
            print("  3. Commit: git add -A && git commit -m 'release: vX.Y.Z'")
            print("  4. Tag: git tag vX.Y.Z && git push --tags")
            print("  5. CI will automatically publish to PyPI with current README.md")
            print("\n  Or manually publish:")
            print("    python3 -m build")
            print("    twine upload dist/*")

        if dockerhub_issues:
            print("\n🔧 Docker Hub Issues:")
            print("  1. Fix DOCKER_HUB_README.md content (namespace, version)")
            print("  2. Ensure DOCKERHUB_ENABLED=true in GitHub repository variables")
            print("  3. Set secrets: DOCKERHUB_USERNAME and DOCKERHUB_TOKEN")
            print("  4. Push tag or run workflow_dispatch to sync")
            print("\n  Manual sync (if needed):")
            print("    gh workflow run release.yml")
    else:
        print("\n💡 Run with --fix to see detailed fix recommendations")
        print("💡 Run with --check-dockerhub to also validate Docker Hub")

    return 1


if __name__ == "__main__":
    sys.exit(main())
