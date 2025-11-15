#!/usr/bin/env python3
"""
Generate release notes for JMo Security from CHANGELOG.md and git commits.

Extracts release notes for a specific version from CHANGELOG.md,
adds contributor list, and generates upgrade notes for major/minor releases.

Usage:
    python3 scripts/dev/generate_release_notes.py v1.0.0

Output:
    Markdown-formatted release notes suitable for GitHub Releases
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Set


def get_version_from_tag(tag: str) -> str:
    """Extract version number from git tag (e.g., 'v1.0.0' → '1.0.0')."""
    return tag.lstrip("v")


def is_major_or_minor_release(version: str) -> bool:
    """Check if version is a major or minor release (not patch)."""
    # Parse semantic version: major.minor.patch
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return False

    major, minor, patch = match.groups()
    # Major release: X.0.0, Minor release: X.Y.0
    return patch == "0"


def extract_changelog_section(version: str, changelog_path: Path = Path("CHANGELOG.md")) -> str:
    """Extract release notes for specific version from CHANGELOG.md."""
    if not changelog_path.exists():
        raise FileNotFoundError(f"CHANGELOG.md not found at {changelog_path}")

    changelog = changelog_path.read_text()

    # Pattern to match: ## [version] or ## version (both formats supported)
    # Extract everything between this heading and the next ## heading (or end of file)
    pattern = rf"## \[?{re.escape(version)}\]?.*?\n(.*?)(?=\n## |\Z)"
    match = re.search(pattern, changelog, re.DOTALL)

    if not match:
        raise ValueError(
            f"Version {version} not found in CHANGELOG.md\n"
            f"   Expected heading: ## [{version}] or ## {version}"
        )

    notes = match.group(1).strip()

    if len(notes) < 50:
        raise ValueError(
            f"Release notes for {version} are too short (< 50 chars)\n"
            f"   Add detailed release notes to CHANGELOG.md"
        )

    return notes


def get_contributors_since_last_release() -> List[str]:
    """Get list of unique contributors since last release tag."""
    try:
        # Get the previous release tag
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", "HEAD^"],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            # No previous tag, get all contributors
            print("   No previous release tag found, listing all contributors")
            result = subprocess.run(
                ["git", "log", "--format=%an <%ae>"],
                capture_output=True,
                text=True,
                check=True,
            )
        else:
            last_tag = result.stdout.strip()
            # Get contributors between last tag and HEAD
            result = subprocess.run(
                ["git", "log", f"{last_tag}..HEAD", "--format=%an <%ae>"],
                capture_output=True,
                text=True,
                check=True,
            )

        # Parse contributors (name + email) and deduplicate
        contributors_raw = result.stdout.strip().split("\n")
        contributors: Set[str] = set()

        for contributor in contributors_raw:
            if contributor.strip():
                # Extract name (before <email>)
                name = contributor.split("<")[0].strip()
                if name:
                    contributors.add(name)

        return sorted(contributors)

    except subprocess.CalledProcessError as e:
        print(f"   WARNING: Failed to fetch contributors: {e}")
        return []


def generate_upgrade_notes(version: str) -> str:
    """Generate upgrade notes for major/minor releases."""
    # Parse version
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return "No breaking changes expected. Standard upgrade process applies."

    major, minor, patch = match.groups()

    if major == "1" and minor == "0" and patch == "0":
        # v1.0.0 specific upgrade notes
        return """**Upgrading from v0.9.x:**

1. **SQLite Historical Storage:**
   - New `.jmo/history.db` database created automatically on first scan
   - Docker users: Mount volume `-v $PWD/.jmo:/scan/.jmo` for persistence
   - No migration needed (new feature)

2. **Output Format Changes:**
   - All outputs now include v1.0.0 metadata wrapper: `{"meta": {...}, "findings": [...]}`
   - Backward compatible: Access findings via `.findings` field
   - CI/CD pipelines: Update scripts to parse metadata envelope

3. **New CLI Commands:**
   - `jmo diff` — Compare two scans for regressions
   - `jmo history` — Manage scan history (13 subcommands)
   - `jmo trends` — Analyze security posture trends (8 subcommands)

4. **Configuration:**
   - No changes required to `jmo.yml` (fully backward compatible)
   - Optional: Enable cross-tool deduplication (default: enabled)

5. **Performance:**
   - Large scans (>1000 findings) now use external JSON mode in HTML dashboard
   - 95% faster dashboard load times (30-60s → <2s)

For detailed migration guide, see: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md#upgrading-to-v100
"""
    else:
        # Generic upgrade notes for future releases
        return f"""**Upgrading from previous version:**

1. Review CHANGELOG.md for breaking changes
2. Update `jmo.yml` configuration if needed
3. Test in non-production environment first
4. Check for new CLI flags or deprecated commands

For detailed upgrade instructions, see: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md
"""


def format_release_notes(version: str, tag: str) -> str:
    """Generate complete release notes for GitHub Release."""
    print(f"Generating release notes for {tag} (version {version})...")

    # Extract changelog section
    print("   Extracting changelog section...")
    changelog_notes = extract_changelog_section(version)

    # Get contributors
    print("   Fetching contributors since last release...")
    contributors = get_contributors_since_last_release()

    # Build release notes
    notes = f"# Release {tag}\n\n"
    notes += changelog_notes
    notes += "\n\n"

    # Add contributors section
    if contributors:
        notes += "## Contributors\n\n"
        notes += "Thank you to everyone who contributed to this release:\n\n"
        for contributor in contributors:
            notes += f"- {contributor}\n"
        notes += "\n"

    # Add upgrade notes for major/minor releases
    if is_major_or_minor_release(version):
        print(f"   Generating upgrade notes (major/minor release: {version})...")
        notes += "## Upgrade Notes\n\n"
        notes += generate_upgrade_notes(version)
        notes += "\n"

    # Add installation instructions
    notes += "## Installation\n\n"
    notes += "**PyPI (Python package):**\n\n"
    notes += "```bash\n"
    notes += f"pip install jmo-security=={version}\n"
    notes += "```\n\n"
    notes += "**Docker:**\n\n"
    notes += "```bash\n"
    notes += f"docker pull ghcr.io/jimmy058910/jmo-security:{tag}\n"
    notes += f"docker run --rm -v $PWD:/scan ghcr.io/jimmy058910/jmo-security:{tag} scan --repo /scan\n"
    notes += "```\n\n"
    notes += "**From source:**\n\n"
    notes += "```bash\n"
    notes += f"git clone https://github.com/jimmy058910/jmo-security-repo.git\n"
    notes += f"cd jmo-security-repo\n"
    notes += f"git checkout {tag}\n"
    notes += "pip install -e .\n"
    notes += "```\n\n"

    # Add links
    notes += "## Resources\n\n"
    notes += "- 📖 [User Guide](https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md)\n"
    notes += "- 🚀 [Quick Start](https://github.com/jimmy058910/jmo-security-repo/blob/main/QUICKSTART.md)\n"
    notes += "- 📝 [Full Changelog](https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md)\n"
    notes += "- 🐛 [Report Issues](https://github.com/jimmy058910/jmo-security-repo/issues)\n"
    notes += "- 💬 [Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)\n"

    return notes


def main() -> int:
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/dev/generate_release_notes.py <tag>")
        print("Example: python3 scripts/dev/generate_release_notes.py v1.0.0")
        return 1

    tag = sys.argv[1]
    version = get_version_from_tag(tag)

    try:
        release_notes = format_release_notes(version, tag)
        print("\n" + "=" * 70)
        print("Release notes generated successfully!")
        print("=" * 70 + "\n")
        print(release_notes)
        return 0

    except (FileNotFoundError, ValueError) as e:
        print(f"\n❌ ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
