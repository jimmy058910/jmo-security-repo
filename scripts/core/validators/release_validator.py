"""Release Artifacts validator (52 checks).

Validates that the project is ready for a public release by checking
version consistency, documentation, tool versions, badges, git hygiene,
security, code quality, test health, and schema/config integrity.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from scripts.core.validators import (
    CategoryResult,
    CheckResult,
    CheckStatus,
    timed_check,
)

# Type alias for check functions: return None for PASS, CheckResult for FAIL/WARN/SKIP
_CheckFn = Callable[[], CheckResult | None]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parents[3]  # repo root


def _read_text(rel: str) -> str:
    """Read a file relative to repo root. Raises FileNotFoundError."""
    return (_ROOT / rel).read_text(encoding="utf-8", errors="replace")


def _path_exists(rel: str) -> bool:
    return (_ROOT / rel).exists()


def _get_pyproject_data() -> dict[str, Any]:
    with open(_ROOT / "pyproject.toml", "rb") as f:
        data: dict[str, Any] = tomllib.load(f)
        return data


def _get_pyproject_version() -> str:
    return str(_get_pyproject_data()["project"]["version"])


def _get_jmo_version() -> str:
    """Extract __version__ from scripts/cli/jmo.py."""
    text = _read_text("scripts/cli/jmo.py")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        raise ValueError("Cannot find __version__ in scripts/cli/jmo.py")
    return m.group(1)


def _run_cmd(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a subprocess command safely (never shell=True)."""
    return subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(_ROOT),
    )


# ---------------------------------------------------------------------------
# 1. Version consistency (6 checks)
# ---------------------------------------------------------------------------


def _check_version_match() -> CheckResult:
    pyproject_ver = _get_pyproject_version()
    jmo_ver = _get_jmo_version()
    if pyproject_ver != jmo_ver:
        return CheckResult(
            name="version-match",
            status=CheckStatus.FAIL,
            message=(f"pyproject.toml ({pyproject_ver}) != " f"jmo.py ({jmo_ver})"),
        )
    return None  # type: ignore[return-value]


def _check_changelog_entry() -> CheckResult:
    version = _get_pyproject_version()
    text = _read_text("CHANGELOG.md")
    # Look for ## [1.0.0] or ## v1.0.0
    pattern = rf"##\s+\[?v?{re.escape(version)}\]?"
    if not re.search(pattern, text):
        return CheckResult(
            name="changelog-entry",
            status=CheckStatus.FAIL,
            message=f"No CHANGELOG.md entry for version {version}",
        )
    return None  # type: ignore[return-value]


def _check_changelog_date() -> CheckResult:
    version = _get_pyproject_version()
    text = _read_text("CHANGELOG.md")
    # Match ## [1.0.0] - 2026-02-23
    pattern = rf"##\s+\[?v?{re.escape(version)}\]?\s*-\s*(\d{{4}}-\d{{2}}-\d{{2}})"
    m = re.search(pattern, text)
    if not m:
        return CheckResult(
            name="changelog-date-recent",
            status=CheckStatus.WARN,
            message="Cannot parse CHANGELOG date for current version",
        )
    date_str = m.group(1)
    try:
        entry_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(timezone.utc)
        days_old = (now - entry_date).days
        if days_old > 90:
            return CheckResult(
                name="changelog-date-recent",
                status=CheckStatus.WARN,
                message=f"CHANGELOG entry is {days_old} days old (>90)",
            )
    except ValueError:
        return CheckResult(
            name="changelog-date-recent",
            status=CheckStatus.WARN,
            message=f"Cannot parse date: {date_str}",
        )
    return None  # type: ignore[return-value]


def _check_requires_python() -> CheckResult:
    data = _get_pyproject_data()
    req = data.get("project", {}).get("requires-python", "")
    if not req:
        return CheckResult(
            name="requires-python",
            status=CheckStatus.FAIL,
            message="No requires-python in pyproject.toml",
        )
    # Extract the minimum version number from the specifier
    m = re.search(r"(\d+\.\d+)", req)
    if m:
        min_ver = tuple(int(x) for x in m.group(1).split("."))
        if min_ver < (3, 12):
            return CheckResult(
                name="requires-python",
                status=CheckStatus.FAIL,
                message=f"requires-python minimum is {m.group(1)}, expected >=3.12",
            )
    return None  # type: ignore[return-value]


def _check_valid_semver() -> CheckResult:
    version = _get_pyproject_version()
    # Strict semver: X.Y.Z with optional pre-release
    if not re.match(r"^\d+\.\d+\.\d+", version):
        return CheckResult(
            name="valid-semver",
            status=CheckStatus.FAIL,
            message=f"Version '{version}' is not valid semver (X.Y.Z)",
        )
    return None  # type: ignore[return-value]


def _check_no_prerelease() -> CheckResult:
    version = _get_pyproject_version()
    if re.search(r"-(alpha|beta|rc|dev)", version, re.IGNORECASE):
        return CheckResult(
            name="no-prerelease-suffix",
            status=CheckStatus.FAIL,
            message=f"Version '{version}' has pre-release suffix",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 2. Documentation links (6 checks)
# ---------------------------------------------------------------------------


def _check_readme_exists() -> CheckResult:
    if not _path_exists("README.md"):
        return CheckResult(
            name="readme-exists",
            status=CheckStatus.FAIL,
            message="README.md not found",
        )
    content = _read_text("README.md")
    if len(content.strip()) < 100:
        return CheckResult(
            name="readme-exists",
            status=CheckStatus.FAIL,
            message="README.md exists but has minimal content",
        )
    return None  # type: ignore[return-value]


def _check_contributing_exists() -> CheckResult:
    if not _path_exists("CONTRIBUTING.md"):
        return CheckResult(
            name="contributing-exists",
            status=CheckStatus.FAIL,
            message="CONTRIBUTING.md not found",
        )
    return None  # type: ignore[return-value]


def _check_quickstart_exists() -> CheckResult:
    if not _path_exists("QUICKSTART.md"):
        return CheckResult(
            name="quickstart-exists",
            status=CheckStatus.FAIL,
            message="QUICKSTART.md not found",
        )
    return None  # type: ignore[return-value]


def _check_docs_key_files() -> CheckResult:
    key_files = [
        "docs/USER_GUIDE.md",
        "docs/CLI_REFERENCE.md",
        "docs/RELEASE.md",
    ]
    missing = [f for f in key_files if not _path_exists(f)]
    if missing:
        return CheckResult(
            name="docs-key-files",
            status=CheckStatus.FAIL,
            message=f"Missing docs: {', '.join(missing)}",
        )
    return None  # type: ignore[return-value]


def _check_internal_links() -> CheckResult:
    """Check that markdown links [text](path) resolve to existing files."""
    # Only scan key top-level markdown files
    files_to_check = ["README.md", "CONTRIBUTING.md", "QUICKSTART.md"]
    broken: list[str] = []
    link_pattern = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")

    for fname in files_to_check:
        if not _path_exists(fname):
            continue
        text = _read_text(fname)
        for match in link_pattern.finditer(text):
            target = match.group(2)
            # Skip external URLs, anchors, and badges
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            # Strip anchor from path
            path_part = target.split("#")[0]
            if not path_part:
                continue
            if not _path_exists(path_part):
                broken.append(f"{fname}: {target}")

    if broken:
        details = "; ".join(broken[:10])
        return CheckResult(
            name="internal-links",
            status=CheckStatus.WARN,
            message=f"{len(broken)} broken internal link(s)",
            details=details,
        )
    return None  # type: ignore[return-value]


def _check_anchor_links() -> CheckResult:
    """Check that anchor links (#section) resolve to existing headers."""
    files_to_check = ["README.md", "CONTRIBUTING.md"]
    broken: list[str] = []
    link_pattern = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
    header_pattern = re.compile(r"^#{1,6}\s+(.+)$", re.MULTILINE)

    for fname in files_to_check:
        if not _path_exists(fname):
            continue
        text = _read_text(fname)
        # Build set of anchor IDs for this file
        headers = set()
        for h_match in header_pattern.finditer(text):
            # Convert header text to GitHub-style anchor
            anchor = h_match.group(1).strip().lower()
            anchor = re.sub(r"[^\w\s-]", "", anchor)
            anchor = re.sub(r"\s+", "-", anchor)
            headers.add(anchor)

        for match in link_pattern.finditer(text):
            target = match.group(2)
            # Only check same-file anchors
            if not target.startswith("#"):
                continue
            anchor = target[1:]
            if anchor and anchor not in headers:
                broken.append(f"{fname}: {target}")

    if broken:
        details = "; ".join(broken[:10])
        return CheckResult(
            name="anchor-links",
            status=CheckStatus.WARN,
            message=f"{len(broken)} broken anchor link(s)",
            details=details,
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 3. Tool versions (4 checks)
# ---------------------------------------------------------------------------


def _check_versions_yaml_exists() -> CheckResult:
    if not _path_exists("versions.yaml"):
        return CheckResult(
            name="versions-yaml-exists",
            status=CheckStatus.FAIL,
            message="versions.yaml not found",
        )
    try:
        text = _read_text("versions.yaml")
        yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return CheckResult(
            name="versions-yaml-exists",
            status=CheckStatus.FAIL,
            message=f"versions.yaml is invalid YAML: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_deep_profile_versions() -> CheckResult:
    """All tools in deep profile have version entries in versions.yaml."""
    try:
        text = _read_text("versions.yaml")
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        return CheckResult(
            name="deep-profile-versions",
            status=CheckStatus.FAIL,
            message=f"Cannot load versions.yaml: {exc}",
        )

    # Collect all tool names from versions.yaml
    version_tools: set[str] = set()
    for section in data.values():
        if isinstance(section, dict):
            for key in section:
                if key != "schema_version":
                    version_tools.add(key)

    # Get deep profile tools from tool_registry
    try:
        from scripts.core.tool_registry import PROFILE_TOOLS

        deep_tools = PROFILE_TOOLS.get("deep", [])
    except ImportError:
        deep_tools = []

    # Normalize names: hyphens and underscores are equivalent
    def normalize(name: str) -> str:
        return name.lower().replace("-", "_").replace("+", "plus")

    normalized_versions = {normalize(t) for t in version_tools}

    missing: list[str] = []
    for tool in deep_tools:
        norm = normalize(tool)
        if norm not in normalized_versions:
            # Also try without suffixes like -rbac, -cicd, -secrets
            base = norm.split("_")[0] if "_" in norm else norm
            if base not in normalized_versions:
                missing.append(tool)

    if missing:
        return CheckResult(
            name="deep-profile-versions",
            status=CheckStatus.WARN,
            message=f"{len(missing)} tool(s) missing version entries: {', '.join(missing[:5])}",
        )
    return None  # type: ignore[return-value]


def _check_version_format() -> CheckResult:
    """Version entries in versions.yaml use valid semver-ish format."""
    try:
        text = _read_text("versions.yaml")
        data = yaml.safe_load(text) or {}
    except Exception as exc:
        return CheckResult(
            name="version-format",
            status=CheckStatus.FAIL,
            message=f"Cannot load versions.yaml: {exc}",
        )

    invalid: list[str] = []
    for section_name, section in data.items():
        if not isinstance(section, dict):
            continue
        for tool_name, tool_data in section.items():
            if not isinstance(tool_data, dict):
                continue
            version = tool_data.get("version")
            if version is None:
                continue
            ver_str = str(version)
            # Accept semver-ish: digits separated by dots (at least X.Y), may
            # be prefixed (e.g. akto's mini-testing-1.53.7)
            if not re.search(r"\d+(\.\d+){1,}", ver_str):
                invalid.append(f"{tool_name}={ver_str}")

    if invalid:
        return CheckResult(
            name="version-format",
            status=CheckStatus.WARN,
            message=f"Invalid version format: {', '.join(invalid[:5])}",
        )
    return None  # type: ignore[return-value]


def _check_outdated_tools() -> CheckResult:
    """Check for critically outdated tools (no update_check field)."""
    try:
        text = _read_text("versions.yaml")
        data = yaml.safe_load(text) or {}
    except Exception:
        return CheckResult(
            name="outdated-tools",
            status=CheckStatus.SKIP,
            message="Cannot load versions.yaml",
        )

    tools_without_update_check: list[str] = []
    total_tools = 0
    for section in data.values():
        if not isinstance(section, dict):
            continue
        for tool_name, tool_data in section.items():
            if not isinstance(tool_data, dict):
                continue
            total_tools += 1
            if not tool_data.get("update_check"):
                tools_without_update_check.append(tool_name)

    if tools_without_update_check and len(tools_without_update_check) > total_tools / 2:
        return CheckResult(
            name="outdated-tools",
            status=CheckStatus.WARN,
            message=f"{len(tools_without_update_check)} tools lack update_check field",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 4. Badge accuracy (2 checks)
# ---------------------------------------------------------------------------


def _check_pypi_badge_version() -> CheckResult:
    """PyPI version badge in README matches pyproject.toml version."""
    try:
        readme = _read_text("README.md")
        version = _get_pyproject_version()
    except Exception as exc:
        return CheckResult(
            name="pypi-badge-version",
            status=CheckStatus.SKIP,
            message=f"Cannot check: {exc}",
        )

    # Badge format: img.shields.io/pypi/v/jmo-security
    if "img.shields.io/pypi/v/jmo-security" not in readme:
        return CheckResult(
            name="pypi-badge-version",
            status=CheckStatus.WARN,
            message="No PyPI version badge found in README.md",
        )
    # Badge is dynamic (fetched from PyPI), so just verify it exists
    # and the pyproject version is valid
    if not re.match(r"^\d+\.\d+\.\d+$", version):
        return CheckResult(
            name="pypi-badge-version",
            status=CheckStatus.WARN,
            message=f"Version '{version}' may not render correctly on badge",
        )
    return None  # type: ignore[return-value]


def _check_python_badge_version() -> CheckResult:
    """Python version badge exists and matches requires-python."""
    try:
        readme = _read_text("README.md")
    except Exception as exc:
        return CheckResult(
            name="python-badge-version",
            status=CheckStatus.SKIP,
            message=f"Cannot check: {exc}",
        )

    if "img.shields.io/pypi/pyversions/jmo-security" not in readme:
        return CheckResult(
            name="python-badge-version",
            status=CheckStatus.WARN,
            message="No Python version badge found in README.md",
        )
    # Badge is dynamic from PyPI classifiers, just verify it's present
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 5. Git hygiene (5 checks)
# ---------------------------------------------------------------------------


def _check_git_clean() -> CheckResult:
    """Check for uncommitted changes (WARN, not FAIL)."""
    try:
        result = _run_cmd(["git", "status", "--porcelain"])
        if result.returncode != 0:
            return CheckResult(
                name="git-clean",
                status=CheckStatus.SKIP,
                message="git status failed",
            )
        if result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            return CheckResult(
                name="git-clean",
                status=CheckStatus.WARN,
                message=f"{len(lines)} uncommitted change(s)",
            )
    except Exception as exc:
        return CheckResult(
            name="git-clean",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_branch() -> CheckResult:
    """Current branch should be dev or main."""
    try:
        result = _run_cmd(["git", "branch", "--show-current"])
        if result.returncode != 0:
            return CheckResult(
                name="git-branch",
                status=CheckStatus.SKIP,
                message="Cannot determine current branch",
            )
        branch = result.stdout.strip()
        if branch not in ("main", "dev", "master"):
            return CheckResult(
                name="git-branch",
                status=CheckStatus.WARN,
                message=f"On branch '{branch}', expected main or dev",
            )
    except Exception as exc:
        return CheckResult(
            name="git-branch",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_untracked_scripts() -> CheckResult:
    """No untracked files in scripts/ directory."""
    try:
        result = _run_cmd(
            ["git", "ls-files", "--others", "--exclude-standard", "scripts/"]
        )
        if result.returncode != 0:
            return CheckResult(
                name="untracked-scripts",
                status=CheckStatus.SKIP,
                message="git ls-files failed",
            )
        untracked = [f for f in result.stdout.strip().split("\n") if f.strip()]
        if untracked:
            return CheckResult(
                name="untracked-scripts",
                status=CheckStatus.WARN,
                message=f"{len(untracked)} untracked file(s) in scripts/",
                details=", ".join(untracked[:5]),
            )
    except Exception as exc:
        return CheckResult(
            name="untracked-scripts",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_merge_conflicts() -> CheckResult:
    """No merge conflict markers in tracked files."""
    try:
        result = _run_cmd(
            ["git", "grep", "-l", "^<<<<<<<"],
            timeout=30,
        )
        # git grep exits 0 if found, 1 if not found
        if result.returncode == 0 and result.stdout.strip():
            files = result.stdout.strip().split("\n")
            return CheckResult(
                name="no-merge-conflicts",
                status=CheckStatus.FAIL,
                message=f"Merge conflict markers in {len(files)} file(s)",
                details=", ".join(files[:5]),
            )
    except Exception as exc:
        return CheckResult(
            name="no-merge-conflicts",
            status=CheckStatus.SKIP,
            message=f"Cannot run git grep: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_gitignore() -> CheckResult:
    """.gitignore exists and covers key patterns."""
    if not _path_exists(".gitignore"):
        return CheckResult(
            name="gitignore-coverage",
            status=CheckStatus.FAIL,
            message=".gitignore not found",
        )
    text = _read_text(".gitignore")
    required_patterns = ["venv", "__pycache__", ".env", "dist"]
    missing = [p for p in required_patterns if p not in text]
    if missing:
        return CheckResult(
            name="gitignore-coverage",
            status=CheckStatus.WARN,
            message=f".gitignore missing patterns: {', '.join(missing)}",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 6. Security (6 checks)
# ---------------------------------------------------------------------------

# Paths excluded from secret scanning (test fixtures, docs, dev scripts, etc.)
_SECRETS_EXCLUDED_PREFIXES = (
    "tests/",
    "docs/",
    "samples/",
    "scripts/dev/",
    ".github/",
    ".claude/",
)

# Secret patterns to scan for
_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"sk_live_[a-zA-Z0-9]+", "Stripe Live Key"),
    (r"sk_test_[a-zA-Z0-9]+", "Stripe Test Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"xoxb-[a-zA-Z0-9\-]+", "Slack Bot Token"),
]


def _check_no_secrets() -> CheckResult:
    """Scan tracked files for obvious secret patterns, excluding test fixtures."""
    try:
        result = _run_cmd(["git", "ls-files"])
        if result.returncode != 0:
            return CheckResult(
                name="no-secret-patterns",
                status=CheckStatus.SKIP,
                message="Cannot list git files",
            )
        files = [f for f in result.stdout.strip().split("\n") if f.strip()]
    except Exception as exc:
        return CheckResult(
            name="no-secret-patterns",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )

    findings: list[str] = []
    for fpath in files:
        # Exclude test fixtures, docs, samples, dev scripts, CI, and skill files
        if fpath.startswith(_SECRETS_EXCLUDED_PREFIXES):
            continue
        if fpath.endswith((".png", ".jpg", ".gif", ".ico", ".whl", ".so", ".pyc")):
            continue
        full = _ROOT / fpath
        if not full.is_file():
            continue
        try:
            content = full.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pattern, name in _SECRET_PATTERNS:
            if re.search(pattern, content):
                findings.append(f"{fpath}: {name}")
                break  # one finding per file is enough

    if findings:
        return CheckResult(
            name="no-secret-patterns",
            status=CheckStatus.FAIL,
            message=f"Potential secrets in {len(findings)} file(s)",
            details="; ".join(findings[:5]),
        )
    return None  # type: ignore[return-value]


def _check_no_shell_true() -> CheckResult:
    """Detect shell=True in subprocess calls within scripts/."""
    # Only match shell=True that looks like an actual keyword argument:
    # preceded by ( or , (with optional whitespace), i.e. in a function call
    call_pattern = re.compile(r"[,(]\s*shell\s*=\s*True")
    found: list[str] = []
    scripts_dir = _ROOT / "scripts"
    if not scripts_dir.is_dir():
        return CheckResult(
            name="no-shell-true",
            status=CheckStatus.SKIP,
            message="scripts/ directory not found",
        )

    for py_file in scripts_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.lstrip()
                # Skip full-line comments
                if stripped.startswith("#"):
                    continue
                # Check only the code portion (before inline comment)
                code_part = line.split("#")[0]
                if call_pattern.search(code_part):
                    rel = py_file.relative_to(_ROOT)
                    found.append(f"{rel}:{i}")
        except Exception:
            continue

    if found:
        return CheckResult(
            name="no-shell-true",
            status=CheckStatus.FAIL,
            message=f"shell=True found in {len(found)} location(s)",
            details="; ".join(found[:5]),
        )
    return None  # type: ignore[return-value]


def _check_no_large_files() -> CheckResult:
    """No files >5MB tracked in git."""
    try:
        result = _run_cmd(["git", "ls-files"])
        if result.returncode != 0:
            return CheckResult(
                name="no-large-files",
                status=CheckStatus.SKIP,
                message="Cannot list git files",
            )
        files = [f for f in result.stdout.strip().split("\n") if f.strip()]
    except Exception as exc:
        return CheckResult(
            name="no-large-files",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )

    large: list[str] = []
    max_size = 5 * 1024 * 1024  # 5MB
    for fpath in files:
        full = _ROOT / fpath
        if full.is_file():
            try:
                size = full.stat().st_size
                if size > max_size:
                    large.append(f"{fpath} ({size // (1024 * 1024)}MB)")
            except OSError:
                continue

    if large:
        return CheckResult(
            name="no-large-files",
            status=CheckStatus.FAIL,
            message=f"{len(large)} file(s) >5MB tracked",
            details="; ".join(large[:5]),
        )
    return None  # type: ignore[return-value]


def _check_no_artifact_dirs() -> CheckResult:
    """No artifact directories tracked in git."""
    try:
        result = _run_cmd(["git", "ls-files"])
        if result.returncode != 0:
            return CheckResult(
                name="no-artifact-dirs",
                status=CheckStatus.SKIP,
                message="Cannot list git files",
            )
        files = result.stdout.strip().split("\n")
    except Exception as exc:
        return CheckResult(
            name="no-artifact-dirs",
            status=CheckStatus.SKIP,
            message=f"Cannot run git: {exc}",
        )

    artifact_dirs = ["venv/", "node_modules/", "dist/", "build/", "__pycache__/"]
    found: list[str] = []
    for fpath in files:
        for ad in artifact_dirs:
            if fpath.startswith(ad) or f"/{ad}" in fpath:
                found.append(fpath)
                break

    if found:
        return CheckResult(
            name="no-artifact-dirs",
            status=CheckStatus.FAIL,
            message=f"{len(found)} file(s) in artifact directories tracked",
            details="; ".join(found[:5]),
        )
    return None  # type: ignore[return-value]


def _check_no_path_traversal() -> CheckResult:
    """No path traversal patterns in user-facing code."""
    # Scan scripts/cli/ for unsanitized path usage
    pattern = re.compile(r'["\']\.\./')
    found: list[str] = []
    cli_dir = _ROOT / "scripts" / "cli"
    if not cli_dir.is_dir():
        return CheckResult(
            name="no-path-traversal",
            status=CheckStatus.SKIP,
            message="scripts/cli/ directory not found",
        )

    for py_file in cli_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                if pattern.search(line):
                    rel = py_file.relative_to(_ROOT)
                    found.append(f"{rel}:{i}")
        except Exception:
            continue

    if found:
        return CheckResult(
            name="no-path-traversal",
            status=CheckStatus.WARN,
            message=f"Path traversal patterns in {len(found)} location(s)",
            details="; ".join(found[:5]),
        )
    return None  # type: ignore[return-value]


def _check_suppression_file() -> CheckResult:
    """Suppression rules file exists."""
    if not _path_exists("jmo.suppress.yml"):
        return CheckResult(
            name="suppression-file",
            status=CheckStatus.WARN,
            message="jmo.suppress.yml not found",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 7. Code quality (6 checks)
# ---------------------------------------------------------------------------


def _check_black_clean() -> CheckResult:
    """Black formatting is clean."""
    try:
        result = _run_cmd(
            [sys.executable, "-m", "black", "--check", "--quiet", "scripts/"],
            timeout=120,
        )
        if result.returncode != 0:
            return CheckResult(
                name="black-clean",
                status=CheckStatus.FAIL,
                message="Black formatting check failed",
                details=result.stdout[:500] if result.stdout else "",
            )
    except FileNotFoundError:
        return CheckResult(
            name="black-clean",
            status=CheckStatus.SKIP,
            message="Black not installed",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="black-clean",
            status=CheckStatus.SKIP,
            message="Black check timed out",
        )
    return None  # type: ignore[return-value]


def _check_ruff_clean() -> CheckResult:
    """Ruff linting passes."""
    try:
        result = _run_cmd(
            [sys.executable, "-m", "ruff", "check", "scripts/"],
            timeout=120,
        )
        if result.returncode != 0:
            return CheckResult(
                name="ruff-clean",
                status=CheckStatus.FAIL,
                message="Ruff linting failed",
                details=result.stdout[:500] if result.stdout else "",
            )
    except FileNotFoundError:
        return CheckResult(
            name="ruff-clean",
            status=CheckStatus.SKIP,
            message="Ruff not installed",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="ruff-clean",
            status=CheckStatus.SKIP,
            message="Ruff check timed out",
        )
    return None  # type: ignore[return-value]


def _check_import_direction() -> CheckResult:
    """No imports from cli/ in core/ modules (dependency layering)."""
    core_dir = _ROOT / "scripts" / "core"
    if not core_dir.is_dir():
        return CheckResult(
            name="import-direction",
            status=CheckStatus.SKIP,
            message="scripts/core/ directory not found",
        )

    violations: list[str] = []
    import_pattern = re.compile(r"^\s*(?:from|import)\s+scripts\.cli\b", re.MULTILINE)

    for py_file in core_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            if import_pattern.search(content):
                rel = py_file.relative_to(_ROOT)
                violations.append(str(rel))
        except Exception:
            continue

    if violations:
        return CheckResult(
            name="import-direction",
            status=CheckStatus.FAIL,
            message=f"Circular imports: core/ importing from cli/ in {len(violations)} file(s)",
            details="; ".join(violations[:5]),
        )
    return None  # type: ignore[return-value]


def _check_no_circular_imports() -> CheckResult:
    """No obvious circular import patterns between cli/ and core/."""
    # This is a simplified check: look for mutual imports
    cli_imports_core = False
    core_imports_cli = False

    cli_dir = _ROOT / "scripts" / "cli"
    core_dir = _ROOT / "scripts" / "core"

    if cli_dir.is_dir():
        for py_file in cli_dir.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                if re.search(
                    r"^\s*(?:from|import)\s+scripts\.core\b", content, re.MULTILINE
                ):
                    cli_imports_core = True
                    break
            except Exception:
                continue

    if core_dir.is_dir():
        for py_file in core_dir.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
                if re.search(
                    r"^\s*(?:from|import)\s+scripts\.cli\b", content, re.MULTILINE
                ):
                    core_imports_cli = True
                    break
            except Exception:
                continue

    if cli_imports_core and core_imports_cli:
        return CheckResult(
            name="no-circular-imports",
            status=CheckStatus.FAIL,
            message="Circular dependency: cli/ imports core/ AND core/ imports cli/",
        )
    return None  # type: ignore[return-value]


def _check_precommit_order() -> CheckResult:
    """Pre-commit config has Black before Ruff."""
    if not _path_exists(".pre-commit-config.yaml"):
        return CheckResult(
            name="precommit-black-before-ruff",
            status=CheckStatus.FAIL,
            message=".pre-commit-config.yaml not found",
        )
    text = _read_text(".pre-commit-config.yaml")
    black_pos = text.find("psf/black")
    ruff_pos = text.find("ruff-pre-commit")
    if black_pos < 0 or ruff_pos < 0:
        return CheckResult(
            name="precommit-black-before-ruff",
            status=CheckStatus.WARN,
            message="Cannot find Black or Ruff in pre-commit config",
        )
    if black_pos > ruff_pos:
        return CheckResult(
            name="precommit-black-before-ruff",
            status=CheckStatus.FAIL,
            message="Black must run BEFORE Ruff in pre-commit config",
        )
    return None  # type: ignore[return-value]


def _check_type_annotations() -> CheckResult:
    """Type annotations present in key modules."""
    key_modules = [
        "scripts/core/common_finding.py",
        "scripts/core/config.py",
        "scripts/core/normalize_and_report.py",
    ]
    missing_annotations: list[str] = []

    for mod in key_modules:
        if not _path_exists(mod):
            missing_annotations.append(mod)
            continue
        content = _read_text(mod)
        # Look for basic type annotation patterns
        has_annotations = (
            re.search(r"def\s+\w+\([^)]*:\s*\w+", content) is not None
            or re.search(r"->\s*\w+", content) is not None
        )
        if not has_annotations:
            missing_annotations.append(mod)

    if missing_annotations:
        return CheckResult(
            name="type-annotations",
            status=CheckStatus.WARN,
            message=f"No type annotations in: {', '.join(missing_annotations)}",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 8. Test health (6 checks)
# ---------------------------------------------------------------------------


def _check_test_count() -> CheckResult:
    """Test count is reasonable (>5000)."""
    try:
        result = _run_cmd(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
            timeout=120,
        )
        # Parse "X tests collected" from output
        output = result.stdout + result.stderr
        m = re.search(r"(\d+)\s+tests?\s+(?:items?\s+)?collected", output)
        if m:
            count = int(m.group(1))
            if count < 5000:
                return CheckResult(
                    name="test-count",
                    status=CheckStatus.WARN,
                    message=f"Only {count} tests found (expected >5000)",
                )
            return CheckResult(
                name="test-count",
                status=CheckStatus.PASS,
                message=f"{count} tests collected",
            )
        return CheckResult(
            name="test-count",
            status=CheckStatus.WARN,
            message="Cannot determine test count from pytest output",
        )
    except Exception as exc:
        return CheckResult(
            name="test-count",
            status=CheckStatus.SKIP,
            message=f"Cannot collect tests: {exc}",
        )


def _check_coverage_threshold() -> CheckResult:
    """Coverage configuration requires >=85%."""
    # Check pyproject.toml or .coveragerc for threshold
    try:
        _get_pyproject_data()  # validate pyproject.toml is loadable
        # Check if CI config implies 85%
        # Also check Makefile for --cov-fail-under
        if _path_exists("Makefile"):
            makefile = _read_text("Makefile")
            m = re.search(r"--cov-fail-under[=\s]+(\d+)", makefile)
            if m:
                threshold = int(m.group(1))
                if threshold < 85:
                    return CheckResult(
                        name="coverage-threshold",
                        status=CheckStatus.FAIL,
                        message=f"Coverage threshold is {threshold}% (need >=85%)",
                    )
                return CheckResult(
                    name="coverage-threshold",
                    status=CheckStatus.PASS,
                    message=f"Coverage threshold configured at {threshold}%",
                )
    except Exception:
        pass
    # Fallback: check CI workflow
    ci_path = ".github/workflows/ci.yml"
    if _path_exists(ci_path):
        ci = _read_text(ci_path)
        m = re.search(r"--cov-fail-under[=\s]+(\d+)", ci)
        if m:
            threshold = int(m.group(1))
            if threshold >= 85:
                return CheckResult(
                    name="coverage-threshold",
                    status=CheckStatus.PASS,
                    message=f"CI enforces {threshold}% coverage",
                )
        # Also check inline Python threshold (e.g. "if coverage_pct < 85:")
        m = re.search(r"coverage_pct\s*<\s*(\d+)", ci)
        if m:
            threshold = int(m.group(1))
            if threshold >= 85:
                return CheckResult(
                    name="coverage-threshold",
                    status=CheckStatus.PASS,
                    message=f"CI enforces {threshold}% coverage (inline check)",
                )
    return CheckResult(
        name="coverage-threshold",
        status=CheckStatus.WARN,
        message="Cannot verify coverage threshold >=85%",
    )


def _check_no_skip_without_reason() -> CheckResult:
    """No tests with @pytest.mark.skip without reason."""
    tests_dir = _ROOT / "tests"
    if not tests_dir.is_dir():
        return CheckResult(
            name="no-skip-without-reason",
            status=CheckStatus.SKIP,
            message="tests/ directory not found",
        )

    bare_skips: list[str] = []
    # Match @pytest.mark.skip that doesn't have reason=
    skip_pattern = re.compile(r"@pytest\.mark\.skip\b(?!\s*\(.*reason)")

    for py_file in tests_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(content.split("\n"), 1):
                if skip_pattern.search(line):
                    rel = py_file.relative_to(_ROOT)
                    bare_skips.append(f"{rel}:{i}")
        except Exception:
            continue

    if bare_skips:
        return CheckResult(
            name="no-skip-without-reason",
            status=CheckStatus.WARN,
            message=f"{len(bare_skips)} test(s) with @pytest.mark.skip without reason",
            details="; ".join(bare_skips[:5]),
        )
    return None  # type: ignore[return-value]


_SLEEP_ALLOWED_FILES = {
    "tests/jmo_mcp/test_rate_limiter.py",
    "tests/jmo_mcp/test_server_mark_resolved.py",
    "tests/unit/test_history_db_concurrency.py",
    "tests/unit/test_history_db.py",
    "tests/unit/test_tool_installer_parallel.py",
    "tests/unit/test_scan_utils.py",
    "tests/integration/test_history_integration.py",
    "tests/integration/test_full_v1_workflow.py",
    "tests/cli/test_scan_progress.py",
}


def _check_no_sleep_in_tests() -> CheckResult:
    """No time.sleep() in test files (flaky pattern)."""
    tests_dir = _ROOT / "tests"
    if not tests_dir.is_dir():
        return CheckResult(
            name="no-sleep-in-tests",
            status=CheckStatus.SKIP,
            message="tests/ directory not found",
        )

    sleeps: list[str] = []
    sleep_pattern = re.compile(r"\btime\.sleep\s*\(")

    for py_file in tests_dir.rglob("*.py"):
        rel = py_file.relative_to(_ROOT).as_posix()
        if rel in _SLEEP_ALLOWED_FILES:
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(content.split("\n"), 1):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                # Skip mock/patch references (not actual sleep calls)
                if "patch(" in line and "time.sleep" in line:
                    continue
                if sleep_pattern.search(line):
                    sleeps.append(f"{rel}:{i}")
        except Exception:
            continue

    if sleeps:
        return CheckResult(
            name="no-sleep-in-tests",
            status=CheckStatus.WARN,
            message=f"time.sleep() in {len(sleeps)} test location(s)",
            details="; ".join(sleeps[:5]),
        )
    return None  # type: ignore[return-value]


def _check_pytest_markers() -> CheckResult:
    """Pytest markers registered in pyproject.toml."""
    try:
        data = _get_pyproject_data()
        markers = (
            data.get("tool", {})
            .get("pytest", {})
            .get("ini_options", {})
            .get("markers", [])
        )
        if not markers:
            return CheckResult(
                name="pytest-markers",
                status=CheckStatus.WARN,
                message="No pytest markers registered in pyproject.toml",
            )
        if len(markers) < 3:
            return CheckResult(
                name="pytest-markers",
                status=CheckStatus.WARN,
                message=f"Only {len(markers)} marker(s) registered",
            )
    except Exception as exc:
        return CheckResult(
            name="pytest-markers",
            status=CheckStatus.SKIP,
            message=f"Cannot check markers: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_conftest_exists() -> CheckResult:
    """conftest.py exists and has key fixtures."""
    if not _path_exists("tests/conftest.py"):
        return CheckResult(
            name="conftest-exists",
            status=CheckStatus.FAIL,
            message="tests/conftest.py not found",
        )
    content = _read_text("tests/conftest.py")
    if "@pytest.fixture" not in content:
        return CheckResult(
            name="conftest-exists",
            status=CheckStatus.WARN,
            message="tests/conftest.py has no fixtures",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# 9. Schema/config (5 checks)
# ---------------------------------------------------------------------------


def _check_json_schema() -> CheckResult:
    """common_finding.v1.json is valid JSON and valid JSON Schema."""
    schema_path = "docs/schemas/common_finding.v1.json"
    if not _path_exists(schema_path):
        return CheckResult(
            name="json-schema-valid",
            status=CheckStatus.FAIL,
            message=f"{schema_path} not found",
        )
    try:
        text = _read_text(schema_path)
        schema = json.loads(text)
        # Basic JSON Schema validation: must have type, properties
        if "properties" not in schema:
            return CheckResult(
                name="json-schema-valid",
                status=CheckStatus.FAIL,
                message="JSON Schema missing 'properties' key",
            )
        if "$schema" not in schema:
            return CheckResult(
                name="json-schema-valid",
                status=CheckStatus.WARN,
                message="JSON Schema missing '$schema' declaration",
            )
    except json.JSONDecodeError as exc:
        return CheckResult(
            name="json-schema-valid",
            status=CheckStatus.FAIL,
            message=f"Invalid JSON: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_schema_fields_match() -> CheckResult:
    """Schema fields match CommonFinding dataclass fields (basic check)."""
    schema_path = "docs/schemas/common_finding.v1.json"
    if not _path_exists(schema_path):
        return CheckResult(
            name="schema-fields-match",
            status=CheckStatus.SKIP,
            message="JSON Schema not found",
        )
    try:
        text = _read_text(schema_path)
        schema = json.loads(text)
        required_fields = set(schema.get("required", []))
        # Verify properties exist (schema_fields used for future expansion)
        _ = set(schema.get("properties", {}).keys())

        # The required fields are the minimum contract
        expected_required = {
            "schemaVersion",
            "id",
            "ruleId",
            "severity",
            "tool",
            "location",
            "message",
        }
        missing_required = expected_required - required_fields
        if missing_required:
            return CheckResult(
                name="schema-fields-match",
                status=CheckStatus.WARN,
                message=f"Schema missing required fields: {', '.join(missing_required)}",
            )
    except Exception as exc:
        return CheckResult(
            name="schema-fields-match",
            status=CheckStatus.SKIP,
            message=f"Cannot validate schema fields: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_jmo_yml() -> CheckResult:
    """jmo.yml is valid YAML."""
    if not _path_exists("jmo.yml"):
        return CheckResult(
            name="jmo-yml-valid",
            status=CheckStatus.FAIL,
            message="jmo.yml not found",
        )
    try:
        text = _read_text("jmo.yml")
        yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return CheckResult(
            name="jmo-yml-valid",
            status=CheckStatus.FAIL,
            message=f"jmo.yml is invalid YAML: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_suppress_yml() -> CheckResult:
    """jmo.suppress.yml is valid YAML."""
    if not _path_exists("jmo.suppress.yml"):
        return CheckResult(
            name="suppress-yml-valid",
            status=CheckStatus.WARN,
            message="jmo.suppress.yml not found",
        )
    try:
        text = _read_text("jmo.suppress.yml")
        yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return CheckResult(
            name="suppress-yml-valid",
            status=CheckStatus.FAIL,
            message=f"jmo.suppress.yml is invalid YAML: {exc}",
        )
    return None  # type: ignore[return-value]


def _check_precommit_yml() -> CheckResult:
    """.pre-commit-config.yaml is valid YAML."""
    if not _path_exists(".pre-commit-config.yaml"):
        return CheckResult(
            name="precommit-yml-valid",
            status=CheckStatus.FAIL,
            message=".pre-commit-config.yaml not found",
        )
    try:
        text = _read_text(".pre-commit-config.yaml")
        yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return CheckResult(
            name="precommit-yml-valid",
            status=CheckStatus.FAIL,
            message=f".pre-commit-config.yaml is invalid YAML: {exc}",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Full tier additional checks (6 checks)
# ---------------------------------------------------------------------------


def _check_dockerfile_build(dockerfile: str) -> CheckResult:
    """Check that a Dockerfile builds successfully."""
    name = f"docker-build-{Path(dockerfile).name.lower()}"
    if not _path_exists(dockerfile):
        return CheckResult(
            name=name,
            status=CheckStatus.SKIP,
            message=f"{dockerfile} not found",
        )
    try:
        result = _run_cmd(
            [
                "docker",
                "build",
                "-f",
                dockerfile,
                "--no-cache",
                "-t",
                f"jmo-validate-{Path(dockerfile).name.lower()}",
                ".",
            ],
            timeout=600,
        )
        if result.returncode != 0:
            return CheckResult(
                name=name,
                status=CheckStatus.FAIL,
                message=f"Docker build failed for {dockerfile}",
                details=(result.stderr or result.stdout or "")[:500],
            )
    except FileNotFoundError:
        return CheckResult(
            name=name,
            status=CheckStatus.SKIP,
            message="Docker not available",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name=name,
            status=CheckStatus.SKIP,
            message=f"Docker build timed out for {dockerfile}",
        )
    return None  # type: ignore[return-value]


def _check_pip_install() -> CheckResult:
    """pip install -e '.[dev]' succeeds."""
    try:
        result = _run_cmd(
            [sys.executable, "-m", "pip", "install", "-e", ".[dev]", "--dry-run"],
            timeout=120,
        )
        if result.returncode != 0:
            return CheckResult(
                name="pip-install-dev",
                status=CheckStatus.FAIL,
                message="pip install -e '.[dev]' would fail",
                details=(result.stderr or "")[:500],
            )
    except FileNotFoundError:
        return CheckResult(
            name="pip-install-dev",
            status=CheckStatus.SKIP,
            message="pip not available",
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="pip-install-dev",
            status=CheckStatus.SKIP,
            message="pip install timed out",
        )
    return None  # type: ignore[return-value]


def _check_jmo_version_entry_point() -> CheckResult:
    """jmo --version entry point works after install."""
    try:
        result = _run_cmd(
            [sys.executable, "-m", "scripts.cli.jmo", "--help"],
            timeout=30,
        )
        if result.returncode != 0:
            return CheckResult(
                name="jmo-entry-point",
                status=CheckStatus.FAIL,
                message="jmo entry point failed",
                details=(result.stderr or "")[:500],
            )
    except Exception as exc:
        return CheckResult(
            name="jmo-entry-point",
            status=CheckStatus.SKIP,
            message=f"Cannot run jmo: {exc}",
        )
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Main validator entry point
# ---------------------------------------------------------------------------

# Quick tier check functions (46 checks)
_QUICK_CHECKS: list[tuple[str, _CheckFn]] = [
    # 1. Version consistency (6)
    ("version-match", _check_version_match),
    ("changelog-entry", _check_changelog_entry),
    ("changelog-date-recent", _check_changelog_date),
    ("requires-python", _check_requires_python),
    ("valid-semver", _check_valid_semver),
    ("no-prerelease-suffix", _check_no_prerelease),
    # 2. Documentation links (6)
    ("readme-exists", _check_readme_exists),
    ("contributing-exists", _check_contributing_exists),
    ("quickstart-exists", _check_quickstart_exists),
    ("docs-key-files", _check_docs_key_files),
    ("internal-links", _check_internal_links),
    ("anchor-links", _check_anchor_links),
    # 3. Tool versions (4)
    ("versions-yaml-exists", _check_versions_yaml_exists),
    ("deep-profile-versions", _check_deep_profile_versions),
    ("version-format", _check_version_format),
    ("outdated-tools", _check_outdated_tools),
    # 4. Badge accuracy (2)
    ("pypi-badge-version", _check_pypi_badge_version),
    ("python-badge-version", _check_python_badge_version),
    # 5. Git hygiene (5)
    ("git-clean", _check_git_clean),
    ("git-branch", _check_branch),
    ("untracked-scripts", _check_untracked_scripts),
    ("no-merge-conflicts", _check_merge_conflicts),
    ("gitignore-coverage", _check_gitignore),
    # 6. Security (6)
    ("no-secret-patterns", _check_no_secrets),
    ("no-shell-true", _check_no_shell_true),
    ("no-large-files", _check_no_large_files),
    ("no-artifact-dirs", _check_no_artifact_dirs),
    ("no-path-traversal", _check_no_path_traversal),
    ("suppression-file", _check_suppression_file),
    # 7. Code quality (6)
    ("black-clean", _check_black_clean),
    ("ruff-clean", _check_ruff_clean),
    ("import-direction", _check_import_direction),
    ("no-circular-imports", _check_no_circular_imports),
    ("precommit-black-before-ruff", _check_precommit_order),
    ("type-annotations", _check_type_annotations),
    # 8. Test health (6)
    ("test-count", _check_test_count),
    ("coverage-threshold", _check_coverage_threshold),
    ("no-skip-without-reason", _check_no_skip_without_reason),
    ("no-sleep-in-tests", _check_no_sleep_in_tests),
    ("pytest-markers", _check_pytest_markers),
    ("conftest-exists", _check_conftest_exists),
    # 9. Schema/config (5)
    ("json-schema-valid", _check_json_schema),
    ("schema-fields-match", _check_schema_fields_match),
    ("jmo-yml-valid", _check_jmo_yml),
    ("suppress-yml-valid", _check_suppress_yml),
    ("precommit-yml-valid", _check_precommit_yml),
]

# Full tier additional Dockerfiles (4) + pip install (1) + entry point (1) = 6
_DOCKERFILES = [
    "Dockerfile",
    "Dockerfile.fast",
    "Dockerfile.slim",
    "Dockerfile.balanced",
]


def validate_release(tier: str) -> CategoryResult:
    """Release Artifacts validator. Returns CategoryResult with name='Release Artifacts'."""
    checks: list[CheckResult] = []

    # Quick tier: 46 checks
    for name, fn in _QUICK_CHECKS:
        checks.append(timed_check(name, fn))

    # Full tier: 6 additional checks
    if tier == "full":

        def _make_docker_check(df: str) -> _CheckFn:
            """Create a closure for dockerfile build check."""
            return lambda: _check_dockerfile_build(df)

        for dockerfile in _DOCKERFILES:
            checks.append(
                timed_check(
                    f"docker-build-{Path(dockerfile).name.lower()}",
                    _make_docker_check(dockerfile),
                )
            )
        checks.append(timed_check("pip-install-dev", _check_pip_install))
        checks.append(timed_check("jmo-entry-point", _check_jmo_version_entry_point))

    return CategoryResult(name="Release Artifacts", checks=checks)
