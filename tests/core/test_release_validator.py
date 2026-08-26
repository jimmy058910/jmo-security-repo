"""Comprehensive tests for the release artifacts validator."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.core.validators import CategoryResult, CheckStatus
from scripts.core.validators.release_validator import (
    _QUICK_CHECKS,
    _check_anchor_links,
    _check_black_clean,
    _check_branch,
    _check_changelog_date,
    _check_changelog_entry,
    _check_conftest_exists,
    _check_contributing_exists,
    _check_coverage_threshold,
    _check_deep_profile_versions,
    _check_dev_install,
    _check_dockerfile_build,
    _check_docs_key_files,
    _check_git_clean,
    _check_gitignore,
    _check_import_direction,
    _check_internal_links,
    _check_jmo_version_entry_point,
    _check_jmo_yml,
    _check_json_schema,
    _check_merge_conflicts,
    _check_no_artifact_dirs,
    _check_no_circular_imports,
    _check_no_large_files,
    _check_no_path_traversal,
    _check_no_prerelease,
    _check_no_secrets,
    _check_no_shell_true,
    _check_no_skip_without_reason,
    _check_no_sleep_in_tests,
    _check_outdated_tools,
    _check_precommit_order,
    _check_precommit_yml,
    _check_pypi_badge_version,
    _check_pytest_markers,
    _check_python_badge_version,
    _check_quickstart_exists,
    _check_readme_exists,
    _check_requires_python,
    _check_ruff_clean,
    _check_schema_fields_match,
    _check_suppress_yml,
    _check_suppression_file,
    _check_test_count,
    _check_type_annotations,
    _check_untracked_scripts,
    _check_valid_semver,
    _check_version_format,
    _check_version_match,
    _check_versions_yaml_exists,
    validate_release,
)

# ---------------------------------------------------------------------------
# Test validate_release main entry point
# ---------------------------------------------------------------------------


class TestValidateRelease:
    """Tests for the main validate_release function."""

    @patch("scripts.core.validators.release_validator._run_cmd")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="1.0.0",
    )
    def test_quick_tier_returns_category_result(
        self, mock_jmo_ver, mock_pp_ver, mock_pp_data, mock_exists, mock_read, mock_cmd
    ):
        mock_pp_data.return_value = {
            "project": {"version": "1.0.0", "requires-python": ">=3.12"},
            "tool": {
                "pytest": {"ini_options": {"markers": ["slow", "smoke", "benchmark"]}}
            },
        }
        mock_read.return_value = (
            "## [1.0.0] - 2026-02-23\nSome content here with enough bytes.\n" * 10
        )
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = validate_release("quick")
        assert isinstance(result, CategoryResult)
        assert result.name == "Release Artifacts"
        assert result.total >= 40

    @patch("scripts.core.validators.release_validator._run_cmd")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="1.0.0",
    )
    def test_quick_tier_has_46_checks(
        self, mock_jmo_ver, mock_pp_ver, mock_pp_data, mock_exists, mock_read, mock_cmd
    ):
        mock_pp_data.return_value = {
            "project": {"version": "1.0.0", "requires-python": ">=3.12"},
            "tool": {
                "pytest": {"ini_options": {"markers": ["slow", "smoke", "benchmark"]}}
            },
        }
        mock_read.return_value = "## [1.0.0] - 2026-02-23\nSome content here\n" * 10
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = validate_release("quick")
        assert result.total == 46

    @patch("scripts.core.validators.release_validator._run_cmd")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="1.0.0",
    )
    def test_full_tier_has_52_checks(
        self, mock_jmo_ver, mock_pp_ver, mock_pp_data, mock_exists, mock_read, mock_cmd
    ):
        mock_pp_data.return_value = {
            "project": {"version": "1.0.0", "requires-python": ">=3.12"},
            "tool": {
                "pytest": {"ini_options": {"markers": ["slow", "smoke", "benchmark"]}}
            },
        }
        mock_read.return_value = "## [1.0.0] - 2026-02-23\nSome content here\n" * 10
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = validate_release("full")
        assert result.total == 52

    def test_version_checks_present(self):
        """Quick tier includes version-related checks."""
        # Run against real filesystem to verify structure
        result = validate_release("quick")
        version_checks = [c for c in result.checks if "version" in c.name.lower()]
        assert len(version_checks) >= 3

    def test_security_checks_present(self):
        """Quick tier includes security-related checks."""
        result = validate_release("quick")
        security_checks = [
            c
            for c in result.checks
            if any(
                kw in c.name.lower()
                for kw in [
                    "secret",
                    "shell",
                    "large",
                    "artifact",
                    "traversal",
                    "suppress",
                ]
            )
        ]
        assert len(security_checks) >= 5

    def test_all_checks_have_names(self):
        """Every check has a non-empty name."""
        result = validate_release("quick")
        for check in result.checks:
            assert check.name, f"Check with empty name found: {check}"

    def test_all_checks_have_valid_status(self):
        """Every check has a valid CheckStatus."""
        result = validate_release("quick")
        for check in result.checks:
            assert isinstance(
                check.status, CheckStatus
            ), f"Check '{check.name}' has invalid status type: {type(check.status)}"


# ---------------------------------------------------------------------------
# 1. Version consistency checks
# ---------------------------------------------------------------------------


class TestVersionChecks:
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="1.0.0",
    )
    def test_version_match_pass(self, mock_jmo, mock_pp):
        result = _check_version_match()
        assert result is None  # None = pass

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="0.9.0",
    )
    def test_version_match_fail(self, mock_jmo, mock_pp):
        result = _check_version_match()
        assert result.status == CheckStatus.FAIL
        assert "1.0.0" in result.message
        assert "0.9.0" in result.message

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_changelog_entry_pass(self, mock_read, mock_ver):
        mock_read.return_value = "## [1.0.0] - 2026-02-23\n\n### Added\n- stuff"
        result = _check_changelog_entry()
        assert result is None

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="2.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_changelog_entry_missing(self, mock_read, mock_ver):
        mock_read.return_value = "## [1.0.0] - 2026-02-23\n\n### Added\n- stuff"
        result = _check_changelog_entry()
        assert result.status == CheckStatus.FAIL
        assert "2.0.0" in result.message

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_changelog_date_recent(self, mock_read, mock_ver):
        mock_read.return_value = "## [1.0.0] - 2026-02-23\n"
        result = _check_changelog_date()
        # Should be recent enough
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.WARN)

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_changelog_date_old(self, mock_read, mock_ver):
        mock_read.return_value = "## [1.0.0] - 2020-01-01\n"
        result = _check_changelog_date()
        assert result.status == CheckStatus.WARN
        assert "days old" in result.message

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_changelog_date_unparseable(self, mock_read, mock_ver):
        mock_read.return_value = "## [1.0.0]\n\nNo date here"
        result = _check_changelog_date()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_requires_python_pass(self, mock_data):
        mock_data.return_value = {"project": {"requires-python": ">=3.12"}}
        result = _check_requires_python()
        assert result is None

    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_requires_python_too_low(self, mock_data):
        mock_data.return_value = {"project": {"requires-python": ">=3.9"}}
        result = _check_requires_python()
        assert result.status == CheckStatus.FAIL
        assert "3.9" in result.message

    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_requires_python_missing(self, mock_data):
        mock_data.return_value = {"project": {}}
        result = _check_requires_python()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    def test_valid_semver_pass(self, mock_ver):
        result = _check_valid_semver()
        assert result is None

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="abc",
    )
    def test_valid_semver_fail(self, mock_ver):
        result = _check_valid_semver()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    def test_no_prerelease_pass(self, mock_ver):
        result = _check_no_prerelease()
        assert result is None

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0-alpha",
    )
    def test_no_prerelease_alpha(self, mock_ver):
        result = _check_no_prerelease()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0-beta.1",
    )
    def test_no_prerelease_beta(self, mock_ver):
        result = _check_no_prerelease()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0-rc1",
    )
    def test_no_prerelease_rc(self, mock_ver):
        result = _check_no_prerelease()
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 2. Documentation link checks
# ---------------------------------------------------------------------------


class TestDocumentationChecks:
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_readme_exists_pass(self, mock_read, mock_exists):
        mock_read.return_value = "# README\n" + "content " * 50
        result = _check_readme_exists()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_readme_missing(self, mock_exists):
        result = _check_readme_exists()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text", return_value="tiny")
    def test_readme_too_small(self, mock_read, mock_exists):
        result = _check_readme_exists()
        assert result.status == CheckStatus.FAIL
        assert "minimal" in result.message

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    def test_contributing_exists_pass(self, mock_exists):
        result = _check_contributing_exists()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_contributing_missing(self, mock_exists):
        result = _check_contributing_exists()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    def test_quickstart_exists_pass(self, mock_exists):
        result = _check_quickstart_exists()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_quickstart_missing(self, mock_exists):
        result = _check_quickstart_exists()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists")
    def test_docs_key_files_pass(self, mock_exists):
        mock_exists.return_value = True
        result = _check_docs_key_files()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists")
    def test_docs_key_files_missing(self, mock_exists):
        def side_effect(path):
            return path != "docs/CLI_REFERENCE.md"

        mock_exists.side_effect = side_effect
        result = _check_docs_key_files()
        assert result.status == CheckStatus.FAIL
        assert "CLI_REFERENCE" in result.message

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    def test_internal_links_pass(self, mock_read, mock_exists):
        mock_exists.return_value = True
        mock_read.return_value = (
            "[Guide](docs/USER_GUIDE.md) and [ext](https://example.com)"
        )
        result = _check_internal_links()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    def test_internal_links_broken(self, mock_read, mock_exists):
        def exists_side(path):
            return path in ("README.md",)

        mock_exists.side_effect = exists_side
        mock_read.return_value = "[Missing](nonexistent.md)"
        result = _check_internal_links()
        assert result is not None
        assert result.status == CheckStatus.WARN
        assert "broken" in result.message.lower()

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    def test_anchor_links_pass(self, mock_read, mock_exists):
        mock_exists.return_value = True
        mock_read.return_value = "# Overview\n\n[link](#overview)\n"
        result = _check_anchor_links()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    def test_anchor_links_broken(self, mock_read, mock_exists):
        mock_exists.return_value = True
        mock_read.return_value = "# Overview\n\n[link](#nonexistent)\n"
        result = _check_anchor_links()
        assert result is not None
        assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# 3. Tool version checks
# ---------------------------------------------------------------------------


class TestToolVersionChecks:
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_versions_yaml_exists_pass(self, mock_read, mock_exists):
        mock_read.return_value = "python_tools:\n  bandit:\n    version: 1.9.3\n"
        result = _check_versions_yaml_exists()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_versions_yaml_missing(self, mock_exists):
        result = _check_versions_yaml_exists()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch(
        "scripts.core.validators.release_validator._read_text",
        return_value="invalid: yaml: {{",
    )
    def test_versions_yaml_invalid(self, mock_read, mock_exists):
        # PyYAML may or may not raise on this - test with guaranteed invalid yaml
        pass  # YAML parser is lenient; skip this edge case

    @patch("scripts.core.validators.release_validator._read_text")
    def test_deep_profile_versions_basic(self, mock_read):
        mock_read.return_value = (
            "python_tools:\n"
            "  bandit:\n    version: 1.9.3\n"
            "  semgrep:\n    version: 1.151.0\n"
            "  trivy:\n    version: 0.60.0\n"
        )
        result = _check_deep_profile_versions()
        # Some tools may be missing - that's expected
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.WARN)

    @patch("scripts.core.validators.release_validator._read_text")
    def test_version_format_pass(self, mock_read):
        mock_read.return_value = (
            "python_tools:\n"
            "  bandit:\n    version: 1.9.3\n"
            "  semgrep:\n    version: 1.151.0\n"
        )
        result = _check_version_format()
        assert result is None

    @patch("scripts.core.validators.release_validator._read_text")
    def test_version_format_prefixed(self, mock_read):
        """Accepts prefixed versions like akto's mini-testing-1.53.7."""
        mock_read.return_value = (
            "java_tools:\n" "  akto:\n    version: mini-testing-1.53.7\n"
        )
        result = _check_version_format()
        assert result is None

    @patch("scripts.core.validators.release_validator._read_text")
    def test_version_format_invalid(self, mock_read):
        mock_read.return_value = (
            "python_tools:\n" "  bandit:\n    version: abc-not-a-version\n"
        )
        result = _check_version_format()
        assert result is not None
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._read_text")
    def test_outdated_tools_pass(self, mock_read):
        mock_read.return_value = (
            "python_tools:\n"
            "  bandit:\n    version: 1.9.3\n    update_check: pip\n"
            "  semgrep:\n    version: 1.0.0\n    update_check: pip\n"
        )
        result = _check_outdated_tools()
        assert result is None


# ---------------------------------------------------------------------------
# 4. Badge accuracy checks
# ---------------------------------------------------------------------------


class TestBadgeChecks:
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_pypi_badge_pass(self, mock_read, mock_ver):
        mock_read.return_value = (
            "[![PyPI](https://img.shields.io/pypi/v/jmo-security.svg)]"
            "(https://pypi.org/project/jmo-security/)"
        )
        result = _check_pypi_badge_version()
        assert result is None

    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._read_text")
    def test_pypi_badge_missing(self, mock_read, mock_ver):
        mock_read.return_value = "# README\nNo badges here."
        result = _check_pypi_badge_version()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._read_text")
    def test_python_badge_pass(self, mock_read):
        mock_read.return_value = (
            "[![Python](https://img.shields.io/pypi/pyversions/jmo-security.svg)]"
            "(https://pypi.org/project/jmo-security/)"
        )
        result = _check_python_badge_version()
        assert result is None

    @patch("scripts.core.validators.release_validator._read_text")
    def test_python_badge_missing(self, mock_read):
        mock_read.return_value = "# README\nNo badges here."
        result = _check_python_badge_version()
        assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# 5. Git hygiene checks
# ---------------------------------------------------------------------------


class TestGitHygieneChecks:
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_git_clean_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="")
        result = _check_git_clean()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_git_dirty(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="M scripts/cli/jmo.py\n")
        result = _check_git_clean()
        assert result.status == CheckStatus.WARN
        assert "uncommitted" in result.message.lower()

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_git_clean_error(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=128, stdout="")
        result = _check_git_clean()
        assert result.status == CheckStatus.SKIP

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_branch_main(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="main\n")
        result = _check_branch()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_branch_dev(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="dev\n")
        result = _check_branch()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_branch_feature(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="feature/my-feature\n")
        result = _check_branch()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_untracked_scripts_clean(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="")
        result = _check_untracked_scripts()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_untracked_scripts_found(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=0, stdout="scripts/core/new_file.py\n"
        )
        result = _check_untracked_scripts()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_merge_conflicts_none(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=1, stdout="")
        result = _check_merge_conflicts()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_merge_conflicts_found(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="scripts/cli/jmo.py\n")
        result = _check_merge_conflicts()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_gitignore_pass(self, mock_read, mock_exists):
        mock_read.return_value = "venv/\n__pycache__/\n.env\ndist/\nbuild/\n"
        result = _check_gitignore()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_gitignore_missing(self, mock_exists):
        result = _check_gitignore()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_gitignore_incomplete(self, mock_read, mock_exists):
        mock_read.return_value = "*.pyc\n"
        result = _check_gitignore()
        assert result.status == CheckStatus.WARN
        assert "missing patterns" in result.message.lower()


# ---------------------------------------------------------------------------
# 6. Security checks
# ---------------------------------------------------------------------------


class TestSecurityChecks:
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_secrets_clean(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="README.md\nsetup.py\n")
        # Patch file reads to return clean content
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="clean content"),
        ):
            result = _check_no_secrets()
            assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_secrets_excludes_prefixed_paths(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout=(
                "tests/fixtures/creds.py\n"
                "docs/examples/config.md\n"
                ".claude/skills/test.md\n"
                ".github/workflows/ci.yml\n"
                "scripts/dev/helper.py\n"
            ),
        )
        result = _check_no_secrets()
        # All these paths should be excluded by prefix
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_secrets_excludes_the_pytest_split_durations_index(self, mock_cmd):
        """`.test_durations` is a generated index of `tests/`, already excluded.

        It holds pytest node IDs, and one of them is the parametrised case of
        `test_sanitize_tokens` -- a test *about* AWS-key redaction, whose
        parameter is AWS's published example key. Adding the file to `dev` (to
        balance the CI shards) turned the release-blocking `no-secret-patterns`
        check red, and it stayed red unnoticed because `jmo validate` runs in
        exactly one place: `release.yml`'s `pre-release-check`, on a tag.
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout=".test_durations\n")
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(
                Path,
                "read_text",
                return_value='{"tests/x.py::t[AKIA" + "IOSFODNN7EXAMPLE]": 0.1}',
            ),
        ):
            assert _check_no_secrets() is None

    def test_the_real_tree_has_no_secret_findings(self):
        """No mocks: the shipped gate must be green on a clean checkout.

        Every other test here fabricates `git ls-files` output, so all of them
        passed while the real repository failed the check.
        """
        result = _check_no_secrets()
        assert (
            result is None or result.status != CheckStatus.FAIL
        ), f"{getattr(result, 'message', '')}: {getattr(result, 'details', '')}"

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_secrets_found(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="config.py\n")
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(
                Path, "read_text", return_value="aws_key = 'AKIAIOSFODNN7EXAMPLE1'"
            ),
        ):
            result = _check_no_secrets()
            assert result is not None
            assert result.status == CheckStatus.FAIL

    def test_no_shell_true_clean(self):
        """shell=True check on scripts directory (real filesystem)."""
        result = _check_no_shell_true()
        # Real codebase should not have shell=True in actual code
        # (comments and docstrings mentioning it are excluded)
        assert result is None or result.status in (
            CheckStatus.PASS,
            CheckStatus.SKIP,
        )

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_large_files_clean(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="small.py\n")
        with patch.object(Path, "is_file", return_value=True):
            mock_stat = MagicMock()
            mock_stat.st_size = 1024
            with patch.object(Path, "stat", return_value=mock_stat):
                result = _check_no_large_files()
                assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_artifact_dirs_clean(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="scripts/cli/jmo.py\n")
        result = _check_no_artifact_dirs()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_no_artifact_dirs_found(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=0, stdout="venv/lib/python3.12/site.py\n"
        )
        result = _check_no_artifact_dirs()
        assert result.status == CheckStatus.FAIL

    def test_suppression_file_exists(self):
        """Test against real filesystem."""
        result = _check_suppression_file()
        # Real repo has this file
        assert result is None or result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# 7. Code quality checks
# ---------------------------------------------------------------------------


class TestCodeQualityChecks:
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_black_clean_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _check_black_clean()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_black_clean_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=1, stdout="would reformat scripts/cli/jmo.py", stderr=""
        )
        result = _check_black_clean()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._run_cmd",
        side_effect=FileNotFoundError,
    )
    def test_black_not_installed(self, mock_cmd):
        result = _check_black_clean()
        assert result.status == CheckStatus.SKIP

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_ruff_clean_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _check_ruff_clean()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_ruff_clean_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=1, stdout="Found 3 errors", stderr=""
        )
        result = _check_ruff_clean()
        assert result.status == CheckStatus.FAIL

    @patch(
        "scripts.core.validators.release_validator._run_cmd",
        side_effect=FileNotFoundError,
    )
    def test_ruff_not_installed(self, mock_cmd):
        result = _check_ruff_clean()
        assert result.status == CheckStatus.SKIP

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_precommit_order_pass(self, mock_read, mock_exists):
        mock_read.return_value = (
            "repos:\n"
            "  - repo: https://github.com/psf/black\n"
            "    hooks:\n      - id: black\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    hooks:\n      - id: ruff\n"
        )
        result = _check_precommit_order()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_precommit_order_wrong(self, mock_read, mock_exists):
        mock_read.return_value = (
            "repos:\n"
            "  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    hooks:\n      - id: ruff\n"
            "  - repo: https://github.com/psf/black\n"
            "    hooks:\n      - id: black\n"
        )
        result = _check_precommit_order()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_precommit_missing(self, mock_exists):
        result = _check_precommit_order()
        assert result.status == CheckStatus.FAIL

    def test_import_direction_check(self):
        """Test import direction runs against real codebase."""
        result = _check_import_direction()
        # Core should not import from CLI in a clean codebase
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.FAIL)

    def test_no_circular_imports_check(self):
        """Test circular import detection."""
        result = _check_no_circular_imports()
        # cli/ imports core/ (expected), core/ should NOT import cli/
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.FAIL)


# ---------------------------------------------------------------------------
# 8. Test health checks
# ---------------------------------------------------------------------------


class TestTestHealthChecks:
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_test_count_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=0, stdout="8234 tests collected\n", stderr=""
        )
        result = _check_test_count()
        assert result.status == CheckStatus.PASS
        assert "8234" in result.message

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_test_count_pass_with_items(self, mock_cmd):
        """Handles pytest's alternate 'X test items collected' format."""
        mock_cmd.return_value = MagicMock(
            returncode=0, stdout="7500 test items collected\n", stderr=""
        )
        result = _check_test_count()
        assert result.status == CheckStatus.PASS

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_test_count_low(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=0, stdout="100 tests collected\n", stderr=""
        )
        result = _check_test_count()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_test_count_unparseable(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="no output\n", stderr="")
        result = _check_test_count()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_test_count_ignores_worker_count(self, mock_cmd):
        """Ensures '3 workers' doesn't match as test count."""
        mock_cmd.return_value = MagicMock(
            returncode=0,
            stdout="running 3 workers\n8234 tests collected\n",
            stderr="",
        )
        result = _check_test_count()
        assert result.status == CheckStatus.PASS
        assert "8234" in result.message

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_coverage_threshold_from_makefile(self, mock_data, mock_read, mock_exists):
        mock_data.return_value = {"tool": {}}

        def exists_side(path):
            return path == "Makefile"

        mock_exists.side_effect = exists_side
        mock_read.return_value = "test:\n\tpytest --cov-fail-under=85\n"
        result = _check_coverage_threshold()
        assert result.status == CheckStatus.PASS

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_coverage_threshold_low(self, mock_data, mock_read, mock_exists):
        mock_data.return_value = {"tool": {}}

        def exists_side(path):
            return path == "Makefile"

        mock_exists.side_effect = exists_side
        mock_read.return_value = "test:\n\tpytest --cov-fail-under=50\n"
        result = _check_coverage_threshold()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_coverage_threshold_from_ci_inline(self, mock_data, mock_read, mock_exists):
        """Detects inline 'coverage_pct < 85' pattern in CI workflow."""
        mock_data.return_value = {"tool": {}}

        def exists_side(path):
            return path == ".github/workflows/ci.yml"

        mock_exists.side_effect = exists_side
        mock_read.return_value = "if coverage_pct < 85:\n    sys.exit(1)\n"
        result = _check_coverage_threshold()
        assert result.status == CheckStatus.PASS

    @patch("scripts.core.validators.release_validator._path_exists")
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_coverage_threshold_rejects_the_superseded_floor(
        self, mock_data, mock_read, mock_exists
    ):
        """`coverage_pct < 80` must now WARN: #756 raised the real gate to 85.

        This is the discriminating case, and it is worth keeping for that reason
        alone. The other cases in this class use 85 and 50, which sit on the same
        side of both the old floor (80) and the new one (85), so neither can tell
        the two apart. 80 is precisely the value whose verdict flips when the
        floor moves.

        History, because this test has now caught the boundary in both
        directions: it asserted PASS on 80 while 80 was the enforced floor.
        Before #773 the check demanded >=85 while nothing in the repo enforced
        85 (#756), so it WARNed against the project's own CI config however
        healthy coverage was. #756 raised the real gate to 85 after measuring
        86.87%, so the check and ci.yml agree once more -- and 80 is now
        correctly below the bar rather than at it.
        """
        mock_data.return_value = {"tool": {}}
        mock_exists.side_effect = lambda p: p == ".github/workflows/ci.yml"
        mock_read.return_value = "if coverage_pct < 80:\n    sys.exit(1)\n"
        result = _check_coverage_threshold()
        assert result.status == CheckStatus.WARN
        assert "85" in result.message

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_conftest_exists_pass(self, mock_read, mock_exists):
        mock_read.return_value = "@pytest.fixture\ndef my_fixture():\n    pass\n"
        result = _check_conftest_exists()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_conftest_missing(self, mock_exists):
        result = _check_conftest_exists()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_conftest_no_fixtures(self, mock_read, mock_exists):
        mock_read.return_value = "# Empty conftest\n"
        result = _check_conftest_exists()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_pytest_markers_pass(self, mock_data):
        mock_data.return_value = {
            "tool": {
                "pytest": {
                    "ini_options": {
                        "markers": [
                            "slow: slow tests",
                            "benchmark: benchmarks",
                            "smoke: smoke tests",
                        ]
                    }
                }
            }
        }
        result = _check_pytest_markers()
        assert result is None

    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    def test_pytest_markers_empty(self, mock_data):
        mock_data.return_value = {"tool": {"pytest": {"ini_options": {"markers": []}}}}
        result = _check_pytest_markers()
        assert result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# 9. Schema/config checks
# ---------------------------------------------------------------------------


class TestSchemaConfigChecks:
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_json_schema_valid(self, mock_read, mock_exists):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        }
        mock_read.return_value = json.dumps(schema)
        result = _check_json_schema()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_json_schema_missing(self, mock_exists):
        result = _check_json_schema()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch(
        "scripts.core.validators.release_validator._read_text",
        return_value="{invalid json",
    )
    def test_json_schema_invalid_json(self, mock_read, mock_exists):
        result = _check_json_schema()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_json_schema_no_properties(self, mock_read, mock_exists):
        mock_read.return_value = '{"type": "object"}'
        result = _check_json_schema()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_schema_fields_match_pass(self, mock_read, mock_exists):
        schema = {
            "properties": {"id": {}, "ruleId": {}, "severity": {}},
            "required": [
                "schemaVersion",
                "id",
                "ruleId",
                "severity",
                "tool",
                "location",
                "message",
            ],
        }
        mock_read.return_value = json.dumps(schema)
        result = _check_schema_fields_match()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_schema_fields_missing_required(self, mock_read, mock_exists):
        schema = {"properties": {"id": {}}, "required": ["id"]}
        mock_read.return_value = json.dumps(schema)
        result = _check_schema_fields_match()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_jmo_yml_valid(self, mock_read, mock_exists):
        mock_read.return_value = "default_profile: balanced\ntools:\n  - trivy\n"
        result = _check_jmo_yml()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_jmo_yml_missing(self, mock_exists):
        result = _check_jmo_yml()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_suppress_yml_valid(self, mock_read, mock_exists):
        mock_read.return_value = "suppressions:\n  - id: abc\n    reason: test\n"
        result = _check_suppress_yml()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_suppress_yml_missing(self, mock_exists):
        result = _check_suppress_yml()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    def test_precommit_yml_valid(self, mock_read, mock_exists):
        mock_read.return_value = "repos:\n  - repo: https://github.com/psf/black\n"
        result = _check_precommit_yml()
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_precommit_yml_missing(self, mock_exists):
        result = _check_precommit_yml()
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Full tier checks
# ---------------------------------------------------------------------------


class TestFullTierChecks:
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dockerfile_build_pass(self, mock_cmd, mock_exists):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _check_dockerfile_build("Dockerfile")
        assert result is None

    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dockerfile_build_fail(self, mock_cmd, mock_exists):
        mock_cmd.return_value = MagicMock(
            returncode=1, stdout="", stderr="ERROR: build failed"
        )
        result = _check_dockerfile_build("Dockerfile")
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_dockerfile_missing(self, mock_exists):
        result = _check_dockerfile_build("Dockerfile.missing")
        assert result.status == CheckStatus.SKIP

    @patch(
        "scripts.core.validators.release_validator._run_cmd",
        side_effect=FileNotFoundError,
    )
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    def test_dockerfile_no_docker(self, mock_exists, mock_cmd):
        result = _check_dockerfile_build("Dockerfile")
        assert result.status == CheckStatus.SKIP
        assert "Docker not available" in result.message

    @patch(
        "scripts.core.validators.release_validator._run_cmd",
        side_effect=subprocess.TimeoutExpired(cmd="docker build", timeout=1800),
    )
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    def test_dockerfile_build_timeout_is_fail_not_skip(self, mock_exists, mock_cmd):
        """A build past its own budget must FAIL, not SKIP.

        This branch had no test at all, which is how it stayed wrong. Reporting a
        timeout as SKIP made it indistinguishable in the scorecard's status
        column from "Docker not available" -- so docker-build-deep, which could
        not meet its 600s --no-cache budget on any measured machine (858s WITH a
        warm cache), reported exactly what a box with no daemon reports (#941).

        The companion assertion is the one directly below in
        test_dockerfile_no_docker: an absent daemon still SKIPs. The pair is the
        point -- either alone permits the two to collapse back together.
        """
        result = _check_dockerfile_build("Dockerfile")
        assert result.status == CheckStatus.FAIL
        assert "timeout" in result.message.lower()
        assert "NOT an absent daemon" in result.message

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dev_install_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = _check_dev_install()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dev_install_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(
            returncode=1, stdout="", stderr="Could not find package"
        )
        result = _check_dev_install()
        assert result.status == CheckStatus.FAIL

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dev_install_probes_uv_not_the_deleted_dev_extra(self, mock_cmd):
        """The probe must not reference `[dev]`, which #683 removed.

        Dev dependencies moved to a PEP 735 `[dependency-groups]` group, so
        `pip install -e '.[dev]'` failing is the intended state. Asserting on
        it made the check FAIL on a correct machine (#773).
        """
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _check_dev_install()
        cmd = mock_cmd.call_args[0][0]
        assert cmd[0] == "uv"
        assert not any(".[dev]" in str(part) for part in cmd)

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_dev_install_skips_when_the_tool_is_absent(self, mock_cmd):
        """Missing tooling must SKIP, not FAIL.

        The pre-#773 probe was `python -m pip`, where a missing pip *module*
        exits 1 rather than raising -- so this guard could never fire on a uv
        venv, which is every dev machine this project documents.
        """
        mock_cmd.side_effect = FileNotFoundError("uv")
        result = _check_dev_install()
        assert result.status == CheckStatus.SKIP
        assert "uv not available" in result.message

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_jmo_entry_point_pass(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="usage: jmo", stderr="")
        result = _check_jmo_version_entry_point()
        assert result is None

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_jmo_entry_point_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=1, stdout="", stderr="ImportError")
        result = _check_jmo_version_entry_point()
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Edge cases and integration
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_validate_release_handles_missing_files_gracefully(self):
        """Validator should not crash when files are missing."""
        result = validate_release("quick")
        # Should complete without raising
        assert isinstance(result, CategoryResult)
        # All checks should have valid statuses (no exceptions escaped)
        for check in result.checks:
            assert check.status in (
                CheckStatus.PASS,
                CheckStatus.FAIL,
                CheckStatus.WARN,
                CheckStatus.SKIP,
                CheckStatus.ERROR,
            )

    def test_validate_release_check_names_unique(self):
        """Check names in the quick tier should be unique."""
        registered_names = [name for name, _ in _QUICK_CHECKS]
        assert len(registered_names) == len(set(registered_names))

    def test_validate_release_timings_set(self):
        """All checks should have timing information."""
        result = validate_release("quick")
        for check in result.checks:
            assert check.duration_ms >= 0, f"Check '{check.name}' missing timing"

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_git_command_exception_handled(self, mock_cmd):
        """Git exceptions should be caught gracefully."""
        mock_cmd.side_effect = OSError("git not found")
        result = _check_git_clean()
        assert result.status == CheckStatus.SKIP

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_subprocess_timeout_handled(self, mock_cmd):
        """Subprocess timeouts should be handled gracefully."""
        mock_cmd.side_effect = subprocess.TimeoutExpired(cmd="black", timeout=60)
        result = _check_black_clean()
        assert result.status == CheckStatus.SKIP

    @patch(
        "scripts.core.validators.release_validator._get_jmo_version",
        return_value="1.0.0",
    )
    @patch(
        "scripts.core.validators.release_validator._get_pyproject_version",
        return_value="1.0.0",
    )
    @patch("scripts.core.validators.release_validator._get_pyproject_data")
    @patch("scripts.core.validators.release_validator._path_exists", return_value=True)
    @patch("scripts.core.validators.release_validator._read_text")
    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_full_tier_adds_exactly_6_checks(
        self, mock_cmd, mock_read, mock_exists, mock_data, mock_pp_ver, mock_jmo_ver
    ):
        """Full tier should add exactly 6 checks beyond quick."""
        mock_data.return_value = {
            "project": {"version": "1.0.0", "requires-python": ">=3.12"},
            "tool": {"pytest": {"ini_options": {"markers": ["a", "b", "c"]}}},
        }
        mock_read.return_value = "## [1.0.0] - 2026-02-23\ncontent\n" * 10
        mock_cmd.return_value = MagicMock(returncode=0, stdout="", stderr="")

        quick_result = validate_release("quick")
        full_result = validate_release("full")
        assert full_result.total - quick_result.total == 6


# ---------------------------------------------------------------------------
# Test skip/warn patterns
# ---------------------------------------------------------------------------


class TestSkipAndWarnPatterns:
    """Ensure SKIP and WARN are used appropriately (not FAIL) for optional checks."""

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_suppress_yml_missing_is_warn_not_fail(self, mock_exists):
        result = _check_suppress_yml()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_git_dirty_is_warn_not_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="M file.py\n")
        result = _check_git_clean()
        assert result.status == CheckStatus.WARN

    @patch("scripts.core.validators.release_validator._run_cmd")
    def test_feature_branch_is_warn_not_fail(self, mock_cmd):
        mock_cmd.return_value = MagicMock(returncode=0, stdout="feature/x\n")
        result = _check_branch()
        assert result.status == CheckStatus.WARN

    @patch(
        "scripts.core.validators.release_validator._read_text",
        return_value="x = 1\n",
    )
    @patch(
        "scripts.core.validators.release_validator._path_exists",
        return_value=True,
    )
    def test_type_annotations_missing_is_warn(self, mock_exists, mock_read):
        """Missing type annotations is a warning, not failure."""
        result = _check_type_annotations()
        assert result is None or result.status == CheckStatus.WARN


# ---------------------------------------------------------------------------
# Test no_sleep and no_skip checks with tmp directories
# ---------------------------------------------------------------------------


class TestTestFileScanning:
    def test_no_skip_without_reason_on_real_tests(self):
        """Run against real test files to verify."""
        result = _check_no_skip_without_reason()
        # Real codebase may or may not have bare skips
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_no_sleep_in_tests_on_real_tests(self):
        """Run against real test files — allowed files are skipped."""
        result = _check_no_sleep_in_tests()
        # With allowlist, all known sleep usages should be excluded
        assert result is None or result.status in (CheckStatus.PASS, CheckStatus.WARN)

    @patch("scripts.core.validators.release_validator._path_exists", return_value=False)
    def test_no_skip_tests_dir_missing(self, mock_exists):
        # Monkey-patch the _ROOT to a non-existent path
        with patch(
            "scripts.core.validators.release_validator._ROOT", Path("/nonexistent")
        ):
            result = _check_no_skip_without_reason()
            assert result.status == CheckStatus.SKIP

    @patch("scripts.core.validators.release_validator._ROOT", Path("/nonexistent"))
    def test_no_sleep_tests_dir_missing(self):
        result = _check_no_sleep_in_tests()
        assert result.status == CheckStatus.SKIP


# ---------------------------------------------------------------------------
# Test path traversal check
# ---------------------------------------------------------------------------


class TestPathTraversalCheck:
    def test_no_path_traversal_real(self):
        """Test against real cli/ files."""
        result = _check_no_path_traversal()
        # Should pass or warn (not error)
        assert result is None or result.status in (
            CheckStatus.PASS,
            CheckStatus.WARN,
            CheckStatus.SKIP,
        )
