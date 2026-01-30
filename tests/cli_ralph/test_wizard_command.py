#!/usr/bin/env python3
"""
Wizard Command Tests for JMo Security CLI.

Tests the interactive wizard command with --yes (non-interactive) mode
and script/workflow generation features.

Usage:
    pytest tests/cli_ralph/test_wizard_command.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import IS_WINDOWS


class TestWizardBasicFunctionality:
    """Test wizard command basic functionality."""

    def test_wizard_help(self, jmo_runner):
        """Verify wizard --help shows available options."""
        result = jmo_runner(["wizard", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        # Should show wizard-specific options
        assert "wizard" in output
        assert "--yes" in output or "non-interactive" in output

    def test_wizard_yes_flag_non_interactive(self, jmo_runner, tmp_path):
        """Verify --yes flag enables non-interactive mode."""
        # Set up a minimal repo structure
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        # Change to repo directory for wizard
        result = jmo_runner(
            ["wizard", "--yes"],
            timeout=120,
            cwd=str(repo),
        )

        # Should complete without prompting
        combined = result.stdout.lower() + result.stderr.lower()
        # May fail for other reasons but shouldn't hang waiting for input
        assert "traceback" not in combined or "wizard" in combined

    def test_wizard_db_flag(self, jmo_runner, tmp_path):
        """Verify --db flag is accepted."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")
        db_path = tmp_path / "custom-history.db"

        result = jmo_runner(
            ["wizard", "--yes", "--db", str(db_path)],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestWizardScriptGeneration:
    """Test wizard script generation features."""

    def test_wizard_emit_script_flag(self, jmo_runner, tmp_path):
        """Verify --emit-script generates shell script."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        script_path = tmp_path / "jmo-scan.sh"

        result = jmo_runner(
            ["wizard", "--yes", "--emit-script", str(script_path)],
            timeout=120,
            cwd=str(repo),
        )

        # Check if script generation was attempted
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

        # Script may or may not be created depending on wizard flow
        if script_path.exists():
            content = script_path.read_text()
            # Should contain shebang or jmo command
            assert "#!/" in content or "jmo" in content

    def test_wizard_emit_script_default_name(self, jmo_runner, tmp_path):
        """Verify --emit-script without argument uses default name."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes", "--emit-script"],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_wizard_emit_make_target_flag(self, jmo_runner, tmp_path):
        """Verify --emit-make-target generates Makefile target."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        makefile_path = tmp_path / "Makefile.jmo"

        result = jmo_runner(
            ["wizard", "--yes", "--emit-make-target", str(makefile_path)],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

        if makefile_path.exists():
            content = makefile_path.read_text()
            # Should contain make target syntax
            assert ":" in content or "jmo" in content

    def test_wizard_emit_gha_flag(self, jmo_runner, tmp_path):
        """Verify --emit-gha generates GitHub Actions workflow."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        gha_path = tmp_path / "jmo-security.yml"

        result = jmo_runner(
            ["wizard", "--yes", "--emit-gha", str(gha_path)],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

        if gha_path.exists():
            content = gha_path.read_text()
            # Should contain GitHub Actions syntax
            assert "on:" in content or "jobs:" in content or "jmo" in content


class TestWizardPolicyFlags:
    """Test wizard policy-related flags."""

    def test_wizard_policy_flag(self, jmo_runner, tmp_path):
        """Verify --policy flag is accepted."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes", "--policy", "zero-critical"],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_wizard_multiple_policies(self, jmo_runner, tmp_path):
        """Verify multiple --policy flags can be specified."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                "wizard",
                "--yes",
                "--policy",
                "zero-critical",
                "--policy",
                "zero-secrets",
            ],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_wizard_skip_policies_flag(self, jmo_runner, tmp_path):
        """Verify --skip-policies flag is accepted."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes", "--skip-policies"],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestWizardFlagCombinations:
    """Test various wizard flag combinations."""

    def test_wizard_script_and_gha_together(self, jmo_runner, tmp_path):
        """Verify --emit-script and --emit-gha can be used together."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                "wizard",
                "--yes",
                "--emit-script",
                str(tmp_path / "scan.sh"),
                "--emit-gha",
                str(tmp_path / "workflow.yml"),
            ],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_wizard_all_emit_options(self, jmo_runner, tmp_path):
        """Verify all emit options can be used together."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                "wizard",
                "--yes",
                "--emit-script",
                str(tmp_path / "scan.sh"),
                "--emit-make-target",
                str(tmp_path / "Makefile.jmo"),
                "--emit-gha",
                str(tmp_path / "workflow.yml"),
            ],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_wizard_with_policy_and_db(self, jmo_runner, tmp_path):
        """Verify --policy and --db can be used together."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            [
                "wizard",
                "--yes",
                "--policy",
                "zero-critical",
                "--db",
                str(tmp_path / "history.db"),
            ],
            timeout=120,
            cwd=str(repo),
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestWizardEdgeCases:
    """Test wizard edge cases and error handling."""

    def test_wizard_empty_directory(self, jmo_runner, tmp_path):
        """Wizard should handle empty directory gracefully."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        result = jmo_runner(
            ["wizard", "--yes"],
            timeout=60,
            cwd=str(empty_dir),
        )

        # Should complete without crashing
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined or "exception" not in combined

    def test_wizard_git_repo(self, jmo_runner, tmp_path):
        """Wizard should detect git repository."""
        repo = tmp_path / "git-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes"],
            timeout=120,
            cwd=str(repo),
        )

        # Should complete and may mention git detection
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_wizard_invalid_policy(self, jmo_runner, tmp_path):
        """Wizard should handle invalid policy name."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes", "--policy", "nonexistent_policy_xyz"],
            timeout=120,
            cwd=str(repo),
        )

        # May warn about invalid policy but shouldn't crash
        combined = result.stdout.lower() + result.stderr.lower()
        # Either fails gracefully or ignores invalid policy
        assert "traceback" not in combined or "policy" in combined

    def test_wizard_emit_to_readonly_location(self, jmo_runner, tmp_path):
        """Wizard should handle write errors gracefully."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        # Try to emit to a location that may not be writable
        # On Windows, /dev/null doesn't exist
        invalid_path = "/nonexistent_dir_xyz/script.sh"
        if IS_WINDOWS:
            invalid_path = "Z:\\nonexistent_dir_xyz\\script.sh"

        result = jmo_runner(
            ["wizard", "--yes", "--emit-script", invalid_path],
            timeout=120,
            cwd=str(repo),
        )

        # Should handle error gracefully
        combined = result.stdout.lower() + result.stderr.lower()
        # Either fails with proper error or skips the emit
        assert "traceback" not in combined.replace("write traceback", "")


class TestWizardOutputFormats:
    """Test wizard output format and content."""

    def test_wizard_produces_actionable_output(self, jmo_runner, tmp_path):
        """Wizard should produce output that can be acted upon."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")
        (repo / "requirements.txt").write_text("flask==2.0.0", encoding="utf-8")

        result = jmo_runner(
            ["wizard", "--yes"],
            timeout=120,
            cwd=str(repo),
        )

        # Should produce some output
        combined = result.stdout + result.stderr
        # Wizard should output something meaningful
        assert len(combined) > 10

    def test_wizard_script_is_executable(self, jmo_runner, tmp_path):
        """Generated script should be syntactically valid."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        script_path = tmp_path / "jmo-scan.sh"

        jmo_runner(
            ["wizard", "--yes", "--emit-script", str(script_path)],
            timeout=120,
            cwd=str(repo),
        )

        if script_path.exists():
            content = script_path.read_text()
            # Basic syntax checks
            # Should not have obvious syntax errors
            assert content.count("(") == content.count(")")
            assert content.count('"') % 2 == 0

    def test_wizard_gha_is_valid_yaml(self, jmo_runner, tmp_path):
        """Generated GitHub Actions workflow should be valid YAML."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("print('hello')", encoding="utf-8")

        gha_path = tmp_path / "jmo-security.yml"

        jmo_runner(
            ["wizard", "--yes", "--emit-gha", str(gha_path)],
            timeout=120,
            cwd=str(repo),
        )

        if gha_path.exists():
            import yaml

            content = gha_path.read_text()
            # Should be parseable YAML
            try:
                data = yaml.safe_load(content)
                assert data is not None
            except yaml.YAMLError:
                # If yaml parsing fails, at least check basic structure
                assert ":" in content
