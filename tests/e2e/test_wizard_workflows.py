"""E2E tests for wizard --yes workflows.

Replaces bash tests M4 (macOS wizard) and W2 (Windows wizard).
Tests that wizard --yes produces valid artifacts (emitted scripts, make targets).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
class TestWizardWorkflows:
    """Test wizard --yes artifact generation."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_wizard_emit_script_macos(self, tmp_path):
        """M4: Wizard --yes emits runnable script on macOS."""
        script_path = tmp_path / "wizard-output.sh"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "wizard",
                "--yes",
                # `--repos-dir` is a `jmo scan` flag, not a wizard flag -- the
                # wizard takes `--target` / `--target-type`. Passing it made
                # argparse exit 2 before `--emit-script` was ever read, so this
                # test asserted nothing about emitted scripts. Confusingly, the
                # script the wizard *emits* does contain `--repos-dir`, because
                # that is the scan command it generates.
                "--target",
                str(E2E_FIXTURES),
                "--target-type",
                "repo",
                "--emit-script",
                str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
        content = script_path.read_text(encoding="utf-8")
        # Script must contain actual jmo scan/ci command, not just a mention
        assert any(
            cmd in content for cmd in ["jmo scan", "jmo ci", "scripts.cli.jmo"]
        ), f"Emitted script doesn't contain a jmo scan command:\n{content[:200]}"
        # Script should scan the preset target, and select no profile (v2.0.0)
        assert E2E_FIXTURES.resolve().as_posix() in content, content[:300]
        assert "--profile-name" not in content

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_wizard_emit_script_windows(self, tmp_path):
        """W2: Wizard --yes emits runnable script on Windows."""
        script_path = tmp_path / "wizard-output.sh"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "wizard",
                "--yes",
                # `--repos-dir` is a `jmo scan` flag, not a wizard flag -- the
                # wizard takes `--target` / `--target-type`. Passing it made
                # argparse exit 2 before `--emit-script` was ever read, so this
                # test asserted nothing about emitted scripts. Confusingly, the
                # script the wizard *emits* does contain `--repos-dir`, because
                # that is the scan command it generates.
                "--target",
                str(E2E_FIXTURES),
                "--target-type",
                "repo",
                "--emit-script",
                str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
        content = script_path.read_text(encoding="utf-8")
        # Script must contain actual jmo scan/ci command, not just a mention
        assert any(
            cmd in content for cmd in ["jmo scan", "jmo ci", "scripts.cli.jmo"]
        ), f"Emitted script doesn't contain a jmo scan command:\n{content[:200]}"
        # Script should scan the preset target, and select no profile (v2.0.0)
        assert E2E_FIXTURES.resolve().as_posix() in content, content[:300]
        assert "--profile-name" not in content
