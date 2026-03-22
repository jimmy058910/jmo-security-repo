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
                "--repos-dir",
                str(E2E_FIXTURES),
                "--profile",
                "fast",
                "--emit-script",
                str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
        content = script_path.read_text()
        assert "jmo" in content.lower(), "Emitted script doesn't contain jmo command"

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
                "--repos-dir",
                str(E2E_FIXTURES),
                "--profile",
                "fast",
                "--emit-script",
                str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
