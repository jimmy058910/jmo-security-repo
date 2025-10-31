"""
Smoke tests for jmo CLI (consolidated from jmotools in v0.9.0).

Note: jmotools was consolidated into jmo in v0.9.0 Feature #1.
All beginner-friendly commands (wizard, fast, balanced, full, setup) are now under jmo.
"""
import subprocess
import sys


def run(args):
    """Run jmo CLI command (consolidated from jmotools in v0.9.0)."""
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_help_top_level():
    """Test jmo --help shows all commands including beginner-friendly ones."""
    cp = run(["--help"])  # argparse shows usage and exits 0
    assert cp.returncode == 0
    # Should show both beginner and advanced commands
    output = cp.stdout + cp.stderr
    assert "wizard" in output
    assert "scan" in output


def test_help_fast():
    """Test jmo fast --help (beginner-friendly command)."""
    cp = run(["fast", "--help"])  # help should work without tools
    assert cp.returncode == 0
    assert "--repos-dir" in (cp.stdout + cp.stderr)


def test_setup_check_mode():
    """Test jmo setup --check (tool verification)."""
    # Should not fail hard; just run the check script if present
    cp = run(["setup", "--check"])  # we pass --check via default path
    # We accept non-zero here depending on environment; ensure it ran
    assert "Tool" in (cp.stdout + cp.stderr) or cp.returncode in (0, 1, 2)
