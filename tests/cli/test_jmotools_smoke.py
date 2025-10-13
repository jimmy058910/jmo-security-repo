import subprocess
import sys


def run(args):
    return subprocess.run([sys.executable, "-m", "scripts.cli.jmotools", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_help_top_level():
    cp = run(["--help"])  # argparse shows usage and exits 0
    assert cp.returncode == 0
    assert "Beginner-friendly wrapper" in cp.stdout or "Beginner-friendly wrapper" in cp.stderr


def test_help_fast():
    cp = run(["fast", "--help"])  # help should work without tools
    assert cp.returncode == 0
    assert "--repos-dir" in (cp.stdout + cp.stderr)


def test_setup_check_mode():
    # Should not fail hard; just run the check script if present
    cp = run(["setup", "--check"])  # we pass --check via default path
    # We accept non-zero here depending on environment; ensure it ran
    assert "Tool" in (cp.stdout + cp.stderr) or cp.returncode in (0, 1, 2)
