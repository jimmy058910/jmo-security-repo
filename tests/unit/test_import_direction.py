"""Tests for the import direction linter and doc link checker."""

from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINTER = REPO_ROOT / "scripts" / "dev" / "check_import_direction.py"
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.sh"


def _load_check_import_direction():
    """Load check_import_direction module without caching issues."""
    spec = importlib.util.spec_from_file_location("check_import_direction", str(LINTER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestImportDirectionLinter:
    """Tests for check_import_direction.py."""

    def test_linter_passes_on_clean_codebase(self) -> None:
        """The current codebase should have no import direction violations."""
        result = subprocess.run(
            [sys.executable, str(LINTER)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0, f"Violations found:\n{result.stdout}"
        assert "passed" in result.stdout.lower()

    def test_linter_detects_from_import_violation(self, tmp_path: Path) -> None:
        """Linter detects 'from scripts.cli...' in core files."""
        core_dir = tmp_path / "scripts" / "core"
        core_dir.mkdir(parents=True)
        bad_file = core_dir / "bad_module.py"
        bad_file.write_text("from scripts.cli.scan_utils import find_tool\n")

        mod = _load_check_import_direction()
        violations = mod.check_file(bad_file)
        assert len(violations) == 1
        assert "scripts.cli" in violations[0]

    def test_linter_detects_direct_import_violation(self, tmp_path: Path) -> None:
        """Linter detects 'import scripts.cli' in core files."""
        core_dir = tmp_path / "scripts" / "core"
        core_dir.mkdir(parents=True)
        bad_file = core_dir / "bad_module.py"
        bad_file.write_text("import scripts.cli.jmo\n")

        mod = _load_check_import_direction()
        violations = mod.check_file(bad_file)
        assert len(violations) == 1
        assert "scripts.cli" in violations[0]

    def test_linter_allows_core_internal_imports(self, tmp_path: Path) -> None:
        """Linter allows imports within the core layer."""
        core_dir = tmp_path / "scripts" / "core"
        core_dir.mkdir(parents=True)
        good_file = core_dir / "good_module.py"
        good_file.write_text(textwrap.dedent("""\
            from scripts.core.config import Config
            import scripts.core.common_finding
            """))

        mod = _load_check_import_direction()
        violations = mod.check_file(good_file)
        assert len(violations) == 0


class TestDocLinks:
    """Tests for check_doc_links.py."""

    def test_doc_links_pass(self) -> None:
        """All documentation links in the codebase should be valid."""
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "dev" / "check_doc_links.py")],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        assert (
            result.returncode == 0
        ), f"Broken links found:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "valid" in result.stdout.lower()
