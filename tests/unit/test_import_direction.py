"""Tests for the import direction linter and doc link checker."""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LINTER = REPO_ROOT / "scripts" / "dev" / "check_import_direction.py"
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"


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


def _load_check_doc_links():
    """Load check_doc_links module without caching issues."""
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDocLinks:
    """Tests for check_doc_links.py."""

    def test_doc_links_pass(self) -> None:
        """Every link in tracked documentation resolves to a tracked path."""
        result = subprocess.run(
            [sys.executable, str(DOC_CHECKER)],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(REPO_ROOT),
        )
        assert (
            result.returncode == 0
        ), f"Dead references found:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # Assert it actually checked something. The previous assertion looked for
        # the word "valid" in the output, which a checker that examined zero
        # files would also have satisfied.
        match = re.search(r"All links in (\d+) tracked file", result.stdout)
        assert match, f"Unexpected success output: {result.stdout!r}"
        assert int(match.group(1)) > 0, "Checker validated zero files"

    def test_untracked_target_is_reported_distinctly(self, tmp_path: Path) -> None:
        """A path present on disk but absent from git is UNTRACKED, not BROKEN.

        This is the whole point of the checker: `Path.exists()` cannot see the
        difference, because the file really is there on the maintainer's
        machine. Only tracked-ness describes what a clone receives.
        """
        mod = _load_check_doc_links()
        tracked = {"docs/real.md", "scripts/dev/tool.py"}

        assert mod.is_tracked("docs/real.md", tracked)
        assert not mod.is_tracked("docs/local-only.md", tracked)

    def test_directory_reference_resolves_via_prefix(self) -> None:
        """A link to a directory is satisfied by any tracked file beneath it."""
        mod = _load_check_doc_links()
        tracked = {".claude/agents/security-auditor.md"}

        assert mod.is_tracked(".claude/agents", tracked)
        assert mod.is_tracked(".claude/agents/", tracked)
        assert not mod.is_tracked(".claude/skills", tracked)

    def test_nested_same_length_fences_do_not_desynchronise(self) -> None:
        """A fence carrying an info string cannot close an open fence.

        Agent files show example output as a ```markdown block that itself
        quotes ```bash blocks. Toggling on every fence loses track after the
        first nested one and starts treating sample links as navigation --
        which is exactly how five bogus findings appeared before this rule
        followed CommonMark.
        """
        mod = _load_check_doc_links()
        text = "\n".join(
            [
                "before",
                "```markdown",
                "[sample](does/not/exist.md)",
                "```bash",
                "echo hi",
                "```",
                "after [real](docs/real.md)",
            ]
        )
        kept = "\n".join(mod.navigable_lines(text))

        assert "does/not/exist.md" not in kept, "sample link leaked out of the fence"
        assert "docs/real.md" in kept, "real link was swallowed by a desynced fence"

    def test_inline_code_and_line_citations_are_not_navigation(self) -> None:
        """Quoted links and GitHub line anchors are citations, not links."""
        mod = _load_check_doc_links()

        kept = "\n".join(mod.navigable_lines("use `[text](file.md)` for links"))
        assert "file.md" not in kept

        assert mod.LINE_ANCHOR_PATTERN.search("scripts/cli/jmo.py#L245")
        assert not mod.LINE_ANCHOR_PATTERN.search("docs/USER_GUIDE.md#configuration")
