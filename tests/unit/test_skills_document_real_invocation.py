#!/usr/bin/env python3
"""Guard: a skill may not document a flag surface it does not have.

Regression for #761.

`.claude/skills/*/SKILL.md` files are Claude Code skills. The frontmatter takes a
single free-text `$ARGUMENTS` string; there is no argparse, no entry point and no
program behind any flag. Two skills nevertheless documented one.

`jmo-refactoring-assistant` was fixed in PR #760. `jmo-security-hardening` is
#761, and measuring it found the defect was **larger than its filing**: not one
`## Parameters` section but 11 sites across three files, including four worked
examples in `examples/vulnerability-fix-examples.md`, a live "Start with
--dry-run" instruction, a surviving "Review --dry-run output" in
`references/limitations.md`, and two flags (`--findings`,
`--auto-detect-targets`) that the Parameters block did not even list.

## Why this is worth a guard rather than an edit

The flags are not merely inert. Three of them read as guarantees that do not
hold, and this is a **security** skill:

* `--dry-run` reads as a guarantee that nothing is written. There is no preview
  mode; edits land directly.
* `--skip-tests` reads as a supported way to ship a security fix without tests,
  in a skill whose whole value is that the fix arrives with them.
* `--security-level ... (default: strict)` reads as a default being applied.
  Nothing applies it.

#760 also showed the failure mode of fixing this by hand: two live
"Use `--dry-run`" instructions survived in a reference file after its Parameters
block was rewritten. A sweep that stops at the heading is not a sweep.

## What is asserted

Three shapes, over every tracked file under `.claude/skills/`:

1. a `Parameters` / `Required` / `Optional` heading -- a skill has none
2. `claude skill <name>` -- not the invocation form; skills are `/<name>`
3. a flag-definition bullet, ``- `--flag`: description``

**Blockquote lines are exempt, and that exemption is the point.** Both fixed
skills carry a "Removed, not reworded" note listing the deleted flags by name, so
the next reader learns they were absent rather than rediscovering them. A guard
that could not tell a quotation from an instruction would delete the record of
its own defect.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"
SKILLS_PREFIX = ".claude/skills/"

_FLAG_HEADING = re.compile(
    r"^#{2,4}\s+(Parameters|Required|Optional)\s*$", re.IGNORECASE
)
_CLI_INVOCATION = re.compile(r"\bclaude\s+skill\s+[a-z0-9][a-z0-9-]*")
# A flag *definition*, not a mention. The colon is what separates
# "- `--dry-run`: Preview fixes without applying" -- a documented option -- from
# "- `--help` is universally supported", which is jmo-ci-debugger correctly
# describing Docker. Matching the mention flagged that line; the property being
# asserted is "this defines an option for this skill".
_FLAG_BULLET = re.compile(r"^\s*[-*]\s+`--[a-z][a-z0-9-]*(?:\s+[A-Z][A-Z_]*)?`\s*:")


def _skill_files() -> list[str]:
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return sorted(
        p
        for p in mod.tracked_paths()
        if p.startswith(SKILLS_PREFIX) and p.endswith(".md")
    )


def test_no_skill_documents_a_flag_it_cannot_parse() -> None:
    """Regression for #761: a documented `--dry-run` that nothing implements."""
    files = _skill_files()
    assert len(files) >= 12, f"skill discovery looks wrong: {len(files)}"
    # The two skills this guard exists for must be in the walk, by name.
    assert any("jmo-security-hardening/SKILL.md" in p for p in files)
    assert any("jmo-refactoring-assistant/SKILL.md" in p for p in files)

    offenders: list[str] = []
    for rel in files:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            # A blockquote is commentary about what was removed, not an
            # instruction. Both fixed skills depend on this.
            if line.lstrip().startswith(">"):
                continue
            if _FLAG_HEADING.match(line.strip()):
                offenders.append(
                    f"{rel}:{lineno}: '{line.strip()}' -- a skill has no parameters"
                )
            elif match := _CLI_INVOCATION.search(line):
                offenders.append(
                    f"{rel}:{lineno}: '{match.group(0)}' -- skills are invoked as /<name>"
                )
            elif _FLAG_BULLET.match(line):
                offenders.append(
                    f"{rel}:{lineno}: {line.strip()[:70]} -- nothing parses this"
                )

    assert not offenders, (
        "a skill documents a command-line surface it does not have (#761). "
        "`$ARGUMENTS` is one free-text string; there is no parser. Describe the "
        "invocation, and if a flag implied a safety guarantee, say plainly that "
        "nothing enforces it:\n" + "\n".join(offenders)
    )


def test_the_removed_flags_are_still_recorded() -> None:
    """The two rewritten skills must keep saying the flags never existed (#761).

    Deleting a documented `--dry-run` silently invites the next author to
    document it again. Both rewrites keep a "Removed, not reworded" note naming
    the deleted flags; this asserts the note survives, which the guard above
    cannot, since it skips blockquotes by design.
    """
    for slug, flags in (
        ("jmo-security-hardening", ("--dry-run", "--skip-tests", "--security-level")),
        ("jmo-refactoring-assistant", ("--dry-run", "--skip-tests")),
    ):
        rel = f"{SKILLS_PREFIX}{slug}/SKILL.md"
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        quoted = "\n".join(
            ln for ln in text.splitlines() if ln.lstrip().startswith(">")
        )
        assert "Removed, not reworded" in quoted, f"{rel} lost its removal note"
        missing = [f for f in flags if f not in quoted]
        assert not missing, f"{rel}'s removal note no longer names {missing}"
