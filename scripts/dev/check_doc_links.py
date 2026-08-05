#!/usr/bin/env python3
"""
Validate that markdown links in tracked documentation resolve to tracked files.

Two distinct failures are reported, because they need different fixes:

  BROKEN    the path does not exist at all - a typo, or a file that was deleted
            without updating its references.
  UNTRACKED the path exists on this machine but git does not track it, so a
            fresh clone does not get it. The reference is a dead end for every
            contributor while looking perfectly fine to the maintainer.

UNTRACKED is the interesting one. `Path.exists()` cannot see it: the file is
right there locally. Only `git ls-files` describes what a clone actually
receives, so tracked-ness - not existence - is the test.

Archival documents (design specs, executed plans, the changelog) are exempt.
They are records of what was true when written, and they legitimately name
paths that have since been deleted; rewriting history to satisfy a linter
would destroy the record.

Exit code 0 = all links resolve, 1 = at least one dead reference.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Run directly (`python scripts/dev/check_doc_links.py`) and sys.path[0] is
# scripts/dev, not the repo root - so scripts.core is not importable without
# this. Same bootstrap as scripts/dev/reconcile_scan_accounting.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(REPO_ROOT))

from scripts.core.unicode_utils import (  # noqa: E402
    harden_console_streams,
    safe_print,
)

# Historical records, exempt by design - see the module docstring.
ARCHIVAL_PREFIXES = (
    "docs/superpowers/",
    "CHANGELOG.md",
)

# Markdown inline links: [text](path)
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# A fenced code block, and an inline code span. Both hold samples rather than
# navigation - the agent and skill files quote broken links on purpose, to
# teach what a broken link looks like.
FENCE_PATTERN = re.compile(r"^\s{0,3}(?P<marker>`{3,}|~{3,})\s*(?P<info>\S.*)?$")
# A code span is delimited by backtick strings of EQUAL length, so ``x`` is one
# span and not two empty ones. Matching only single backticks left the contents
# of a double-backtick span visible to LINK_PATTERN, which reported a quoted
# sample as a real BROKEN reference.
INLINE_CODE_PATTERN = re.compile(r"(?P<ticks>`+)(?:(?!(?P=ticks)).)*(?P=ticks)")

# A GitHub line anchor (`file.py#L42`, `file.py#L42-L51`). These are citations
# pointing at a line of source on the web, not links into the repo tree.
LINE_ANCHOR_PATTERN = re.compile(r"#L\d")


def navigable_lines(text: str) -> list[str]:
    """Lines with code fences dropped and inline code spans blanked out.

    Follows the CommonMark closing rule rather than toggling on every fence:
    a closer repeats the opener's character, is at least as long, and carries
    no info string. Toggling desynchronises on same-length nested fences - a
    ```markdown block quoting a ```bash block - which is exactly the shape
    these agent files use to show example output.
    """
    lines: list[str] = []
    opener: str | None = None
    for raw in text.splitlines():
        fence = FENCE_PATTERN.match(raw)
        if fence:
            marker, info = fence.group("marker"), fence.group("info")
            if opener is None:
                opener = marker
                continue
            closes = marker[0] == opener[0] and len(marker) >= len(opener) and not info
            if closes:
                opener = None
                continue
        lines.append("" if opener else INLINE_CODE_PATTERN.sub("``", raw))
    return lines


def tracked_paths() -> set[str]:
    """Every path git tracks, as forward-slash repo-relative strings."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def collect_files(tracked: set[str]) -> list[str]:
    """Every tracked Markdown file except the archival ones.

    Derived from `git ls-files` rather than an allowlist. An allowlist silently
    stops covering whatever it was not updated for: the previous one named nine
    files and left 75 tracked Markdown files unchecked, which between them held
    17 dead references that CI reported as green.
    """
    return sorted(
        p for p in tracked if p.endswith(".md") and not p.startswith(ARCHIVAL_PREFIXES)
    )


def is_tracked(target: str, tracked: set[str]) -> bool:
    """True if git tracks this path, either as a file or as a directory prefix."""
    if target in tracked:
        return True
    prefix = target.rstrip("/") + "/"
    return any(p.startswith(prefix) for p in tracked)


def check_file(rel_path: str, tracked: set[str]) -> list[str]:
    """Return dead-reference messages for one documentation file."""
    source = REPO_ROOT / rel_path
    problems: list[str] = []
    text = "\n".join(navigable_lines(source.read_text(encoding="utf-8")))

    for match in LINK_PATTERN.finditer(text):
        link = match.group(1).strip()

        if link.startswith(("http://", "https://", "mailto:", "#")):
            continue

        # A line citation points at source on the web, not into the tree.
        if LINE_ANCHOR_PATTERN.search(link):
            continue

        # Strip any anchor; a bare anchor was handled above.
        path_part = link.split("#", 1)[0]
        if not path_part:
            continue

        # Repo-relative form of a link written relative to its own file.
        try:
            resolved = (source.parent / path_part).resolve()
            target = resolved.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # Escapes the repo entirely - not ours to validate.
            continue

        if is_tracked(target, tracked):
            continue

        kind = "UNTRACKED" if resolved.exists() else "BROKEN   "
        problems.append(f"  {kind} {rel_path} -> {link}")

    return problems


def main() -> int:
    # This tool prints file paths and link text - arbitrary repository content -
    # so a single character the console cannot encode would otherwise crash the
    # guard itself on a non-UTF-8 Windows console. Harden the stream once rather
    # than guarding each call site.
    harden_console_streams()

    safe_print("Checking documentation links resolve to tracked files...")
    tracked = tracked_paths()

    files = collect_files(tracked)
    problems: list[str] = []
    for rel_path in files:
        problems.extend(check_file(rel_path, tracked))

    if problems:
        for line in sorted(problems):
            safe_print(line)
        safe_print(f"\n{len(problems)} dead reference(s) across {len(files)} file(s).")
        safe_print("BROKEN    -> fix the path, or remove the link.")
        safe_print("UNTRACKED -> the file exists locally but ships to nobody. Either")
        safe_print("             track it (see the .claude/ allowlist in .gitignore)")
        safe_print("             or stop referencing it from a tracked file.")
        return 1

    safe_print(f"All links in {len(files)} tracked file(s) resolve to tracked paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
