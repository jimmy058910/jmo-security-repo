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

# Documentation surfaces whose links must resolve in a fresh clone. Anything
# tracked under .claude/ is included automatically (see collect_files) since
# that directory is the public/private boundary this guard exists to hold.
EXPLICIT_FILES = (
    "CLAUDE.md",
    "AGENTS.md",
    "README.md",
    "CONTRIBUTING.md",
    "QUICKSTART.md",
    "ROADMAP.md",
    "TEST.md",
    "docs/index.md",
    "docs/KNOWN_LIMITATIONS.md",
)

# Historical records. Exempt by design - see the module docstring.
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
INLINE_CODE_PATTERN = re.compile(r"`[^`]*`")

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
    """Documentation surfaces to check: the explicit list plus all of .claude/."""
    files = [f for f in EXPLICIT_FILES if f in tracked]
    files.extend(
        sorted(p for p in tracked if p.startswith(".claude/") and p.endswith(".md"))
    )
    return files


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
    print("Checking documentation links resolve to tracked files...")
    tracked = tracked_paths()

    files = [f for f in collect_files(tracked) if not f.startswith(ARCHIVAL_PREFIXES)]
    problems: list[str] = []
    for rel_path in files:
        problems.extend(check_file(rel_path, tracked))

    if problems:
        for line in sorted(problems):
            print(line)
        print(f"\n{len(problems)} dead reference(s) across {len(files)} file(s).")
        print("BROKEN    -> fix the path, or remove the link.")
        print("UNTRACKED -> the file exists locally but ships to nobody. Either")
        print("             track it (see the .claude/ allowlist in .gitignore)")
        print("             or stop referencing it from a tracked file.")
        return 1

    print(f"All links in {len(files)} tracked file(s) resolve to tracked paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
