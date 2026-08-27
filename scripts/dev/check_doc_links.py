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
import unicodedata
from collections.abc import Iterator
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


# A link inside a heading renders as its text alone, so the URL must come off
# before the filter runs - stripping punctuation from it would otherwise glue
# the URL to the text (`the-guidedocsuser_guidemd`).
HEADING_LINK_PATTERN = re.compile(r"\[([^\]]*)\]\([^)]*\)")

# Join controls (U+200C/U+200D) glue emoji sequences together. GitHub keeps
# them; they are `\p{Join_Control}`, which Python exposes nowhere.
JOIN_CONTROLS = frozenset("‌‍")


def _is_slug_char(char: str) -> bool:
    """True for the characters GitHub's slug filter keeps.

    GitHub drops everything outside `[\\p{Word}\\- ]`, and Ruby's `\\p{Word}` is
    `Alnum + Mark + Connector_Punctuation + Join_Control`. Python's `\\w` covers
    the first and third but **not** marks - so a `[^\\w\\- ]` port silently
    disagrees on `⚠️`, dropping the U+FE0F variation selector GitHub retains.
    Measured against `gh api markdown` across all 177 tracked files: this
    predicate agrees on 3873/3873 anchors, the regex on 3868.
    """
    if char in "- _":
        return True
    if char.isalnum():
        return True
    return unicodedata.category(char).startswith("M") or char in JOIN_CONTROLS


# An ATX heading. The space after the hashes is required, which is what keeps
# `#!/usr/bin/env python` and a `#719` issue reference from becoming anchors.
# The corpus has no setext (`Title\n=====`) headings; every `---` under a line
# of prose is a YAML frontmatter terminator.
HEADING_PATTERN = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.*?)\s*#*\s*$")


def heading_anchor(text: str) -> str:
    """The `#fragment` GitHub generates for a heading with this text.

    Backticks and `**` need no special case: they are punctuation, and the
    filter drops them like any other. Note that a dropped character leaves its
    surrounding spaces behind, so an emoji between two words produces a double
    hyphen - that is GitHub's behaviour, not an artefact.
    """
    rendered = HEADING_LINK_PATTERN.sub(r"\1", text).lower()
    kept = "".join(char for char in rendered if _is_slug_char(char))
    return kept.replace(" ", "-")


def unfenced_lines(text: str) -> Iterator[str]:
    """Yield the lines that are not inside a fenced code block.

    Follows the CommonMark closing rule rather than toggling on every fence:
    a closer repeats the opener's character, is at least as long, and carries
    no info string. Toggling desynchronises on same-length nested fences - a
    ```markdown block quoting a ```bash block - which is exactly the shape
    these agent files use to show example output.

    Both callers need this and neither needs the other's transformation, so it
    lives here once. Duplicating the closing rule is how the two would drift.
    """
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
        if opener is None:
            yield raw


def navigable_lines(text: str) -> list[str]:
    """Lines with code fences dropped and inline code spans blanked out."""
    return [INLINE_CODE_PATTERN.sub("``", raw) for raw in unfenced_lines(text)]


def collect_anchors(text: str) -> set[str]:
    """Every `#fragment` a reader can actually link to in this document.

    Headings are the only source: the corpus carries no `<a id=>` and no inline
    HTML in any heading. Code spans are deliberately *not* blanked first - the
    anchor derives from the heading's rendered text, and blanking
    ``## `jmo tools check` MANUAL`` would drop three of its four words.
    """
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for raw in unfenced_lines(text):
        heading = HEADING_PATTERN.match(raw)
        if not heading:
            continue
        base = heading_anchor(heading.group("title").strip())
        count = seen.get(base, 0)
        seen[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def tracked_paths() -> set[str]:
    """Every path git tracks, as forward-slash repo-relative strings."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
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


def check_text(
    rel_path: str,
    text: str,
    tracked: set[str],
    anchors: dict[str, set[str]],
) -> list[str]:
    """Return dead-reference messages for one document's Markdown source."""
    source = REPO_ROOT / rel_path
    problems: list[str] = []
    navigable = "\n".join(navigable_lines(text))

    for match in LINK_PATTERN.finditer(navigable):
        link = match.group(1).strip()

        if link.startswith(("http://", "https://", "mailto:")):
            continue

        # A line citation points at source on the web, not at a heading.
        if LINE_ANCHOR_PATTERN.search(link):
            continue

        path_part, _, fragment = link.partition("#")

        # A bare `#anchor` - the shape every table of contents uses - names a
        # heading in the file it is written in.
        if not path_part:
            if fragment and fragment not in anchors.get(rel_path, set()):
                problems.append(f"  NO ANCHOR {rel_path} -> {link}")
            continue

        # Repo-relative form of a link written relative to its own file.
        try:
            resolved = (source.parent / path_part).resolve()
            target = resolved.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # Escapes the repo entirely - not ours to validate.
            continue

        if not is_tracked(target, tracked):
            kind = "UNTRACKED" if resolved.exists() else "BROKEN   "
            problems.append(f"  {kind} {rel_path} -> {link}")
            # The path is the fix; its anchor is downstream noise.
            continue

        # Only Markdown grows headings, so only Markdown has anchors to verify.
        if fragment and target in anchors and fragment not in anchors[target]:
            problems.append(f"  NO ANCHOR {rel_path} -> {link}")

    return problems


def check_file(
    rel_path: str, tracked: set[str], anchors: dict[str, set[str]]
) -> list[str]:
    """Return dead-reference messages for one documentation file."""
    text = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
    return check_text(rel_path, text, tracked, anchors)


def main() -> int:
    # This tool prints file paths and link text - arbitrary repository content -
    # so a single character the console cannot encode would otherwise crash the
    # guard itself on a non-UTF-8 Windows console. Harden the stream once rather
    # than guarding each call site.
    harden_console_streams()

    safe_print("Checking documentation links resolve to tracked files...")
    tracked = tracked_paths()

    # Anchors come from every tracked Markdown file, archival included: those
    # are exempt as link *sources*, not as link *targets*. A link into a plan's
    # heading is as checkable as any other.
    anchors = {
        path: collect_anchors((REPO_ROOT / path).read_text(encoding="utf-8"))
        for path in tracked
        if path.endswith(".md")
    }

    files = collect_files(tracked)
    problems: list[str] = []
    for rel_path in files:
        problems.extend(check_file(rel_path, tracked, anchors))

    if problems:
        for line in sorted(problems):
            safe_print(line)
        safe_print(f"\n{len(problems)} dead reference(s) across {len(files)} file(s).")
        safe_print("BROKEN    -> fix the path, or remove the link.")
        safe_print("UNTRACKED -> the file exists locally but ships to nobody. Either")
        safe_print("             track it (see the .claude/ allowlist in .gitignore)")
        safe_print("             or stop referencing it from a tracked file.")
        safe_print("NO ANCHOR -> the file resolves but names no such heading. This one")
        safe_print(
            "             fails silently in a browser - it scrolls to the top of"
        )
        safe_print(
            "             the page, which looks exactly like a link that worked."
        )
        return 1

    safe_print(f"All links in {len(files)} tracked file(s) resolve to tracked paths.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
