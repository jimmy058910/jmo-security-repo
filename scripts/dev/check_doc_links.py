#!/usr/bin/env python3
"""
Validate that markdown links in key documentation files resolve to real files.

Checks: CLAUDE.md, docs/index.md (if present)
Skips: http/https URLs, anchor-only links (#section)
Exit code 0 = all links valid, 1 = broken links found.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Files to check for broken links
FILES_TO_CHECK = [
    REPO_ROOT / "CLAUDE.md",
    REPO_ROOT / "docs" / "index.md",
]

# Pattern to extract markdown links: [text](path)
LINK_PATTERN = re.compile(r"\[.*?\]\(([^)]+)\)")


def check_links_in_file(file_path: Path) -> list[str]:
    """Return list of broken link messages for a file."""
    if not file_path.exists():
        return []

    broken: list[str] = []
    text = file_path.read_text(encoding="utf-8")

    for match in LINK_PATTERN.finditer(text):
        link = match.group(1)

        # Skip URLs
        if link.startswith(("http://", "https://")):
            continue

        # Skip anchor-only links
        if link.startswith("#"):
            continue

        # Strip anchor from file links (e.g., file.md#section -> file.md)
        path_part = link.split("#")[0]
        if not path_part:
            continue

        # Resolve relative to the file's directory
        resolved = file_path.parent / path_part
        if not resolved.exists():
            rel = file_path.relative_to(REPO_ROOT)
            broken.append(f"  BROKEN: {rel} -> {link}")

    return broken


def main() -> int:
    print("Checking documentation links...")
    broken: list[str] = []

    for f in FILES_TO_CHECK:
        broken.extend(check_links_in_file(f))

    if broken:
        for b in broken:
            print(b)
        print(f"\n{len(broken)} broken link(s) found. Fix the paths above.")
        return 1

    print("All documentation links are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
