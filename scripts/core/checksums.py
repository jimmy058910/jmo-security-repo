"""Read a release's sha256 checksum file and hash a download (#1374).

Every checksum file the pinned tools publish is `sha256sum` output: a digest,
whitespace, then the asset's name, which hadolint marks binary with a leading
`*`. goreleaser lists every asset in one file, opa writes one file per asset.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_LINE = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$")


def parse_sha256sums(text: str) -> dict[str, str]:
    """Asset name -> lower-case sha256 hex, for every line that is one."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        match = _LINE.match(line.strip())
        if match:
            sums[match.group(2).removeprefix("./")] = match.group(1).lower()
    return sums


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
