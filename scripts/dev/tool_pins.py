#!/usr/bin/env python3
"""Print every tool pin in versions.yaml as `NAME_VERSION=x.y.z`, one per line.

The workflows read their tool versions through this at run time rather than
carrying copies of them:

    - name: Read tool pins from versions.yaml
      id: pins
      run: python3 scripts/dev/tool_pins.py >> "$GITHUB_OUTPUT"

    - name: Install trivy
      env:
        TRIVY_VERSION: ${{ steps.pins.outputs.TRIVY_VERSION }}

A copy in a workflow is one the weekly tool-update PR cannot move: that job's
token may not push `.github/workflows/`, so every bump of a workflow-pinned tool
left its PR out of sync until someone pushed the edit by hand (#1470).
`update_versions.py --sync` fails if a copy comes back.

Needs only PyYAML, so a job without the project venv can run it.

Exit code 0 = pins printed, 1 = versions.yaml unreadable or an entry unusable.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
VERSIONS_YAML = REPO_ROOT / "versions.yaml"
PINNED_SECTIONS = ("python_tools", "binary_tools", "special_tools")

# versions.yaml key -> the variable stem used for its pin, where `key.upper()`
# does not produce one. Deriving the name silently misses abbreviations and
# hyphens: `noseyparker` was pinned as NP_VERSION and `dependency-check` as
# DC_VERSION, so both were unreachable by --sync and stayed correct only by
# luck (#797). Both left in v2.0.0. `osv-scanner` uppercases to OSV-SCANNER,
# which is no shell variable.
VERSION_VAR_ALIASES: dict[str, str] = {"osv-scanner": "OSV_SCANNER"}

# A pin is written into $GITHUB_OUTPUT and from there into a download URL, so it
# must be a plain dotted number. Anything else, a newline above all, could add a
# line of its own to that file.
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_STEM = re.compile(r"[A-Z][A-Z0-9_]*")


def read_pins(path: Path) -> dict[str, str]:
    """Return `{NAME_VERSION: version}` for every pinned registry entry.

    Raises ValueError for an entry a workflow could not use safely. Nothing is
    returned, and so nothing printed, unless every entry is usable.
    """
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    for section in PINNED_SECTIONS:
        for tool, info in (data.get(section) or {}).items():
            stem = VERSION_VAR_ALIASES.get(tool) or str(tool).upper()
            if not _STEM.fullmatch(stem):
                raise ValueError(
                    f"{tool}: {stem!r} is not a variable name; "
                    "add a VERSION_VAR_ALIASES entry"
                )
            version = info["version"]
            # YAML reads an unquoted 2.15 as the float 2.15, and 2.10 as 2.1,
            # so a two-part version has to be quoted to arrive intact.
            if not isinstance(version, str) or not _VERSION.fullmatch(version):
                raise ValueError(
                    f"{tool}: version {version!r} is not a dotted version string"
                )
            pins[f"{stem}_VERSION"] = version
    return pins


def main() -> int:
    try:
        pins = read_pins(VERSIONS_YAML)
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"tool_pins: {exc!r}", file=sys.stderr)
        return 1
    for name, version in pins.items():
        print(f"{name}={version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
