"""Single source for the JMo Security version string used in artifacts.

Three of the four `jmo diff` artifacts used to hardcode `1.0.0` -- the JSON
written to stdout, the Markdown footer, and the SARIF `driver.version` that a
GitHub Security upload records as the producing tool. The fourth read
`pyproject.toml`, which is correct in a source checkout and absent from an
installed wheel, so a pip user got `1.0.0` from that path too.

Resolution order:

1. Installed distribution metadata. Correct for anyone who installed the
   package, and the only source that survives packaging.
2. `pyproject.toml` at the repository root. Covers a source checkout that has
   not been installed.
3. `"unknown"`. Better than a number that is wrong -- a stale version in an
   uploaded SARIF misattributes findings to a release that did not produce
   them.
"""

from __future__ import annotations

import tomllib
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

DISTRIBUTION_NAME = "jmo-security"
UNKNOWN_VERSION = "unknown"


@lru_cache(maxsize=1)
def get_jmo_version() -> str:
    """Return the JMo Security version, or "unknown" if it cannot be resolved."""
    try:
        return version(DISTRIBUTION_NAME)
    except PackageNotFoundError:
        pass

    # scripts/core/jmo_version.py -> scripts/core -> scripts -> repo root
    pyproject = Path(__file__).resolve().parent.parent.parent / "pyproject.toml"
    try:
        with open(pyproject, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return UNKNOWN_VERSION

    resolved = data.get("project", {}).get("version")
    return resolved if isinstance(resolved, str) and resolved else UNKNOWN_VERSION
