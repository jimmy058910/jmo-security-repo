"""osv-scanner's offline vulnerability databases: where JMo keeps them and which exist.

A scan never downloads (Phase 4 decision): osv-scanner runs with
`--offline-vulnerabilities` and `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` pointed
at `cache_dir()`, where it reads `osv-scalibr/<ecosystem>/all.zip` (measured,
2.6.0: "Loaded npm local db from ...\\osv-db/osv-scalibr/npm/all.zip"). This
module is the read side: which lockfile belongs to which ecosystem, and which
ecosystems have a database. `jmo tools update` fills the cache (Task O2).

`core`, and imports nothing from JMo: `tool_descriptors` imports it, and
`paths` sits on an import chain that leads back to `tool_descriptors`.
"""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatch
from pathlib import Path, PurePath

# Every lockfile name osv-scanner 2.6.0 accepts through `-L` (measured one by
# one, 2026-09-27), and the OSV ecosystem it is matched in: the bucket name at
# https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip, which
# is also the cache's directory name. Case matters (`PyPI`, `crates.io`).
#
# Names it rejects abort the WHOLE run (rc 127, no output), so they are not
# here: go.sum, requirements.in, package.json, Pipfile, pyproject.toml,
# verification-metadata.xml, deps.json. A glob matches like `Path.glob`.
LOCKFILE_ECOSYSTEMS: dict[str, str] = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "requirements*.txt": "PyPI",
    "poetry.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "pdm.lock": "PyPI",
    "uv.lock": "PyPI",
    "pylock.toml": "PyPI",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
    "Gemfile.lock": "RubyGems",
    "gradle.lockfile": "Maven",
    "pom.xml": "Maven",
    "packages.lock.json": "NuGet",
    "packages.config": "NuGet",
    "pubspec.lock": "Pub",
    "mix.lock": "Hex",
    "renv.lock": "CRAN",
    "conan.lock": "ConanCenter",
}

# Each ecosystem once, in the map's order: what the cache can hold.
ECOSYSTEMS: tuple[str, ...] = tuple(dict.fromkeys(LOCKFILE_ECOSYSTEMS.values()))


def cache_dir() -> Path:
    """JMo's own cache (`~/.jmo/osv-db`), resolved when called, as every
    other `~/.jmo` path is (`scripts/core/paths.py`)."""
    return Path.home() / ".jmo" / "osv-db"


def database_path(ecosystem: str, cache: Path | None = None) -> Path:
    """Where osv-scanner reads one ecosystem's database."""
    return (cache or cache_dir()) / "osv-scalibr" / ecosystem / "all.zip"


def ecosystem_of(lockfile: str | PurePath) -> str | None:
    """The ecosystem a lockfile is matched in, by its file name."""
    name = PurePath(lockfile).name
    for pattern, ecosystem in LOCKFILE_ECOSYSTEMS.items():
        if fnmatch(name, pattern):
            return ecosystem
    return None


def present_ecosystems(
    ecosystems: Iterable[str] = ECOSYSTEMS, cache: Path | None = None
) -> frozenset[str]:
    """The ecosystems whose database is in the cache.

    An unreadable path counts as absent: Python 3.12 raises from `is_file()`
    where 3.11 returned False (#1163).
    """
    present = set()
    for ecosystem in ecosystems:
        try:
            if database_path(ecosystem, cache).is_file():
                present.add(ecosystem)
        except OSError:
            continue
    return frozenset(present)
