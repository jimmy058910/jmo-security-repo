"""osv-scanner's offline vulnerability databases: where JMo keeps them and which exist.

A scan never downloads (Phase 4 decision): osv-scanner runs with
`--offline-vulnerabilities` and `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` pointed
at `cache_dir()`, where it reads `osv-scalibr/<ecosystem>/all.zip` (measured,
2.6.0: "Loaded npm local db from ...\\osv-db/osv-scalibr/npm/all.zip"). O1 built
the read side: which lockfile belongs to which ecosystem, and which ecosystems
have a database. This module also fills the cache (Task O2, Ruling 30):
`fetch_ecosystem`/`fetch_all` download OSV's own hosted zips, one ecosystem at
a time, atomically. `ToolInstaller._post_install` calls them when osv-scanner
is installed, and `cmd_tools_update` calls them on every `jmo tools update`
(decision 6) -- never a scan, and never the image build.

`core`, and imports nothing from JMo: `tool_descriptors` imports it, and
`paths` sits on an import chain that leads back to `tool_descriptors`. That is
also why `FETCH_TIMEOUT_SECONDS` below is its own constant rather than
`install_config.DOWNLOAD_TIMEOUT_SECONDS`: `install_config` imports
`tool_registry`, which imports `tool_descriptors`, which imports this module --
importing `install_config` from here would close that cycle.
"""

from __future__ import annotations

import os
import tempfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path, PurePath

import requests

# Every lockfile name osv-scanner 2.6.0 accepts through `-L` (measured one by
# one, 2026-09-27), and the OSV ecosystem it is matched in: the bucket name at
# https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip, which
# is also the cache's directory name. Case matters (`PyPI`, `crates.io`).
#
# Names it rejects abort the WHOLE run (rc 127, no output), so they are not
# here: go.sum, requirements.in, package.json, Pipfile, pyproject.toml,
# verification-metadata.xml, deps.json. It decides by the exact name, so a
# `Requirements.txt` or `Package-Lock.json` is rejected too (measured, 2.6.0:
# "could not determine extractor"), and `ecosystem_of` matches case-sensitively.
#
# `conan.lock` is accepted by osv-scanner but not here: OSV publishes no
# ConanCenter database (404, and absent from its ecosystems list), so its row
# could only ever fail (Ruling 42; docs/KNOWN_LIMITATIONS.md).
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
    """The ecosystem a lockfile is matched in, by its exact file name.

    Case-sensitive on every platform, as osv-scanner decides: on Windows the
    walk's glob ignores case, and a `Requirements.txt` it found beside a
    `package-lock.json` lost both files' findings (rc 127, no output).
    """
    name = PurePath(lockfile).name
    for pattern, ecosystem in LOCKFILE_ECOSYSTEMS.items():
        if fnmatchcase(name, pattern):
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


# The bucket osv-scanner's own database format is hosted at (measured, O1's
# report); `{ecosystem}` is one of the values in LOCKFILE_ECOSYSTEMS above --
# same name, same case (`PyPI`, `crates.io`).
OSV_DATABASE_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# A stall timeout for `requests`, not a whole-download cap: with `stream=True`
# it resets on every chunk received, so npm's ~206 MB zip does not need a
# larger value just because it is the biggest of the eleven.
FETCH_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class FetchResult:
    """One ecosystem's fetch attempt."""

    ecosystem: str
    success: bool
    message: str


def _get(url: str, *, timeout: float, **kwargs):
    """`fetch_ecosystem`'s one call to `requests.get`, through a name that
    exists only in this module.

    A test guard (`tests/conftest.py`'s
    `_guard_no_unmarked_osv_database_download`, fix round 1, review Ruling
    43 named risk (b)) needs to intercept exactly this call, without
    touching `requests.get` itself -- that symbol is one shared module
    attribute, and patching it globally would also intercept every OTHER
    module's real, unrelated network calls (measured: it broke
    `kev_integration.py`'s real CISA KEV feed fetch in an unrelated test).
    Patching `osv_database._get` instead reaches only this module.

    `timeout` is its own required keyword, not folded into `**kwargs`: bandit's
    B113 ("call to requests without timeout") pattern-matches the literal
    argument at the `requests.get` call site, and cannot see one hidden a
    level up inside a caller's `**kwargs`.
    """
    return requests.get(url, timeout=timeout, **kwargs)


def fetch_ecosystem(
    ecosystem: str,
    cache: Path | None = None,
    *,
    base_url: str = OSV_DATABASE_BASE_URL,
    timeout: float = FETCH_TIMEOUT_SECONDS,
) -> FetchResult:
    """Download one ecosystem's `all.zip` into the cache.

    `curl -f` semantics via `requests`' `raise_for_status()`: an HTTP error is
    a failure, and the response body (an HTML error page, for instance) is
    never kept as the zip. The download lands in a temp file in the SAME
    directory as the destination -- so the final `os.replace` is one
    filesystem, not a cross-volume copy -- and is validated with
    `zipfile.testzip()`, and that the zip has at least one member (fix round
    1, review Minor #3: `testzip()` alone accepts a zero-member zip, and a
    structurally valid but empty `all.zip` would silently replace a good
    database with a useless one), before it replaces the old file.

    Every filesystem step is guarded, not only the download (fix round 1,
    review Important #2): creating the cache directory, the temp file
    itself, and the final replace can each raise `OSError` (disk full, a
    permission error, `dest` existing as a directory -- `os.replace` raises
    `IsADirectoryError` in that case), and each becomes a failed
    `FetchResult` here rather than an uncaught exception. That is what lets
    `fetch_all` isolate one ecosystem's filesystem error from every
    ecosystem after it, the same guarantee Ruling 31 already gives HTTP and
    zip-content failures.

    Any failure along the way leaves yesterday's database exactly as it was
    and deletes the partial temp file; nothing is ever written in place at
    `dest`.
    """
    dest = database_path(ecosystem, cache)
    url = f"{base_url}/{ecosystem}/all.zip"
    tmp_path: Path | None = None

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            dir=dest.parent, prefix=f".{dest.name}.", suffix=".part"
        )
        tmp_path = Path(tmp_name)

        with os.fdopen(fd, "wb") as tmp_file:
            try:
                with _get(url, stream=True, timeout=timeout) as response:
                    response.raise_for_status()
                    for chunk in response.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            tmp_file.write(chunk)
            except (requests.exceptions.RequestException, OSError) as exc:
                return FetchResult(ecosystem, False, f"download failed: {exc}")

        try:
            with zipfile.ZipFile(tmp_path) as zf:
                bad_member = zf.testzip()
                has_members = bool(zf.infolist())
        except zipfile.BadZipFile as exc:
            return FetchResult(ecosystem, False, f"corrupt zip: {exc}")
        if bad_member is not None:
            return FetchResult(
                ecosystem, False, f"corrupt zip: bad member {bad_member!r}"
            )
        if not has_members:
            return FetchResult(
                ecosystem, False, "corrupt zip: no members (an empty archive)"
            )

        os.replace(tmp_path, dest)
        return FetchResult(ecosystem, True, f"fetched into {dest}")
    except OSError as exc:
        # Everything that touches the filesystem outside the download loop
        # above (which already has its own, more specific "download failed"
        # message): `mkdir`, `mkstemp`, and `os.replace`. Always a
        # `FetchResult`, never an exception out of this function.
        return FetchResult(ecosystem, False, f"filesystem error: {exc}")
    finally:
        # `os.replace` above already moved a successful download out from
        # under this path; on any failure it still exists here and must not
        # be left behind as a stray `.part` file (the "no partial file left
        # on an interrupted download" requirement). Best-effort: a cleanup
        # failure must not discard this ecosystem's already-computed
        # FetchResult, or masquerade as this ecosystem's actual outcome.
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def fetch_all(
    ecosystems: Iterable[str] = ECOSYSTEMS,
    cache: Path | None = None,
    *,
    base_url: str = OSV_DATABASE_BASE_URL,
    timeout: float = FETCH_TIMEOUT_SECONDS,
) -> list[FetchResult]:
    """Fetch every ecosystem's database, one at a time.

    Each ecosystem is independent (Ruling 31): one HTTP error, a corrupt zip,
    or a filesystem error (disk full, a permission error, `dest` existing as
    a directory) does not stop the rest -- `fetch_ecosystem` never raises for
    any of those, always returning a `FetchResult` -- and the returned list
    says which ecosystem(s) failed and why. `ecosystems` defaults to
    `ECOSYSTEMS`, the same list `present_ecosystems` reads -- there is no
    second, hand-written list.
    """
    return [
        fetch_ecosystem(eco, cache=cache, base_url=base_url, timeout=timeout)
        for eco in ecosystems
    ]
