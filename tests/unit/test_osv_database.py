"""osv-scanner's offline databases, the read side (v2.0.0 Phase 4, O1).

osv-scanner reads `<cache>/osv-scalibr/<ecosystem>/all.zip` from the directory
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` names (measured, 2.6.0). The ecosystem
is the bucket name at osv-vulnerabilities.storage.googleapis.com, spelled as
the bucket spells it: a directory named `pypi` is a database osv-scanner never
finds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.core import osv_database
from scripts.core.osv_database import (
    ECOSYSTEMS,
    LOCKFILE_ECOSYSTEMS,
    cache_dir,
    database_path,
    ecosystem_of,
    present_ecosystems,
)

# Every name osv-scanner 2.6.0 accepts through `-L` (measured one by one,
# 2026-09-27), and its bucket. `requirements*.txt` is a pattern: two names
# stand for it.
ACCEPTED = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
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
    # Ruling 31: mapped here, fetched by O2 beside the ten.
    "renv.lock": "CRAN",
    "conan.lock": "ConanCenter",
}

# Each aborts the WHOLE osv-scanner run when handed through `-L` (rc 127, no
# output, every other lockfile's findings lost; measured on 2.6.0).
REJECTED = (
    "go.sum",
    "requirements.in",
    "package.json",
    "Pipfile",
    "pyproject.toml",
    "verification-metadata.xml",
    "deps.json",
)


@pytest.mark.parametrize(("name", "ecosystem"), sorted(ACCEPTED.items()))
def test_every_accepted_lockfile_maps_to_its_bucket(name, ecosystem) -> None:
    assert ecosystem_of(name) == ecosystem
    # By name wherever it sits in the tree.
    assert ecosystem_of(f"services/api/{name}") == ecosystem


@pytest.mark.parametrize("name", REJECTED)
def test_a_name_osv_scanner_rejects_maps_to_nothing(name) -> None:
    assert ecosystem_of(name) is None


def test_the_map_is_exactly_the_accepted_names() -> None:
    """The walk's patterns are derived from this map, so a name added here is
    a name handed to osv-scanner: one it rejects would cost every other
    lockfile's findings."""
    stood_for = {"requirements.txt", "requirements-dev.txt"}
    assert set(LOCKFILE_ECOSYSTEMS) == (set(ACCEPTED) - stood_for) | {
        "requirements*.txt"
    }


def test_the_ecosystems_are_the_twelve_bucket_spellings() -> None:
    assert set(ECOSYSTEMS) == {
        "npm",
        "PyPI",
        "Go",
        "Maven",
        "crates.io",
        "RubyGems",
        "Packagist",
        "NuGet",
        "Pub",
        "Hex",
        "CRAN",
        "ConanCenter",
    }
    assert len(ECOSYSTEMS) == len(set(ECOSYSTEMS))


def test_the_cache_is_jmos_own_and_resolved_when_asked(tmp_path, monkeypatch) -> None:
    """Under the home directory as the other `~/.jmo` paths are, and read at
    call time, so a changed home is followed."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    assert cache_dir() == tmp_path / ".jmo" / "osv-db"
    assert database_path("npm") == (
        tmp_path / ".jmo" / "osv-db" / "osv-scalibr" / "npm" / "all.zip"
    )
    assert database_path("PyPI", tmp_path / "c") == (
        tmp_path / "c" / "osv-scalibr" / "PyPI" / "all.zip"
    )


def test_present_means_the_zip_is_there(tmp_path) -> None:
    for ecosystem in ("npm", "Go"):
        path = database_path(ecosystem, tmp_path)
        path.parent.mkdir(parents=True)
        path.write_bytes(b"PK")
    # A directory without its zip (an interrupted fetch) is not a database,
    # and nor is a directory where the zip should be.
    (tmp_path / "osv-scalibr" / "PyPI").mkdir(parents=True)
    database_path("Maven", tmp_path).mkdir(parents=True)

    assert present_ecosystems(cache=tmp_path) == {"npm", "Go"}
    assert present_ecosystems(["Go", "PyPI"], cache=tmp_path) == {"Go"}


def test_the_default_cache_is_the_one_consulted(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(osv_database, "cache_dir", lambda: tmp_path)
    path = database_path("crates.io")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"PK")

    assert present_ecosystems() == {"crates.io"}


def test_an_unreadable_cache_counts_as_absent(tmp_path, monkeypatch) -> None:
    """Python 3.12 raises from `is_file()` where 3.11 returned False (#1163)."""

    def denied(self) -> bool:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "is_file", denied)

    assert present_ecosystems(cache=tmp_path) == frozenset()
