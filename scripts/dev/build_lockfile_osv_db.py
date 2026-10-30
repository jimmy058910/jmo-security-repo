#!/usr/bin/env python3
"""Build the frozen osv-scanner database the lockfile-format oracle reads.

    python scripts/dev/build_lockfile_osv_db.py [--out DIR]

`tests/integration/test_lockfile_formats.py` proves that every lockfile format
JMo claims (`osv_database.LOCKFILE_ECOSYSTEMS`) reaches osv-scanner. Its inputs
are the lockfiles of QuackatronHQ/sca-kitchen-sink, fetched and never committed
(`fetch_answer_keys.py`); this is the answer key: one synthetic advisory per
lockfile, each affecting exactly one package at exactly the version that
lockfile pins, in the ecosystem's own version scheme. The advisories are
synthetic, so none matches a real package by accident, and the zips hold no
lockfile, so nothing here raises a Dependabot alert.

It writes `<out>/osv-scalibr/<ecosystem>/all.zip`, the layout osv-scanner reads
from `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`, into `tests/fixtures/osv-db-lockfiles`
(`tests/fixtures/osv-db`, whose three advisories other tests count exactly, is
not touched). A zip's bytes are a function of this file alone: entries sorted,
a fixed timestamp and mode, stored without compression (a deflate stream is a
function of the zlib that wrote it), written with `write_bytes`. Running it
twice, anywhere, gives identical files, and
`tests/unit/test_build_lockfile_osv_db.py` rebuilds them and compares.

Advisories that two lockfiles legitimately share. Two lockfiles of one
ecosystem that pin the same package at the same version are one hit for
osv-scanner whichever of them the advisory was written for, so the oracle is
not one pair per lockfile but `EXPECTED_PAIRS`: each lockfile's own advisory,
plus every pair a sibling yields because it pins the same package@version.
Each membership below was read off the lockfile text, not off osv-scanner's
output.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = ROOT / "tests" / "fixtures" / "osv-db-lockfiles"

PUBLISHED = "2026-10-30T00:00:00Z"
ZIP_TIME = (2026, 10, 30, 0, 0, 0)
DETAILS = "Synthetic advisory for JMo's tests; not a real vulnerability."
SUMMARY = "Synthetic advisory for JMo's tests; not a real vulnerability"


class Advisory(NamedTuple):
    """One synthetic advisory: `package` at exactly `version`, in `ecosystem`'s
    own naming and version scheme (OSV writes a Go version without its `v`),
    picked from `lockfile`, a path inside sca-kitchen-sink."""

    id: str
    ecosystem: str
    package: str
    version: str
    lockfile: str


# In the order of the plan: npm, PyPI, Go, crates.io, Packagist, RubyGems, Maven,
# NuGet. Each package@version is read in its lockfile's text (a note says where
# a sibling pins it too).
ADVISORIES: tuple[Advisory, ...] = (
    # bun.lock pins form-data 4.0.3; the other three npm lockfiles pin 4.0.2.
    Advisory(
        "JMO-TEST-2026-0101", "npm", "form-data", "4.0.3", "javascript/bun/bun.lock"
    ),
    # These three npm lockfiles hold the same 44 packages at the same versions;
    # bun.lock differs on exactly form-data, undici-types, @types/cors and
    # @types/node, which is why each advisory below is one of those four.
    Advisory(
        "JMO-TEST-2026-0102",
        "npm",
        "form-data",
        "4.0.2",
        "javascript/npm/package-lock.json",
    ),
    Advisory(
        "JMO-TEST-2026-0103",
        "npm",
        "undici-types",
        "6.20.0",
        "javascript/pnpm/pnpm-lock.yaml",
    ),
    Advisory(
        "JMO-TEST-2026-0104",
        "npm",
        "@types/cors",
        "2.8.17",
        "javascript/yarn/yarn.lock",
    ),
    # poetry.lock and uv.lock pin certifi and click at versions of their own.
    Advisory(
        "JMO-TEST-2026-0105",
        "PyPI",
        "certifi",
        "2025.1.31",
        "python/poetry/poetry.lock",
    ),
    Advisory(
        "JMO-TEST-2026-0106",
        "PyPI",
        "django",
        "4.2.16",
        "python/requirements/requirements.txt",
    ),
    Advisory("JMO-TEST-2026-0107", "PyPI", "click", "8.2.1", "python/uv/uv.lock"),
    # go.mod says v1.3.0; OSV's Go versions carry no `v`.
    Advisory(
        "JMO-TEST-2026-0108",
        "Go",
        "github.com/google/uuid",
        "1.3.0",
        "golang/gomod/go.mod",
    ),
    Advisory(
        "JMO-TEST-2026-0109", "crates.io", "url", "1.7.2", "rust/cargo/Cargo.lock"
    ),
    Advisory(
        "JMO-TEST-2026-0110",
        "Packagist",
        "guzzlehttp/guzzle",
        "6.5.4",
        "php/composer/composer.lock",
    ),
    Advisory(
        "JMO-TEST-2026-0111", "RubyGems", "rack", "2.0.6", "ruby/rubygems/Gemfile.lock"
    ),
    # All six of pom.xml's packages are pinned by gradle.lockfile at the same
    # versions, so this one is found in both.
    Advisory(
        "JMO-TEST-2026-0112",
        "Maven",
        "org.apache.logging.log4j:log4j-core",
        "2.14.1",
        "java/maven/pom.xml",
    ),
    Advisory(
        "JMO-TEST-2026-0113",
        "Maven",
        "commons-io:commons-io",
        "2.4",
        "java/gradle/gradle.lockfile",
    ),
    # packages.lock.json has 16 packages; this one is in no other NuGet file
    # (API.deps.json has Microsoft.IdentityModel.Logging 6.15.0).
    Advisory(
        "JMO-TEST-2026-0114",
        "NuGet",
        "Microsoft.IdentityModel.Logging",
        "6.10.0",
        "csharp/nuget/packages.lock.json",
    ),
    # All four of packages.config's packages are in packages.lock.json, at the
    # same versions, so this one is found in both (API.deps.json has 12.0.3).
    Advisory(
        "JMO-TEST-2026-0115",
        "NuGet",
        "Newtonsoft.Json",
        "13.0.1",
        "csharp/nuget/packages.config",
    ),
    Advisory(
        "JMO-TEST-2026-0116", "NuGet", "AutoMapper", "10.1.1", "csharp/API.deps.json"
    ),
)

# The (lockfile, advisory id) pairs one scan of all the lockfiles yields, and
# nothing else. Written out, not derived: the oracle may not grade osv-scanner
# by osv-scanner.
EXPECTED_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {
        # 0101 form-data 4.0.3: bun.lock alone.
        ("javascript/bun/bun.lock", "JMO-TEST-2026-0101"),
        # 0102 form-data 4.0.2, 0103 undici-types 6.20.0, 0104 @types/cors 2.8.17:
        # package-lock.json, pnpm-lock.yaml and yarn.lock each; bun.lock pins
        # form-data 4.0.3, undici-types 7.8.0 and @types/cors 2.8.19.
        ("javascript/npm/package-lock.json", "JMO-TEST-2026-0102"),
        ("javascript/pnpm/pnpm-lock.yaml", "JMO-TEST-2026-0102"),
        ("javascript/yarn/yarn.lock", "JMO-TEST-2026-0102"),
        ("javascript/npm/package-lock.json", "JMO-TEST-2026-0103"),
        ("javascript/pnpm/pnpm-lock.yaml", "JMO-TEST-2026-0103"),
        ("javascript/yarn/yarn.lock", "JMO-TEST-2026-0103"),
        ("javascript/npm/package-lock.json", "JMO-TEST-2026-0104"),
        ("javascript/pnpm/pnpm-lock.yaml", "JMO-TEST-2026-0104"),
        ("javascript/yarn/yarn.lock", "JMO-TEST-2026-0104"),
        # 0105 certifi 2025.1.31: poetry.lock (uv.lock pins 2025.4.26).
        ("python/poetry/poetry.lock", "JMO-TEST-2026-0105"),
        # 0106 django 4.2.16: requirements.txt alone.
        ("python/requirements/requirements.txt", "JMO-TEST-2026-0106"),
        # 0107 click 8.2.1: uv.lock (poetry.lock pins 8.1.8).
        ("python/uv/uv.lock", "JMO-TEST-2026-0107"),
        ("golang/gomod/go.mod", "JMO-TEST-2026-0108"),
        ("rust/cargo/Cargo.lock", "JMO-TEST-2026-0109"),
        ("php/composer/composer.lock", "JMO-TEST-2026-0110"),
        ("ruby/rubygems/Gemfile.lock", "JMO-TEST-2026-0111"),
        # 0112 log4j-core 2.14.1: pom.xml and gradle.lockfile.
        ("java/maven/pom.xml", "JMO-TEST-2026-0112"),
        ("java/gradle/gradle.lockfile", "JMO-TEST-2026-0112"),
        # 0113 commons-io 2.4: gradle.lockfile alone.
        ("java/gradle/gradle.lockfile", "JMO-TEST-2026-0113"),
        # 0114 Microsoft.IdentityModel.Logging 6.10.0: packages.lock.json alone.
        ("csharp/nuget/packages.lock.json", "JMO-TEST-2026-0114"),
        # 0115 Newtonsoft.Json 13.0.1: packages.config and packages.lock.json.
        ("csharp/nuget/packages.config", "JMO-TEST-2026-0115"),
        ("csharp/nuget/packages.lock.json", "JMO-TEST-2026-0115"),
        # 0116 AutoMapper 10.1.1: API.deps.json alone.
        ("csharp/API.deps.json", "JMO-TEST-2026-0116"),
    }
)


def ecosystems() -> tuple[str, ...]:
    """The ecosystems with an advisory, in the table's order."""
    return tuple(dict.fromkeys(a.ecosystem for a in ADVISORIES))


def record(advisory: Advisory) -> dict[str, object]:
    """The OSV record, in the shape of `tests/fixtures/osv-db`'s: affecting
    `version` and no other, `introduced` and `last_affected` being the same."""
    return {
        "affected": [
            {
                "package": {
                    "ecosystem": advisory.ecosystem,
                    "name": advisory.package,
                },
                "ranges": [
                    {
                        "events": [
                            {"introduced": advisory.version},
                            {"last_affected": advisory.version},
                        ],
                        "type": "ECOSYSTEM",
                    }
                ],
            }
        ],
        "details": DETAILS,
        "id": advisory.id,
        "modified": PUBLISHED,
        "published": PUBLISHED,
        "schema_version": "1.6.0",
        "severity": [
            {
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "type": "CVSS_V3",
            }
        ],
        "summary": SUMMARY,
    }


def database(ecosystem: str) -> bytes:
    """One ecosystem's `all.zip`: a JSON file per advisory, sorted by name."""
    members = sorted(
        (f"{a.id}.json", json.dumps(record(a), indent=2, sort_keys=True) + "\n")
        for a in ADVISORIES
        if a.ecosystem == ecosystem
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in members:
            info = zipfile.ZipInfo(name, date_time=ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3  # not the writing platform's
            info.external_attr = 0o600 << 16
            archive.writestr(info, text.encode())
    return buffer.getvalue()


def database_path(out: Path, ecosystem: str) -> Path:
    return out / "osv-scalibr" / ecosystem / "all.zip"


def build(out: Path = DEFAULT_OUT) -> list[Path]:
    """Write every ecosystem's database under `out`; the paths written."""
    written = []
    for ecosystem in ecosystems():
        path = database_path(out, ecosystem)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(database(ecosystem))
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write the frozen osv-scanner database the lockfile oracle reads."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="where osv-scalibr/<ecosystem>/all.zip go (default %(default)s)",
    )
    args = parser.parse_args(argv)
    for path in build(args.out):
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
