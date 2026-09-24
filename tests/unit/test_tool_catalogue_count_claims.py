"""Every scanner, tool and adapter count in user-facing text must equal what
the code derives (#1003).

The catalogue total was stated as both 28 and 29 across README, ROADMAP,
QUICKSTART, SECURITY.md, AGENTS.md, CONTRIBUTING, FAQ, the Homebrew formula
and the wizard's own `--help`, through several releases, because nothing
compared the prose to the registry. README.md said 28 on line 13 and 29 on
line 83. Whichever a reader trusts, the other one is evidence the numbers are
not maintained -- the credibility problem #747 and #750 were about.

This guard matches the *shape* of a claim rather than any one sentence: a
literal grep for last time's number is walked around by the next drift. Two
shapes:

- catalogue claims: "N scanners", "N security tools", "all N tools",
  "N+ tools", "N tool versions" -> `len(TOOL_MATRIX)`;
- adapter claims ("15 adapters") -> the adapter files on disk.

v2.0.0 removed scan profiles, and with them the per-profile size claims this
file used to check ("balanced (17 tools", `| slim | 13 |`, the profile comments
in `jmo.yml`, the wizard's `--help`). There is one tool list now, so there is
one number.

Deliberately not scanned: CHANGELOG.md and the versioned winget manifest under
packaging/winget/**/1.0.0/ (history that was true when written),
docs/internal/ (dated measurement snapshots), docs/superpowers/ (plans),
and dev-only/, .claude/ (not shipped). DOCKER_HUB_README.md joined
the list with #1103, which rewrote its v1.0.0 "What's New" section.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from scripts.core.tool_registry import TOOL_MATRIX
from scripts.core.validators.scan_validator import EXPECTED_ADAPTERS

REPO_ROOT = Path(__file__).resolve().parents[2]

CATALOGUE = len(TOOL_MATRIX)
ADAPTERS = len(list((REPO_ROOT / "scripts" / "core" / "adapters").glob("*_adapter.py")))


def _advertised_files() -> list[Path]:
    fixed = [
        "README.md",
        "QUICKSTART.md",
        "ROADMAP.md",
        "SECURITY.md",
        "AGENTS.md",
        "CONTRIBUTING.md",
        "CLAUDE.md",
        "Makefile",
        "samples/README.md",
        "docs/mkdocs.yml",
        "DOCKER_HUB_README.md",
    ]
    globbed = [
        *sorted((REPO_ROOT / "docs").glob("*.md")),
        *sorted((REPO_ROOT / "docs" / "examples").glob("*.md")),
        *sorted((REPO_ROOT / "docs" / "brand").glob("*.md")),
        *sorted((REPO_ROOT / "packaging" / "homebrew").glob("*.rb")),
    ]
    return [REPO_ROOT / f for f in fixed] + globbed


FILES = _advertised_files()

CATALOGUE_CLAIMS = [
    re.compile(
        r"\b(\d+)\+?\s+(?:external\s+)?(?:security\s+)?scanners?\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(\d+)\+?\s+(?:external\s+)?security\s+tools?\b(?!\s+adapters)",
        re.IGNORECASE,
    ),
    re.compile(r"\ball\s+(\d+)\+?\s+tools\b", re.IGNORECASE),
    # "28+ tools" in the Homebrew formula's description. Bounded below at two
    # digits so that consensus phrasing ("4+ tools agree", "8+ tools broke on
    # musl") is not read as a catalogue claim. The bound used to be 20, which
    # was safe beside a 28-tool catalogue and would miss a claim about the
    # 12-tool matrix outright.
    re.compile(r"\b([1-9]\d+)\+\s+tools\b", re.IGNORECASE),
    re.compile(r"\b(\d+)\s+tool\s+versions\b", re.IGNORECASE),
]
ADAPTER_CLAIMS = [
    re.compile(r"\b(\d+)\s+(?:security\s+tool\s+)?adapters\b", re.IGNORECASE)
]


def _numbers(patterns: list[re.Pattern[str]], line: str) -> list[int]:
    return [int(m.group(1)) for p in patterns for m in p.finditer(line)]


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    yield from enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)


def _where(path: Path, lineno: int, line: str) -> str:
    return f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line.strip()[:110]}"


def _claims(patterns: list[re.Pattern[str]]) -> list[tuple[str, int]]:
    return [
        (_where(path, lineno, line), n)
        for path in FILES
        for lineno, line in _lines(path)
        for n in _numbers(patterns, line)
    ]


def test_the_oracles_and_the_extractors_are_not_empty():
    """An extractor that finds nothing satisfies every assertion built on it.

    These were floors (`CATALOGUE >= 20`, `>= 10` live claims), and v2.0.0
    broke both honestly: the matrix is 12, and its docs prefer stating no count
    at all, so the live claims may fall to none. So each oracle is checked
    against an independent source and each extractor against a line built to
    exercise its shape, including the one that must NOT match.
    """
    assert CATALOGUE == len(set(TOOL_MATRIX)) > 0
    assert len(EXPECTED_ADAPTERS) == ADAPTERS
    assert all(path.is_file() for path in FILES)

    assert _numbers(CATALOGUE_CLAIMS, "runs 12 scanners") == [12]
    assert _numbers(CATALOGUE_CLAIMS, "12 security tools") == [12]
    assert _numbers(CATALOGUE_CLAIMS, "all 12 tools") == [12]
    assert _numbers(CATALOGUE_CLAIMS, "12+ tools") == [12]
    assert _numbers(CATALOGUE_CLAIMS, "12 tool versions") == [12]
    assert _numbers(CATALOGUE_CLAIMS, "when 4+ tools agree") == []
    assert _numbers(ADAPTER_CLAIMS, "15 adapters") == [15]


def test_catalogue_claims_match_the_registry():
    wrong = [
        f"{where} -> says {n}, TOOL_MATRIX has {CATALOGUE}"
        for where, n in _claims(CATALOGUE_CLAIMS)
        if n != CATALOGUE
    ]
    assert not wrong, "\n".join(wrong)


def test_adapter_claims_match_the_files_on_disk():
    wrong = [
        f"{where} -> says {n}, on disk {ADAPTERS}"
        for where, n in _claims(ADAPTER_CLAIMS)
        if n != ADAPTERS
    ]
    assert not wrong, "\n".join(wrong)
