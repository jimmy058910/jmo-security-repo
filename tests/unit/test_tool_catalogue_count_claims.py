"""Every scanner, tool, profile-size and adapter count in user-facing text
must equal what the registry derives (#1003).

The catalogue total was stated as both 28 and 29 across README, ROADMAP,
QUICKSTART, SECURITY.md, AGENTS.md, CONTRIBUTING, FAQ, the Homebrew formula
and the wizard's own `--help`, through several releases, because nothing
compared the prose to `PROFILE_TOOLS`. README.md said 28 on line 13 and 29 on
line 83. Whichever a reader trusts, the other one is evidence the numbers are
not maintained -- the credibility problem #747 and #750 were about.

This guard matches the *shape* of a claim rather than any one sentence, the
way `test_docs_manual_install_counts.py` does: a literal grep for last time's
number is walked around by the next drift. Four shapes:

- catalogue claims: "N scanners", "N security tools", "all N tools",
  "N tool versions" -> the union of PROFILE_TOOLS;
- profile claims in prose ("balanced (17 tools", "deep: 29 tools") and in
  markdown tables (`| slim | 13 |`, `| **Balanced** | ... | 17 |`) -> that
  profile's size;
- adapter claims ("27 adapters") -> the adapter files on disk;
- the profile comments in the shipped `jmo.yml`.

Deliberately not scanned: CHANGELOG.md and the versioned winget manifest under
packaging/winget/**/1.0.0/ (history that was true when written),
docs/internal/ (dated measurement snapshots), docs/superpowers/ (plans),
DOCKER_HUB_README.md (rewritten under #1103 -- add it here when that lands),
and dev-only/, paperclip/, .claude/ (not shipped).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from scripts.core.tool_registry import PROFILE_TOOLS

REPO_ROOT = Path(__file__).resolve().parents[2]

CATALOGUE = len({tool for tools in PROFILE_TOOLS.values() for tool in tools})
PROFILE_SIZES = {name: len(tools) for name, tools in PROFILE_TOOLS.items()}
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
    ]
    globbed = [
        *sorted((REPO_ROOT / "docs").glob("*.md")),
        *sorted((REPO_ROOT / "docs" / "examples").glob("*.md")),
        *sorted((REPO_ROOT / "docs" / "brand").glob("*.md")),
        *sorted((REPO_ROOT / "packaging" / "homebrew").glob("*.rb")),
    ]
    return [REPO_ROOT / f for f in fixed] + globbed


FILES = _advertised_files()

_PROFILE = r"(fast|slim|balanced|deep)"

CATALOGUE_CLAIMS = [
    re.compile(
        r"\b(\d+)\+?\s+(?:external\s+)?(?:security\s+)?scanners?\b", re.IGNORECASE
    ),
    re.compile(
        r"\b(\d+)\+?\s+(?:external\s+)?security\s+tools?\b(?!\s+adapters)",
        re.IGNORECASE,
    ),
    re.compile(r"\ball\s+(\d+)\+?\s+tools\b", re.IGNORECASE),
    # "28+ tools" in the Homebrew formula's description. Bounded below so that
    # consensus phrasing ("4+ tools agree", "8+ tools broke on musl") is not
    # read as a catalogue claim: no profile is anywhere near 20.
    re.compile(r"\b((?:[2-9]\d|\d{3,}))\+\s+tools\b", re.IGNORECASE),
    re.compile(r"\b(\d+)\s+tool\s+versions\b", re.IGNORECASE),
]
PROFILE_PROSE = re.compile(
    rf"\b{_PROFILE}\b[^|\n]{{0,30}}?\b(\d+)\s+tools\b", re.IGNORECASE
)
# Lazy `{0,2}?`: the size is the FIRST numeric column after the profile name.
# Greedy took the last one, reading `| **Balanced** | 17 | 0 |` as 0.
PROFILE_ROW = re.compile(
    rf"^\|\s*\**`?{_PROFILE}`?\**\s*\|(?:\s*[^|\n]*\|){{0,2}}?\s*(\d+)\s*\|",
    re.IGNORECASE,
)
PROFILE_NAMES = re.compile(rf"\b{_PROFILE}\b", re.IGNORECASE)
ADAPTER_CLAIMS = [
    re.compile(r"\b(\d+)\s+(?:security\s+tool\s+)?adapters\b", re.IGNORECASE)
]


def _expected_catalogue(line: str) -> set[int]:
    """The catalogue total -- or, on a line about exactly one profile, that
    profile's size too (`:fast  # ~800 MB, 9 scanners` is a profile claim)."""
    names = {m.group(1).lower() for m in PROFILE_NAMES.finditer(line)}
    if len(names) == 1:
        return {CATALOGUE, PROFILE_SIZES[names.pop()]}
    return {CATALOGUE}


def _lines(path: Path) -> Iterator[tuple[int, str]]:
    yield from enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)


def _where(path: Path, lineno: int, line: str) -> str:
    return f"{path.relative_to(REPO_ROOT).as_posix()}:{lineno}: {line.strip()[:110]}"


def _catalogue_claims() -> list[tuple[str, int, set[int]]]:
    found = []
    for path in FILES:
        for lineno, line in _lines(path):
            for pattern in CATALOGUE_CLAIMS:
                for m in pattern.finditer(line):
                    found.append(
                        (
                            _where(path, lineno, line),
                            int(m.group(1)),
                            _expected_catalogue(line),
                        )
                    )
    return found


def _profile_claims() -> list[tuple[str, str, int]]:
    found = []
    for path in FILES:
        for lineno, line in _lines(path):
            for m in PROFILE_PROSE.finditer(line):
                found.append(
                    (_where(path, lineno, line), m.group(1).lower(), int(m.group(2)))
                )
            m = PROFILE_ROW.match(line)
            if m:
                found.append(
                    (_where(path, lineno, line), m.group(1).lower(), int(m.group(2)))
                )
    return found


def _adapter_claims() -> list[tuple[str, int]]:
    found = []
    for path in FILES:
        for lineno, line in _lines(path):
            for pattern in ADAPTER_CLAIMS:
                for m in pattern.finditer(line):
                    found.append((_where(path, lineno, line), int(m.group(1))))
    return found


def _jmo_yml_profile_comments() -> list[tuple[str, str, int]]:
    path = REPO_ROOT / "jmo.yml"
    found = []
    current = None
    for lineno, line in _lines(path):
        head = re.match(rf"^  {_PROFILE}:\s*$", line)
        if head:
            current = head.group(1)
            continue
        if current is None:
            continue
        if line and not line.startswith(" "):
            current = None
            continue
        comment = re.match(r"^\s+#.*?\b(\d+)\s+tools\b", line)
        if comment:
            found.append((_where(path, lineno, line), current, int(comment.group(1))))
    return found


def test_the_oracles_and_the_extractors_are_not_empty():
    """An extractor that finds nothing satisfies every assertion built on it."""
    assert CATALOGUE >= 20
    assert ADAPTERS >= 20
    assert set(PROFILE_SIZES) == {"fast", "slim", "balanced", "deep"}
    assert all(path.is_file() for path in FILES)
    assert len(_catalogue_claims()) >= 10
    assert len(_profile_claims()) >= 10
    assert len(_adapter_claims()) >= 1
    assert len(_jmo_yml_profile_comments()) == 4


def test_catalogue_claims_match_the_registry():
    wrong = [
        f"{where} -> says {n}, registry {sorted(expected)}"
        for where, n, expected in _catalogue_claims()
        if n not in expected
    ]
    assert not wrong, "\n".join(wrong)


def test_profile_claims_match_the_registry():
    wrong = [
        f"{where} -> {profile} says {n}, registry {PROFILE_SIZES[profile]}"
        for where, profile, n in _profile_claims()
        if n != PROFILE_SIZES[profile]
    ]
    assert not wrong, "\n".join(wrong)


def test_adapter_claims_match_the_files_on_disk():
    wrong = [
        f"{where} -> says {n}, on disk {ADAPTERS}"
        for where, n in _adapter_claims()
        if n != ADAPTERS
    ]
    assert not wrong, "\n".join(wrong)


def test_jmo_yml_profile_comments_match_the_registry():
    wrong = [
        f"{where} -> {profile} says {n}, registry {PROFILE_SIZES[profile]}"
        for where, profile, n in _jmo_yml_profile_comments()
        if n != PROFILE_SIZES[profile]
    ]
    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize("profile", ["fast", "slim", "balanced", "deep"])
def test_the_wizard_help_derives_its_profile_sizes(profile):
    """`jmo wizard --help` said slim=14, balanced=18 while `jmo --help` said 13
    and 17: one binary disagreeing with itself. The help text is now built
    from PROFILE_TOOLS, so this reads the real parser."""
    from scripts.cli.jmo import build_parser

    parser = build_parser()
    wizard = next(
        a
        for a in parser._subparsers._group_actions[0].choices.values()
        if a.prog.endswith(" wizard")
    )
    help_text = wizard.format_help()
    assert re.search(rf"\b{profile}={PROFILE_SIZES[profile]}\b", help_text), help_text
