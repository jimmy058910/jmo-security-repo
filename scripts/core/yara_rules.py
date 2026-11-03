"""Keep only the signature-base rules JMo may redistribute (v2.0.0 Phase 6, decision 6).

signature-base is under the Detection Rule License 1.1, but not every rule in it
is. A rule can name another license in its own `license` metadata, and a file
can name one only in a header comment (measured at `36ab7042`: about 18 files,
Apache-2.0, CC BY-NC, GPL and others). This reads a fetched rule tree in place:

- a rule whose metadata names a license other than DRL is cut out of its file;
- a file is *ambiguous* when a comment outside its rules mentions a license that
  is not DRL, or when it holds rules licensed otherwise beside rules with no
  license line. An ambiguous file has to be on the reviewed list: "drop" removes
  it whole (a header wins over its rules' DRL metadata), "keep" keeps it and
  reads its unlabelled rules as DRL. One the list does not name raises
  `UnreviewedRuleFile`, so a new pin cannot ship a file nobody read;
- any other rule with no license line is DRL, as the repository's LICENSE says;
- a file left with no rules is deleted.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

RULE_SUFFIXES = (".yar", ".yara")

Review = tuple[Literal["drop", "keep"], str]

# "Detection Rule License", SigmaHQ's "Detection-Rule-License" and its
# "Detetction Rule License" all end the same way.
_DRL = re.compile(r"rule[ -]licen[cs]e", re.IGNORECASE)
_LICENSE_WORD = re.compile(r"licen[cs]e", re.IGNORECASE)
# Read on the skeleton, where strings and comments are blank, so a match is
# YARA source: `$rule`, `#rule` and `myrule` are not headers.
_HEADER = re.compile(r"(?<![\w$#@!])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)")
_LICENSE_KEY = re.compile(r"(?<![\w$#@!])license\s*=", re.IGNORECASE)
# Read on `code`: the skeleton has the value blanked to spaces.
_VALUE = re.compile(r'\s*"((?:[^"\\\n]|\\.)*)"')


@dataclass(frozen=True)
class Dropped:
    file: str
    rule: str
    reason: str


@dataclass
class FilterResult:
    kept_files: int = 0
    kept_rules: int = 0
    dropped: list[Dropped] = field(default_factory=list)


class UnreviewedRuleFile(ValueError):
    """An ambiguous rule file the reviewed list does not name."""


@dataclass(frozen=True)
class _Rule:
    name: str
    start: int
    end: int
    licenses: tuple[str, ...]

    @property
    def other_license(self) -> str | None:
        """The first license this rule names that is not DRL."""
        return next((v for v in self.licenses if not _DRL.search(v)), None)


def _views(text: str) -> tuple[str, str, list[tuple[int, int]]]:
    """Split YARA source into what a parser would see.

    Returns `code` (comments blanked), `skeleton` (comments, text strings and
    regexes blanked) and the comments' spans. Blanking keeps every newline, so
    offsets and line starts are the original's. Outside a comment, `/` only
    ever opens a regex: YARA divides with `\\`.
    """
    code = list(text)
    skel = list(text)
    comments: list[tuple[int, int]] = []

    def blank(view: list[str], start: int, end: int) -> None:
        for k in range(start, end):
            if view[k] != "\n":
                view[k] = " "

    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i) or text.startswith("/*", i):
            if text[i + 1] == "/":
                end = text.find("\n", i)
                end = n if end < 0 else end
            else:
                end = text.find("*/", i + 2)
                end = n if end < 0 else end + 2
            comments.append((i, end))
            blank(code, i, end)
            blank(skel, i, end)
            i = end
        elif text[i] in '"/':
            quote, j = text[i], i + 1
            while j < n and text[j] not in (quote, "\n"):
                j += 2 if text[j] == "\\" else 1
            end = min(j + 1, n)
            blank(skel, i, end)
            i = end
        else:
            i += 1
    return "".join(code), "".join(skel), comments


def _rules(code: str, skel: str) -> list[_Rule]:
    rules: list[_Rule] = []
    for header in _HEADER.finditer(skel):
        if rules and header.start() < rules[-1].end:
            continue
        k = skel.find("{", header.end())
        if k < 0:
            break  # not YARA; the compiler will say so
        depth = 0
        while k < len(skel):
            depth += {"{": 1, "}": -1}.get(skel[k], 0)
            if depth == 0:
                break
            k += 1
        end = k + 1
        licenses = tuple(
            value.group(1)
            for key in _LICENSE_KEY.finditer(skel, header.start(), end)
            if (value := _VALUE.match(code, key.end()))
        )
        rules.append(_Rule(header.group(2), header.start(), end, licenses))
    return rules


def _ambiguity(
    text: str, rules: list[_Rule], comments: list[tuple[int, int]]
) -> str | None:
    """Why a file needs a human's reading, or None."""
    for start, end in comments:
        if any(r.start <= start < r.end for r in rules):
            continue  # inside a rule: annotations of its patterns, not its license
        for line in text[start:end].splitlines():
            if _LICENSE_WORD.search(line) and not _DRL.search(line):
                return (
                    f"a comment outside its rules mentions a license: {line.strip()!r}"
                )
    if any(r.other_license for r in rules) and any(not r.licenses for r in rules):
        return "rules licensed otherwise sit beside rules with no license line"
    return None


def filter_rules(rules_dir: Path, reviewed: Mapping[str, Review]) -> FilterResult:
    """Cut every rule JMo may not redistribute out of `rules_dir`, in place."""
    result = FilterResult()
    paths = sorted(
        p for p in rules_dir.rglob("*") if p.suffix in RULE_SUFFIXES and p.is_file()
    )
    for path in paths:
        name = path.relative_to(rules_dir).as_posix()
        # surrogateescape round-trips any byte a rule file holds.
        text = path.read_bytes().decode("utf-8", errors="surrogateescape")
        code, skel, comments = _views(text)
        rules = _rules(code, skel)
        review = reviewed.get(name)
        if review is None and (why := _ambiguity(text, rules, comments)):
            raise UnreviewedRuleFile(
                f"{name}: {why}. Read it, then list it in YARA_RULES_REVIEWED "
                f"(scripts/core/install_config.py) as 'drop' or 'keep'."
            )
        if review is not None and review[0] == "drop":
            result.dropped += [Dropped(name, r.name, review[1]) for r in rules]
            path.unlink()
            continue
        gone = [r for r in rules if r.other_license]
        result.dropped += [Dropped(name, r.name, r.other_license or "") for r in gone]
        if rules and len(gone) == len(rules):
            path.unlink()
            continue
        for r in reversed(gone):
            end = r.end + 1 if text[r.end : r.end + 1] == "\n" else r.end
            text = text[: r.start] + text[end:]
        if gone:
            path.write_bytes(text.encode("utf-8", errors="surrogateescape"))
        result.kept_files += 1
        result.kept_rules += len(rules) - len(gone)
    return result
