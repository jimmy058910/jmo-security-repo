#!/usr/bin/env python3
"""Guard: no user-facing document may quantify deduplication's effect.

Regression for #855.

"Cross-tool deduplication -- 30-40% noise reduction" shipped in 16 places across
12 tracked files. **No corpus, profile or scan was ever cited alongside it, and
nothing in the repository reproduces it.** Re-measured through the real
``jmo report`` during Phase 8 of the v1.1.0 fix program, on the only corpus
still available:

    Clustering 266 findings for cross-tool duplicates...
    Cross-tool clustering complete: 266 -> 266 findings (0 removed, 0.0% reduction)

Chunk 7 measured the same corpus at 266 -> 265 (0.4%), and a deep scan of
``tests/e2e/fixtures`` at 244 -> 242 (0.8%). Nothing in that range rounds to 30%.

**The figure is not so much wrong as unsourceable.** How much clustering removes
depends entirely on how much a profile's tools overlap, and the corpora above are
SBOM plus SAST plus SCA tools looking at different things, with almost nothing to
agree on. A profile dominated by several SCA tools reporting the same CVEs could
plausibly cluster heavily. That is exactly why a bare percentage cannot be
advertised without naming what produced it.

So the property asserted here is not "30-40 is the wrong number". It is that **an
advertised percentage attributed to deduplication has no source**, and the fix
was to describe the mechanism instead. The guard matches the *shape* of such a
claim rather than the retired wording, because the same claim had already drifted
into three spellings across four files -- "30-40%", "30-40%" with an en dash, and
"20-40%" in a test module's own docstring.

Two design choices worth keeping:

* **Coverage comes from ``git ls-files``, not a glob of the working tree.** A
  first version walked the tree and failed on ``PRODUCT_DEFINITION.md``, which is
  gitignored -- so the guard was red locally and green in CI, on a file no clone
  receives. What ships is what this checks.
* **The dedup vocabulary is specific, and "noise" alone is not in it.** Matching
  bare "noise reduction" also caught v0.9.0's "EPSS/KEV prioritization (30-50%
  noise reduction)" and a v1.1.0 dashboard entry's "Noise reduction: 80%". Both
  are unsourced claims of the same family, but neither is about deduplication,
  and a guard that reddens on its neighbours' subjects gets an exemption rather
  than a fix.

A second, stronger check follows: the similarity weights quoted in
``_cluster_cross_tool_duplicates``' own docstring are compared against
``SimilarityCalculator``'s real defaults. That asserts a property against the
source of truth rather than a pattern -- the docstring had drifted to
"Location 35%, Message 40%, Metadata 25%" while the code had used 50/25/25 since
before v1.0.0, with a code comment saying so thirty lines further down.

Companion to ``test_docs_manual_install_counts.py``, which guards a different
family of doc claim on the same registry-as-truth principle.
"""

from __future__ import annotations

import importlib.util
import inspect
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"

# Text surfaces a user or contributor reads before forming an expectation about
# what deduplication does.
CHECKED_SUFFIXES = (".md", ".yaml", ".yml", ".rb")

# One exemption beyond the repository's own archival set: this file quotes the
# retired number in order to state that it is unattributed. Removing it there
# would delete the correction.
EXTRA_ALLOWED = frozenset({"docs/KNOWN_LIMITATIONS.md"})

# Three separate conditions, because any two of them alone produce noise.
#
# `duplicat\w*` is deliberately absent from the vocabulary: it also spells the
# code-quality sense, and `.claude/agents/code-quality-auditor.md` carries seven
# percentages about duplicated *source lines* that have nothing to do with
# findings.
_DEDUP_WORD = re.compile(r"dedup\w*|cross-tool|cluster\w*|consensus", re.IGNORECASE)
# A claim that the percentage is an *effect*. Without this, the guard reddens on
# `deduplication.similarity_threshold` and on "findings with >=65% similarity are
# clustered" -- a sourced configuration value, not an advertised outcome.
_REDUCTION_WORD = re.compile(
    r"reduc\w*|fewer|elimina\w*|removes?\b|removed\b|shrink\w*|noise", re.IGNORECASE
)
_PCT = re.compile(r"\d{1,3}\s*(?:-|–|—|to)?\s*\d{0,3}\s*%")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


def _doc_link_checker():
    """The repo's own definition of "tracked" and "archival", not a copy of it."""
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_user_facing_doc_quantifies_deduplication() -> None:
    """Regression for #855: an advertised dedup percentage has no source."""
    mod = _doc_link_checker()
    tracked = mod.tracked_paths()

    candidates = sorted(
        p
        for p in tracked
        if p.endswith(CHECKED_SUFFIXES)
        and not p.startswith(mod.ARCHIVAL_PREFIXES)
        and p not in EXTRA_ALLOWED
    )
    # If discovery collapses, the guard passes on nothing and goes inert -- the
    # exact failure mode a `paths:` matching zero files produces.
    assert len(candidates) >= 100, f"file discovery looks wrong: {len(candidates)}"

    offenders = [
        f"{rel}:{lineno}: {line.strip()[:100]}"
        for rel in candidates
        for lineno, line in _quantified_dedup_claims(
            (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace"), mod
        )
    ]

    assert not offenders, (
        "user-facing text attributes a percentage to deduplication, which no "
        "corpus in this repository reproduces (#855). Describe the mechanism "
        "instead; a measured figure belongs in docs/KNOWN_LIMITATIONS.md beside "
        "the corpus that produced it:\n" + "\n".join(offenders)
    )


def _quantified_dedup_claims(text: str, mod) -> list[tuple[int, str]]:
    """Lines claiming a percentage effect for deduplication.

    A percentage in a table cell carries no vocabulary of its own -- the retired
    ``| Reduction | 30-40% fewer reported findings |`` row said "deduplication"
    only in the ``## Cross-Tool Deduplication`` heading two levels above it. So
    the deduplication context is taken from the enclosing heading stack, while
    the effect claim and the number must both appear on the line itself.

    **Fence tracking is load-bearing, not incidental.** The first version of this
    guard let that exact row survive its own mutation test, because two of the
    section's YAML samples open with the comment ``# jmo.yml``. Read as Markdown
    that is an h1, and an h1 pops every enclosing heading -- so by the row's line
    the stack was ``{1: "jmo.yml", 3: "Performance"}`` and the word
    "Deduplication" was no longer in scope. Reuses ``check_doc_links``'
    ``FENCE_PATTERN`` and its CommonMark closing rule rather than a private copy,
    which is how the two would drift; line numbers are kept, which is why
    ``unfenced_lines`` is not called directly.
    """
    hits: list[tuple[int, str]] = []
    stack: dict[int, str] = {}
    opener: str | None = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        fence = mod.FENCE_PATTERN.match(line)
        if fence:
            marker, info = fence.group("marker"), fence.group("info")
            if opener is None:
                opener = marker
                continue
            if marker[0] == opener[0] and len(marker) >= len(opener) and not info:
                opener = None
            continue
        if opener is not None:
            continue

        heading = _HEADING.match(line)
        if heading:
            level = len(heading.group(1))
            stack = {lv: t for lv, t in stack.items() if lv < level}
            stack[level] = heading.group(2)
            continue

        context = line + " " + " ".join(stack.values())
        if (
            _DEDUP_WORD.search(context)
            and _REDUCTION_WORD.search(line)
            and _PCT.search(line)
        ):
            hits.append((lineno, line))
    return hits


# A false-positive rate is the same defect as #855's reduction figure with a
# different subject, and a worse one: a reduction figure oversells a feature,
# while a false-positive rate is ADVICE. A reader who sees `noseyparker
# ~30-40%` reasonably decides not to run it, or to discount its findings by a
# third.
_FALSE_POSITIVE_WORD = re.compile(r"false[\s_-]?positive", re.IGNORECASE)
_TABLE_SEPARATOR = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _quantified_false_positive_claims(text: str, mod) -> list[tuple[int, str]]:
    """Lines giving a percentage for a false-positive rate.

    Two shapes, because the defect had two:

    **In a table column.** `docs/USAGE_MATRIX.md`'s Matrix 8 carried a
    `False Positive Rate` column for 24 tools -- the issue said 11 -- and not
    one data row contained the words "false positive". The vocabulary lived in
    the HEADER and the numbers lived below it, exactly as #855's retired
    `| Reduction | 30-40% |` row kept its subject two headings up. So a table
    header is tracked the way that guard tracks a heading stack, and a
    percentage in a column whose header names false positives is a hit.

    **In prose.** `<10% false positives` as a profile-selection criterion in a
    contributor doc: vocabulary and number on one line, nothing to correlate.

    Fence tracking is shared with the deduplication guard, and for the reason
    recorded there: a YAML sample opening `# jmo.yml` reads as an h1 and pops
    the heading stack.
    """
    hits: list[tuple[int, str]] = []
    opener: str | None = None
    fp_columns: set[int] = set()
    header_cells: list[str] | None = None

    for lineno, line in enumerate(text.splitlines(), start=1):
        fence = mod.FENCE_PATTERN.match(line)
        if fence:
            marker, info = fence.group("marker"), fence.group("info")
            if opener is None:
                opener = marker
                continue
            if marker[0] == opener[0] and len(marker) >= len(opener) and not info:
                opener = None
            continue
        if opener is not None:
            continue

        if not line.strip().startswith("|"):
            # Any non-table line ends the current table's column context.
            fp_columns, header_cells = set(), None
            if _FALSE_POSITIVE_WORD.search(line) and _PCT.search(line):
                hits.append((lineno, line))
            continue

        if _TABLE_SEPARATOR.match(line) and header_cells is not None:
            fp_columns = {
                i
                for i, cell in enumerate(header_cells)
                if _FALSE_POSITIVE_WORD.search(cell)
            }
            continue

        cells = _cells(line)
        if fp_columns:
            for index in fp_columns:
                if index < len(cells) and _PCT.search(cells[index]):
                    hits.append((lineno, line))
                    break
        elif _FALSE_POSITIVE_WORD.search(line) and _PCT.search(line):
            hits.append((lineno, line))
        header_cells = cells
    return hits


def test_no_user_facing_doc_quantifies_a_false_positive_rate() -> None:
    """Regression for #1047: an advertised false-positive rate has no source.

    `git grep -i "false positive rate" -- scripts/ tests/` is empty, and the
    only commit ever to touch the column was a documentation reorganisation.

    `CHANGELOG.md` is out of scope, and that is not an oversight: it is already
    in `check_doc_links.ARCHIVAL_PREFIXES`, because frozen release notes record
    what was claimed at the time rather than advising a reader today. Its
    "95% false positive reduction" lines stay.
    """
    mod = _doc_link_checker()
    tracked = mod.tracked_paths()

    candidates = sorted(
        p
        for p in tracked
        if p.endswith(CHECKED_SUFFIXES)
        and not p.startswith(mod.ARCHIVAL_PREFIXES)
        and p not in EXTRA_ALLOWED
    )
    assert len(candidates) >= 100, f"file discovery looks wrong: {len(candidates)}"

    offenders = [
        f"{rel}:{lineno}: {line.strip()[:100]}"
        for rel in candidates
        for lineno, line in _quantified_false_positive_claims(
            (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace"), mod
        )
    ]

    assert not offenders, (
        "user-facing text gives a false-positive percentage, which no corpus in "
        "this repository reproduces (#1047). A false-positive rate depends on "
        "the codebase, the rule set and the tool version -- none of which this "
        "project measures -- and it is read as advice about which scanners to "
        "trust:\n" + "\n".join(offenders)
    )


def test_the_false_positive_detector_finds_the_shape_it_was_written_for() -> None:
    """The rule, on the table it was written for.

    The repository no longer contains one, which is the fix -- so without this
    the assertion above is green over a population of zero and cannot tell a
    working detector from one that returns nothing.
    """
    mod = _doc_link_checker()

    table = "\n".join(
        [
            "## Matrix 8: Tool-Specific Use Cases",
            "",
            "| Tool | Primary Use Case | Common Flags | False Positive Rate |",
            "|------|------------------|--------------|---------------------|",
            "| **trufflehog** | Verified secret detection | `--only-verified` | ~5% (verified) |",
            "| **noseyparker** | Deep secret scanning | N/A | ~30-40% |",
            "| **syft** | SBOM generation | `-q` | 0% (informational) |",
        ]
    )
    hits = _quantified_false_positive_claims(table, mod)
    assert [n for n, _ in hits] == [5, 6, 7], f"expected all three rows, got {hits}"

    # The same table without the column must be clean -- otherwise the detector
    # is reporting the rows rather than the claim.
    cleaned = "\n".join(
        line.rsplit("|", 2)[0] + "|" if line.startswith("|") else line
        for line in table.splitlines()
    )
    assert _quantified_false_positive_claims(cleaned, mod) == []

    # The prose shape, which has no column to correlate.
    prose = "| **fast** | <5 min, core capability, <10% false positives | trufflehog |"
    assert _quantified_false_positive_claims(prose, mod)

    # A percentage with no false-positive vocabulary anywhere is not a hit.
    assert (
        _quantified_false_positive_claims("Coverage is 85% on the marker suite.", mod)
        == []
    )


def test_clustering_docstring_states_the_real_weights() -> None:
    """The documented similarity weights must equal the code's defaults (#855).

    Asserts against ``SimilarityCalculator.__init__``'s signature rather than a
    restated list, so changing a default without updating the docstring fails
    here instead of shipping another release of wrong percentages.
    """
    from scripts.core.dedup_enhanced import SimilarityCalculator
    from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

    params = inspect.signature(SimilarityCalculator.__init__).parameters
    actual = {
        "Location": params["location_weight"].default,
        "Message": params["message_weight"].default,
        "Metadata": params["metadata_weight"].default,
    }
    assert abs(sum(actual.values()) - 1.0) < 0.01, f"weights do not sum to 1: {actual}"

    doc = inspect.getdoc(_cluster_cross_tool_duplicates) or ""
    documented = {
        name: int(pct)
        for name, pct in re.findall(
            r"^\s*-\s*(Location|Message|Metadata)\b[^:]*:\s*(\d{1,3})%\s*weight",
            doc,
            re.MULTILINE,
        )
    }
    assert set(documented) == set(actual), (
        "the clustering docstring no longer states all three weights; it read "
        f"{documented!r}"
    )

    mismatches = [
        f"{name}: docstring says {documented[name]}%, code default is "
        f"{actual[name] * 100:.0f}%"
        for name in actual
        if abs(documented[name] / 100 - actual[name]) > 0.005
    ]
    assert not mismatches, "\n".join(mismatches)
