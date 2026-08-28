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
