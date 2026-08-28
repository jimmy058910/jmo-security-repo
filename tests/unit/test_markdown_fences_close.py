#!/usr/bin/env python3
"""Guard: a fenced code block must actually close.

Regression for #740.

CommonMark says a closing fence "may be followed only by spaces or tabs", so
```` ```text ```` is not a closer -- it is another opener. The block stays open
and swallows everything after it: headings render as code, tables render as
code, and links into those headings silently fail.

Measured before the Phase 8 repair, across 181 tracked Markdown files:

    13 files, 123 info-string closers, 6 ending inside an unclosed fence

`docs/RESULTS_GUIDE.md` showed the scale when it was repaired earlier: `gh api
markdown` emitted **31** heading anchors for a file whose source declares
**95**, and 10 of its 14 table-of-contents links pointed into the swallowed
region.

**123 is a cascade, not 123 independent defects.** Once one fence fails to
close, every later fence is parsed as being inside it, so it is counted too. In
`docs/RESULTS_QUICK_REFERENCE.md` 29 were flagged and 15 were real; the repair
changed 15 lines and revealed 17 headings.

## Why this is a ratchet and not a clean assertion

Five files were repaired mechanically and verified: the repair may only strip an
info string, and the result must re-parse with no info-string closer and no
unclosed fence at EOF. Eight were **refused by that verification** and are
recorded below with their exact counts.

They are refused for a real reason. They nest a ```python or ```json sample
inside a ```markdown sample at three backticks each, which CommonMark cannot
express -- the inner block's bare closer ends the outer one. Repairing them
means deciding where the author intended each sample to end, and that is a
reading of the document rather than a transformation of it. Two automated models
were tried and both were rejected by the verification on every one of the eight.

So each is pinned to the count it has. A new defect in a clean file fails; a
defect getting worse inside a recorded file fails; and fixing one fails too,
until its entry is removed here. That last one is deliberate -- it is what stops
the inventory going stale. Tracked in #1044.

**The pinned count is a ratchet, not a fingerprint**, and the cascade is why.
Measured on `.claude/agents/release-readiness.md`: turning its line-93
```` ```diff ```` into a bare closer moves the flagged lines from `[93, 513]` to
`[118, 513]` and leaves the count at **2**. Nothing was repaired -- the
desynchronisation simply surfaces further down. So a change inside a recorded
file that leaves the count identical is invisible here, and correctly so: it has
not fixed anything. A real repair collapses the count (the five done in Phase 8
went 31, 29, 17, 5 and 2 straight to 0), which is what makes the stale-entry
check fire.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"

# file -> (info-string closers, ends inside an unclosed fence)
#
# Was 13 files at #740, 8 after Phase 8, and is **1** after Phase 9 (#1044).
# The seven `.claude/agents/*.md` files were all one defect with one repair:
# each embeds a sample REPORT at three backticks, the report contains code
# samples at three backticks, and CommonMark reads the first inner closer as
# closing the report. Promoting the container to four backticks and closing it
# where the author meant to fixes each -- and the author's close is always
# there to be found, spelled ```text immediately before the next task heading.
# `security-auditor.md` needed FIVE, because its report embeds a documentation
# sample which itself embeds bash.
#
# The counts collapsed 11, 6, 4, 4, 4, 2, 1 -> 0. That is what a real repair
# looks like here, per the ratchet note above.
#
# **`packaging/README.md` is NOT the same defect and is split out (#1051).**
# Its strays are not a nested sample: `792bd921` ("comprehensive markdownlint
# fixes") took the file from 336 to 785 lines by DUPLICATING fenced content as
# bare text and leaving a stray ```text opener after each copy. Repairing it
# means deleting duplicated prose, not promoting a container, and that is a
# different reading with a different risk.
KNOWN_BROKEN: dict[str, tuple[int, bool]] = {
    "packaging/README.md": (7, True),
}


def _checker():
    """Reuse check_doc_links' FENCE_PATTERN and tracked-file definition."""
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fence_health(text: str, fence_pattern) -> tuple[int, bool]:
    """(info-string closers, ends inside an unclosed fence), CommonMark rules."""
    opener: str | None = None
    bad = 0
    for line in text.splitlines():
        fence = fence_pattern.match(line)
        if not fence:
            continue
        marker, info = fence.group("marker"), fence.group("info")
        if opener is None:
            opener = marker
            continue
        same = marker[0] == opener[0] and len(marker) >= len(opener)
        if same and not info:
            opener = None
        elif same and info:
            bad += 1
    return bad, opener is not None


def _survey() -> dict[str, tuple[int, bool]]:
    mod = _checker()
    docs = sorted(p for p in mod.tracked_paths() if p.endswith(".md"))
    # Coverage from git, so a gitignored file cannot make this red locally and
    # green in CI.
    assert len(docs) >= 150, f"doc discovery looks wrong: {len(docs)}"
    health = {}
    for rel in docs:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        bad, ends_open = _fence_health(text, mod.FENCE_PATTERN)
        if bad or ends_open:
            health[rel] = (bad, ends_open)
    return health


def test_no_tracked_markdown_closes_a_fence_with_an_info_string() -> None:
    """Regression for #740: a fence that does not close swallows the document."""
    health = _survey()

    new = {rel: v for rel, v in health.items() if rel not in KNOWN_BROKEN}
    assert not new, (
        "a code fence is closed with an info string, so the block never closes "
        "and everything after it renders as code (#740). A closing fence may "
        "carry only spaces:\n"
        + "\n".join(
            f"  {rel}: {bad} info-string closer(s)"
            + (", ends inside an unclosed fence" if ends_open else "")
            for rel, (bad, ends_open) in sorted(new.items())
        )
    )


def test_the_known_broken_inventory_is_exact() -> None:
    """The eight refused files may not drift, in either direction (#1044).

    Recording them as "known broken" without a count would let them get worse
    silently. Requiring the exact count means a repair has to come back here and
    delete its entry, which is the only thing that keeps this list honest.
    """
    health = _survey()

    worse = {
        rel: (KNOWN_BROKEN[rel], health.get(rel))
        for rel in KNOWN_BROKEN
        if health.get(rel, (0, False))[0] > KNOWN_BROKEN[rel][0]
    }
    assert not worse, f"a recorded file got worse: {worse}"

    fixed = {
        rel: (KNOWN_BROKEN[rel], health.get(rel, (0, False)))
        for rel in KNOWN_BROKEN
        if health.get(rel, (0, False)) != KNOWN_BROKEN[rel]
    }
    assert not fixed, (
        "a file in KNOWN_BROKEN no longer matches its recorded state. If it was "
        "repaired, delete its entry here (that is the point of recording the "
        "count):\n"
        + "\n".join(
            f"  {rel}: recorded {was}, measured {now}"
            for rel, (was, now) in sorted(fixed.items())
        )
    )
