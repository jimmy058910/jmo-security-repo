#!/usr/bin/env python3
"""Guard: ci.yml's branch-protection comment must name the right rulesets.

Regression for #1038.

The header block above `quick-checks` is the instruction surface an agent reads
before deciding whether a red check blocks a merge. It said:

    `dev` has NO ruleset at all, so a PR into `dev` [...] has no required check
    whatsoever.

and ended by telling the reader to verify with
``gh api repos/:owner/:repo/rulesets/9147592`` -- **main's** ruleset. Both halves
mislead in the same direction: someone asking "can a red check block a merge into
`dev`?" reads main's rules and concludes the opposite of the truth.

The first half was true when written and false from 2026-08-27, when #993 created
a ruleset on `dev` to stop auto-delete-on-merge eating the branch, which it had
done three times.

**The load-bearing half survives the correction and is asserted here**: `dev` has
no *required status checks*, which is what makes `phase-audit`, `policy-gate`,
`docker-smoke` and `dashboard-smoke` visible-but-non-blocking there.

## What is asserted, and what cannot be

The rules themselves live on GitHub, not in this repository, so a test cannot
read them without the network. What it can do is pin the measurement and check
that the comment agrees with it -- the same shape as the fence inventory in
``test_markdown_fences_close.py``. Measured 2026-08-28::

    $ gh api repos/jimmy058910/jmo-security-repo/rulesets \\
        -q '.[] | "\\(.id) \\(.name)"'
    21702985 Protect dev branch
    9147592  Protect main branch

    $ gh api .../rulesets/21702985 -q '[.rules[].type] | join(", ")'
    deletion, non_fast_forward

    $ gh api .../rulesets/9147592  -q '[.rules[].type] | join(", ")'
    required_status_checks, pull_request, non_fast_forward, deletion

If a ruleset changes on GitHub this guard will not notice, and saying so is more
useful than implying otherwise. What it does catch is the failure that actually
happened: a comment drifting away from a recorded fact, and a verification
command pointing at the wrong branch's ruleset.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# branch -> (ruleset id, whether it requires status checks). Measured 2026-08-28
# with the `gh api` calls in the module docstring.
RULESETS: dict[str, tuple[str, bool]] = {
    "main": ("9147592", True),
    "dev": ("21702985", False),
}


def _header_comment() -> str:
    """The comment block above the first job, which is the instruction surface."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    start = text.index("WHAT ACTUALLY GATES A MERGE")
    end = text.index("# Fast validation checks", start)
    block = text[start:end]
    assert len(block) > 500, "header comment block looks truncated"
    return block


def test_the_comment_names_a_ruleset_for_every_protected_branch() -> None:
    """Regression for #1038: it claimed `dev` had none."""
    block = _header_comment()

    for branch, (ruleset_id, _) in RULESETS.items():
        assert ruleset_id in block, (
            f"ci.yml's header comment does not name ruleset {ruleset_id}, which "
            f"governs `{branch}`. A reader cannot check a ruleset this file does "
            "not name."
        )

    # The defect was not a missing id -- 9147592 was there all along -- but a
    # claim that a branch had no ruleset at all.
    for branch in RULESETS:
        denial = re.search(
            rf"`{branch}`[^.\n]{{0,60}}\bno ruleset\b", block, re.IGNORECASE
        )
        assert not denial, (
            f"the comment says `{branch}` has no ruleset, but "
            f"{RULESETS[branch][0]} governs it: {denial.group(0)!r}"
        )


def test_each_verification_command_points_at_its_own_branch() -> None:
    """The `gh api .../rulesets/<id>` example must match the branch beside it.

    #1038's second half: the block told a reader checking `dev` to query
    `rulesets/9147592`, which is main's. Following that instruction produces the
    opposite of the truth, which is worse than no instruction.
    """
    block = _header_comment()
    pairs = re.findall(r"(\w+)\s*->\s*`gh api [^`]*rulesets/(\d+)`", block)
    assert pairs, "the comment no longer shows a per-branch verification command"

    expected = {branch: ruleset_id for branch, (ruleset_id, _) in RULESETS.items()}
    found = dict(pairs)
    assert found == expected, (
        f"a verification command names the wrong branch's ruleset: {found} "
        f"against {expected}"
    )


def test_the_true_half_of_the_claim_survived() -> None:
    """`dev` has no required status checks, and the comment must still say so.

    This is the part that decides whether an agent treats a red `phase-audit` as
    blocking. A correction that dropped it would fix a stale fact by deleting a
    live one.
    """
    block = _header_comment()
    assert not RULESETS["dev"][
        1
    ], "recorded state says dev requires checks; update this test"
    assert re.search(
        r"`dev`[\s\S]{0,400}?NO REQUIRED\s*\n?\s*#\s*STATUS CHECKS", block
    ) or re.search(r"NO REQUIRED STATUS CHECKS", block), (
        "the comment no longer states that `dev` has no required status checks, "
        "which is what makes phase-audit and policy-gate advisory there"
    )
