#!/usr/bin/env python3
"""Tests for `scripts/dev/check_doc_links.py`.

The interesting half is fragment validation. A link's *file* half fails loudly
when it is wrong - the page 404s. Its `#fragment` half fails silently: a browser
that cannot find the anchor scrolls to the top of the page, which is
indistinguishable from a link that worked. So a wrong anchor survives every
form of review that consists of clicking it.
"""

from __future__ import annotations

from scripts.dev.check_doc_links import (
    check_text,
    collect_anchors,
    heading_anchor,
)


def test_lowercases_and_hyphenates_spaces() -> None:
    assert heading_anchor("Scan Profiles") == "scan-profiles"


def test_drops_punctuation_rather_than_hyphenating_it() -> None:
    """`:` vanishes; the space beside it is what becomes the hyphen.

    Order matters. Hyphenating before stripping would yield `setup--fast`.
    """
    assert heading_anchor("Setup: Fast Path") == "setup-fast-path"
    assert heading_anchor("What's New?") == "whats-new"
    assert heading_anchor("jmo.yml Key Settings") == "jmoyml-key-settings"


def test_keeps_underscores_and_existing_hyphens() -> None:
    """GitHub's filter strips everything outside `[\\w- ]`, and `_` is a word char."""
    assert heading_anchor("per_tool overrides") == "per_tool-overrides"
    assert heading_anchor("Pre-commit Order") == "pre-commit-order"


def test_backticks_and_bold_need_no_special_case() -> None:
    """They are punctuation, so the same filter that drops `:` drops them."""
    assert heading_anchor("`jmo tools check` MANUAL state") == (
        "jmo-tools-check-manual-state"
    )
    assert heading_anchor("**Bold** text") == "bold-text"


def test_a_link_renders_as_its_text_only() -> None:
    """A link is the one construct the punctuation filter gets wrong alone.

    Stripping punctuation from `[the guide](docs/USER_GUIDE.md)` leaves the URL
    glued to the text (`the-guidedocsuser_guidemd`). No heading in this repo is
    a link today; this exists so that adding one does not make the checker
    report a *working* anchor as broken.
    """
    assert heading_anchor("See [the guide](docs/USER_GUIDE.md)") == "see-the-guide"


def test_a_dropped_character_leaves_its_spaces_behind() -> None:
    """Removing an emoji between two words yields a DOUBLE hyphen.

    The filter deletes the character but not the spaces around it, and both
    spaces then become hyphens. 117 headings in this repo carry an emoji or an
    em-dash, so getting this wrong would mis-derive every one of them.
    """
    assert heading_anchor("Fast Profile [OK] Works") == "fast-profile-ok-works"
    assert heading_anchor("Fast Profile ✅ Works") == "fast-profile--works"
    assert heading_anchor("B.2 Platform choice — Cloudflare") == (
        "b2-platform-choice--cloudflare"
    )


def test_keeps_unicode_letters_that_are_not_punctuation() -> None:
    """The filter is `\\w`-based, not ASCII-based: an accent is a word char."""
    assert heading_anchor("Café Settings") == "café-settings"


def test_keeps_the_invisible_selector_an_emoji_leaves_behind() -> None:
    """`⚠️` is two code points, and GitHub drops only the first.

    U+FE0F VARIATION SELECTOR-16 is a Unicode *mark*, and GitHub's filter keeps
    `\\p{Word}` - which in Ruby includes marks. Python's `\\w` does not, so a
    naive port silently disagrees. Measured against `gh api markdown`, which
    renders `packaging/WINDOWS_COMPATIBILITY.md` with the selector retained.

    This direction matters: anyone copying an anchor from GitHub's own
    heading-link button gets the selector, and dropping it would make the
    checker redden CI over a link that works.
    """
    assert heading_anchor("Balanced Profile ⚠️ Partially Works") == (
        "balanced-profile-️-partially-works"
    )


def test_keeps_the_zero_width_joiner_inside_an_emoji_sequence() -> None:
    """U+200D is `\\p{Join_Control}`, which GitHub's filter also keeps."""
    assert heading_anchor("Team \U0001f468‍\U0001f4bb Notes") == ("team-‍-notes")


def test_collects_headings_at_every_level() -> None:
    doc = "# Top\n\nprose\n\n### Deeply Nested\n"
    assert collect_anchors(doc) == {"top", "deeply-nested"}


def test_repeated_heading_text_gets_a_numeric_suffix() -> None:
    """GitHub numbers the *later* occurrences, leaving the first bare.

    Both anchors are valid targets, so a checker that recorded only one would
    report a working link as broken.
    """
    doc = "## Usage\n\n## Usage\n\n## Usage\n"
    assert collect_anchors(doc) == {"usage", "usage-1", "usage-2"}


def test_ignores_hash_lines_inside_a_code_fence() -> None:
    """A shell comment is not a heading, and must not become a valid anchor.

    Without this the checker accepts links to anchors that do not exist -
    3873 headings in this repo sit alongside a great many `# comment` lines.
    """
    doc = "# Real\n\n```bash\n# Not A Heading\n```\n"
    assert collect_anchors(doc) == {"real"}


def test_requires_a_space_after_the_hashes() -> None:
    """`#!/usr/bin/env` and `#4 issue refs` are not headings."""
    doc = "#!/usr/bin/env python\n\n#719 was merged\n\n# Real\n"
    assert collect_anchors(doc) == {"real"}


# --------------------------------------------------------------------------
# Fragment validation
# --------------------------------------------------------------------------

TRACKED = {"README.md", "docs/GUIDE.md", "scripts/core/thing.py"}
ANCHORS = {
    "README.md": {"install", "usage"},
    "docs/GUIDE.md": {"configuration"},
}


def test_a_fragment_naming_a_real_heading_is_accepted() -> None:
    problems = check_text(
        "README.md", "See [config](docs/GUIDE.md#configuration).", TRACKED, ANCHORS
    )
    assert problems == []


def test_a_fragment_naming_no_heading_is_reported() -> None:
    """The failure this whole change exists to catch.

    The file resolves, so every existing check passes; the browser silently
    scrolls to the top of the page instead of reporting anything.
    """
    problems = check_text(
        "README.md", "See [config](docs/GUIDE.md#confguration).", TRACKED, ANCHORS
    )
    assert len(problems) == 1
    assert "NO ANCHOR" in problems[0]
    assert "docs/GUIDE.md#confguration" in problems[0]


def test_a_bare_fragment_resolves_against_its_own_file() -> None:
    """`[Usage](#usage)` is the dominant shape - every table of contents."""
    assert check_text("README.md", "[Usage](#usage)", TRACKED, ANCHORS) == []

    problems = check_text("README.md", "[Usage](#usaeg)", TRACKED, ANCHORS)
    assert len(problems) == 1
    assert "NO ANCHOR" in problems[0]


def test_a_line_citation_is_not_an_anchor() -> None:
    """`thing.py#L42` points at source on the web, not at a heading."""
    assert (
        check_text("README.md", "[l](scripts/core/thing.py#L42)", TRACKED, ANCHORS)
        == []
    )


def test_a_fragment_on_a_non_markdown_target_is_not_checked() -> None:
    """Only Markdown grows headings, so only Markdown has anchors to verify."""
    assert (
        check_text("README.md", "[x](scripts/core/thing.py#frag)", TRACKED, ANCHORS)
        == []
    )


def test_a_fragment_is_not_checked_when_the_file_itself_is_broken() -> None:
    """One dead reference, not two. The path is the fix; the anchor is noise."""
    problems = check_text("README.md", "[x](docs/GONE.md#anything)", TRACKED, ANCHORS)
    assert len(problems) == 1
    assert "BROKEN" in problems[0]


def test_a_fragment_inside_a_code_fence_is_a_sample_not_a_link() -> None:
    """Skill files quote broken links on purpose, to teach what one looks like."""
    doc = "```md\n[x](docs/GUIDE.md#nope)\n```\n"
    assert check_text("README.md", doc, TRACKED, ANCHORS) == []
