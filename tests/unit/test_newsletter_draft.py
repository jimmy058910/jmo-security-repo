"""Unit tests for ``scripts.core.newsletter.draft_generator``.

Covers parser, subject-line formula, customer-story integration, plain-text
fallback, and the safety property that Resend ``{{{property|fallback}}}``
placeholders survive Python ``string.Template`` substitution untouched.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from scripts.core.newsletter import draft_generator as dg
from scripts.core.newsletter.draft_generator import generate_draft

CHANGELOG_FIXTURE = """\
# Changelog

## [Unreleased]

## [2.0.0] - 2026-06-15

### Summary

Major release introducing **bold things**.

### Added

- New `feature_x` flag
- [Docs link](https://example.com/docs)

## [1.9.0] - 2026-05-01

### Summary

Smaller follow-up.

### Fixed

- Edge case in parser
"""

# Minimal chrome that exercises all {{var}} placeholders the generator maps.
MIN_CHROME = """\
<!DOCTYPE html>
<html lang="en">
<head><title>{{subject}}</title></head>
<body>
<div style="display:none;">{{preheader}}</div>
<table>
  <tr>
    <td>JMo Security</td>
    <td>{{issue_label}}</td>
  </tr>
  <tr>
    <td>
      <!--CONTENT-->
    </td>
  </tr>
  <tr>
    <td>
      <a href="{{unsubscribe_url}}">Unsubscribe</a>
      <a href="{{preferences_url}}">Preferences</a>
      <p>{{sender_address}}</p>
    </td>
  </tr>
</table>
</body>
</html>
"""

# Newsletter body only — injected into MIN_CHROME at build time.
MIN_TEMPLATE = """\
<p>Hey {{{first_name|there}}},</p>
<h1>${headline}</h1>
<div>${meta_line}</div>
<div class="badge">${badge_label}</div>
<section>${release_body_html}</section>
${customer_story_block}
<a href="${primary_cta_url}">${primary_cta_label}</a>
"""


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    """Build a tiny pretend-repo with a CHANGELOG, template body, and chrome."""
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG_FIXTURE, encoding="utf-8")
    (tmp_path / "template.html").write_text(MIN_TEMPLATE, encoding="utf-8")
    (tmp_path / "chrome.html").write_text(MIN_CHROME, encoding="utf-8")
    return tmp_path


def test_parse_iter_skips_unreleased():
    entries = list(dg._iter_release_entries(CHANGELOG_FIXTURE))
    versions = [e.version for e in entries]
    assert versions == ["2.0.0", "1.9.0"]


def test_extract_release_by_version_known():
    entry = dg._extract_release_by_version(CHANGELOG_FIXTURE, "1.9.0")
    assert entry.version == "1.9.0"
    assert entry.release_date == "2026-05-01"
    assert "Edge case in parser" in entry.raw_markdown


def test_extract_release_by_version_unknown_raises():
    with pytest.raises(RuntimeError, match="no entry"):
        dg._extract_release_by_version(CHANGELOG_FIXTURE, "9.9.9")


def test_extract_releases_by_date_range_inclusive():
    entries = dg._extract_releases_by_date_range(
        CHANGELOG_FIXTURE,
        start=datetime.date(2026, 5, 1),
        end=datetime.date(2026, 6, 15),
    )
    versions = [e.version for e in entries]
    # Sorted newest-first
    assert versions == ["2.0.0", "1.9.0"]


def test_extract_releases_by_date_range_excludes_outside_window():
    entries = dg._extract_releases_by_date_range(
        CHANGELOG_FIXTURE,
        start=datetime.date(2026, 5, 2),
        end=datetime.date(2026, 6, 14),
    )
    assert entries == []


def test_subject_uses_customer_quote_when_present():
    entry = dg._extract_release_by_version(CHANGELOG_FIXTURE, "2.0.0")
    subject = dg._build_subject(entry, customer_quote="caught a real bug")
    assert subject == "JMo v2.0.0 released \u2014 caught a real bug"


def test_subject_falls_back_to_first_subsection_when_no_quote():
    entry = dg._extract_release_by_version(CHANGELOG_FIXTURE, "2.0.0")
    subject = dg._build_subject(entry, customer_quote=None)
    assert subject == "JMo v2.0.0 released \u2014 Summary"


def test_extract_customer_quote_prefers_blockquote():
    md = '> "JMo flagged a hardcoded key two days before audit."\n\n— Engineer'
    quote = dg._extract_customer_quote(md)
    assert quote == "JMo flagged a hardcoded key two days before audit."


def test_extract_customer_quote_truncates_long_lines():
    md = "> " + "x" * 200
    quote = dg._extract_customer_quote(md)
    assert quote is not None
    assert len(quote) <= 60
    assert quote.endswith("\u2026")


def test_extract_customer_quote_returns_none_when_empty():
    assert dg._extract_customer_quote(None) is None
    assert dg._extract_customer_quote("") is None


def test_inline_md_escapes_html_first():
    out = dg._inline_md("<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_inline_md_supports_bold_code_links():
    out = dg._inline_md("**bold** with `code` and [link](https://example.com)")
    assert "<strong" in out and "bold</strong>" in out
    assert "<code" in out and "code</code>" in out
    assert 'href="https://example.com"' in out and ">link</a>" in out


def test_markdown_to_email_html_handles_bullets():
    md = "### Heading\n\n- one\n- two\n\nplain paragraph"
    out = dg._markdown_to_email_html(md)
    assert "Heading</h2>" in out
    assert "<h2" in out
    assert "<ul" in out
    assert "one</li>" in out
    assert "two</li>" in out
    assert "plain paragraph</p>" in out


def test_html_to_plain_text_strips_tags_and_renders_links():
    sample = '<p>Hello <a href="https://example.com">there</a></p>'
    text = dg._html_to_plain_text(sample)
    assert "<p>" not in text
    assert "Hello there (https://example.com)" in text


def test_html_to_plain_text_drops_style_blocks():
    sample = "<style>body { color: red; }</style><p>Visible</p>"
    text = dg._html_to_plain_text(sample)
    assert "color" not in text
    assert "Visible" in text


def test_generate_draft_default_release_only(repo_root: Path, tmp_path: Path):
    out_dir = tmp_path / "drafts"
    draft = generate_draft(
        output_dir=out_dir,
        repo_root=repo_root,
        template_path=repo_root / "template.html",
        chrome_path=repo_root / "chrome.html",
        include_customer_story=False,
    )
    assert draft.version == "2.0.0"
    assert draft.release_date == "2026-06-15"
    assert draft.html_path is not None
    assert draft.text_path is not None
    assert draft.html_path.exists()
    assert draft.text_path.exists()
    assert "Released 2026-06-15" in draft.html
    # Resend send-time placeholders survive untouched
    assert "{{{first_name|there}}}" in draft.html
    assert "{{{unsubscribe}}}" in draft.html
    # Customer story block omitted when not requested
    assert "Customer Story" not in draft.html


def test_generate_draft_with_customer_story(repo_root: Path, tmp_path: Path):
    story_path = tmp_path / "active.md"
    story_path.write_text(
        "# A real story\n\n> Caught a hardcoded key.\n\n— **engineer**",
        encoding="utf-8",
    )
    draft = generate_draft(
        output_dir=tmp_path / "drafts",
        repo_root=repo_root,
        template_path=repo_root / "template.html",
        chrome_path=repo_root / "chrome.html",
        customer_story_path=story_path,
    )
    assert "Customer Story" in draft.html
    assert "Caught a hardcoded key" in draft.html
    # Subject was driven by the customer quote, not the changelog subsection
    assert "Caught a hardcoded key" in draft.subject


def test_generate_draft_missing_story_silently_omits(repo_root: Path, tmp_path: Path):
    draft = generate_draft(
        output_dir=tmp_path / "drafts",
        repo_root=repo_root,
        template_path=repo_root / "template.html",
        chrome_path=repo_root / "chrome.html",
        customer_story_path=tmp_path / "does-not-exist.md",
    )
    assert "Customer Story" not in draft.html


def test_generate_draft_date_range(repo_root: Path, tmp_path: Path):
    draft = generate_draft(
        output_dir=tmp_path / "drafts",
        repo_root=repo_root,
        template_path=repo_root / "template.html",
        chrome_path=repo_root / "chrome.html",
        date_range_start=datetime.date(2026, 4, 1),
        date_range_end=datetime.date(2026, 7, 1),
        include_customer_story=False,
    )
    # Both 1.9.0 and 2.0.0 fall in the window; primary is the most recent
    assert draft.version == "2.0.0"
    assert "v1.9.0" in draft.html  # multi-version meta line


def test_generate_draft_pinned_version(repo_root: Path, tmp_path: Path):
    draft = generate_draft(
        output_dir=tmp_path / "drafts",
        repo_root=repo_root,
        template_path=repo_root / "template.html",
        chrome_path=repo_root / "chrome.html",
        version="1.9.0",
        include_customer_story=False,
    )
    assert draft.version == "1.9.0"
    assert "Edge case in parser" in draft.html


def test_generate_draft_empty_date_range_raises(repo_root: Path, tmp_path: Path):
    with pytest.raises(RuntimeError, match="No CHANGELOG releases"):
        generate_draft(
            output_dir=tmp_path / "drafts",
            repo_root=repo_root,
            template_path=repo_root / "template.html",
            chrome_path=repo_root / "chrome.html",
            date_range_start=datetime.date(2030, 1, 1),
            date_range_end=datetime.date(2030, 12, 31),
            include_customer_story=False,
        )


def test_truncate_subject_fragment_preserves_short_text():
    assert dg._truncate_subject_fragment("short") == "short"


def test_truncate_subject_fragment_word_boundary():
    out = dg._truncate_subject_fragment("the quick brown fox jumps", max_len=15)
    assert out.endswith("\u2026")
    assert " " not in out[-2:-1]  # truncation snapped at word boundary
