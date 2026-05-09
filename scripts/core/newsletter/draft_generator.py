"""Newsletter draft generator for JMo Security.

Assembles the full HTML + plain-text content for a JMo Updates broadcast from
three input sources, producing a static file pair that can be reviewed before
being uploaded to Resend as a broadcast draft.

Inputs
------
1. **Release notes** — pulled from the repo `CHANGELOG.md` for either a single
   version (`version="1.0.5"`) or every release whose header date falls inside
   a `[date_range_start, date_range_end]` window.
2. **Customer story** — optional markdown file (default
   `dev-only/customer-stories/active.md`). The directory `dev-only/` is
   gitignored, so customer stories live outside source control by design — see
   the package README for the convention. When the file is missing, the
   customer-story section is omitted from the rendered email.
3. **Community CTA** — hard-coded in `template.html` (see
   `scripts/core/newsletter/template.html`).

Substitution layers
-------------------
The HTML template has two distinct substitution layers:

- **Build-time (Python)**: `${name}` placeholders that this module fills in
  when the draft is assembled (version, release body, customer-story HTML).
- **Send-time (Resend)**: `{{{property|fallback}}}` triple-brace placeholders
  that Resend hydrates per-recipient when the broadcast fires (e.g.
  `{{{first_name|there}}}`, `{{{unsubscribe}}}`). These are passed through
  untouched.

CLI
---
::

    # Default: most-recent CHANGELOG release, default customer-story path
    python -m scripts.core.newsletter.draft_generator \\
        --output-dir results/newsletter-drafts

    # Date-range mode (all releases whose header date is in [start, end])
    python -m scripts.core.newsletter.draft_generator \\
        --start 2026-04-01 --end 2026-04-30 \\
        --output-dir results/newsletter-drafts

    # Skip the customer-story section explicitly
    python -m scripts.core.newsletter.draft_generator \\
        --no-customer-story --output-dir /tmp

The static files written are review-ready: open the `.html` in a browser, the
`.txt` in any plain editor. They are NOT automatically uploaded to Resend; the
companion module `scripts/core/newsletter_broadcast.py` handles broadcast
creation and is invoked separately once the content has been reviewed.
"""

from __future__ import annotations

import argparse
import datetime
import html
import logging
import re
import string
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_TEMPLATE = PACKAGE_DIR / "template.html"
DEFAULT_CHROME = REPO_ROOT / "docs/brand/templates/email-chrome.html"
DEFAULT_CUSTOMER_STORY = REPO_ROOT / "dev-only" / "customer-stories" / "active.md"

# Inline style constants — values derived from docs/brand/tokens.css.
# Inlined here because email clients strip <style> blocks.
_EMAIL_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif"
_H2_STYLE = (
    f"font-size:15px;color:#1976d2;text-transform:uppercase;letter-spacing:0.5px;"
    f"margin:28px 0 10px;border-bottom:1px solid #eeeeee;padding-bottom:6px;"
    f"font-family:{_EMAIL_FONT};"
)
_P_STYLE = f"margin:0 0 14px;font-size:15px;color:#424242;font-family:{_EMAIL_FONT};"
_UL_STYLE = "padding-left:20px;margin:0 0 14px;"
_LI_STYLE = f"margin-bottom:8px;font-size:15px;color:#424242;font-family:{_EMAIL_FONT};"
_STRONG_STYLE = "color:#212121;"
_CODE_STYLE = (
    "font-family:ui-monospace,'SF Mono','Cascadia Code',monospace;"
    "background:#f5f5f5;padding:2px 6px;border-radius:4px;font-size:13px;"
)
_A_STYLE = "color:#1976d2;text-decoration:none;"

# Chrome {{var}} → string.Template ${var} mapping.
# Send-time Resend placeholders become {{{triple-brace}}} which string.Template ignores.
_CHROME_VAR_MAP = (
    ("{{unsubscribe_url}}", "{{{unsubscribe}}}"),
    ("{{preferences_url}}", "{{{preferences_url}}}"),
    ("{{subject}}", "${subject}"),
    ("{{preheader}}", "${preheader}"),
    ("{{issue_label}}", "${issue_label}"),
    ("{{sender_address}}", "${sender_address}"),
)

SENDER_ADDRESS_PLACEHOLDER = (
    "JMo Security Tools &middot; open-source project &middot; "
    '<a href="https://jmotools.com" style="color:#616161;">jmotools.com</a>'
)


@dataclass(frozen=True)
class ReleaseEntry:
    """A single CHANGELOG release block parsed from `CHANGELOG.md`."""

    version: str
    release_date: str
    raw_markdown: str


@dataclass(frozen=True)
class NewsletterDraft:
    """Assembled draft ready for review or Resend upload."""

    subject: str
    html: str
    text: str
    version: str
    release_date: str
    html_path: Optional[Path] = None
    text_path: Optional[Path] = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_draft(
    *,
    output_dir: Optional[Path] = None,
    date_range_start: Optional[datetime.date] = None,
    date_range_end: Optional[datetime.date] = None,
    customer_story_path: Optional[Path] = None,
    version: Optional[str] = None,
    template_path: Optional[Path] = None,
    chrome_path: Optional[Path] = None,
    repo_root: Optional[Path] = None,
    include_customer_story: bool = True,
) -> NewsletterDraft:
    """Build a newsletter draft and optionally write the HTML + text files.

    Resolution order for which release(s) to include:

    1. If ``version`` is given, include only that single release.
    2. Else if a date range is given, include every release whose header date
       is inside ``[date_range_start, date_range_end]`` (inclusive).
    3. Else default to the single most recent release in the changelog.

    The function never raises when the customer-story file is missing; it
    silently omits that block. Pass ``include_customer_story=False`` to skip
    even when the file exists.
    """
    repo = repo_root or REPO_ROOT
    template = template_path or DEFAULT_TEMPLATE
    chrome = chrome_path or DEFAULT_CHROME

    template_body = template.read_text(encoding="utf-8")
    chrome_text = chrome.read_text(encoding="utf-8")
    changelog_text = (repo / "CHANGELOG.md").read_text(encoding="utf-8")

    if version:
        entries = [_extract_release_by_version(changelog_text, version)]
    elif date_range_start or date_range_end:
        entries = _extract_releases_by_date_range(
            changelog_text,
            start=date_range_start,
            end=date_range_end,
        )
        if not entries:
            raise RuntimeError(
                f"No CHANGELOG releases found between "
                f"{date_range_start} and {date_range_end}"
            )
    else:
        entries = [_most_recent_release(changelog_text)]

    primary = entries[0]
    release_body_html = "\n\n".join(
        _markdown_to_email_html(e.raw_markdown) for e in entries
    )

    customer_story_md = None
    if include_customer_story:
        story_path = customer_story_path or DEFAULT_CUSTOMER_STORY
        if story_path.exists():
            customer_story_md = story_path.read_text(encoding="utf-8")
            logger.info("Loaded customer story from %s", story_path)
        else:
            logger.info(
                "No customer-story file at %s — section will be omitted", story_path
            )

    customer_story_block = _render_customer_story_block(customer_story_md)
    customer_quote = _extract_customer_quote(customer_story_md)

    subject = _build_subject(primary, customer_quote)
    headline_version = (
        primary.version if len(entries) == 1 else _multi_version_label(entries)
    )
    badge_label = "Release Notes" if len(entries) == 1 else "Release Round-Up"

    preheader = _build_preheader(primary, entries)
    issue_label = (
        f"v{primary.version}" if len(entries) == 1 else _multi_version_label(entries)
    )

    # Merge newsletter body into chrome content slot (standalone line only —
    # the chrome file comment also contains the slot marker inline).
    combined = re.sub(
        r"(?m)^\s*<!--CONTENT-->\s*$",
        lambda _: template_body,
        chrome_text,
        count=1,
    )
    for old, new in _CHROME_VAR_MAP:
        combined = combined.replace(old, new)

    rendered_html = string.Template(combined).substitute(
        subject=html.escape(subject),
        preheader=html.escape(preheader),
        issue_label=html.escape(issue_label),
        badge_label=html.escape(badge_label),
        headline=html.escape(f"JMo Security v{headline_version}"),
        meta_line=_meta_line(entries),
        release_body_html=release_body_html,
        customer_story_block=customer_story_block,
        primary_cta_url=(
            f"https://github.com/jimmy058910/jmo-security-repo/releases/tag/v{primary.version}"
        ),
        primary_cta_label=f"View v{primary.version} on GitHub",
        sender_address=SENDER_ADDRESS_PLACEHOLDER,
    )

    plain_text = _html_to_plain_text(rendered_html)

    html_path: Optional[Path] = None
    text_path: Optional[Path] = None
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        slug = primary.version.replace(".", "_")
        html_path = output_dir / f"newsletter-v{slug}.html"
        text_path = output_dir / f"newsletter-v{slug}.txt"
        html_path.write_text(rendered_html, encoding="utf-8")
        text_path.write_text(plain_text, encoding="utf-8")
        logger.info("Wrote draft HTML to %s", html_path)
        logger.info("Wrote draft text to %s", text_path)

    return NewsletterDraft(
        subject=subject,
        html=rendered_html,
        text=plain_text,
        version=primary.version,
        release_date=primary.release_date,
        html_path=html_path,
        text_path=text_path,
    )


# ---------------------------------------------------------------------------
# CHANGELOG parsing
# ---------------------------------------------------------------------------

_RELEASE_HEADER_RE = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?",
    re.MULTILINE,
)


def _iter_release_entries(changelog_text: str) -> Iterator[ReleaseEntry]:
    """Yield ``ReleaseEntry`` objects for every ``## [x.y.z] - YYYY-MM-DD`` block.

    Entries with no date (e.g. the ``## [Unreleased]`` placeholder) are skipped.
    """
    matches = list(_RELEASE_HEADER_RE.finditer(changelog_text))
    for idx, match in enumerate(matches):
        version = match.group("version").strip()
        date_str = match.group("date")
        if not date_str:
            continue  # skip "Unreleased"
        start = match.start()
        end = (
            matches[idx + 1].start() if idx + 1 < len(matches) else len(changelog_text)
        )
        yield ReleaseEntry(
            version=version,
            release_date=date_str,
            raw_markdown=changelog_text[start:end].strip(),
        )


def _extract_release_by_version(changelog_text: str, version: str) -> ReleaseEntry:
    for entry in _iter_release_entries(changelog_text):
        if entry.version == version:
            return entry
    raise RuntimeError(f"CHANGELOG.md has no entry for version {version!r}")


def _extract_releases_by_date_range(
    changelog_text: str,
    *,
    start: Optional[datetime.date],
    end: Optional[datetime.date],
) -> list[ReleaseEntry]:
    out: list[ReleaseEntry] = []
    for entry in _iter_release_entries(changelog_text):
        try:
            entry_date = datetime.date.fromisoformat(entry.release_date)
        except ValueError:
            continue
        if start and entry_date < start:
            continue
        if end and entry_date > end:
            continue
        out.append(entry)
    out.sort(key=lambda e: e.release_date, reverse=True)
    return out


def _most_recent_release(changelog_text: str) -> ReleaseEntry:
    for entry in _iter_release_entries(changelog_text):
        return entry  # _iter_release_entries yields in CHANGELOG order
    raise RuntimeError("CHANGELOG.md has no dated release entries")


# ---------------------------------------------------------------------------
# Markdown -> email HTML
# ---------------------------------------------------------------------------


def _markdown_to_email_html(md: str) -> str:
    r"""Convert CHANGELOG markdown to email-safe HTML.

    Handles ``### subhead``, ``## subhead`` (skipping the top-level
    ``## [version]`` line), ``**bold**``, ``\`code\```, ``[text](url)`` links,
    and ``-``/``*`` bullets. Anything more exotic falls through as plain text.
    """
    lines = md.split("\n")
    out: list[str] = []
    in_list = False

    for line in lines:
        if _RELEASE_HEADER_RE.match(line):
            continue

        if line.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f'<h2 style="{_H2_STYLE}">{html.escape(line[4:].strip())}</h2>')
            continue

        if line.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append(f'<h2 style="{_H2_STYLE}">{html.escape(line[3:].strip())}</h2>')
            continue

        if line.startswith("- ") or line.startswith("* "):
            if not in_list:
                out.append(f'<ul style="{_UL_STYLE}">')
                in_list = True
            out.append(f'  <li style="{_LI_STYLE}">{_inline_md(line[2:])}</li>')
            continue

        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue

        if in_list:
            if line.startswith("  "):
                continue  # skip nested-list continuations
            out.append("</ul>")
            in_list = False

        text = _inline_md(line.strip())
        if text:
            out.append(f'<p style="{_P_STYLE}">{text}</p>')

    if in_list:
        out.append("</ul>")

    return "\n".join(out)


def _inline_md(text: str) -> str:
    """Apply inline markdown (bold, code, links) to an already-escaped fragment."""
    text = html.escape(text)
    text = re.sub(
        r"\*\*(.+?)\*\*",
        rf'<strong style="{_STRONG_STYLE}">\1</strong>',
        text,
    )
    text = re.sub(
        r"`([^`]+)`",
        rf'<code style="{_CODE_STYLE}">\1</code>',
        text,
    )
    text = re.sub(
        r"\[([^\]]+)\]\(([^)\s]+)\)",
        rf'<a href="\2" style="{_A_STYLE}">\1</a>',
        text,
    )
    return text


# ---------------------------------------------------------------------------
# Customer story
# ---------------------------------------------------------------------------


def _render_customer_story_block(story_md: Optional[str]) -> str:
    if not story_md or not story_md.strip():
        return ""
    body_html = _markdown_to_email_html(story_md)
    return f'<h2 style="{_H2_STYLE}">Customer Story</h2>\n{body_html}\n'


def _extract_customer_quote(story_md: Optional[str]) -> Optional[str]:
    """Return a short subject-line-friendly quote pulled from the story.

    Strategy: first markdown blockquote line (``>``), trimmed to ~60 chars.
    Falls back to the first non-heading sentence if no blockquote is present.
    """
    if not story_md:
        return None
    for line in story_md.splitlines():
        stripped = line.strip()
        if stripped.startswith(">"):
            quote = stripped.lstrip(">").strip().strip('"').strip()
            if quote:
                return _truncate_subject_fragment(quote)
    for line in story_md.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", ">", "-", "*")):
            return _truncate_subject_fragment(stripped)
    return None


def _truncate_subject_fragment(text: str, max_len: int = 60) -> str:
    if len(text) <= max_len:
        return text
    cut = text[: max_len - 1].rsplit(" ", 1)[0]
    return f"{cut}\u2026"


# ---------------------------------------------------------------------------
# Subject line and meta
# ---------------------------------------------------------------------------


def _build_subject(primary: ReleaseEntry, customer_quote: Optional[str]) -> str:
    if customer_quote:
        return f"JMo v{primary.version} released \u2014 {customer_quote}"
    fallback_tagline = _first_subsection_title(primary.raw_markdown) or "what's new"
    return f"JMo v{primary.version} released \u2014 {fallback_tagline}"


def _first_subsection_title(release_md: str) -> Optional[str]:
    for line in release_md.splitlines():
        if line.startswith("### "):
            return line[4:].strip()
    return None


def _meta_line(entries: list[ReleaseEntry]) -> str:
    if len(entries) == 1:
        e = entries[0]
        return (
            f"Released {html.escape(e.release_date)} &nbsp;&middot;&nbsp; "
            f'<a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md">'
            f"Full changelog</a>"
        )
    versions = ", ".join(f"v{e.version}" for e in entries)
    earliest = entries[-1].release_date
    latest = entries[0].release_date
    return (
        f"Releases {html.escape(versions)} ({html.escape(earliest)} \u2192 "
        f"{html.escape(latest)}) &nbsp;&middot;&nbsp; "
        f'<a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md">'
        f"Full changelog</a>"
    )


def _multi_version_label(entries: list[ReleaseEntry]) -> str:
    return f"{entries[-1].version} \u2192 {entries[0].version}"


def _build_preheader(primary: ReleaseEntry, entries: list[ReleaseEntry]) -> str:
    """Build hidden inbox-preview text (kept under ~90 chars)."""
    if len(entries) == 1:
        tag = _first_subsection_title(primary.raw_markdown) or "what's new"
        return f"JMo Security v{primary.version} is out \u2014 {tag}"
    versions = _multi_version_label(entries)
    return f"JMo Security {versions} \u2014 catch up on what shipped"


# ---------------------------------------------------------------------------
# HTML -> plain text fallback
# ---------------------------------------------------------------------------

_BLOCK_TAGS_TO_NEWLINE = (
    "p",
    "div",
    "br",
    "li",
    "tr",
    "h1",
    "h2",
    "h3",
    "h4",
    "blockquote",
    "ul",
    "ol",
)


def _html_to_plain_text(rendered_html: str) -> str:
    """Best-effort HTML -> plain-text conversion for the email fallback body."""
    text = rendered_html
    text = re.sub(
        r"<!--[\s\S]*?-->", "", text
    )  # strip HTML comments (e.g. chrome header)
    text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<head[\s\S]*?</head>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"<script[\s\S]*?</script>", "", text, flags=re.IGNORECASE)

    text = re.sub(
        r"<h1[^>]*>(.*?)</h1>",
        lambda m: f"\n\n{m.group(1).upper()}\n",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"<h2[^>]*>(.*?)</h2>",
        lambda m: f"\n\n-- {m.group(1)} --\n",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"<li[^>]*>(.*?)</li>",
        lambda m: f"\n  - {m.group(1).strip()}",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r'<a [^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        r"\2 (\1)",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    for tag in _BLOCK_TAGS_TO_NEWLINE:
        text = re.sub(rf"</?{tag}[^>]*>", "\n", text, flags=re.IGNORECASE)

    text = re.sub(r"<[^>]+>", "", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]+", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip() + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_date(value: str) -> datetime.date:
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Expected YYYY-MM-DD, got {value!r}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a JMo newsletter draft (HTML + plain text).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir", type=Path, help="Directory to write the .html + .txt files"
    )
    parser.add_argument(
        "--start", type=_parse_date, help="Date-range start (YYYY-MM-DD)"
    )
    parser.add_argument("--end", type=_parse_date, help="Date-range end (YYYY-MM-DD)")
    parser.add_argument(
        "--version", help="Pin to a single CHANGELOG version (e.g. 1.0.5)"
    )
    parser.add_argument(
        "--customer-story", type=Path, help="Path to a customer-story markdown file"
    )
    parser.add_argument(
        "--no-customer-story",
        action="store_true",
        help="Do not include the customer-story section even if the default file exists",
    )
    parser.add_argument(
        "--print",
        action="store_true",
        help="Also print the assembled subject line and plain text to stdout",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _build_parser().parse_args(argv)

    try:
        draft = generate_draft(
            output_dir=args.output_dir,
            date_range_start=args.start,
            date_range_end=args.end,
            version=args.version,
            customer_story_path=args.customer_story,
            include_customer_story=not args.no_customer_story,
        )
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Subject:    {draft.subject}")
    print(f"Version:    {draft.version}  ({draft.release_date})")
    if draft.html_path:
        print(f"HTML:       {draft.html_path}")
    if draft.text_path:
        print(f"Plain text: {draft.text_path}")
    if args.print:
        print("\n--- PLAIN TEXT ---\n")
        print(draft.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
