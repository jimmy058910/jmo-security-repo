"""Resend Broadcasts integration for JMo Security newsletter digest sends.

Creates draft broadcasts in Resend's dashboard for Jimmy to review and send.
Broadcast = outbound bulk send to an audience (distinct from transactional
welcome emails in email_service.py which use resend.Emails.send()).

Workflow:
  1. Agent calls create_broadcast() or uses the CLI to build an HTML digest
  2. Draft lands in Resend dashboard (https://resend.com/broadcasts)
  3. Jimmy reviews and clicks Send in the dashboard

Environment Variables:
    RESEND_API_KEY: Resend API key (same key used by email_service.py)
    RESEND_AUDIENCE_ID: Resend audience ID for the subscriber list. Find it at
                        https://resend.com/audiences — copy the audience UUID.
    JMO_FROM_EMAIL: Sender address (default: marketing@jmotools.com)

Usage (CLI):
    # Create a v1.0.5 release digest draft — lands in Resend dashboard
    python scripts/core/newsletter_broadcast.py --release-notes

    # Create draft and immediately send (use with care)
    python scripts/core/newsletter_broadcast.py --release-notes --send

    # Custom subject + HTML from file
    python scripts/core/newsletter_broadcast.py \\
        --subject "JMo Security: April DevSecOps round-up" \\
        --html-file my_digest.html

Usage (Python):
    from scripts.core.newsletter_broadcast import create_broadcast
    broadcast_id = create_broadcast(
        subject="JMo Security v1.0.5 is out",
        html="<h1>What changed</h1>...",
        audience_id="your-audience-uuid",
    )
"""

from __future__ import annotations

import argparse
import datetime
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import resend

    RESEND_AVAILABLE = True
except ImportError:
    resend = None  # noqa: F841
    RESEND_AVAILABLE = False

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_AUDIENCE_ID = os.getenv("RESEND_AUDIENCE_ID", "")
FROM_EMAIL = os.getenv("JMO_FROM_EMAIL", "marketing@jmotools.com")
FROM_NAME = "JMo Security"

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Core API helpers
# ---------------------------------------------------------------------------


def create_broadcast(
    subject: str,
    html: str,
    audience_id: str,
    *,
    from_email: str = FROM_EMAIL,
    from_name: str = FROM_NAME,
    reply_to: Optional[str] = None,
) -> str:
    """Create a draft broadcast in Resend.

    Returns the broadcast ID string. The broadcast remains in Draft state
    until explicitly sent via send_broadcast() or the Resend dashboard.

    Args:
        subject: Email subject line.
        html: Full HTML body of the email.
        audience_id: Resend audience UUID (find at resend.com/audiences).
        from_email: Sender email address.
        from_name: Sender display name.
        reply_to: Optional reply-to address.

    Returns:
        Broadcast ID string.

    Raises:
        RuntimeError: If Resend SDK unavailable, API key missing, or API error.
    """
    _check_sdk()

    resend.api_key = RESEND_API_KEY

    params: dict = {
        "audience_id": audience_id,
        "from": f"{from_name} <{from_email}>",
        "subject": subject,
        "html": html,
    }
    if reply_to:
        params["reply_to"] = reply_to

    try:
        response = resend.Broadcasts.create(params)
    except Exception as exc:
        raise RuntimeError(f"Resend Broadcasts.create failed: {exc}") from exc

    broadcast_id = _extract_id(response)
    if not broadcast_id:
        raise RuntimeError(f"Unexpected Resend response (no id): {response!r}")

    logger.info("Created broadcast draft %s", broadcast_id)
    return broadcast_id


def send_broadcast(broadcast_id: str) -> bool:
    """Immediately send an existing draft broadcast.

    Args:
        broadcast_id: Broadcast UUID returned by create_broadcast().

    Returns:
        True on success.

    Raises:
        RuntimeError: On API error.
    """
    _check_sdk()

    resend.api_key = RESEND_API_KEY

    try:
        response = resend.Broadcasts.send({"broadcast_id": broadcast_id})
    except Exception as exc:
        raise RuntimeError(f"Resend Broadcasts.send failed: {exc}") from exc

    logger.info("Sent broadcast %s — response: %r", broadcast_id, response)
    return True


def list_audiences() -> list[dict]:
    """Return all Resend audiences for the current API key.

    Returns:
        List of audience dicts (keys: id, name, created_at).

    Raises:
        RuntimeError: If SDK unavailable or API error.
    """
    _check_sdk()

    resend.api_key = RESEND_API_KEY

    try:
        response = resend.Audiences.list()
    except Exception as exc:
        raise RuntimeError(f"Resend Audiences.list failed: {exc}") from exc

    if isinstance(response, dict):
        data = response.get("data", [])
        return list(data)
    return list(response) if response else []


# ---------------------------------------------------------------------------
# Release-note digest builder
# ---------------------------------------------------------------------------


def build_release_digest_html(
    version: Optional[str] = None, days: int = 7
) -> tuple[str, str]:
    """Build an HTML email digest from pyproject.toml version + CHANGELOG.

    Args:
        version: Version string to highlight (e.g. "1.0.5"). Defaults to
                 the version declared in pyproject.toml.
        days: Approximate lookback window used in the intro copy. The CHANGELOG
              section for the current version is always included in full.

    Returns:
        (subject, html) tuple ready for create_broadcast().
    """
    if version is None:
        version = _read_version_from_pyproject()

    changelog_section = _extract_changelog_section(version)
    release_date = _extract_release_date(
        changelog_section
    ) or datetime.date.today().strftime("%Y-%m-%d")

    subject = f"JMo Security v{version} — what's new"
    html = _render_digest_html(version, release_date, changelog_section)
    return subject, html


def _read_version_from_pyproject() -> str:
    pyproject = REPO_ROOT / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not parse version from pyproject.toml")
    return match.group(1)


def _extract_changelog_section(version: str) -> str:
    """Return the raw markdown block for a given version from CHANGELOG.md."""
    changelog = REPO_ROOT / "CHANGELOG.md"
    text = changelog.read_text(encoding="utf-8")

    # Match ## [1.0.5] - 2026-04-27 ... (next ## [...] header)
    pattern = rf"(## \[{re.escape(version)}\].*?)(?=\n## \[|\Z)"
    match = re.search(pattern, text, re.DOTALL)
    if not match:
        return f"## [{version}]\n\nNo changelog entry found for v{version}."
    return match.group(1).strip()


def _extract_release_date(section: str) -> Optional[str]:
    match = re.search(r"\d{4}-\d{2}-\d{2}", section)
    return match.group(0) if match else None


def _render_digest_html(version: str, release_date: str, changelog_md: str) -> str:
    """Convert version + changelog markdown to a styled HTML email."""

    # Convert a subset of markdown to HTML for email rendering
    html_body = _markdown_to_email_html(changelog_md)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      line-height: 1.65;
      color: #1a202c;
      max-width: 620px;
      margin: 0 auto;
      padding: 24px 16px;
      background: #f7fafc;
    }}
    .card {{
      background: #ffffff;
      border-radius: 12px;
      padding: 32px 36px;
      box-shadow: 0 1px 4px rgba(0,0,0,0.07);
    }}
    .badge {{
      display: inline-block;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #fff;
      padding: 4px 14px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 0.3px;
      margin-bottom: 16px;
    }}
    h1 {{ font-size: 24px; margin: 0 0 6px 0; color: #1a202c; }}
    .meta {{ font-size: 13px; color: #718096; margin-bottom: 24px; }}
    h2 {{
      font-size: 15px;
      color: #667eea;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin: 28px 0 10px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
    }}
    p {{ margin: 0 0 14px; font-size: 15px; }}
    ul {{ padding-left: 20px; margin: 0 0 14px; }}
    li {{ margin-bottom: 8px; font-size: 15px; }}
    strong {{ color: #2d3748; }}
    code {{
      background: #edf2f7;
      color: #553c9a;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'Menlo', 'Courier New', monospace;
      font-size: 13px;
    }}
    .cta-row {{ text-align: center; margin: 32px 0 20px; }}
    .cta {{
      background: #667eea;
      color: #ffffff !important;
      padding: 12px 28px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      font-size: 15px;
      display: inline-block;
    }}
    .footer {{
      margin-top: 28px;
      font-size: 12px;
      color: #a0aec0;
      text-align: center;
      border-top: 1px solid #e2e8f0;
      padding-top: 20px;
    }}
    .footer a {{ color: #a0aec0; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Release Notes</div>
    <h1>JMo Security v{version}</h1>
    <div class="meta">Released {release_date} &nbsp;·&nbsp; <a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md">Full changelog</a></div>

    {html_body}

    <div class="cta-row">
      <a class="cta" href="https://github.com/jimmy058910/jmo-security-repo/releases/tag/v{version}">
        View Release on GitHub
      </a>
    </div>

    <div class="footer">
      <p>
        You're receiving this because you subscribed at jmotools.com.<br>
        <a href="{{{{unsubscribe}}}}">Unsubscribe</a> &nbsp;·&nbsp;
        <a href="https://jmotools.com">jmotools.com</a>
      </p>
    </div>
  </div>
</body>
</html>"""


def _markdown_to_email_html(md: str) -> str:
    """Convert CHANGELOG markdown to email-safe HTML.

    Handles: ## headings, ### headings, **bold**, `code`, - bullets.
    Skips the top-level ## [version] header (already rendered separately).
    """
    lines = md.split("\n")
    out: list[str] = []
    in_list = False

    for line in lines:
        # Skip the top ## [version] - date header
        if re.match(r"^## \[\d", line):
            continue

        # ### subsection headings → h2 styled
        if line.startswith("### "):
            if in_list:
                out.append("</ul>")
                in_list = False
            heading = line[4:].strip()
            out.append(f"<h2>{heading}</h2>")
            continue

        # ## headings (Summary, Changed, Fixed, etc.)
        if line.startswith("## "):
            if in_list:
                out.append("</ul>")
                in_list = False
            heading = line[3:].strip()
            out.append(f"<h2>{heading}</h2>")
            continue

        # Bullet list items
        if line.startswith("- ") or line.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            item = _inline_md(line[2:])
            out.append(f"  <li>{item}</li>")
            continue

        # Blank line
        if not line.strip():
            if in_list:
                out.append("</ul>")
                in_list = False
            continue

        # Regular paragraph text (indented continuation lines treated as text)
        if in_list:
            # Continuation of previous list item context — skip deep sub-bullets
            if line.startswith("  "):
                continue
            out.append("</ul>")
            in_list = False

        text = _inline_md(line.strip())
        if text:
            out.append(f"<p>{text}</p>")

    if in_list:
        out.append("</ul>")

    return "\n".join(out)


def _inline_md(text: str) -> str:
    """Convert inline markdown (bold, code) to HTML."""
    # **bold**
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # `code`
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # [link text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


# ---------------------------------------------------------------------------
# SDK guard
# ---------------------------------------------------------------------------


def _check_sdk() -> None:
    if not RESEND_AVAILABLE:
        raise RuntimeError("resend package not installed. Run: pip install resend")
    if not RESEND_API_KEY:
        raise RuntimeError(
            "RESEND_API_KEY environment variable not set. "
            "Get your key at https://resend.com/api-keys"
        )


def _extract_id(response: object) -> Optional[str]:
    if isinstance(response, dict):
        return response.get("id")
    return getattr(response, "id", None)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a newsletter broadcast draft in Resend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Draft v1.0.5 release notes (leaves draft in Resend dashboard):
  python scripts/core/newsletter_broadcast.py --release-notes

  # Draft AND immediately send (skips dashboard review):
  python scripts/core/newsletter_broadcast.py --release-notes --send

  # Custom HTML:
  python scripts/core/newsletter_broadcast.py \\
    --subject "April DevSecOps round-up" \\
    --html-file my_digest.html

  # List audiences to find your RESEND_AUDIENCE_ID:
  python scripts/core/newsletter_broadcast.py --list-audiences
""",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--release-notes",
        action="store_true",
        help="Auto-generate HTML from current pyproject.toml version + CHANGELOG",
    )
    mode.add_argument(
        "--html-file",
        metavar="PATH",
        help="Path to an HTML file to use as the email body",
    )

    parser.add_argument(
        "--subject",
        metavar="TEXT",
        help="Email subject line (auto-generated for --release-notes if omitted)",
    )
    parser.add_argument(
        "--version",
        metavar="X.Y.Z",
        help="Override version for --release-notes (default: pyproject.toml)",
    )
    parser.add_argument(
        "--audience-id",
        metavar="UUID",
        default=RESEND_AUDIENCE_ID,
        help="Resend audience UUID (default: $RESEND_AUDIENCE_ID env var)",
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Immediately send the broadcast instead of leaving it as a draft",
    )
    parser.add_argument(
        "--list-audiences",
        action="store_true",
        help="List available Resend audiences and exit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the subject + HTML to stdout, do not call Resend API",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --list-audiences
    if args.list_audiences:
        try:
            audiences = list_audiences()
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        if not audiences:
            print("No audiences found.")
            return 0
        print(f"{'ID':<40}  Name")
        print("-" * 60)
        for a in audiences:
            print(f"{a.get('id', ''):<40}  {a.get('name', '')}")
        return 0

    # Build subject + html
    if args.release_notes:
        try:
            subject, html = build_release_digest_html(version=args.version)
        except Exception as exc:
            print(f"Error building digest: {exc}", file=sys.stderr)
            return 1
        if args.subject:
            subject = args.subject
    elif args.html_file:
        html_path = Path(args.html_file)
        if not html_path.exists():
            print(f"Error: HTML file not found: {html_path}", file=sys.stderr)
            return 1
        html = html_path.read_text(encoding="utf-8")
        if not args.subject:
            print("Error: --subject required when using --html-file", file=sys.stderr)
            return 1
        subject = args.subject
    else:
        parser.print_help()
        return 1

    if args.dry_run:
        print(f"Subject: {subject}\n")
        print(html)
        return 0

    audience_id = args.audience_id
    if not audience_id:
        print(
            "Error: RESEND_AUDIENCE_ID not set. Pass --audience-id or set the env var.\n"
            "Run --list-audiences to find your audience UUID.",
            file=sys.stderr,
        )
        return 1

    # Create draft
    print("Creating broadcast draft…")
    print(f"  Subject:  {subject}")
    print(f"  Audience: {audience_id}")
    try:
        broadcast_id = create_broadcast(
            subject=subject,
            html=html,
            audience_id=audience_id,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"  Draft ID: {broadcast_id}")
    print(f"  View at:  https://resend.com/broadcasts/{broadcast_id}")

    if args.send:
        print("\nSending broadcast…")
        try:
            send_broadcast(broadcast_id)
        except RuntimeError as exc:
            print(f"Error sending: {exc}", file=sys.stderr)
            return 1
        print("Sent.")
    else:
        print(
            "\nBroadcast is in Draft state. Review at https://resend.com/broadcasts"
            "\nthen click Send when ready."
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
