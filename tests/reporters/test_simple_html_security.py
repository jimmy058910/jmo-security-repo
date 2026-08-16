#!/usr/bin/env python3
"""`simple-report.html` must not render attacker-controlled text as markup.

`simple_html_reporter` carries its own private `_escape_html` rather than
sharing one, which is the shape chunk 9's stored XSS had: the dashboard's
escaper replaced a literal lowercase `</script>` while the HTML tokenizer also
ends a script element on `</SCRIPT>`. This reporter's escaping is *correct* --
measured, not assumed -- but nothing asserted it, so a future edit could
regress it in silence.

Following chunk 9's lesson, this asserts the **property** (the produced
document contains no live element or event handler that came from finding
text) rather than the escaper's spelling. Six tests there asserted `<\\/script>`
and passed while `</SCRIPT>` broke out.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

from scripts.core.reporters.simple_html_reporter import write_simple_html

# Each breaks out of a different context: script text, table markup, a
# double-quoted attribute, a single-quoted attribute, raw element injection,
# and text that is already entity-encoded (which must not be double-decoded).
PAYLOADS = [
    "</SCRIPT><img src=x onerror=alert(1)>",
    "</td></tr><script>alert(1)</script>",
    '" onmouseover=alert(1) x="',
    "' onfocus=alert(1) autofocus='",
    "<img src=x onerror=alert(1)>",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
]

DANGEROUS_TAGS = {"script", "img", "iframe", "svg", "object", "embed", "link"}


class _LiveMarkupCollector(HTMLParser):
    """Records any dangerous element or `on*` handler in the parsed document."""

    def __init__(self) -> None:
        super().__init__()
        self.found: list[tuple] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in DANGEROUS_TAGS:
            self.found.append(("element", tag, dict(attrs)))
        for name, value in attrs:
            if name.lower().startswith("on"):
                self.found.append(("handler", tag, name, value))


def _render(tmp_path: Path, payload: str) -> str:
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "a" * 16,
            "ruleId": payload,
            "severity": "HIGH",
            "tool": {"name": payload, "version": "1.0"},
            "location": {"path": payload},
            "message": payload,
            "detected_by": [{"name": payload}, {"name": "bandit"}],
        }
    ]
    out = tmp_path / "simple-report.html"
    write_simple_html(findings, out)
    return out.read_text(encoding="utf-8")


@pytest.mark.parametrize("payload", PAYLOADS)
def test_finding_text_cannot_introduce_live_markup(tmp_path, payload):
    html = _render(tmp_path, payload)

    collector = _LiveMarkupCollector()
    collector.feed(html)

    assert (
        collector.found == []
    ), f"payload {payload!r} produced live markup: {collector.found}"
    # belt and braces: the tokenizer above is the oracle, but a raw <script>
    # anywhere in a document with no script blocks is unambiguous
    assert not re.search(r"<script", html, re.IGNORECASE)


def test_escaped_payload_is_visible_as_text(tmp_path):
    """Neutralised, not silently dropped -- the finding must still be readable."""
    html = _render(tmp_path, "<img src=x onerror=alert(1)>")
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_ampersand_is_escaped_before_the_other_replacements(tmp_path):
    """`&` must be replaced first or every other entity is double-escaped."""
    html = _render(tmp_path, "a & b < c")
    assert "a &amp; b &lt; c" in html
    assert "&amp;lt;" not in html


def test_a_clean_finding_renders_without_entities(tmp_path):
    """Negative control: escaping must not mangle ordinary text."""
    html = _render(tmp_path, "Hardcoded password detected")
    assert "Hardcoded password detected" in html
