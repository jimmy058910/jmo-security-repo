"""A dashboard must say which template produced it.

``write_html`` renders one of several documents. Two of them are not the
product: a build vendored into ``tests/fixtures/dashboard/`` so the suite can
run without Node, and a static summary page. Because
``scripts/dashboard/dist/`` is gitignored, CI and every fresh clone take the
*fixture* branch -- and before v1.1.0 that branch logged nothing at any level
and produced a document whose head was byte-identical to the real build's.

Measured on ``origin/dev`` at 4d47be4, rendering the same 242 findings:

    rung                 bytes      <title>                    log records
    react build (dist)   1,834,086  JMo Security Dashboard     0
    test fixture         1,773,454  JMo Security Dashboard     0
    static fallback          1,649  JMo Security - Findings..  1 WARNING

The harmless rung was the loud one. These tests hold the line that every rung
is now distinguishable, in the log *and* in the artifact -- whoever opens
``dashboard.html`` days later never sees the log line.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path

import pytest

from scripts.core.reporters.html_reporter import (
    PROVENANCE_META_NAME,
    TEMPLATE_FALLBACK,
    TEMPLATE_REACT_BUILD,
    TEMPLATE_REACT_BUILD_STALE,
    TEMPLATE_TEST_FIXTURE,
    write_html,
)

LOGGER_NAME = "scripts.core.reporters.html_reporter"

#: Everything write_html needs from a build, and nothing else.
TEMPLATE_HTML = (
    "<!DOCTYPE html><html><head><title>JMo Security Dashboard</title>"
    "<script>window.__FINDINGS__ = []</script></head>"
    '<body><div id="root"></div></body></html>'
)

FINDINGS = [{"id": "f1", "severity": "HIGH", "message": "example"}]

#: Repo paths that must keep satisfying the contracts write_html asserts.
REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_SOURCE = REPO_ROOT / "scripts" / "dashboard" / "index.html"
VENDORED_FIXTURE = (
    REPO_ROOT / "tests" / "fixtures" / "dashboard" / "test-inline-dashboard.html"
)


def build_tree(
    root: Path,
    *,
    react: str | None = None,
    fixture: str | None = None,
) -> Path:
    """Lay out a fake repo and return the path html_reporter should think it is.

    ``write_html`` resolves both the build and the fixture relative to its own
    ``__file__``, so pointing that at a tree we control is what selects a rung
    deterministically.
    """
    reporters = root / "scripts" / "core" / "reporters"
    reporters.mkdir(parents=True, exist_ok=True)
    module = reporters / "html_reporter.py"
    module.touch()
    if react is not None:
        dist = root / "scripts" / "dashboard" / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "index.html").write_text(react, encoding="utf-8")
    if fixture is not None:
        fixture_dir = root / "tests" / "fixtures" / "dashboard"
        fixture_dir.mkdir(parents=True, exist_ok=True)
        (fixture_dir / "test-inline-dashboard.html").write_text(
            fixture, encoding="utf-8"
        )
    return module


def render(monkeypatch, module: Path, out: Path, findings=FINDINGS) -> str:
    monkeypatch.setattr(f"{LOGGER_NAME}.__file__", str(module), raising=False)
    write_html(findings, out)
    return out.read_text(encoding="utf-8")


def declared_source(html: str) -> str | None:
    match = re.search(rf'<meta name="{PROVENANCE_META_NAME}" content="([^"]+)"', html)
    return match.group(1) if match else None


def banner_source(html: str) -> str | None:
    match = re.search(rf'data-{PROVENANCE_META_NAME}-banner="([^"]+)"', html)
    return match.group(1) if match else None


def records_at_or_above(caplog, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= level and r.name == LOGGER_NAME]


# --- the acceptance criterion ------------------------------------------------


def test_every_template_source_is_distinguishable(tmp_path, monkeypatch):
    """The same findings rendered from different templates must not look alike.

    This is the property the chunk exists to establish. Before the fix all
    three rungs produced a document declaring nothing about its own origin, so
    auditing a dashboard locally and auditing one from CI audited two different
    documents with no way to tell which was which.
    """
    rendered: dict[str, str] = {}

    react_tree = build_tree(tmp_path / "a", react=TEMPLATE_HTML, fixture=TEMPLATE_HTML)
    rendered["react"] = render(monkeypatch, react_tree, tmp_path / "a.html")

    fixture_tree = build_tree(tmp_path / "b", fixture=TEMPLATE_HTML)
    rendered["fixture"] = render(monkeypatch, fixture_tree, tmp_path / "b.html")

    bare_tree = build_tree(tmp_path / "c")
    rendered["fallback"] = render(monkeypatch, bare_tree, tmp_path / "c.html")

    declared = {name: declared_source(html) for name, html in rendered.items()}
    assert declared == {
        "react": TEMPLATE_REACT_BUILD,
        "fixture": TEMPLATE_TEST_FIXTURE,
        "fallback": TEMPLATE_FALLBACK,
    }
    assert len(set(declared.values())) == 3, "two rungs declare the same origin"


def test_only_the_real_build_is_unbannered(tmp_path, monkeypatch):
    """A template that is not the product says so in the page itself."""
    react = build_tree(tmp_path / "a", react=TEMPLATE_HTML)
    fixture = build_tree(tmp_path / "b", fixture=TEMPLATE_HTML)
    bare = build_tree(tmp_path / "c")

    assert banner_source(render(monkeypatch, react, tmp_path / "a.html")) is None
    assert (
        banner_source(render(monkeypatch, fixture, tmp_path / "b.html"))
        == TEMPLATE_TEST_FIXTURE
    )
    assert (
        banner_source(render(monkeypatch, bare, tmp_path / "c.html"))
        == TEMPLATE_FALLBACK
    )


def test_the_fallback_page_carries_exactly_one_banner(tmp_path, monkeypatch):
    """The static page ships its own banner; nothing should stack a second."""
    bare = build_tree(tmp_path / "c")
    html = render(monkeypatch, bare, tmp_path / "c.html")
    assert html.count(f"data-{PROVENANCE_META_NAME}-banner") == 1


# --- log levels --------------------------------------------------------------


def test_a_real_build_does_not_warn(tmp_path, monkeypatch, caplog):
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        render(monkeypatch, tree, tmp_path / "out.html")
    assert records_at_or_above(caplog, logging.WARNING) == []
    assert records_at_or_above(caplog, logging.INFO), "the chosen template is unlogged"


def test_the_test_fixture_warns_and_names_itself(tmp_path, monkeypatch, caplog):
    """The dangerous rung must be the loud one.

    On origin/dev this branch emitted zero records at any level, including
    DEBUG -- so a CI-produced dashboard was indistinguishable from the product.
    """
    tree = build_tree(tmp_path, fixture=TEMPLATE_HTML)
    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        render(monkeypatch, tree, tmp_path / "out.html")

    warnings = records_at_or_above(caplog, logging.WARNING)
    assert len(warnings) == 1, f"expected one warning, got {warnings}"
    message = warnings[0].getMessage()
    assert "TEST FIXTURE" in message
    assert "npm run build" in message


def test_the_static_fallback_warns(tmp_path, monkeypatch, caplog):
    tree = build_tree(tmp_path)
    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        render(monkeypatch, tree, tmp_path / "out.html")
    warnings = records_at_or_above(caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "npm run build" in warnings[0].getMessage()


# --- staleness ---------------------------------------------------------------


def test_a_build_older_than_its_sources_is_reported_stale(
    tmp_path, monkeypatch, caplog
):
    """A stale build is the second way to get a wrong dashboard silently.

    Measured at the start of this chunk: the local ``dist/index.html`` was three
    months old and 219 KB larger than a fresh build, and nothing said so.
    """
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    src = tmp_path / "scripts" / "dashboard" / "src"
    src.mkdir(parents=True)
    app = src / "App.tsx"
    app.write_text("// newer than the build\n", encoding="utf-8")
    future = time.time() + 10
    os.utime(app, (future, future))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        html = render(monkeypatch, tree, tmp_path / "out.html")

    assert declared_source(html) == TEMPLATE_REACT_BUILD_STALE
    warnings = records_at_or_above(caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "STALE" in warnings[0].getMessage()
    assert "App.tsx" in warnings[0].getMessage()


def test_a_dependency_change_also_makes_a_build_stale(tmp_path, monkeypatch):
    """package.json counts as a build input.

    This chunk opened with ``npm run build`` failing because the installed tree
    was five months behind ``package-lock.json`` -- recharts 2.15.4 against a
    locked 3.8.1. A dependency change invalidates a bundle exactly as a source
    change does.
    """
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    pkg = tmp_path / "scripts" / "dashboard" / "package.json"
    pkg.write_text("{}\n", encoding="utf-8")
    future = time.time() + 10
    os.utime(pkg, (future, future))

    html = render(monkeypatch, tree, tmp_path / "out.html")
    assert declared_source(html) == TEMPLATE_REACT_BUILD_STALE


def test_a_fresh_build_is_not_reported_stale(tmp_path, monkeypatch):
    """The negative control: sources older than the build are fine."""
    src_root = tmp_path / "scripts" / "dashboard" / "src"
    src_root.mkdir(parents=True)
    app = src_root / "App.tsx"
    app.write_text("// older than the build\n", encoding="utf-8")
    past = time.time() - 600
    os.utime(app, (past, past))

    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    html = render(monkeypatch, tree, tmp_path / "out.html")
    assert declared_source(html) == TEMPLATE_REACT_BUILD


# --- the build contract ------------------------------------------------------


def test_the_shipped_source_template_declares_the_expected_placeholder():
    """``write_html`` injects findings by string-replacing this exact text.

    If the source template's spelling drifts -- an added space, a minifier
    change -- every dashboard silently degrades to the static fallback. The
    built ``dist/`` is gitignored so it cannot be asserted here, but its source
    is tracked and is where any such drift starts.
    """
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")
    assert "window.__FINDINGS__ = []" in source, (
        f"{DASHBOARD_SOURCE} no longer contains the placeholder write_html "
        "replaces; every dashboard would fall back to the static page"
    )


def test_the_vendored_fixture_still_satisfies_the_placeholder_contract():
    """The fixture is what CI renders. If it drifts, CI renders the fallback."""
    assert VENDORED_FIXTURE.exists(), f"{VENDORED_FIXTURE} is missing"
    fixture = VENDORED_FIXTURE.read_text(encoding="utf-8")
    assert "window.__FINDINGS__ = []" in fixture


def test_a_template_without_the_placeholder_falls_back_and_says_so(
    tmp_path, monkeypatch, caplog
):
    """A template that cannot receive findings must not be shipped as one."""
    tree = build_tree(
        tmp_path,
        react="<!DOCTYPE html><html><head><title>x</title></head><body></body></html>",
    )
    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        html = render(monkeypatch, tree, tmp_path / "out.html")

    assert declared_source(html) == TEMPLATE_FALLBACK
    assert "Fallback HTML Mode" in html
    assert any(
        "placeholder" in r.getMessage()
        for r in records_at_or_above(caplog, logging.WARNING)
    )


# --- provenance survives both data modes -------------------------------------


@pytest.mark.parametrize("count", [1, 1500])
def test_provenance_is_recorded_in_both_inline_and_external_mode(
    tmp_path, monkeypatch, count
):
    """External mode replaces the placeholder differently; the mark must stay."""
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    findings = [
        {"id": f"f{i}", "severity": "HIGH", "message": f"finding {i}"}
        for i in range(count)
    ]
    html = render(monkeypatch, tree, tmp_path / "out.html", findings=findings)
    assert declared_source(html) == TEMPLATE_REACT_BUILD


@pytest.mark.parametrize("char", ["<", ">", "&"])
def test_no_markup_significant_character_reaches_the_embedded_payload(
    tmp_path, monkeypatch, char
):
    """State the escaper's invariant, one character at a time.

    Only ``<`` can actually break out of a ``<script>`` element, so mutation
    testing showed the ``>`` and ``&`` escapes to be redundant *here* -- both
    survived. They are kept as defence-in-depth for any future embedding
    context, and this pins them so "redundant" stays a measured claim rather
    than an unverified one.
    """
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    findings = [
        {
            "id": "probe",
            "severity": "HIGH",
            "message": "</SCRIPT> & <!-- <script> ` </script >",
        }
    ]
    html = render(monkeypatch, tree, tmp_path / "out.html", findings=findings)

    prefix = "window.__FINDINGS__ = "
    start = html.index(prefix) + len(prefix)
    payload = html[start : html.index("</script>", start)]
    assert char not in payload, f"raw {char!r} reached the payload: {payload[:200]}"


def test_the_static_fallback_ships_the_same_security_headers(tmp_path, monkeypatch):
    """Every dashboard.html gets the headers, including the one with no React.

    tests/reporters/test_html_security.py asserts these of "the dashboard", but
    only ever rendered from a template that had them. The static fallback is
    written to the same filename and carried none.
    """
    tree = build_tree(tmp_path)
    html = render(monkeypatch, tree, tmp_path / "out.html")
    for header in (
        'http-equiv="Content-Security-Policy"',
        'http-equiv="X-Frame-Options"',
        'http-equiv="X-Content-Type-Options"',
        'name="referrer"',
        'name="robots"',
    ):
        assert header in html, f"static fallback is missing {header}"


def test_the_provenance_meta_stays_inside_head(tmp_path, monkeypatch):
    """A meta tag outside <head> is not a header; browsers ignore placement."""
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    html = render(monkeypatch, tree, tmp_path / "out.html")
    head = re.search(r"<head>(.*?)</head>", html, flags=re.DOTALL)
    assert head, "no <head> in the rendered document"
    assert PROVENANCE_META_NAME in head.group(1)
