"""A dashboard must say which template produced it, and be the real one.

``write_html`` renders one of two documents: the built React bundle at
``scripts/dashboard/dist/index.html``, or a static summary page. These tests
hold two lines.

**Provenance.** Whoever opens ``dashboard.html`` days later never sees the log
line, so the artifact itself has to say where it came from. Measured on
``origin/dev`` at 4d47be4, rendering the same 242 findings, when there were
three rungs and none of them said:

    rung                 bytes      <title>                    log records
    react build (dist)   1,834,086  JMo Security Dashboard     0
    test fixture         1,773,454  JMo Security Dashboard     0
    static fallback          1,649  JMo Security - Findings..  1 WARNING

The harmless rung was the loud one.

**The bundle is the product.** The third rung above is gone. It existed only
because ``scripts/dashboard/dist/`` was gitignored, so no distribution carried
a dashboard at all (#862) and CI rendered a 2025-11-17 vendored build (#864).
The bundle is now tracked and shipped as package data, which is what
``test_the_shipped_bundle_*`` guards -- if it stops satisfying the injection
contract, every dashboard silently degrades to the static page.

Freshness -- whether the tracked bundle still matches its sources -- is not
checkable here, because it needs Node. It belongs to ``dashboard-smoke``, which
rebuilds and compares byte for byte. The mtime check that used to live in
``_resolve_template`` was deleted rather than moved: with ``dist/`` tracked,
git's checkout order made every build input newer than the bundle, so it
reported "stale" on every fresh clone.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from pathlib import Path

import pytest

from scripts.core.reporters.html_reporter import (
    PROVENANCE_META_NAME,
    TEMPLATE_FALLBACK,
    TEMPLATE_REACT_BUILD,
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
SHIPPED_BUNDLE = REPO_ROOT / "scripts" / "dashboard" / "dist" / "index.html"


def build_tree(root: Path, *, react: str | None = None) -> Path:
    """Lay out a fake repo and return the path html_reporter should think it is.

    ``write_html`` resolves the build relative to its own ``__file__``, so
    pointing that at a tree we control is what selects a rung deterministically.
    """
    reporters = root / "scripts" / "core" / "reporters"
    reporters.mkdir(parents=True, exist_ok=True)
    module = reporters / "html_reporter.py"
    module.touch()
    if react is not None:
        dist = root / "scripts" / "dashboard" / "dist"
        dist.mkdir(parents=True, exist_ok=True)
        (dist / "index.html").write_text(react, encoding="utf-8")
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

    react_tree = build_tree(tmp_path / "a", react=TEMPLATE_HTML)
    rendered["react"] = render(monkeypatch, react_tree, tmp_path / "a.html")

    bare_tree = build_tree(tmp_path / "c")
    rendered["fallback"] = render(monkeypatch, bare_tree, tmp_path / "c.html")

    declared = {name: declared_source(html) for name, html in rendered.items()}
    assert declared == {
        "react": TEMPLATE_REACT_BUILD,
        "fallback": TEMPLATE_FALLBACK,
    }
    assert len(set(declared.values())) == 2, "two rungs declare the same origin"


def test_only_the_real_build_is_unbannered(tmp_path, monkeypatch):
    """A template that is not the product says so in the page itself."""
    react = build_tree(tmp_path / "a", react=TEMPLATE_HTML)
    bare = build_tree(tmp_path / "c")

    assert banner_source(render(monkeypatch, react, tmp_path / "a.html")) is None
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


def test_the_static_fallback_warns(tmp_path, monkeypatch, caplog):
    tree = build_tree(tmp_path)
    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        render(monkeypatch, tree, tmp_path / "out.html")
    warnings = records_at_or_above(caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "npm run build" in warnings[0].getMessage()


# --- mtime is not a staleness signal for a tracked bundle --------------------


def test_checkout_order_does_not_make_the_tracked_bundle_look_stale(
    tmp_path, monkeypatch, caplog
):
    """A build input newer than the bundle must not change the verdict.

    This is the regression test for the check that used to live here. ``dist/``
    is tracked now, and ``git checkout`` writes a tree in path order: measured
    on a fresh clone of this repo with the bundle tracked, mtimes spread over
    17.3 ms, ``scripts/dashboard/dist/`` sorted before every build input, and
    all seven landed newer -- ``_resolve_template`` returned ``react-build-stale``
    naming ``src/App.tsx``, +26.5 ms. Deterministically, on every clone.

    So the property is not "staleness is detected", it is "mtime cannot be
    consulted". Re-introducing any mtime comparison fails this test.
    """
    tree = build_tree(tmp_path, react=TEMPLATE_HTML)
    dashboard = tmp_path / "scripts" / "dashboard"
    src = dashboard / "src"
    src.mkdir(parents=True)

    # Every input the deleted check looked at, all newer than the bundle --
    # exactly the state a fresh clone produces.
    future = time.time() + 60
    for rel in ("src/App.tsx", "package.json", "package-lock.json", "index.html"):
        f = dashboard / rel
        f.write_text("// newer than the bundle\n", encoding="utf-8")
        os.utime(f, (future, future))

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        html = render(monkeypatch, tree, tmp_path / "out.html")

    assert declared_source(html) == TEMPLATE_REACT_BUILD
    assert banner_source(html) is None, "a clone must not render a banner"
    assert records_at_or_above(caplog, logging.WARNING) == [], (
        "a fresh clone must not warn: every build input is newer than the "
        "bundle there, which says nothing about whether it is current"
    )


# --- the build contract ------------------------------------------------------


def test_the_shipped_source_template_declares_the_expected_placeholder():
    """``write_html`` injects findings by string-replacing this exact text.

    If the source template's spelling drifts -- an added space, a minifier
    change -- every dashboard silently degrades to the static fallback. This
    asserts the *source*; the test below asserts the built artifact, which is
    what actually gets rendered.
    """
    source = DASHBOARD_SOURCE.read_text(encoding="utf-8")
    assert "window.__FINDINGS__ = []" in source, (
        f"{DASHBOARD_SOURCE} no longer contains the placeholder write_html "
        "replaces; every dashboard would fall back to the static page"
    )


def test_the_shipped_bundle_is_tracked_and_present():
    """The bundle is the product, so its absence is a packaging failure.

    Before #862 this file could not be asserted at all: ``dist/`` was covered
    by a blanket ``dist/`` in ``.gitignore``, so a wheel built from a clean
    checkout carried 0 of its 196 entries under ``scripts/dashboard/`` and a
    pip-installed ``jmo report`` produced a 2,468-byte static page every time.
    It is tracked and declared as package data now, and this is the check that
    it stays that way.
    """
    assert SHIPPED_BUNDLE.exists(), (
        f"{SHIPPED_BUNDLE} is missing. It is tracked in git and shipped as "
        "package data -- without it every dashboard is the static fallback"
    )
    assert SHIPPED_BUNDLE.stat().st_size > 100_000, (
        "the bundle is implausibly small for a single-file Vite build; "
        "vite-plugin-singlefile inlines all JS and CSS into it"
    )

    # Present on disk is not the property that matters -- an ignored file is
    # present for whoever built it and absent from every clone, which is
    # exactly the state #862 describes. So ask git, not the filesystem.
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout, so tracking cannot be verified here")
    listed = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", SHIPPED_BUNDLE.as_posix()],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert listed.returncode == 0, (
        f"{SHIPPED_BUNDLE} exists but git does not track it, so no clone and no "
        f"sdist would have it: {listed.stderr.strip()}. Check the dist/ "
        "negations in .gitignore."
    )


def test_the_shipped_bundle_satisfies_the_placeholder_contract():
    """If the built bundle drifts, every dashboard degrades to the fallback.

    This is the always-on half of the dashboard's gate: it needs no Node, so it
    runs in the ordinary test shards, which are required checks. The other half
    -- whether the bundle still matches its sources -- needs a rebuild and lives
    in ``dashboard-smoke``.
    """
    bundle = SHIPPED_BUNDLE.read_text(encoding="utf-8")
    assert "window.__FINDINGS__ = []" in bundle, (
        f"{SHIPPED_BUNDLE} no longer contains the placeholder write_html "
        "replaces; every dashboard would fall back to the static page"
    )


def test_rendering_from_the_shipped_bundle_declares_the_real_build(tmp_path):
    """End to end on the real artifact, not a synthetic one.

    Every other test here builds a fake tree with a two-line template. This one
    renders the file a user actually gets, so a bundle that is present and
    contains the placeholder but still fails to produce a ``react-build``
    document cannot pass.
    """
    out = tmp_path / "dashboard.html"
    write_html(FINDINGS, out)
    html = out.read_text(encoding="utf-8")

    assert declared_source(html) == TEMPLATE_REACT_BUILD
    assert banner_source(html) is None
    assert '"f1"' in html, "findings were not injected into the bundle"


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
