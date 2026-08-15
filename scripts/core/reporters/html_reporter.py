#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Threshold for inline vs external JSON mode
# Below this: embed JSON directly in HTML (fast, self-contained)
# Above this: load JSON via async fetch() (prevents 50-100 MB HTML files)
INLINE_THRESHOLD = 1000

# --- Template provenance -----------------------------------------------------
#
# write_html renders one of several documents and, before v1.1.0, the artifact
# did not say which. Two of them are not the product:
#
#   react-build        the real dashboard, produced by `npm run build`
#   react-build-stale  a real build, but older than the sources it was built
#                      from -- so it can be missing fixes that are on main
#   test-fixture       a build vendored into tests/ so the suite can run
#                      without Node. It is not the product: it lags src/ and
#                      it fetches a different data file in external mode
#   fallback           a static summary page with no dashboard at all
#
# `scripts/dashboard/dist/` is gitignored, so CI and every fresh clone take the
# test-fixture branch -- which used to log nothing at any level and produce a
# document whose head is byte-identical to the real build's.
TEMPLATE_REACT_BUILD = "react-build"
TEMPLATE_REACT_BUILD_STALE = "react-build-stale"
TEMPLATE_TEST_FIXTURE = "test-fixture"
TEMPLATE_FALLBACK = "fallback"

#: Name of the <meta> tag that records which template produced a dashboard.
PROVENANCE_META_NAME = "jmo-dashboard-template"

#: Templates that are not the product. These also get a visible in-page banner,
#: because a log line is not visible to whoever opens the HTML file later.
NON_PRODUCT_TEMPLATES = frozenset({TEMPLATE_TEST_FIXTURE, TEMPLATE_FALLBACK})

#: Files whose mtime, if newer than dist/index.html, means the build is stale.
#: package.json / package-lock.json are included deliberately: a dependency
#: change invalidates a bundle just as surely as a source change does.
_BUILD_INPUT_FILES = (
    "index.html",
    "package.json",
    "package-lock.json",
    "vite.config.ts",
    "tailwind.config.js",
    "postcss.config.js",
    "tsconfig.json",
)


def escape_json_for_script(payload: str) -> str:
    """Make a JSON document safe to embed inside an HTML ``<script>`` element.

    The HTML tokenizer leaves script-data context on ``</script`` matched
    **case-insensitively** and terminated by whitespace, ``/`` or ``>``. So
    replacing the single literal ``</script>`` is not a guard: ``</SCRIPT>``,
    ``</ScRiPt>`` and ``</script >`` all still close the element, and anything
    after them is parsed as live markup. Scanner findings carry raw lines from
    the scanned repository (``context.snippet``, ``context.code_snippet``), so
    that content is attacker-influenced whenever an untrusted repo is scanned.

    Escaping the three characters that can *begin* markup as ``\\uXXXX`` makes
    every end tag, comment open and entity unrepresentable regardless of case
    or terminator. Unlike the previous ``<\\script`` form it also leaves the
    result **valid JSON** as well as valid JavaScript.

    ``json.dumps`` defaults to ``ensure_ascii=True``, which already escapes
    U+2028/U+2029, so no further handling is needed for those.

    Only ``<`` is load-bearing inside a ``<script>`` element: script data is raw
    text, so ``>`` cannot start anything and entity references are not parsed
    there. ``>`` and ``&`` are escaped anyway -- it is the conventional recipe,
    it costs nothing, and it means the same payload stays inert if it is ever
    embedded somewhere that *does* parse them. Mutation testing confirmed both
    are redundant for the current call sites, so the invariant they provide is
    asserted explicitly rather than left to a coverage number.

    Args:
        payload: The output of ``json.dumps``.

    Returns:
        The same document with ``<``, ``>`` and ``&`` escaped.
    """
    return (
        payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    )


def _exists(path: Path) -> bool:
    """``Path.exists()`` that cannot raise.

    Python 3.12 made ``Path.exists()`` propagate ``OSError`` subclasses other
    than ``FileNotFoundError``/``NotADirectoryError``. A results directory
    bind-mounted from a host with a different UID raises ``PermissionError``
    here, which would turn "no dashboard build" into a crash.
    """
    try:
        return path.exists()
    except OSError:
        return False


def _build_inputs(dashboard_dir: Path) -> Iterator[Path]:
    """Yield every file whose change should invalidate ``dist/index.html``."""
    src = dashboard_dir / "src"
    if _exists(src):
        try:
            yield from (p for p in src.rglob("*") if p.is_file())
        except OSError:  # pragma: no cover - defensive, same class as _exists
            pass
    for name in _BUILD_INPUT_FILES:
        candidate = dashboard_dir / name
        if _exists(candidate):
            yield candidate


def _stale_build_input(dashboard_dir: Path, build_path: Path) -> Path | None:
    """Return a build input newer than the build itself, or ``None``.

    Only the first such file is reported: the point is to name a concrete
    reason the build is out of date, not to enumerate every one.
    """
    try:
        built_at = build_path.stat().st_mtime
    except OSError:
        return None
    for candidate in _build_inputs(dashboard_dir):
        try:
            if candidate.stat().st_mtime > built_at:
                return candidate
        except OSError:
            continue
    return None


def _resolve_template() -> tuple[str | None, str]:
    """Pick the dashboard template and say, out loud, which one was picked.

    Returns:
        ``(template_html, source)``. ``template_html`` is ``None`` when no
        template is available and the caller must write the static fallback;
        ``source`` is always one of the ``TEMPLATE_*`` constants.
    """
    # Resolved per call, not at import: tests patch this module's __file__ to
    # point the lookup at a fixture tree.
    dashboard_dir = Path(__file__).parent.parent.parent / "dashboard"
    react_build_path = dashboard_dir / "dist" / "index.html"

    if _exists(react_build_path):
        template = react_build_path.read_text(encoding="utf-8")
        stale = _stale_build_input(dashboard_dir, react_build_path)
        if stale is not None:
            logger.warning(
                "Dashboard rendered from a STALE React build: %s is newer than "
                "%s. Run 'npm run build' in %s -- this report may be missing "
                "dashboard fixes that are already in the source tree.",
                stale,
                react_build_path,
                dashboard_dir,
            )
            return template, TEMPLATE_REACT_BUILD_STALE
        logger.info("Dashboard rendered from the React build at %s", react_build_path)
        return template, TEMPLATE_REACT_BUILD

    # Go up to repo root: scripts/core/reporters/ -> scripts/core -> scripts -> repo_root
    repo_root = Path(__file__).parent.parent.parent.parent
    fixture_path = (
        repo_root / "tests" / "fixtures" / "dashboard" / "test-inline-dashboard.html"
    )
    if _exists(fixture_path):
        logger.warning(
            "No dashboard build at %s, so this report was rendered from the "
            "TEST FIXTURE at %s. That fixture is a vendored old build kept so "
            "the test suite can run without Node -- it is NOT the product and "
            "its behaviour differs from a real build. Run 'npm run build' in "
            "%s to produce the real dashboard.",
            react_build_path,
            fixture_path,
            dashboard_dir,
        )
        return fixture_path.read_text(encoding="utf-8"), TEMPLATE_TEST_FIXTURE

    logger.warning(
        "React dashboard build not found. "
        "Run 'npm run build' in %s for the interactive dashboard. "
        "Using fallback HTML.",
        dashboard_dir,
    )
    return None, TEMPLATE_FALLBACK


def _mark_template_source(doc: str, source: str) -> str:
    """Record in the document itself which template produced it.

    Always adds a machine-readable ``<meta>`` tag. For templates that are not
    the product, also adds a banner the reader cannot miss -- whoever opens
    ``dashboard.html`` days later never sees the log line.
    """
    meta = f'<meta name="{PROVENANCE_META_NAME}" content="{html.escape(source, quote=True)}" />'
    # Insert last in <head> so no existing header-ordering guarantee moves.
    if "</head>" in doc:
        doc = doc.replace("</head>", f"  {meta}\n</head>", 1)
    elif "<head>" in doc:
        doc = doc.replace("<head>", f"<head>\n  {meta}", 1)
    else:
        doc = f"{meta}\n{doc}"

    if source in NON_PRODUCT_TEMPLATES:
        doc = _insert_non_product_banner(doc, source)
    return doc


def _insert_non_product_banner(doc: str, source: str) -> str:
    """Put a visible "this is not the built dashboard" banner in the body."""
    if f"data-{PROVENANCE_META_NAME}-banner" in doc:
        return doc
    banner = (
        f'<div data-{PROVENANCE_META_NAME}-banner="{html.escape(source, quote=True)}" '
        'style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;'
        "padding:12px 16px;margin:12px;font-family:-apple-system,BlinkMacSystemFont,"
        '&quot;Segoe UI&quot;,Roboto,sans-serif;color:#5c4400">'
        "<strong>This is not the built JMo dashboard.</strong> "
        f"It was rendered from the <code>{html.escape(source)}</code> template "
        "because <code>scripts/dashboard/dist/index.html</code> was missing. "
        "Run <code>npm run build</code> in <code>scripts/dashboard/</code> and "
        "re-run <code>jmo report</code> for the real dashboard."
        "</div>"
    )
    # React renders into #root and leaves its siblings alone, so a banner
    # placed before it survives hydration.
    root_div = '<div id="root">'
    if root_div in doc:
        return doc.replace(root_div, banner + root_div, 1)
    if "<body>" in doc:
        return doc.replace("<body>", "<body>\n" + banner, 1)
    return banner + doc


def write_html(findings: list[dict[str, Any]], out_path: str | Path) -> None:
    """
    Write interactive React dashboard with dual-mode support.

    Mode selection:
    - ≤1000 findings: Inline mode (self-contained HTML, fast loading)
    - >1000 findings: External mode (async JSON loading, prevents browser freeze)

    The template is chosen by :func:`_resolve_template`, which logs which one it
    picked; the result is stamped with a ``jmo-dashboard-template`` meta tag so
    the artifact says so too.

    Args:
        findings: List of CommonFinding dicts
        out_path: Path to write dashboard.html
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    total = len(findings)

    template, source = _resolve_template()
    if template is None:
        _write_fallback_html(findings, p, source)
        return

    # Verify placeholder exists before attempting replacement
    placeholder = "window.__FINDINGS__ = []"
    if placeholder not in template:
        logger.warning(
            "The %s template does not contain the expected placeholder '%s', so "
            "findings cannot be injected into it. Using fallback HTML.",
            source,
            placeholder,
        )
        _write_fallback_html(findings, p, TEMPLATE_FALLBACK)
        return

    # Decide: Inline vs External mode
    if total <= INLINE_THRESHOLD:
        # Mode 1: Inline - Embed JSON directly (self-contained, fast)
        # Escaping happens AFTER json.dumps so the JSON structure is intact;
        # see escape_json_for_script for why a </script> replacement is not
        # sufficient on its own.
        data_json = escape_json_for_script(json.dumps(findings))

        # Replace placeholder with inline data
        doc = template.replace(
            "window.__FINDINGS__ = []", f"window.__FINDINGS__ = {data_json}"
        )
    else:
        # Mode 2: External - Load JSON via fetch() (prevents 50-100 MB HTML files)
        # Write dashboard data separately for async loading
        # Uses dashboard-data.json to avoid overwriting the metadata-wrapped
        # findings.json produced by basic_reporter.write_json()
        findings_json_path = p.parent / "dashboard-data.json"
        findings_json_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")

        # Replace placeholder with fetch() call
        doc = template.replace(
            "window.__FINDINGS__ = []",
            "window.__FINDINGS__ = []  // Loaded via fetch() in App.tsx",
        )

    p.write_text(_mark_template_source(doc, source), encoding="utf-8")


def _write_fallback_html(
    findings: list[dict[str, Any]],
    out_path: Path,
    source: str = TEMPLATE_FALLBACK,
) -> None:
    """
    Write a simple fallback HTML when React build is not available.

    Used in CI/test environments where React dashboard hasn't been built.

    Args:
        findings: List of CommonFinding dicts
        out_path: Path to write fallback dashboard.html
        source: Provenance value stamped into the document. Defaults to
            ``TEMPLATE_FALLBACK``, which is what this page always is.
    """
    total = len(findings)
    safe_total = html.escape(str(total))
    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <!-- Security headers, matching scripts/dashboard/index.html. This page is
         written to dashboard.html just as the React build is, so it must not
         be the one variant that ships without them. -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none';">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta name="referrer" content="no-referrer">
    <meta name="robots" content="noindex, nofollow">

    <title>JMo Security - Findings Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        .alert {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }}
        .stats {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <h1>JMo Security Findings Report</h1>
    <div class="alert" data-{PROVENANCE_META_NAME}-banner="{source}">
        <strong>⚠️  Fallback HTML Mode</strong><br>
        This is a simplified HTML report. The interactive React dashboard was not available.<br>
        To view the full interactive dashboard, build the React app with <code>npm run build</code> in <code>scripts/dashboard/</code>.
    </div>
    <div class="stats">
        <h2>Summary</h2>
        <p><strong>Total Findings:</strong> {safe_total}</p>
        <p>For detailed findings, please view the JSON report at <code>findings.json</code>.</p>
    </div>
</body>
</html>
"""
    out_path.write_text(_mark_template_source(content, source), encoding="utf-8")
