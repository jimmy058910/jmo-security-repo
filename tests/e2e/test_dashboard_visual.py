"""Visual dashboard regression tests using Playwright.

Tests that dashboard.html renders correctly with real findings data.
Requires: pip install pytest-playwright && playwright install chromium

Run: make test-e2e-visual
Skip: pytest tests/e2e/ --ignore=tests/e2e/test_dashboard_visual.py

Dashboard structure notes (from scripts/dashboard/src/):
- React app rendered into #root div
- Page title: "JMo Security Dashboard" (scripts/dashboard/index.html)
- Findings table: <table> with <tbody> and <tr> rows
- Severity displayed as text in <td> with classes text-critical/text-high/etc.
- Fallback HTML (no React build): simple page with class="stats" summary only,
  no findings table rows — tests account for both render modes.

CommonFinding schema v1.2.0 required fields:
  schemaVersion, id, ruleId, severity, tool.{name,version},
  location.{path}, message
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Skip entire module if playwright not installed
pytest.importorskip("playwright")

from playwright.sync_api import Page  # noqa: E402

# ---------------------------------------------------------------------------
# Helper: build a minimal CommonFinding dict the React dashboard can consume
# ---------------------------------------------------------------------------

_SEVERITIES = ["CRITICAL"] * 2 + ["HIGH"] * 5 + ["MEDIUM"] * 8 + ["LOW"] * 3


def _make_finding(index: int, severity: str) -> dict:
    """Return a minimal CommonFinding dict for the given severity."""
    return {
        "schemaVersion": "1.2.0",
        "id": f"finding-{index}",
        "ruleId": f"TEST-{index:03d}",
        "severity": severity,
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {"path": "src/app.py", "startLine": index * 10},
        "message": f"Test finding {index} ({severity})",
        "title": f"Test Finding {index} ({severity})",
        "description": f"Description for finding {index}",
    }


# ---------------------------------------------------------------------------
# Session-scoped fixture: generate dashboard.html once for all visual tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sample_dashboard(tmp_path_factory) -> Path:
    """Generate a dashboard.html with sample findings data.

    Uses the real write_html() function; falls back gracefully when the
    React build is not present (CI/test environments).
    """
    from scripts.core.reporters.html_reporter import write_html

    tmp_dir = tmp_path_factory.mktemp("dashboard")
    findings = [_make_finding(i, sev) for i, sev in enumerate(_SEVERITIES, start=1)]

    dashboard_path = tmp_dir / "dashboard.html"
    write_html(findings, str(dashboard_path))

    assert dashboard_path.exists(), "Dashboard generation failed"
    return dashboard_path


@pytest.fixture
def dashboard_page(page: Page, sample_dashboard: Path) -> Page:
    """Load the dashboard in a Playwright page and wait for DOM ready."""
    # as_posix() is safe here — Playwright's file:// URL always needs forward slashes
    file_url = f"file:///{sample_dashboard.resolve().as_posix()}"
    page.goto(file_url)
    page.wait_for_load_state("domcontentloaded")
    return page


# ---------------------------------------------------------------------------
# Core rendering tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDashboardRendering:
    """Dashboard.html renders correctly and contains expected content."""

    def test_dashboard_loads_without_js_errors(self, dashboard_page: Page):
        """Dashboard loads without JavaScript console errors.

        Registers error listener then reloads to capture errors from scratch.
        """
        errors: list[str] = []
        dashboard_page.on("pageerror", lambda err: errors.append(str(err)))
        dashboard_page.reload()
        dashboard_page.wait_for_load_state("domcontentloaded")
        assert not errors, f"JavaScript errors on load: {errors}"

    def test_dashboard_has_title(self, dashboard_page: Page):
        """Dashboard HTML has a non-empty <title> element."""
        title = dashboard_page.title()
        assert title, "Dashboard has no <title>"

    def test_page_title_contains_jmo(self, dashboard_page: Page):
        """Page title mentions JMo or Security (both React and fallback modes)."""
        title = dashboard_page.title().lower()
        assert (
            "jmo" in title or "security" in title
        ), f"Unexpected page title: {dashboard_page.title()!r}"

    def test_dashboard_body_is_nonempty(self, dashboard_page: Page):
        """Dashboard body has visible content."""
        body_text = dashboard_page.text_content("body") or ""
        assert len(body_text.strip()) > 0, "Dashboard body is empty"

    def test_severity_labels_present(self, dashboard_page: Page):
        """All four severity levels appear somewhere on the page.

        Works for both React dashboard (severity column in table) and the
        fallback HTML (which embeds severity counts in the stats div).
        The React app renders severities synchronously from window.__FINDINGS__,
        so domcontentloaded is sufficient — no extra wait needed.
        """
        page_text = dashboard_page.text_content("body") or ""
        page_text_upper = page_text.upper()
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert (
                severity in page_text_upper
            ), f"Severity '{severity}' not visible in dashboard"

    def test_findings_table_rows_present(self, dashboard_page: Page):
        """Findings table has at least one data row.

        Only asserts when the React dashboard is active (table element exists).
        Skips gracefully for the fallback HTML which has no table.
        """
        table = dashboard_page.locator("table")
        if table.count() == 0:
            pytest.skip(
                "No <table> in generated HTML — fallback mode, skipping row check"
            )

        # React renders <tbody><tr> for each paginated finding
        rows = dashboard_page.locator("table tbody tr")
        assert rows.count() > 0, "Findings table has no rows"

    def test_react_root_mounted(self, dashboard_page: Page):
        """React mounts into #root when the React build is available.

        Skips when #root element is absent (fallback HTML mode).
        """
        root = dashboard_page.locator("#root")
        if root.count() == 0:
            pytest.skip(
                "No #root element — fallback HTML mode, skipping React mount check"
            )

        # #root should have child content once React hydrates
        child_count = root.evaluate("el => el.children.length")
        assert child_count > 0, "#root exists but React has not mounted any children"


# ---------------------------------------------------------------------------
# Responsive viewport tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDashboardResponsive:
    """Dashboard renders without errors at various viewport sizes."""

    @pytest.mark.parametrize(
        "width,height,label",
        [
            (375, 812, "mobile"),
            (768, 1024, "tablet"),
            (1440, 900, "desktop"),
        ],
    )
    def test_responsive_viewport(
        self,
        page: Page,
        sample_dashboard: Path,
        width: int,
        height: int,
        label: str,
    ):
        """Dashboard renders at the given viewport size without a blank body."""
        page.set_viewport_size({"width": width, "height": height})
        file_url = f"file:///{sample_dashboard.resolve().as_posix()}"
        page.goto(file_url)
        page.wait_for_load_state("domcontentloaded")

        # Capture screenshot for manual inspection / visual diff
        screenshots_dir = Path("e2e-screenshots")
        screenshots_dir.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshots_dir / f"dashboard-{label}.png"))

        # Basic sanity: page loaded with a title and non-blank body
        assert page.title(), f"Dashboard has no title at {label} ({width}x{height})"
        body_text = page.text_content("body") or ""
        assert (
            len(body_text.strip()) > 0
        ), f"Dashboard body is empty at {label} ({width}x{height})"


# ---------------------------------------------------------------------------
# Filter / interaction smoke tests (React-only, skipped in fallback mode)
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestDashboardInteraction:
    """Smoke tests for dashboard interactive features (requires React build)."""

    def _require_react(self, dashboard_page: Page) -> None:
        """Skip test if the React dashboard did not render."""
        if dashboard_page.locator("#root").count() == 0:
            pytest.skip(
                "No #root element — fallback HTML mode, skipping interaction tests"
            )
        root_children = dashboard_page.locator("#root").evaluate(
            "el => el.children.length"
        )
        if root_children == 0:
            pytest.skip("React did not mount — skipping interaction tests")

    def test_findings_table_column_headers(self, dashboard_page: Page):
        """FindingsTable renders expected column headers (Severity, Rule, Path)."""
        self._require_react(dashboard_page)
        table = dashboard_page.locator("table")
        if table.count() == 0:
            pytest.skip("No <table> present — skipping header check")

        headers_text = (dashboard_page.text_content("table thead") or "").upper()
        for expected in ("SEVERITY", "RULE", "PATH"):
            assert (
                expected in headers_text
            ), f"Column header '{expected}' not found in table thead"

    def test_page_has_no_broken_root(self, dashboard_page: Page):
        """Dashboard does not display a bare empty #root (white-screen failure)."""
        root = dashboard_page.locator("#root")
        if root.count() == 0:
            pytest.skip("No #root — fallback HTML mode")

        # A white-screen failure would leave #root with zero children
        child_count = root.evaluate("el => el.children.length")
        assert (
            child_count > 0
        ), "Dashboard #root has no children — possible white-screen failure"
