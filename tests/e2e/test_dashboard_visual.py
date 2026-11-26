"""The dashboards `jmo report` and `jmo diff` write, read in a real browser.

Each test opens a page the CLI wrote from a results directory with a known
content, and asserts what a user would read on it: the counts, the rows, what a
filter leaves, the compliance and analytics tabs. The expected numbers are
literals of the seed below, never read back from the report, so a report that
drops or invents a finding fails here as well as a dashboard that misdraws one.

This file replaced one that handed 18 synthetic findings straight to
`write_html` and asserted the severity names were on the page. The filter chips
print all five names whatever the data, so that passed with no finding at all,
and its row and header checks skipped instead of failing when no table drew.
Here nothing skips: a missing table is a failure.

Requires the `visual` extra and a browser (`uv sync --group dev --extra visual`,
then `uv run playwright install chromium`). Without playwright the module skips
on import, which is what a dev machine and the PR shards see; the scheduled
`e2e-visual` job installs both and fails on any skip.

Seed and its expected counts:

    trivy, 14 misconfigurations       CRITICAL 2, HIGH 3, MEDIUM 6, LOW 3
    opengrep, 4 results with CWEs     ERROR 2 (HIGH), WARNING 2 (MEDIUM)
    together, 18 findings             CRITICAL 2, HIGH 5, MEDIUM 8, LOW 3

Each record is a real one from the golden fixtures with its id, line, message
and severity replaced. None names a CVE, so no EPSS or KEV lookup has anything
to find; `jmo report` still tries to download the KEV catalogue, and the
subprocesses here point their proxy at a closed port so that it fails at once
and offline (the report is written either way, measured).
"""

from __future__ import annotations

import copy
import functools
import http.server
import json
import os
import re
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")

from playwright.sync_api import Page, expect

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden"

# (severity, how many) per tool. The adapters map opengrep's ERROR to HIGH and
# WARNING to MEDIUM.
TRIVY_SEED = (("CRITICAL", 2), ("HIGH", 3), ("MEDIUM", 6), ("LOW", 3))
OPENGREP_SEED = (("ERROR", 2), ("WARNING", 2))

TOTAL = 18
BY_SEVERITY = {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 8, "LOW": 3, "INFO": 0}
BY_TOOL = {"trivy": 14, "opengrep": 4}
BIG = 1001  # one over html_reporter.INLINE_THRESHOLD: the data moves to a file

# A closed port: the report's KEV download fails at once instead of reaching
# the network (see the module docstring).
OFFLINE = "http://127.0.0.1:9"

# Chromium logs these two for any page that sets the headers in a <meta>
# element, as dashboard.html does: both headers only take effect as HTTP
# response headers. They are not script errors.
META_HEADER_CONSOLE_ERRORS = (
    "The Content Security Policy directive 'frame-ancestors' is ignored when "
    "delivered via a <meta> element.",
    "X-Frame-Options may only be set via an HTTP header sent along with a "
    "document. It may not be set inside <meta>.",
)

# The history panel asks for scans.json and treats a refusal as "no history";
# from a file:// page Chromium refuses the fetch and logs it. No report writes
# scans.json, so every dashboard makes this request, and the history, trends
# and compare views it would feed never appear (#1483).
SCAN_HISTORY_FETCH = re.compile(r"Fetch API cannot load file:.*/scans\.json\. ")

SHOWING = re.compile(r"Showing \d+ of \d+")


# ---------------------------------------------------------------------------
# Seeding and running the CLI
# ---------------------------------------------------------------------------


def _golden(tool: str) -> dict:
    (version,) = (GOLDEN / tool).iterdir()
    return json.loads((version / "raw-output.json").read_bytes())


def _trivy_output(seed: tuple[tuple[str, int], ...], first: int = 1) -> dict:
    """trivy's JSON with one Dockerfile misconfiguration per seeded finding."""
    real = _golden("trivy")
    result = next(r for r in real["Results"] if r.get("Misconfigurations"))
    template = result["Misconfigurations"][0]
    records = []
    n = first - 1
    for severity, count in seed:
        for _ in range(count):
            n += 1
            record = copy.deepcopy(template)
            record.update(
                ID=f"DS-9{n:03d}",
                AVDID=f"AVD-DS-9{n:03d}",
                Severity=severity,
                Title=f"Seeded check {n}",
                Message=f"Seeded trivy finding {n} ({severity})",
            )
            record["CauseMetadata"]["StartLine"] = n
            record["CauseMetadata"]["EndLine"] = n
            records.append(record)
    doc = {k: v for k, v in real.items() if k != "Results"}
    doc["Results"] = [dict(result, Misconfigurations=records)] if records else []
    return doc


def _opengrep_output(seed: tuple[tuple[str, int], ...]) -> dict:
    """opengrep's JSON with one app.py result per seeded finding; each keeps
    the template's CWE and OWASP metadata, which the compliance tab reads."""
    real = _golden("opengrep")
    template = real["results"][0]
    results = []
    n = 0
    for severity, count in seed:
        for _ in range(count):
            n += 1
            result = copy.deepcopy(template)
            result["check_id"] = f"seeded.rule-{n}"
            result["path"] = "app.py"
            result["start"]["line"] = result["end"]["line"] = 10 * n
            result["extra"]["severity"] = severity
            result["extra"]["message"] = f"Seeded opengrep finding {n} ({severity})"
            results.append(result)
    return dict(real, results=results)


def _seed(results: Path, outputs: dict[str, dict]) -> Path:
    """A results directory holding one target, `app`, with these tool outputs."""
    target = results / "individual-repos" / "app"
    target.mkdir(parents=True)
    for tool, doc in outputs.items():
        (target / f"{tool}.json").write_bytes(json.dumps(doc).encode())
    return results


def _jmo(args: list[str], base: Path) -> subprocess.CompletedProcess:
    """Run the CLI with a home of its own and no network, from `base`."""
    home = base / "home"
    home.mkdir(exist_ok=True)
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    for proxy in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        env[proxy] = OFFLINE
    env.pop("NO_PROXY", None)
    env.pop("no_proxy", None)
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(base),
        env=env,
    )


def _report(results: Path, base: Path) -> Path:
    done = _jmo(["report", str(results)], base)
    assert done.returncode == 0, done.stderr[-3000:]
    return results / "summaries"


def _finding_count(summaries: Path) -> int:
    return len(json.loads((summaries / "findings.json").read_bytes())["findings"])


@pytest.fixture(scope="session")
def base(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("dashboards")


@pytest.fixture(scope="session")
def seeded(base: Path) -> Path:
    """`summaries/` of `jmo report` on the 18-finding seed."""
    results = _seed(
        base / "seeded",
        {
            "trivy": _trivy_output(TRIVY_SEED),
            "opengrep": _opengrep_output(OPENGREP_SEED),
        },
    )
    summaries = _report(results, base)
    # A report that lost a finding fails here, before any browser test blames
    # the dashboard for it.
    assert _finding_count(summaries) == TOTAL
    return summaries


@pytest.fixture(scope="session")
def big(base: Path) -> Path:
    """`summaries/` of a 1001-finding report, whose dashboard fetches its data."""
    results = _seed(base / "big", {"trivy": _trivy_output((("MEDIUM", BIG),))})
    summaries = _report(results, base)
    assert _finding_count(summaries) == BIG
    assert (summaries / "dashboard-data.json").is_file(), (
        "over INLINE_THRESHOLD the dashboard's data belongs in dashboard-data.json"
    )
    return summaries


@pytest.fixture(scope="session")
def clean(base: Path) -> Path:
    """`summaries/` of a report on a scan whose tool ran and found nothing."""
    results = _seed(base / "clean", {"trivy": _trivy_output(())})
    summaries = _report(results, base)
    assert _finding_count(summaries) == 0
    return summaries


@pytest.fixture(scope="session")
def diff_html(base: Path) -> Path:
    """`jmo diff --format html` between the seed and a later scan of it that
    fixed DS-9001 (CRITICAL) and DS-9014 (LOW) and added one HIGH."""
    old = _seed(
        base / "old",
        {
            "trivy": _trivy_output(TRIVY_SEED),
            "opengrep": _opengrep_output(OPENGREP_SEED),
        },
    )
    trivy = _trivy_output(TRIVY_SEED)
    trivy["Results"][0]["Misconfigurations"] = [
        m
        for m in trivy["Results"][0]["Misconfigurations"]
        if m["ID"] not in {"DS-9001", "DS-9014"}
    ]
    opengrep = _opengrep_output(OPENGREP_SEED)
    added = copy.deepcopy(opengrep["results"][0])
    added["check_id"] = "seeded.rule-new"
    added["start"]["line"] = added["end"]["line"] = 99
    added["extra"]["severity"] = "ERROR"
    added["extra"]["message"] = "A finding the second scan added"
    opengrep["results"].append(added)
    new = _seed(base / "new", {"trivy": trivy, "opengrep": opengrep})
    _report(old, base)
    _report(new, base)
    out = base / "diff.html"
    done = _jmo(
        ["diff", str(old), str(new), "--format", "html", "--output", str(out)], base
    )
    assert done.returncode == 0, done.stderr[-3000:]
    return out


@pytest.fixture(scope="session")
def served(base: Path, big: Path, clean: Path) -> Iterator[str]:
    """An HTTP server on 127.0.0.1 for the session's directory; yields its URL.

    The external-data dashboard fetches `dashboard-data.json`, and browsers
    refuse fetch() from a file:// page, so it can only be read when served.
    """

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args) -> None:
            pass

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(Quiet, directory=str(base))
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


# ---------------------------------------------------------------------------
# Reading the page
# ---------------------------------------------------------------------------


class Problems:
    """What went wrong on a page while it was open: an uncaught script error,
    a console error, or a load the server refused.

    The history panel's request for scans.json is the one expected refusal
    (see SCAN_HISTORY_FETCH). Served, it is a 404, and Chromium's console line
    for a 404 does not name the URL, so failed loads are judged by their
    response instead of by that line.
    """

    def __init__(self, page: Page) -> None:
        self.errors: list[str] = []
        page.on("pageerror", lambda e: self.errors.append(str(e)))
        page.on("console", self._console)
        page.on("response", self._response)

    def _console(self, message) -> None:
        text = message.text
        if (
            message.type != "error"
            or text in META_HEADER_CONSOLE_ERRORS
            or SCAN_HISTORY_FETCH.match(text)
            or text.startswith("Failed to load resource:")
        ):
            return
        self.errors.append(text)

    def _response(self, response) -> None:
        if response.status >= 400 and not response.url.endswith("/scans.json"):
            self.errors.append(f"{response.status} {response.url}")


def _open(page: Page, url: str) -> Problems:
    problems = Problems(page)
    page.goto(url)
    return problems


def _open_dashboard(page: Page, summaries: Path) -> Problems:
    """Open dashboard.html and wait until React has drawn the findings count."""
    problems = _open(page, (summaries / "dashboard.html").as_uri())
    expect(page.get_by_text(SHOWING).first).to_be_visible()
    return problems


def _showing(page: Page) -> str:
    return page.get_by_text(SHOWING).first.inner_text()


def _rows(page: Page):
    return page.locator("table tbody tr")


def _column(page: Page, name: str) -> list[str]:
    """The text of one column, by its header, for every row on the page."""
    headers = [
        h.strip().rstrip(" ▲▼").upper()
        for h in page.locator("table thead th").all_inner_texts()
    ]
    index = headers.index(name.upper())
    return [
        row.locator("td").nth(index).inner_text().strip() for row in _rows(page).all()
    ]


def _chip(page: Page, severity: str):
    return page.get_by_role("button", name=f"Filter {severity} severity findings")


# ---------------------------------------------------------------------------
# The dashboard of the seeded report
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTheSeededDashboard:
    def test_every_finding_is_counted_and_drawn(self, page: Page, seeded: Path):
        problems = _open_dashboard(page, seeded)
        assert _showing(page) == f"Showing {TOTAL} of {TOTAL}"
        expect(_rows(page)).to_have_count(TOTAL)  # the default page holds 25
        expect(page.get_by_text("Page 1 of 1").first).to_be_visible()
        assert sorted(_column(page, "Severity")) == sorted(
            sev for sev, n in BY_SEVERITY.items() for _ in range(n)
        )
        assert problems.errors == []

    def test_the_table_has_its_columns(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        headers = page.locator("table thead").inner_text().upper()
        for name in ("SEVERITY", "RULE", "TARGET", "PATH", "MESSAGE", "TOOL"):
            assert name in headers, headers

    def test_each_severity_chip_counts_its_findings(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        for severity, count in BY_SEVERITY.items():
            expect(_chip(page, severity)).to_have_text(f"{severity}({count})")

    def test_a_chip_clicked_off_hides_that_severity(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        _chip(page, "CRITICAL").click()
        expect(_chip(page, "CRITICAL")).to_have_attribute("aria-pressed", "false")
        left = TOTAL - BY_SEVERITY["CRITICAL"]
        assert _showing(page) == f"Showing {left} of {TOTAL}"
        expect(_rows(page)).to_have_count(left)
        assert "CRITICAL" not in _column(page, "Severity")

    def test_with_every_other_chip_off_only_the_criticals_remain(
        self, page: Page, seeded: Path
    ):
        _open_dashboard(page, seeded)
        for severity in ("HIGH", "MEDIUM", "LOW", "INFO"):
            _chip(page, severity).click()
        assert _showing(page) == f"Showing 2 of {TOTAL}"
        expect(_rows(page)).to_have_count(2)
        assert _column(page, "Severity") == ["CRITICAL", "CRITICAL"]
        assert sorted(_column(page, "Rule")) == ["DS-9001", "DS-9002"]

    def test_with_every_chip_off_the_table_says_it_is_empty(
        self, page: Page, seeded: Path
    ):
        _open_dashboard(page, seeded)
        for severity in BY_SEVERITY:
            _chip(page, severity).click()
        assert _showing(page) == f"Showing 0 of {TOTAL}"
        expect(page.get_by_text("No findings to display")).to_be_visible()
        expect(_rows(page)).to_have_count(0)

    @pytest.mark.parametrize("tool", sorted(BY_TOOL))
    def test_the_tool_filter_keeps_one_tools_findings(
        self, page: Page, seeded: Path, tool: str
    ):
        _open_dashboard(page, seeded)
        page.select_option("#tool-filter", tool)
        assert _showing(page) == f"Showing {BY_TOOL[tool]} of {TOTAL}"
        assert set(_column(page, "Tool")) == {tool}

    def test_search_finds_a_rule_by_its_id(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        page.get_by_placeholder("Search rule, message, or path...").fill(
            "seeded.rule-3"
        )
        assert _showing(page) == f"Showing 1 of {TOTAL}"
        assert _column(page, "Rule") == ["seeded.rule-3"]

    def test_the_compliance_tab_shows_each_frameworks_coverage(
        self, page: Page, seeded: Path
    ):
        """Each framework's percentage is the share of the report's findings
        that carry a mapping to it, as `findings.json` records them.

        Mapping a rule to a framework is the report's job and is tested where
        the mappings live; this checks the tab draws what the report wrote.
        """
        findings = json.loads((seeded / "findings.json").read_bytes())["findings"]
        keys = {
            "OWASP Top 10 2021": "owaspTop10_2021",
            "CWE Top 25 2024": "cweTop25_2024",
            "CIS Controls v8.1": "cisControlsV8_1",
            "NIST CSF 2.0": "nistCsf2_0",
            "PCI DSS 4.0": "pciDss4_0",
            "MITRE ATT&CK": "mitreAttack",
        }
        expected = {
            name: round(
                100
                * sum(1 for f in findings if (f.get("compliance") or {}).get(key))
                / len(findings)
            )
            for name, key in keys.items()
        }
        # Meta-guard: the seed maps to some frameworks fully and others only
        # through opengrep's CWEs, so a tab that drew one value everywhere
        # (0, 100, or the average) cannot match.
        assert len(set(expected.values())) > 1 and min(expected.values()) > 0, expected

        _open_dashboard(page, seeded)
        page.get_by_role("button", name="Compliance").click()
        expect(page.get_by_text("Compliance Framework Coverage")).to_be_visible()
        drawn = {}
        for name in keys:
            row = page.locator(
                "div.flex.justify-between", has=page.get_by_role("link", name=name)
            )
            drawn[name] = int(row.locator("span.font-bold").inner_text().rstrip("%"))
        assert drawn == expected

        # Python's round() rounds a half to even and Math.round rounds it up;
        # no seeded share lands on a half.
        average = round(sum(expected.values()) / len(expected))
        expect(
            page.get_by_text("Average Coverage").locator("xpath=..")
        ).to_contain_text(f"{average}%")

    def test_the_analytics_tab_totals_the_findings(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        page.get_by_role("button", name="Analytics").click()
        cards = {
            "Total Findings": TOTAL,
            "Critical + High": BY_SEVERITY["CRITICAL"] + BY_SEVERITY["HIGH"],
            "Tools Used": len(BY_TOOL),
            "Files Affected": 2,  # trivy's Dockerfile and opengrep's app.py
        }
        for label, value in cards.items():
            card = page.get_by_text(label, exact=True).locator("xpath=..")
            expect(card.locator("div.text-3xl")).to_have_text(str(value))

    @pytest.mark.parametrize(
        "width,height",
        [(375, 812), (768, 1024), (1440, 900)],
        ids=["mobile", "tablet", "desktop"],
    )
    def test_every_viewport_draws_the_findings(
        self, page: Page, seeded: Path, width: int, height: int
    ):
        page.set_viewport_size({"width": width, "height": height})
        problems = _open_dashboard(page, seeded)
        assert _showing(page) == f"Showing {TOTAL} of {TOTAL}"
        expect(_rows(page)).to_have_count(TOTAL)
        assert problems.errors == []

    def test_the_page_says_which_template_drew_it(self, seeded: Path):
        """The raw file names the React build, so a report that fell back to
        the static page fails here even though that page has no table."""
        html = (seeded / "dashboard.html").read_text(encoding="utf-8")
        assert 'name="jmo-dashboard-template" content="react-build"' in html
        assert "data-jmo-dashboard-template-banner" not in html

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "issue draft 'The dashboard template meta lands inside the inlined "
            "JS bundle, not the document head': _mark_template_source inserts "
            "it before the first '</head>', which in the React build is inside "
            "ExportButton's HTML template string"
        ),
    )
    def test_the_template_meta_is_in_the_document_head(self, page: Page, seeded: Path):
        _open_dashboard(page, seeded)
        content = page.evaluate(
            "document.head.querySelector('meta[name=\"jmo-dashboard-template\"]')"
            "?.content ?? null"
        )
        assert content == "react-build"


# ---------------------------------------------------------------------------
# Over the inline threshold, and with nothing found
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTheLargeDashboard:
    def test_served_it_draws_all_1001_across_41_pages(self, page: Page, served: str):
        problems = _open(page, f"{served}/big/summaries/dashboard.html")
        expect(page.get_by_text(f"Showing {BIG} of {BIG}")).to_be_visible()
        expect(_rows(page)).to_have_count(25)
        expect(page.get_by_text("Page 1 of 41").first).to_be_visible()
        page.get_by_role("button", name="Last").first.click()
        expect(page.get_by_text("Page 41 of 41").first).to_be_visible()
        expect(_rows(page)).to_have_count(BIG - 40 * 25)
        assert problems.errors == []

    def test_from_a_file_url_it_says_to_serve_it(self, page: Page, big: Path):
        """Browsers refuse fetch() from a file:// page, so the external-data
        dashboard cannot load when opened as a file; it must say why."""
        _open(page, (big / "dashboard.html").as_uri())
        expect(page.get_by_text("Loading Failed")).to_be_visible()
        expect(page.get_by_text(re.compile(r"python3 -m http\.server"))).to_be_visible()


@pytest.mark.e2e
class TestTheCleanDashboard:
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "issue draft 'A scan with no findings writes a dashboard that says "
            "Loading Failed': useFindings reads an empty window.__FINDINGS__ as "
            "external mode and fetches a dashboard-data.json no report writes"
        ),
    )
    @pytest.mark.parametrize("how", ["file", "http"])
    def test_a_report_with_no_findings_says_there_are_none(
        self, page: Page, clean: Path, served: str, how: str
    ):
        url = (
            (clean / "dashboard.html").as_uri()
            if how == "file"
            else f"{served}/clean/summaries/dashboard.html"
        )
        _open(page, url)
        expect(page.get_by_text("Showing 0 of 0")).to_be_visible(timeout=5000)
        expect(page.get_by_text("No findings to display")).to_be_visible()


# ---------------------------------------------------------------------------
# The diff dashboard
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestTheDiffDashboard:
    def test_the_summary_counts_the_changes(self, page: Page, diff_html: Path):
        problems = _open(page, diff_html.as_uri())
        cards = {
            ".summary-card.new": ("1", "HIGH: 1"),
            ".summary-card.resolved": ("2", "CRITICAL: 1, LOW: 1"),
            ".summary-card.modified": ("0", "None"),
        }
        for selector, (count, breakdown) in cards.items():
            card = page.locator(selector)
            expect(card.locator(".count")).to_have_text(count)
            expect(card).to_contain_text(breakdown)
        expect(page.locator("#summary")).to_contain_text("Net Change: -1")
        expect(page.locator("#summary")).to_contain_text("Trend: improving")
        expect(page.locator(".finding-card")).to_have_count(3)
        assert problems.errors == []

    @pytest.mark.parametrize(
        "severity,rule",
        [("CRITICAL", "DS-9001"), ("LOW", "DS-9014"), ("HIGH", "seeded.rule-new")],
    )
    def test_the_severity_filter_keeps_one_card(
        self, page: Page, diff_html: Path, severity: str, rule: str
    ):
        _open(page, diff_html.as_uri())
        page.select_option("#severity-filter", severity)
        visible = page.locator(".finding-card:visible")
        expect(visible).to_have_count(1)
        expect(visible).to_contain_text(rule)
