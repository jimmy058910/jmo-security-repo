"""No artifact `jmo report` writes holds the scanning machine's directory (#1007).

The case is osv-scanner's golden output, which names the directory it scanned in
two places per advisory: `lockfile:<root>/package-lock.json` in a table and
`<root>\\osv-scanner.toml` in the text that tells the reader what to ignore.
Measured before the fix, through `jmo report` with every output on: SARIF 1,896
(`rules[].help` and `properties.remediation`), `findings.json` 1,249 (`remediation`
and `raw`), `dashboard.html` 1,249 (the same findings, embedded). Reading
`findings.sarif` or the dashboard off a personal machine was reading a path
under the user's home directory.

The guard walks what the report wrote, not a list of the fields that held the
root, so a field a later adapter adds is checked on the day it lands. Its one
exemption is `raw` in `findings.json` and `findings.yaml` (J5, 2026-10-29): that
is each tool's verbatim output, and the guard asserts it still holds the root,
so redacting it there fails too.
"""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.core import normalize_and_report as nr
from scripts.core.adapters.common import scan_root_pattern, strip_scan_roots
from scripts.core.common_finding import fingerprint
from scripts.core.reporters import html_reporter
from scripts.core.scan_timings import State, ToolRun, write_scan_timings

#: The directory the golden was captured in; its output names it throughout.
ROOT = "C:/Projects/_archive/2026-09-12-jmo-v2-evidence/coverage/NodeGoat"
GOLDEN = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "golden"
    / "osv_scanner"
    / "v2.5.1"
    / "raw-output.json"
)

#: Where the case is allowed to keep the root: the tool's verbatim output.
VERBATIM_KEY = "raw"
VERBATIM_FILES = ("findings.json", "findings.yaml")

#: The root as each artifact spells it: as given, with backslashes, and as a
#: backslash path inside JSON text. The `file:///` form contains the first.
FORMS = tuple(
    form.casefold()
    for form in (ROOT, ROOT.replace("/", "\\"), ROOT.replace("/", "\\\\"))
)

#: What the case's outputs promise to write, so a report that wrote nothing
#: cannot pass for one that is clean.
EXPECTED_FILES = {
    "findings.json",
    "findings.yaml",
    "findings.sarif",
    "dashboard.html",
    "simple-report.html",
    "SUMMARY.md",
    "findings.csv",
}


def _count(text: str) -> int:
    folded = text.casefold()
    return sum(folded.count(form) for form in FORMS)


def _strings(node, skip: str | None = None) -> Iterator[str]:
    """Every string in a parsed document, keys included, except below `skip`."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            if key != skip:
                yield from _strings(value, skip)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value, skip)


def _embedded_findings(page: str):
    """The findings `dashboard.html` embeds, decoded, or None when it holds none."""
    marker = "window.__FINDINGS__ = "
    start = page.find(marker)
    assert start != -1, "dashboard.html has no findings placeholder at all"
    start += len(marker)
    if not page.startswith("[", start) or page.startswith("[]", start):
        return None
    data, _ = json.JSONDecoder().raw_decode(page, start)
    return data


def _load_yaml(text: str):
    # The libyaml loader reads these 2 MB in a fraction of the pure-Python one.
    return yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))


def _run_report(tmp_path: Path, monkeypatch) -> Path:
    """`jmo report` over the golden, every output format on; returns `summaries/`."""
    results = tmp_path / "results"
    target = results / "individual-repos" / "NodeGoat"
    target.mkdir(parents=True)
    (target / "osv-scanner.json").write_bytes(GOLDEN.read_bytes())
    write_scan_timings(
        target,
        {"osv-scanner": ToolRun("osv-scanner", State.RAN)},
        target="NodeGoat",
        target_type="repo",
        wall_seconds=1.0,
        root=ROOT,
    )
    (tmp_path / "jmo.yml").write_bytes(
        b"outputs: [json, md, yaml, html, simple-html, sarif, csv, compliance]\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    with patch.object(sys, "argv", ["jmo", "report", "--results-dir", str(results)]):
        args = jmo.parse_args()
    args.store_history = False
    assert jmo.cmd_report(args) == 0
    return results / "summaries"


@pytest.mark.parametrize("mode", ["inline", "external"])
def test_no_scan_root_in_any_shipped_artifact(tmp_path, monkeypatch, mode):
    if mode == "external":
        # The dashboard writes its findings to `dashboard-data.json` above this
        # many; zero sends the golden's 291 down that path.
        monkeypatch.setattr(html_reporter, "INLINE_THRESHOLD", 0)
    summaries = _run_report(tmp_path, monkeypatch)

    files = sorted(p for p in summaries.rglob("*") if p.is_file())
    names = {p.name for p in files}
    assert names >= EXPECTED_FILES, f"missing artifacts: {EXPECTED_FILES - names}"
    assert ("dashboard-data.json" in names) == (mode == "external")

    leaks: dict[str, int] = {}
    kept_in_raw = dict.fromkeys(VERBATIM_FILES, 0)
    findings_seen = 0
    for path in files:
        text = path.read_bytes().decode("utf-8")
        if path.name in VERBATIM_FILES:
            document = json.loads(text) if path.suffix == ".json" else _load_yaml(text)
            findings_seen += len(document["findings"])
            leaks[path.name] = sum(
                _count(s) for s in _strings(document, skip=VERBATIM_KEY)
            )
            kept_in_raw[path.name] = sum(
                _count(s) for s in _strings(_raw_values(document))
            )
        elif path.suffix in (".json", ".sarif"):
            leaks[path.name] = sum(_count(s) for s in _strings(json.loads(text)))
        else:
            leaks[path.name] = _count(text)
            if path.suffix == ".html" and path.name == "dashboard.html":
                embedded = _embedded_findings(text)
                assert (embedded is not None) == (mode == "inline")
                leaks["dashboard.html (embedded findings)"] = sum(
                    _count(s) for s in _strings(embedded)
                )

    assert findings_seen > 0, "the report holds no findings, so nothing was checked"
    assert {name: n for name, n in leaks.items() if n} == {}, (
        "the scan root is in what the report wrote"
    )
    # J5: `raw` is the tool's verbatim output. The case holds the root there, so
    # a redaction that reached it would leave 0, and the guard above would pass
    # on a report that had lost the tool's own words.
    assert all(n > 0 for n in kept_in_raw.values()), kept_in_raw


def _raw_values(node) -> list:
    """Every value under a key named `raw`, at any depth."""
    found: list = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == VERBATIM_KEY:
                found.append(value)
            else:
                found.extend(_raw_values(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_raw_values(value))
    return found


def _finding_naming(root: str, *, finding_id: str | None = None) -> dict:
    """What an adapter returns for a tool whose message names where it looked."""
    path = f"{root}/src/app.py"
    message = f"Hardcoded secret in {path}"
    return {
        "id": finding_id or fingerprint("bandit", "B105", path, 3, message),
        "tool": {"name": "bandit"},
        "ruleId": "B105",
        "location": {"path": path, "startLine": 3},
        "message": message,
        "raw": {"filename": path},
    }


def test_a_message_naming_the_root_gives_one_id_whichever_directory_was_scanned():
    """An id says what was found and where in the repository, not on which disk.

    No golden adapter's message names the root, so this builds the case the
    rewrite has to be safe for: the same finding from two checkouts. Dropping
    the root from `message` alone would leave each id hashed from its own
    checkout's text.
    """
    here = _finding_naming("C:/work/one/app")
    there = _finding_naming("/home/other/app")
    nr._normalize_paths_and_ids([here], ("C:/work/one/app",))
    nr._normalize_paths_and_ids([there], ("/home/other/app",))

    message = "Hardcoded secret in src/app.py"
    assert here["message"] == there["message"] == message
    expected = fingerprint("bandit", "B105", "src/app.py", 3, message)
    assert here["id"] == there["id"] == expected
    # J5: the tool's own output is not rewritten.
    assert here["raw"] == {"filename": "C:/work/one/app/src/app.py"}


def test_a_finding_on_the_root_directory_itself_keeps_one_id():
    """`normalize_finding_path` leaves a path equal to the root alone; the id
    must follow the path the finding carries after the root is dropped."""
    root = "C:/work/one/app"
    finding = {
        "id": fingerprint("bandit", "B105", root, None, "world-writable"),
        "tool": {"name": "bandit"},
        "ruleId": "B105",
        "location": {"path": root},
        "message": "world-writable",
    }

    assert nr._normalize_paths_and_ids([finding], (root,)) == (1, 1)

    assert finding["location"]["path"] == "."
    assert finding["id"] == fingerprint("bandit", "B105", ".", None, "world-writable")


def test_an_id_the_adapter_did_not_hash_from_the_message_is_left_alone():
    """As for the path (zap, nuclei): re-keying it would merge distinct findings."""
    finding = _finding_naming("C:/work/one/app", finding_id="GET:/login:user:0")
    nr._normalize_paths_and_ids([finding], ("C:/work/one/app",))

    assert finding["message"] == "Hardcoded secret in src/app.py"
    assert finding["id"] == "GET:/login:user:0"


@pytest.mark.parametrize(
    ("roots", "text", "expected"),
    [
        (("C:/work/app",), "lockfile:C:/work/app/lock.json", "lockfile:lock.json"),
        (("C:/work/app",), r"edit `C:\work\app\ignore.toml`", "edit `ignore.toml`"),
        # The backslash path as it reads inside JSON text.
        (("C:/work/app",), "C:\\\\work\\\\app\\\\a.txt", "a.txt"),
        # A drive letter and a directory name differ in case between tools.
        (("C:/work/app",), r"c:\WORK\App\x", "x"),
        # A root recorded with backslashes finds the forward-slash spelling.
        ((r"C:\work\app",), "C:/work/app/x", "x"),
        # The root itself is `.`, and a deeper root wins over the one holding it.
        (("/srv/a",), "scanned /srv/a today", "scanned . today"),
        (("/srv/a", "/srv/a/b"), "/srv/a/b/x and /srv/a/y", "x and y"),
        # Text that only starts like the root is not under it.
        (("/app",), "/application/x github.com/app/x /app-old/y", None),
    ],
)
def test_the_root_is_dropped_in_every_spelling_and_only_as_a_whole_directory(
    roots, text, expected
):
    pattern = scan_root_pattern(roots)
    assert pattern is not None
    assert strip_scan_roots(text, pattern) == (text if expected is None else expected)


@pytest.mark.parametrize("roots", [(), (".",), ("repos/app",), ("/",), ("",)])
def test_a_root_that_names_no_directory_removes_nothing(roots):
    # `.` would otherwise find every full stop in the report.
    assert scan_root_pattern(roots) is None


def test_the_dashboard_redacts_a_copy_and_leaves_the_findings_alone(tmp_path):
    findings = [
        {
            "id": "a",
            "message": f"in {ROOT}/package-lock.json",
            "raw": {"source": f"lockfile:{ROOT}/package-lock.json"},
            "context": {"duplicates": [{"raw": {"path": ROOT.replace("/", "\\")}}]},
        }
    ]
    before = copy.deepcopy(findings)
    page = tmp_path / "dashboard.html"

    html_reporter.write_html(findings, page, (ROOT,))

    assert findings == before
    assert _embedded_findings(page.read_bytes().decode("utf-8")) == [
        {
            "id": "a",
            "message": "in package-lock.json",
            "raw": {"source": "lockfile:package-lock.json"},
            "context": {"duplicates": [{"raw": {"path": "."}}]},
        }
    ]
