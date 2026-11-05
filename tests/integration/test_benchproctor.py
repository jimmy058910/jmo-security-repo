"""BenchProctor's TypeScript and JavaScript cases grade the rule bundle (Phase 6, F7; J7).

TheAuditorTool/BenchProctor's 2026.07.22 quicktest bundles hold, per framework,
6,200 generated test cases (62 categories, 50 vulnerable and 50 safe each), their
labels (`expectedresults-2026.07.22.csv`) and the bundle's own scorer
(`score_sarif.py`). They are the answer key here, pinned by sha256 and fetched,
never committed:

    python scripts/dev/fetch_answer_keys.py benchproctor

Each framework is scanned with `jmo scan --tools opengrep`, and the scorer grades
JMo's `findings.sarif`, run as a subprocess (`python -I`), never imported. Its
default matching counts a test as detected when a finding names the test's file
and carries the test's CWE; `--match-mode filename` is never used, since it
rewards flagging every file. The scorer reads a CWE from a result's `taxa`,
which the SARIF reporter writes from `risk.cwe` since this task: before it, it
credited 0 of 1,527 findings on express_ts.

The labels are generated, not audited, so the gate is a drop, not a threshold:
a framework's Youden's J (macro-averaged TPR minus FPR, the scorer's
"Category-Averaged" score) may not fall below its recorded value by more than
the spread of two identical runs plus a recorded tolerance.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.dev import fetch_answer_keys as keys
from tests.conftest import scanner_installed

FETCH_COMMAND = "python scripts/dev/fetch_answer_keys.py benchproctor"
BASELINE = Path(__file__).parent / "baselines" / "benchproctor.json"
RECORD = "JMO_RECORD_BENCHPROCTOR"
LABELS = "expectedresults-2026.07.22.csv"
FRAMEWORKS = {
    "express_ts": "typescript",
    "nestjs": "typescript",
    "express": "javascript",
    "koa": "javascript",
}

_MACRO = re.compile(
    r"^MACRO AVERAGE\s+(-?[\d.]+)%\s+(-?[\d.]+)%\s+([+-]?[\d.]+)%", re.MULTILINE
)
_TOTAL = re.compile(r"^TOTAL\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s", re.MULTILINE)


def parse_score(report: str) -> dict[str, float | int]:
    """The scorer's macro TPR, FPR and J (percent), and its flat counts."""
    macro, total = _MACRO.search(report), _TOTAL.search(report)
    if not macro or not total:
        raise ValueError(f"not a score_sarif.py report: {report[-500:]!r}")
    tpr, fpr, j = (float(x) for x in macro.groups())
    tp, fp, fn, tn = (int(x) for x in total.groups())
    return {"tpr": tpr, "fpr": fpr, "j": j, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


REPORT = """\
==================================================
CATEGORY-AVERAGED SCORING (macro-averaged)
--------------------------------------------------
cmdi             78       72.0%   44.0%  +28.0%
--------------------------------------------------
MACRO AVERAGE              7.6%    5.4%   +2.3%

TOTAL                   237   167   2863  2933     7.6%    5.4%   +2.3%
"""


def test_the_scorers_summary_is_read() -> None:
    assert parse_score(REPORT) == {
        "tpr": 7.6,
        "fpr": 5.4,
        "j": 2.3,
        "tp": 237,
        "fp": 167,
        "fn": 2863,
        "tn": 2933,
    }


def test_a_negative_j_is_read_as_negative() -> None:
    report = REPORT.replace("+2.3%\n\nTOTAL", "-1.5%\n\nTOTAL")
    assert parse_score(report)["j"] == -1.5


def test_text_that_is_not_a_score_is_refused() -> None:
    with pytest.raises(ValueError, match="not a score_sarif.py report"):
        parse_score("Error: SARIF file not found")


@pytest.fixture(scope="module")
def bundles() -> dict[str, Path]:
    """Each language's extracted bundle; skips when the key is not fetched and
    fails when a zip is not the pin."""
    root = keys.benchproctor_dir()
    for rel, expected in keys.BENCHPROCTOR_FILES.items():
        path = root / rel
        if not path.is_file():
            pytest.skip(
                f"answer key {keys.BENCHPROCTOR} is not fetched: run `{FETCH_COMMAND}`"
            )
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            pytest.fail(
                f"{path} is not the pinned file (sha256 {actual}, pinned {expected}): "
                f"run `{FETCH_COMMAND}`",
                pytrace=False,
            )
    return {lang: keys.benchproctor_bundle(lang) for lang in set(FRAMEWORKS.values())}


@pytest.mark.requires_tools
@pytest.mark.timeout(1800)
@pytest.mark.parametrize("framework", list(FRAMEWORKS))
def test_benchproctor_scores_the_rule_bundle_no_worse_than_recorded(
    framework, bundles, jmo_runner, tmp_path
) -> None:
    if not scanner_installed("opengrep"):
        pytest.skip("opengrep is not installed")
    bundle = bundles[FRAMEWORKS[framework]]
    config = tmp_path / "jmo.yml"
    config.write_bytes(b"outputs:\n  - json\n  - sarif\n")
    results = tmp_path / "results"
    run = jmo_runner(
        [
            "scan",
            "--repo",
            str(bundle / framework),
            "--tools",
            "opengrep",
            "--config",
            str(config),
            "--results-dir",
            str(results),
            "--no-store-history",
        ],
        timeout=1500,
    )
    assert run.returncode == 0, run.stderr[-2000:]
    rows = json.loads(
        (results / "individual-repos" / framework / "scan-timings.json").read_bytes()
    )["tools"]
    assert [(r["tool"], r["state"]) for r in rows] == [("opengrep", "ran")], rows

    scored = subprocess.run(
        [
            sys.executable,
            "-I",
            str(bundle / "score_sarif.py"),
            str(results / "summaries" / "findings.sarif"),
            str(bundle / framework / LABELS),
        ],
        cwd=bundle,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert scored.returncode == 0, scored.stderr[-2000:]
    score = parse_score(scored.stdout)
    print(f"{framework}: {score}")

    recorded = json.loads(BASELINE.read_bytes()) if BASELINE.is_file() else {}
    if os.environ.get(RECORD):
        frameworks = recorded.setdefault("frameworks", {})
        # The time and peak memory each framework took stay the measurement's
        # (F7 Step 1): one sample here would measure the runner (#742).
        frameworks[framework] = {**frameworks.get(framework, {}), **score}
        BASELINE.write_bytes((json.dumps(recorded, indent=2) + "\n").encode())
        pytest.skip(f"recorded {framework} in {BASELINE.name}: J {score['j']}%")

    assert recorded["source"]["commit"] == keys.BENCHPROCTOR_COMMIT, (
        "another key's baseline"
    )
    was = recorded["frameworks"][framework]
    allowed = was["spread"] + recorded["tolerance"]
    assert score["j"] >= was["j"] - allowed, (
        f"{framework}: Youden's J {score['j']}% fell below the recorded {was['j']}% by "
        f"more than {allowed} points (TPR {score['tpr']}% was {was['tpr']}%, "
        f"FPR {score['fpr']}% was {was['fpr']}%)"
    )
