"""zap runs one at a time in a scan, so two URL targets both get a report (#1422).

ZAP allows one process per home directory, and every zap run JMo starts uses
JMo's own home (`zap_home()`). Measured on ZAP 2.17.0 before this: two plan
runs started together on one home, one finished rc 0 with a report and the
other returned rc 1 in 0.4 s with "The home directory is already in use", and
through `jmo scan` with two URLs one zap row read `ran` and the other `failed`.

The zap here is a stand-in in a home of the test's own: it holds a lock in its
`-dir` home for the length of its run and refuses to start while another run
holds it, as ZAP does, then writes the report the plan names.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in is zap.sh, run by its shebang"
)

ROOT = Path(__file__).resolve().parents[2]

STAND_IN = """#!{python}
import sys, time
from pathlib import Path

import yaml

args = sys.argv[1:]
if "-version" in args:
    print("2.17.0")
    sys.exit(0)
home = Path(args[args.index("-dir") + 1])
plan = Path(args[args.index("-autorun") + 1])
home.mkdir(parents=True, exist_ok=True)
lock = home / "in-use"
try:
    lock.mkdir()
except FileExistsError:
    print(
        "The home directory is already in use. Ensure no other ZAP instances "
        "are running with the same home directory"
    )
    sys.exit(1)
try:
    time.sleep(2)
    jobs = yaml.safe_load(plan.read_bytes())["jobs"]
    report = next(job for job in jobs if job["type"] == "report")["parameters"]
    Path(report["reportDir"], report["reportFile"]).write_text('{{"site": []}}')
finally:
    lock.rmdir()
"""


def test_two_url_targets_each_get_a_zap_report(tmp_path) -> None:
    home = tmp_path / "home"
    zap_dir = home / ".jmo" / "bin" / "zap"
    zap_dir.mkdir(parents=True)
    zap = zap_dir / "zap.sh"
    zap.write_bytes(STAND_IN.format(python=sys.executable).encode())
    zap.chmod(0o755)
    results = tmp_path / "results"
    env = {**os.environ, "HOME": str(home), "PYTHONPATH": str(ROOT)}
    env.pop("JMO_NON_INTERACTIVE", None)

    # Nothing listens on port 9: the redirect probe is refused at once.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "scan",
            "--url",
            "http://127.0.0.1:9/one",
            "--url",
            "http://127.0.0.1:9/two",
            "--tools",
            "zap",
            "--threads",
            "2",
            "--results-dir",
            str(results),
            "--history-db",
            str(tmp_path / "history.db"),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=110,
    )

    metadata = json.loads((results / ".scan_metadata.json").read_text(encoding="utf-8"))
    rows = [row for row in metadata["tool_runs"] if row["tool"] == "zap"]
    assert [row["state"] for row in rows] == ["ran", "ran"], (
        rows,
        proc.stderr[-2000:],
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
