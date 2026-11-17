"""The committed opengrep rule bundle still fires on juice-shop (v2.0.0 Phase 5, PR B, task B7).

An earlier merge of these rules lost four findings in juice-shop, an intentionally
vulnerable web application, and nothing noticed. This is the guard that would:
four files of juice-shop are scanned through JMo's opengrep row, as `jmo scan` runs
it, and the bundle must report these (rule, file, line), never the column:

    tainted-sql-string          routes/login.ts           34
    tainted-sql-string          routes/search.ts          23
    hardcoded-jwt-secret        lib/insecurity.ts         56
    template-explicit-unescape  views/promotionVideo.pug  79

The other six findings the four files give (measured, opengrep 1.32.0: two
`sequelize-raw-query`, two `express-sequelize-injection`, two `hardcoded-hmac-key`)
are not asserted: a rule that stops firing is a decision about coverage, and these
four are the ones that were lost.

The files are fetched, never committed (`scripts/dev/fetch_rule_fixture.py`: by commit
and sha256; `lib/insecurity.ts` holds an RSA private key). They are STORED in a
gitignored directory, and that directory cannot be scanned: opengrep honours the
repository's `.gitignore` when its target lies inside a git work tree, so the row
read `failed:examined 0 files` from it (measured, 1.32.0; docs/KNOWN_LIMITATIONS.md).
So each test copies the four files, at their relative paths, into a pytest `tmp_path`
and scans that copy, through the row. `tmp_path` must lie outside any git work tree
that ignores it: a `--basetemp` inside the checkout's ignored directories would
bring the 0-files result back, which `test_the_fixture_is_read` names.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from scripts.cli.scan_jobs import tool_loop
from scripts.core.adapters.common import normalize_finding_path
from scripts.core.adapters.opengrep_adapter import OpengrepAdapter
from scripts.core.scan_timings import State, ToolRun
from scripts.core.tool_runner import ToolResult, ToolRunner
from scripts.dev import fetch_rule_fixture

pytestmark = pytest.mark.requires_tools

ROOT = Path(__file__).resolve().parents[2]
STORED = fetch_rule_fixture.DEFAULT_DEST
BUNDLE = ROOT / "scripts" / "jmo_rules"
FETCH_SCRIPT = "python scripts/dev/fetch_rule_fixture.py"

#: (rule id's last segment, path relative to the target, line)
EXPECTED = {
    ("tainted-sql-string", "routes/login.ts", 34),
    ("tainted-sql-string", "routes/search.ts", 23),
    ("hardcoded-jwt-secret", "lib/insecurity.ts", 56),
    ("template-explicit-unescape", "views/promotionVideo.pug", 79),
}

PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")


def _stored_files() -> dict[str, Path]:
    """The four stored files, or a skip that names the script that fetches them.
    A file that is there with the wrong hash is a failure, not a skip: it is not the
    file the lines above were measured on."""
    stored = {path: STORED / path for path in fetch_rule_fixture.FILES}
    absent = [path for path, file in stored.items() if not file.is_file()]
    if absent:
        pytest.skip(f"the juice-shop fixture is not fetched ({absent}): {FETCH_SCRIPT}")
    for path, expected in fetch_rule_fixture.FILES.items():
        actual = hashlib.sha256(stored[path].read_bytes()).hexdigest()
        assert actual == expected, (
            f"{stored[path]} is not the pinned file: {FETCH_SCRIPT}"
        )
    return stored


@pytest.fixture
def target(tmp_path: Path) -> Path:
    """A copy of the four files, at their relative paths, in a directory whose name
    holds a dot, outside the checkout."""
    stored = _stored_files()
    copy = tmp_path / "v1.2.target"
    for path, file in stored.items():
        (copy / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, copy / path)
    return copy


def _scan(
    target: Path, out: Path, *, per_tool_config: dict | None = None
) -> tuple[ToolRun, list[ToolResult]]:
    """The opengrep row, run for real through the scan loop, with the process results
    kept so a test can read the exit code and stderr."""
    if shutil.which("opengrep") is None:
        pytest.skip("opengrep is not on PATH")
    results: list[ToolResult] = []

    class Keeping(ToolRunner):
        def run_all_parallel(self):
            got = super().run_all_parallel()
            results.extend(got)
            return got

    out.mkdir(parents=True, exist_ok=True)
    row = tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=target,
        target_label="juice-shop",
        out_dir=out,
        timeout=300,
        retries=0,
        per_tool_config=per_tool_config or {},
        allow_missing_tools=False,
        runner_cls=Keeping,
        repo_root=target,
    )["opengrep"]
    return row, results


def _document(out: Path) -> dict:
    return json.loads((out / "opengrep.json").read_bytes())


# opengrep names a file with the separator of the OS it runs on: `lib\insecurity.ts`
# on Windows (measured on the windows-opengrep job), `lib/insecurity.ts` elsewhere.
# The report phase puts every tool's `location.path` through
# `normalize_finding_path`, so these tests compare paths through it too, never
# through a `.replace` of their own: what they check is the spelling a user's report
# ends up with.


def _scanned(out: Path) -> list[str]:
    """`paths.scanned` of the scan in `out`, as the report phase spells a path."""
    return [normalize_finding_path(path) for path in _document(out)["paths"]["scanned"]]


def _triples(out: Path) -> set[tuple[str, str, int]]:
    """(rule, path, line) of each result, the path as the report phase spells it."""
    return {
        (
            r["check_id"].rsplit(".", 1)[-1],
            normalize_finding_path(r["path"]),
            r["start"]["line"],
        )
        for r in _document(out)["results"]
    }


def test_the_fixture_is_read(tmp_path, target) -> None:
    """Before any rule is asked about: the row ran and read all four files. A scan
    that read none (a `.gitignore` above the target, a default-ignored ancestor) must
    say so rather than look like four lost findings."""
    row, _ = _scan(target, tmp_path / "out")

    assert row.state is State.RAN, row
    assert sorted(_scanned(tmp_path / "out")) == sorted(fetch_rule_fixture.FILES), (
        "opengrep did not read the four files; is the target inside an ignored directory?"
    )


def test_the_four_fixture_findings(tmp_path, target) -> None:
    row, _ = _scan(target, tmp_path / "out")

    assert row.state is State.RAN, row
    missing = EXPECTED - _triples(tmp_path / "out")
    assert not missing, f"the bundle no longer reports {sorted(missing)}"


def _bundle_rule_ids() -> set[str]:
    ids: set[str] = set()
    for name in ("javascript", "typescript", "generic"):
        document = yaml.safe_load((BUNDLE / f"{name}.yaml").read_text(encoding="utf-8"))
        ids.update(rule["id"] for rule in document["rules"])
    return ids


def test_ids_do_not_depend_on_the_working_directory(
    tmp_path, target, monkeypatch
) -> None:
    """A rule id is exactly the bundle's, and a finding's id (which hashes the rule
    id, the path and the line) is the same from any directory. Without
    `--no-rewrite-rule-ids` opengrep prefixes a rule's id with the directories of its
    config file as seen from where it runs, and the target's path, here one with a dot
    in it, is what it would be seen from."""
    bundle_ids = _bundle_rule_ids()

    def ids_from(cwd: Path, scanned: Path, out: Path) -> tuple[list[str], list[str]]:
        monkeypatch.chdir(cwd)
        row, _ = _scan(scanned, out)
        assert row.state is State.RAN, row
        rule_ids = sorted(r["check_id"] for r in _document(out)["results"])
        finding_ids = sorted(
            f.id for f in OpengrepAdapter().parse(out / "opengrep.json")
        )
        return rule_ids, finding_ids

    from_root = ids_from(Path("/"), target, tmp_path / "out-root")
    from_target = ids_from(target, Path("."), tmp_path / "out-target")

    assert from_root[0], "no findings to compare"
    assert set(from_root[0]) <= bundle_ids, (
        f"not the bundle's ids: {sorted(set(from_root[0]) - bundle_ids)[:3]}"
    )
    assert from_root == from_target


class _Proxy:
    """A proxy that answers nobody: it records the first bytes of every connection
    (an HTTPS request through a proxy opens with `CONNECT <host>:443`) and hangs
    up. A refused port was the earlier proxy, and the evidence was the error text;
    2.0.0 retries a refused proxy without a word for minutes (measured
    2026-11-17: 1.32.0 failed in 25 s with `ProxyError`, 2.0.0 was still silent
    at 90 s), so the evidence is now what reached the socket, the same on both."""

    def __init__(self) -> None:
        self.requests: list[str] = []
        self._server = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._server.getsockname()[1]}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:  # closed: the test is over
                return
            with conn:
                conn.settimeout(5)
                try:
                    self.requests.append(conn.recv(4096).decode("latin-1"))
                except OSError as exc:
                    self.requests.append(f"<nothing read: {exc}>")

    def close(self) -> None:
        self._server.close()


@pytest.fixture
def proxy(monkeypatch) -> Iterator[_Proxy]:
    """Every proxy variable at the recording proxy, and no host exempt from it."""
    recorder = _Proxy()
    for var in PROXY_VARS:
        monkeypatch.setenv(var, recorder.url)
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    yield recorder
    recorder.close()


def test_the_proxy_variables_reach_opengrep(tmp_path, proxy) -> None:
    """The control for the test below: a run that DOES ask for the network goes
    through the proxy. If opengrep ever stopped honouring the variables, that test
    would pass and prove nothing. opengrep is stopped once the request arrives:
    what it does with a proxy that hangs up is not the question."""
    binary = shutil.which("opengrep")
    if binary is None:
        pytest.skip("opengrep is not on PATH")
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.py").write_text("x = 1\n", encoding="utf-8")
    env = dict(os.environ, SEMGREP_LOG_FILE=str(tmp_path / "semgrep.log"))

    run = subprocess.Popen(
        [binary, "scan", "--config", "https://rules.invalid/rules.yaml", "."],
        cwd=work,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 120
        while not proxy.requests and run.poll() is None:
            if time.monotonic() > deadline:
                break
            time.sleep(0.1)
    finally:
        run.kill()
        run.wait(timeout=60)

    assert any("rules.invalid" in r for r in proxy.requests), proxy.requests


def test_a_scan_makes_no_network_call(tmp_path, target, proxy) -> None:
    """Every proxy variable points at the recording proxy and nothing is exempt from
    it, so a scan that fetched a rule configuration over HTTP(S) would reach it: the
    control above shows opengrep's client honours them, and a rule URL given as
    `--config` is the one network path observed. Measured on 1.32.0, and seen NOT to
    use the network: a local config under `--enable-version-check`, and there is no
    `--metrics` option to turn off (rc 2, "unknown option"). 2.0.0 ignores both
    version-check flags, and a local scan of the bundle sent the proxy nothing on
    either version (2026-11-17). This scan ran, exited 0, found the four findings,
    and nothing reached the proxy.

    This does NOT prove the absence of a raw socket, which ignores proxy variables.
    Task B8 step 3 proves the stronger claim: `unshare -rn` around the same
    `jmo scan` gives the same finding set as the networked run."""
    out = tmp_path / "out"

    row, results = _scan(target, out)

    assert row.state is State.RAN, row
    (result,) = results
    assert result.returncode == 0, result.stderr[-600:]
    assert proxy.requests == []
    assert _triples(out) >= EXPECTED
