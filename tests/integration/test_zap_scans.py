"""zap through `jmo scan`, against the fixture in `tests/fixtures/samples/zap/`
(#1331, #1348). Real ZAP: `requires_tools`, and slow (15-30 s a scan).

Measured on ZAP 2.17.0 before the fix (Phase 4, PR API):

- `--api-spec` reached 0 of the 4 operations its definition lists: zap ran a
  URL scan (`-quickurl`), an API has no links to spider, and a local file was
  refused outright (#1331).
- `--url http://h/` (a bare root with a slash) made zap's spider stop at the
  page it was given, and the reflected XSS one link away was missed; `http://h`,
  `http://h/app` and `http://h/app/` found it (#1348). Through an automation
  plan none of the four misses it, so the fix is the plan and no URL rule.
- With no explicit target, an imported definition was attacked at the server it
  names: 1,278 requests to `prod.invalid`, none to the fixture. So `--api-spec`
  needs `--url`, and the fixture proxies zap to count any request elsewhere.

These redirect `Path.home()` to a directory shared by the module, so the Ko-fi
counter and JMo's ZAP home land there (one fresh home, ~25 s, then reused) and a
run here never reaches the real `~/.jmo/zap-home`. zap itself is resolved
first, from the real home. Run them one at a time: two zap processes cannot
share a home.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.core.normalize_and_report import count_findings
from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.core.tool_utils import find_tool
from tests.fixtures.samples.zap import fixture_server as fx

SPEC = Path(fx.__file__).resolve().parent / "openapi.json"
OPERATIONS = {"items_list", "items_get", "login", "admin_users"}
# The operations with a parameter to attack; `admin_users` has none.
PARAMETERISED = ("items_list", "items_get", "login")
REFLECTED_XSS = "40012"  # ZAP's "Cross Site Scripting (Reflected)"

pytestmark = [pytest.mark.requires_tools, pytest.mark.timeout(600)]


@pytest.fixture(scope="module")
def zap_binary() -> str:
    d = DESCRIPTORS["zap"]
    found = next(filter(None, (find_tool(n) for n in (d.binary, d.name))), None)
    if found is None:
        pytest.skip("zap is not installed")
    return found


@pytest.fixture(scope="module")
def shared_home(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("home")


@pytest.fixture
def jmo_scan(tmp_path, monkeypatch, zap_binary, shared_home):
    """`jmo scan --tools zap` with `flags` as `per_tool.zap.flags`; returns
    (rc, the URL target's output directory)."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: shared_home))
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool",
        lambda name, *a, **k: zap_binary if name in ("zap.sh", "zap") else None,
    )
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")

    def run(*argv: str, flags: tuple[str, ...] = ()) -> tuple[int, Path]:
        cfg = tmp_path / "jmo.yml"
        cfg.write_bytes(
            yaml.safe_dump(
                {"outputs": ["json"], "per_tool": {"zap": {"flags": list(flags)}}}
            ).encode()
        )
        results = tmp_path / "results"
        full = [
            "jmo",
            "scan",
            *argv,
            "--tools",
            "zap",
            "--results-dir",
            str(results),
            "--config",
            str(cfg),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", full):
            rc = jmo.cmd_scan(jmo.parse_args())
        (out,) = (results / "individual-web").iterdir()
        return rc, out

    return run


def _alerts(report: Path) -> list[dict]:
    data = json.loads(report.read_bytes())
    return [alert for site in data.get("site", []) for alert in site["alerts"]]


def test_a_spec_scan_attacks_every_operation_at_the_target_only(
    jmo_scan, tmp_path
) -> None:
    log = tmp_path / "requests.jsonl"
    f = fx.start("api", log)
    try:
        rc, out = jmo_scan(
            "--url", f.url, "--api-spec", str(SPEC), flags=tuple(fx.proxy_flags(f.port))
        )
    finally:
        f.close()

    requests = fx.read_log(log)
    reached = Counter(r["op"] for r in requests)
    attacked = Counter(r["op"] for r in requests if r["payload"])
    assert rc == 0
    assert set(reached) >= OPERATIONS, reached
    # `{id}` included: a path parameter is attacked too.
    assert all(attacked[op] for op in PARAMETERISED), attacked
    # Every request came through the fixture's proxy, so one meant for the
    # definition's own server would have been logged here, not lost to DNS.
    assert {r["via"] for r in requests} == {"proxy"}
    elsewhere = [r for r in requests if "prod.invalid" in r["target"]]
    assert not elsewhere, elsewhere[:3]
    # One finding per alert instance, not per alert.
    instances = sum(len(a["instances"]) for a in _alerts(out / "zap.json"))
    assert instances > 0
    assert count_findings(out / "zap.json") == instances


@pytest.mark.parametrize("path", ["", "/", "/app", "/app/"])
def test_a_url_scan_finds_the_reflected_xss_whatever_the_slash(
    jmo_scan, tmp_path, path
) -> None:
    f = fx.start("spider", tmp_path / "requests.jsonl")
    try:
        rc, out = jmo_scan("--url", f.url + path)
    finally:
        f.close()

    assert rc == 0
    found = [a["pluginid"] for a in _alerts(out / "zap.json")]
    assert REFLECTED_XSS in found, found
