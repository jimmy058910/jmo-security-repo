"""zap runs one automation plan, which JMo writes for each target (#1331, #1348).

Measured on ZAP 2.17.0 before any of this was written (Phase 4, PR API):

- `-quickurl` with a bare root (`http://h/`) stopped the spider at that page and
  missed a reflected XSS one link away; through a plan (`-autorun`) none of
  `http://h`, `http://h/`, `http://h/app`, `http://h/app/` missed it.
- An `openapi` job imports a definition; its `targetUrl` decides where the
  operations are sent. Without it, 1,278 requests went to the server the
  definition names. An empty path keeps the definition's base path, and any
  path, `/` included, replaces it: the URL as typed is the user's choice.
- `-autorun` exits 0 on success, 2 when a job only warned (its report written),
  and 1 on an error: a definition it cannot read writes no report.
- activeScan reads `maxScanDurationInMins` (`maxDuration` is "Unrecognised
  parameter", a warning). The spider job reads its own `maxDuration`, default
  unlimited: `-config spider.maxDuration=1` on the command line did not stop it
  (341 s of crawling, killed, no report), the job's own `maxDuration: 1` did
  (1:08).
- ZAP persists `-config` values into its home's `config.xml`, so every run uses
  a home of JMo's own, `~/.jmo/zap-home`, and starts from no `config.xml`
  (measured: no slower, same requests and findings). ZAP does not create a home
  whose parent is missing (rc 1, "Unable to create home directory").

The real-binary gates are `tests/integration/test_zap_scans.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import tool_flags, write_zap_plan
from scripts.core import tool_utils
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    ZAP_PLAN,
    ScanContext,
    zap_home,
    zap_minutes,
    zap_plan,
)
from scripts.core.tool_runner import ToolResult

TARGET = "http://127.0.0.1:8080"
REPORT = Path("/results/individual-web/127.0.0.1_8080/zap.json")


def _jobs(plan: str) -> dict[str, dict]:
    return {job["type"]: job for job in yaml.safe_load(plan)["jobs"]}


# --- the time budget ----------------------------------------------------------


class TestTheTimeoutIsThePlansWholeBudget:
    """The plan stops its long jobs itself, so it writes its report before
    JMo's timeout kills zap: a killed zap writes nothing."""

    def test_the_shipped_floor_gives_the_spider_five_minutes_and_the_attack_eight(
        self,
    ):
        assert zap_minutes(900, spider=True) == (5, 8)

    def test_a_spec_scan_has_no_spider_and_gives_the_attack_thirteen(self):
        assert zap_minutes(900, spider=False) == (0, 13)

    @pytest.mark.parametrize("timeout", [1, 30, 59, 60, 119, 120, 180, 240])
    def test_every_job_gets_at_least_a_minute(self, timeout):
        crawl, attack = zap_minutes(timeout, spider=True)
        assert crawl >= 1
        assert attack >= 1
        assert zap_minutes(timeout, spider=False)[1] >= 1

    @pytest.mark.parametrize("timeout", [300, 600, 900, 1800, 3600])
    def test_the_jobs_and_two_minutes_of_reserve_fit_in_the_timeout(self, timeout):
        """The reserve: the one-minute passive wait, startup (14-25 s
        measured), each capped job's 5-8 s overshoot, and the report."""
        crawl, attack = zap_minutes(timeout, spider=True)
        assert crawl + attack + 2 <= timeout // 60
        assert crawl == (timeout // 60) // 3


# --- the plan -----------------------------------------------------------------


class TestAUrlScanPlan:
    def test_it_spiders_waits_attacks_and_reports_in_that_order(self):
        doc = yaml.safe_load(zap_plan(TARGET, REPORT, 900))

        assert [job["type"] for job in doc["jobs"]] == [
            "spider",
            "passiveScan-wait",
            "activeScan",
            "report",
        ]
        (context,) = doc["env"]["contexts"]
        # Its scope: below, `test_the_context_is_the_target_as_typed_and_no_wider`.
        assert (context["name"], context["urls"]) == ("target", [TARGET])
        # An error fails the plan (rc 1); a warning does not stop it.
        assert doc["env"]["parameters"]["failOnError"] is True
        assert doc["env"]["parameters"]["failOnWarning"] is False

    def test_each_long_job_is_bounded_by_the_budget(self):
        jobs = _jobs(zap_plan(TARGET, REPORT, 900))

        assert jobs["spider"]["parameters"] == {
            "context": "target",
            "url": TARGET,
            "maxDuration": 5,
        }
        assert jobs["passiveScan-wait"]["parameters"] == {"maxDuration": 1}
        assert jobs["activeScan"]["parameters"] == {
            "context": "target",
            "maxScanDurationInMins": 8,
        }

    def test_the_report_is_the_json_the_adapter_reads_where_the_scan_reads_it(self):
        report = _jobs(zap_plan(TARGET, REPORT, 900))["report"]

        assert report["parameters"] == {
            "template": "traditional-json",
            "reportDir": str(REPORT.parent),
            "reportFile": "zap.json",
        }
        # Every alert, whatever ZAP thinks of its risk or its confidence.
        assert report["risks"] == ["info", "low", "medium", "high"]
        assert report["confidences"] == [
            "falsepositive",
            "low",
            "medium",
            "high",
            "confirmed",
        ]

    @pytest.mark.parametrize("path", ["", "/", "/app", "/app/"])
    def test_the_url_is_kept_as_typed(self, path):
        """#1348's defect was `-quickurl`'s, and a plan has none of it."""
        url = TARGET + path
        doc = yaml.safe_load(zap_plan(url, REPORT, 900))

        assert doc["env"]["contexts"][0]["urls"] == [url]
        assert _jobs(zap_plan(url, REPORT, 900))["spider"]["parameters"]["url"] == url


class TestASpecScanPlan:
    def test_an_openapi_job_replaces_the_spider(self, tmp_path):
        spec = str(tmp_path / "openapi.json")
        doc = yaml.safe_load(zap_plan(TARGET, REPORT, 900, api_spec=spec))

        assert [job["type"] for job in doc["jobs"]] == [
            "openapi",
            "passiveScan-wait",
            "activeScan",
            "report",
        ]
        jobs = _jobs(zap_plan(TARGET, REPORT, 900, api_spec=spec))
        assert jobs["openapi"]["parameters"] == {
            "apiFile": spec,
            "targetUrl": TARGET,
            "context": "target",
        }
        assert jobs["activeScan"]["parameters"]["maxScanDurationInMins"] == 13

    @pytest.mark.parametrize(
        "spec", ["http://h.test/openapi.json", "https://h.test/v3/api-docs"]
    )
    def test_a_spec_served_over_http_is_fetched_by_zap(self, spec):
        params = _jobs(zap_plan(TARGET, REPORT, 900, api_spec=spec))["openapi"][
            "parameters"
        ]

        assert params == {"apiUrl": spec, "targetUrl": TARGET, "context": "target"}

    @pytest.mark.parametrize("path", ["", "/", "/v2", "/v2/"])
    def test_the_target_is_the_url_exactly_as_typed(self, path):
        """ZAP gives the slash meaning (an empty path keeps the definition's
        base path; any path, `/` included, replaces it), so normalising it
        would take away the user's only way to choose."""
        url = TARGET + path
        params = _jobs(zap_plan(url, REPORT, 900, api_spec="/specs/openapi.json"))[
            "openapi"
        ]["parameters"]

        assert params["targetUrl"] == url


@pytest.mark.parametrize(
    "url",
    [
        "http://h.test/?a=1&b=2#frag",
        "http://h.test/a: b",
        "http://h.test/'quoted'\"too\"",
        "http://h.test/caf\u00e9",
    ],
)
def test_a_value_yaml_reads_specially_comes_back_as_written(url):
    """`yaml.safe_dump`, not a template: `#` starts a YAML comment and `: ` a
    mapping. ASCII only, so the JVM's default charset cannot change it."""
    spec = r"C:\Users\some one\specs & more\open api.json"
    plan = zap_plan(url, REPORT, 900, api_spec=spec)

    assert plan.isascii()
    params = _jobs(plan)["openapi"]["parameters"]
    assert params["targetUrl"] == url
    assert params["apiFile"] == spec


# --- the context: what the spider and the active scan may touch --------------


def _python(regex: str) -> str:
    """A context regex in Python's dialect: `re` has no `\\Q...\\E`, so each
    quoted run is escaped instead."""
    return re.sub(
        r"\\Q(.*?)\\E", lambda m: re.escape(m.group(1)), regex, flags=re.DOTALL
    )


def _in_context(context: dict, url: str) -> bool:
    """ZAP's reading of a plan's context (2.17.0): each `urls` entry becomes
    the regex `<entry>.*`, unescaped (read from automation-beta-0.58.0's
    ContextWrapper); every regex matches the whole URL, case ignored, with
    the URL's query cut off (measured: an include holding the query matched
    nothing, one without it put the target in scope)."""
    cut = url.split("?", 1)[0]
    includes = [f"{u}.*" for u in context["urls"]] + context.get("includePaths", [])
    excludes = context.get("excludePaths", [])

    def hit(regexes):
        return any(re.fullmatch(_python(r), cut, re.IGNORECASE) for r in regexes)

    return hit(includes) and not hit(excludes)


def _context(url: str) -> dict:
    return yaml.safe_load(zap_plan(url, REPORT, 900))["env"]["contexts"][0]


SCOPES = [
    # (target, in its scope, out of it)
    (
        "http://127.0.0.1:8080/search?q=hello",
        ["http://127.0.0.1:8080/search?q=hello", "http://127.0.0.1:8080/search?q=x"],
        ["http://127.0.0.1:8080/", "http://127.0.0.1:8080/app/search?q=hello"],
    ),
    (
        "http://127.0.0.1:8080/search?q=a+b",
        ["http://127.0.0.1:8080/search?q=a+b"],
        ["http://127.0.0.1:8080/"],
    ),
    (
        "http://127.0.0.1:8080/search?q=(x",
        ["http://127.0.0.1:8080/search?q=(x", "http://127.0.0.1:8080/search?q=1"],
        ["http://127.0.0.1:8080/"],
    ),
    (
        "http://example.com",
        ["http://example.com", "http://example.com/", "http://example.com/a?b=1"],
        [
            "http://example.com.evil.test/",
            "http://exampleXcom/",
            "http://example.com:8443/",
        ],
    ),
    (
        "http://h.test/app/",
        ["http://h.test/app/", "http://h.test/app/search?q=1"],
        ["http://h.test/", "http://h.test/search?q=1", "http://hXtest/app/"],
    ),
    (
        "http://h.test/a(b/[c]{1}$",
        ["http://h.test/a(b/[c]{1}$", "http://h.test/a(b/[c]{1}$/d?e=1"],
        ["http://h.test/a"],
    ),
]


@pytest.mark.parametrize(("target", "inside", "outside"), SCOPES)
def test_the_context_is_the_target_as_typed_and_no_wider(target, inside, outside):
    """Under 73e80aca the context was `urls: [target]`: `/search?q=hello`
    put its own target out of scope (1 request, nothing attacked, rc 0),
    `q=(x` did not compile (rc 1, "Invalid URL"), and `http://example.com`
    also took in `http://example.com.evil.test/`."""
    context = _context(target)

    assert [u for u in inside if not _in_context(context, u)] == []
    assert [u for u in outside if _in_context(context, u)] == []


@pytest.mark.parametrize("target", [t for t, _, _ in SCOPES])
def test_every_context_regex_compiles(target):
    """A `urls` entry is a regex to ZAP: `q=(x` as one ended the plan at
    rc 1. The entry is the target without its query, with every regex
    character in its path percent-encoded."""
    context = _context(target)

    (entry,) = context["urls"]
    assert "?" not in entry
    for regex in [f"{entry}.*", *context["includePaths"], *context["excludePaths"]]:
        re.compile(_python(regex))


def test_a_quoted_target_survives_a_backslash_e_inside_it():
    """`\\E` ends a Java quote, so one inside the URL is split out of it."""
    target = "http://h.test/a\\Eb"

    assert _in_context(_context(target), target)
    assert not _in_context(_context(target), "http://h.test/aXb")


def test_the_spider_starts_at_the_target_as_typed():
    """The context's `urls` entry loses the query; the spider's seed keeps it."""
    url = "http://127.0.0.1:8080/search?q=(x"
    assert _jobs(zap_plan(url, REPORT, 900))["spider"]["parameters"]["url"] == url


# --- the command line ---------------------------------------------------------


def _ctx(tmp_path: Path, **kw) -> ScanContext:
    defaults = {
        "tool": "zap",
        "target_type": "url",
        "target": TARGET,
        "out_dir": tmp_path,
        "binary": str(Path("/opt/zap/zap.sh")),
        "plan": tmp_path / ZAP_PLAN,
    }
    return ScanContext(**{**defaults, **kw})


class TestTheCommandLine:
    def test_zap_runs_jmos_plan_silently_in_jmos_home(self, tmp_path):
        ctx = _ctx(tmp_path, flags=("-config", "api.disablekey=true"))
        (inv,) = DESCRIPTORS["zap"].invocations["url"](ctx)

        assert inv.command == (
            str(Path("/opt/zap/zap.sh")),
            "-cmd",
            "-silent",
            "-dir",
            str(zap_home()),
            "-autorun",
            str(tmp_path / ZAP_PLAN),
            "-config",
            "api.disablekey=true",
        )
        assert inv.output_file == tmp_path / "zap.json"
        # zap.bat resolves its jar against the working directory.
        assert inv.cwd == Path("/opt/zap")

    def test_the_target_is_never_on_the_command_line(self, tmp_path):
        (inv,) = DESCRIPTORS["zap"].invocations["url"](_ctx(tmp_path))

        assert TARGET not in inv.command
        assert not {"-quickurl", "-quickout", "-quickprogress"} & set(inv.command)

    def test_a_warning_is_a_run_and_an_error_is_not(self, tmp_path):
        """rc 2 wrote its report; rc 1 (a definition it cannot read) did not."""
        (inv,) = DESCRIPTORS["zap"].invocations["url"](_ctx(tmp_path))

        assert inv.ok_return_codes == (0, 2)

    def test_without_a_plan_it_refuses_to_build(self, tmp_path):
        with pytest.raises(ValueError, match="plan"):
            DESCRIPTORS["zap"].invocations["url"](_ctx(tmp_path, plan=None))

    @staticmethod
    def _zap_bat(tmp_path, monkeypatch, *jars):
        where = tmp_path / "zap"
        where.mkdir()
        for name in ("zap.bat", *jars):
            (where / name).write_bytes(b"")
        monkeypatch.setattr(
            tool_utils,
            "find_tool",
            lambda name: "C:/jre/bin/java.exe" if name == "java" else None,
        )
        return where

    def test_on_windows_java_runs_its_jar_with_the_same_arguments(
        self, tmp_path, monkeypatch
    ):
        """zap.bat is `java -Xmx512m -jar zap-<version>.jar %*`, and running
        it puts every argument through cmd.exe: a plan under a results
        directory holding `&` ran the rest of its path as a command (#1403,
        measured)."""
        where = self._zap_bat(tmp_path, monkeypatch, "zap-2.17.0.jar")
        ctx = _ctx(
            tmp_path,
            binary=str(where / "zap.bat"),
            flags=("-config", "api.disablekey=true"),
        )
        (inv,) = DESCRIPTORS["zap"].invocations["url"](ctx)

        assert inv.command == (
            "C:/jre/bin/java.exe",
            "-Xmx512m",
            "-jar",
            str(where / "zap-2.17.0.jar"),
            "-cmd",
            "-silent",
            "-dir",
            str(zap_home()),
            "-autorun",
            str(tmp_path / ZAP_PLAN),
            "-config",
            "api.disablekey=true",
        )
        assert inv.cwd == where

    def test_a_zap_bat_java_cannot_replace_is_never_built(self, tmp_path, monkeypatch):
        """The scan loop fails its row first (`_zap_launch`); the builder
        refuses too rather than fall back to zap.bat."""
        where = self._zap_bat(tmp_path, monkeypatch)
        with pytest.raises(ValueError, match="found: none"):
            DESCRIPTORS["zap"].invocations["url"](
                _ctx(tmp_path, binary=str(where / "zap.bat"))
            )

    def test_its_home_is_jmos_and_not_the_users_zap(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert zap_home() == tmp_path / ".jmo" / "zap-home"

    def test_only_zap_reads_a_plan(self):
        assert [n for n, d in DESCRIPTORS.items() if d.automation_plan] == ["zap"]

    @pytest.mark.parametrize(
        "flags",
        [
            ["-autorun", "other.yaml"],
            ["-quickurl", "http://elsewhere.test"],
            ["-quickout", "other.html"],
        ],
    )
    def test_a_user_flag_that_would_run_something_else_is_refused(self, flags):
        cfg = {"zap": {"flags": [*flags, "-config", "api.disablekey=true"]}}
        assert tool_flags(cfg, "zap") == ["-config", "api.disablekey=true"]


# --- staging the plan ---------------------------------------------------------


class TestWriteZapPlan:
    @pytest.fixture(autouse=True)
    def home(self, tmp_path, monkeypatch) -> Path:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
        return home

    def test_it_writes_the_plan_beside_the_outputs_as_dot_prefixed_scratch(
        self, tmp_path
    ):
        """Dot-prefixed, as `.gitleaks.toml`: the report reads every
        `<tool>.json` in the directory, and nothing else."""
        out = tmp_path / "out"
        out.mkdir()

        path = write_zap_plan(
            out, target=TARGET, report=out / "zap.json", timeout=900, api_spec=""
        )

        assert path == (out / ZAP_PLAN).absolute()
        assert path.name.startswith(".")
        raw = path.read_bytes()
        assert b"\r" not in raw
        assert raw.decode("utf-8") == zap_plan(
            TARGET, (out / "zap.json").absolute(), 900
        )

    def test_it_creates_the_home_and_its_parents(self, tmp_path, home):
        """ZAP will not: rc 1, "Unable to create home directory"."""
        out = tmp_path / "out"
        out.mkdir()

        write_zap_plan(out, target=TARGET, report=out / "zap.json", timeout=900)

        assert (home / ".jmo" / "zap-home").is_dir()

    def test_it_drops_what_an_earlier_run_stored_and_keeps_the_rest(
        self, tmp_path, home
    ):
        """A `-config` value (an upstream proxy) is stored in `config.xml` and
        applied to every later run; a killed run can leave the file
        unparseable. The add-ons beside it are what makes reuse fast."""
        zap = home / ".jmo" / "zap-home"
        (zap / "plugin").mkdir(parents=True)
        (zap / "plugin" / "openapi-beta-48.zap").write_bytes(b"addon")
        (zap / "config.xml").write_bytes(b"<config><httpProxy/></config>")
        out = tmp_path / "out"
        out.mkdir()

        write_zap_plan(out, target=TARGET, report=out / "zap.json", timeout=900)

        assert not (zap / "config.xml").exists()
        assert (zap / "plugin" / "openapi-beta-48.zap").read_bytes() == b"addon"


# --- the scan loop -------------------------------------------------------------


class _Recording:
    definitions: list = []

    def __init__(self, tools, progress_callback=None):
        type(self).definitions = list(tools)

    def run_all_parallel(self):
        return [
            ToolResult(tool=d.name, status="success", returncode=0)
            for d in self.definitions
        ]


def _run(tmp_path, monkeypatch, tools, **kw):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    rows = tool_loop.run_tools(
        tools=tools,
        target_type="url",
        target=kw.pop("target", TARGET),
        target_label=TARGET,
        out_dir=out,
        timeout=600,
        retries=0,
        per_tool_config=kw.pop("per_tool_config", {}),
        allow_missing_tools=False,
        runner_cls=_Recording,
        find_tool_func=lambda name: f"/opt/{name}/{name}",
        write_stub_func=lambda tool, path: None,
        **kw,
    )
    return rows, out, {d.name: d for d in _Recording.definitions}


class TestTheLoopWritesTheRowsPlan:
    def test_zap_runs_the_plan_written_for_this_target(self, tmp_path, monkeypatch):
        _, out, defs = _run(
            tmp_path, monkeypatch, ["zap"], per_tool_config={"zap": {"timeout": 1200}}
        )

        plan_path = Path(defs["zap"].command[defs["zap"].command.index("-autorun") + 1])
        assert plan_path == (out / ZAP_PLAN).absolute()
        jobs = _jobs(plan_path.read_bytes().decode())
        assert jobs["spider"]["parameters"]["url"] == TARGET
        # per_tool.zap.timeout is the plan's budget, not the scan's (600 s):
        # 20 minutes -> 6 + 12.
        assert jobs["spider"]["parameters"]["maxDuration"] == 6
        assert jobs["activeScan"]["parameters"]["maxScanDurationInMins"] == 12
        assert jobs["report"]["parameters"]["reportDir"] == str(out.absolute())
        assert defs["zap"].timeout == 1200

    def test_a_spec_reaches_the_plan(self, tmp_path, monkeypatch):
        spec = str(tmp_path / "openapi.json")
        _, out, _ = _run(tmp_path, monkeypatch, ["zap"], api_spec=spec)

        jobs = _jobs((out / ZAP_PLAN).read_bytes().decode())
        assert jobs["openapi"]["parameters"] == {
            "apiFile": spec,
            "targetUrl": TARGET,
            "context": "target",
        }
        assert "spider" not in jobs

    def test_another_url_tool_gets_no_plan(self, tmp_path, monkeypatch):
        _, out, defs = _run(tmp_path, monkeypatch, ["nuclei"])

        assert not (out / ZAP_PLAN).exists()
        assert TARGET in defs["nuclei"].command

    def test_a_tool_that_is_not_installed_gets_no_plan(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
        out = tmp_path / "out"
        out.mkdir()

        rows = tool_loop.run_tools(
            tools=["zap"],
            target_type="url",
            target=TARGET,
            target_label=TARGET,
            out_dir=out,
            timeout=600,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
            runner_cls=_Recording,
            find_tool_func=lambda name: None,
        )

        assert rows["zap"].label == "failed:not installed"
        assert not (out / ZAP_PLAN).exists()


def test_the_tracked_definitions_are_the_ones_the_fixture_serves(tmp_path):
    """The real-binary gate imports the file, and the fixture serves `spec()`:
    if they drifted, the import would list operations the server lacks."""
    from tests.fixtures.samples.zap import fixture_server as fx

    tracked = Path(fx.__file__).resolve().parent
    fx.write_specs(tmp_path)

    for name in ("openapi.json", "openapi-v1.json"):
        assert (tmp_path / name).read_bytes() == (tracked / name).read_bytes()
