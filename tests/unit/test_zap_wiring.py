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

import http.client
import http.server
import json
import logging
import re
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

import pytest
import yaml

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import tool_flags, write_zap_plan
from scripts.core import tool_utils
from scripts.core.scan_timings import Reason, State
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    ZAP_PLAN,
    ScanContext,
    _in_zap_scope,
    url_redirect,
    zap_home,
    zap_minutes,
    zap_plan,
)
from scripts.core.tool_runner import ToolResult
from tests.fixtures.samples.zap import fixture_server as fx

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


def _node_name(url: str) -> str:
    """The name ZAP gives a URL's site-tree node, which is what its active
    scan matches a context against (`Context.isInContext(SiteNode)` reads
    `getHierarchicNodeName`, disassembled from zap-2.17.0.jar): the scheme's
    default port dropped and the path percent-decoded. The spider matches the
    URL as requested. Scoped by the typed spelling alone, `http://h:80/app/`
    and `http://h/my%20app/` attacked nothing (measured)."""
    parts = urlsplit(url)
    netloc = parts.netloc
    if parts.port == {"http": 80, "https": 443}[parts.scheme.lower()]:
        netloc = netloc.rsplit(":", 1)[0]
    return urlunsplit((parts.scheme, netloc, unquote(parts.path), parts.query, ""))


def _in_scope(context: dict, url: str) -> bool:
    """Inside for both of ZAP's readers: the spider and the active scan."""
    return _in_context(context, url) and _in_context(context, _node_name(url))


def _out_of_scope(context: dict, url: str) -> bool:
    """Outside for both: neither may reach it."""
    return not _in_context(context, url) and not _in_context(context, _node_name(url))


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
    # The scheme's default port, typed: ZAP's node names drop it.
    (
        "http://h.test:80/app/",
        ["http://h.test:80/app/search?q=1", "http://h.test/app/search?q=1"],
        [
            "http://h.test/",
            "http://h.test:80/",
            "http://h.test/apple",
            "http://h.test:8080/app/",
            "https://h.test/app/",
            "http://h.test.evil.test/app/",
        ],
    ),
    # Any other port is a different server: it stays.
    (
        "http://h.test:8080/app/",
        ["http://h.test:8080/app/x"],
        ["http://h.test/app/x", "http://h.test:80/app/x"],
    ),
    (
        "http://h.test:80",
        ["http://h.test:80/", "http://h.test/search?q=1"],
        ["http://h.test:8080/", "http://h.test.evil.test/", "https://h.test/"],
    ),
    (
        "https://h.test:443/",
        ["https://h.test:443/x", "https://h.test/x"],
        [
            "http://h.test/x",
            "https://h.test:4430/x",
            "https://h.test:8443/x",
            "https://h.test.evil.test/x",
        ],
    ),
    # A percent-encoded path: ZAP's node names decode it.
    (
        "http://h.test/my%20app/",
        ["http://h.test/my%20app/search?q=1", "http://h.test/my app/search?q=1"],
        ["http://h.test/", "http://h.test/my%20apple", "http://h.test/myXapp/"],
    ),
    (
        "http://h.test/caf%C3%A9/",
        ["http://h.test/caf%C3%A9/x", "http://h.test/café/x"],
        ["http://h.test/", "http://h.test/cafe/x", "http://h.test/caf%C3%A9x"],
    ),
    # 127.0.0.1 and localhost name one host: a site that redirects from one to
    # the other was attacked by nothing (#1431). Port, scheme and path stay.
    (
        "http://127.0.0.1:8080/app/",
        ["http://localhost:8080/app/x", "http://127.0.0.1:8080/app/x"],
        [
            "http://localhost:8080/",
            "http://localhost:8081/app/",
            "https://localhost:8080/app/",
            "http://localhost.evil.test:8080/app/",
        ],
    ),
    (
        "http://localhost:8080",
        ["http://127.0.0.1:8080/x", "http://localhost:8080/x"],
        ["http://127.0.0.1:8081/", "http://127.0.0.2:8080/"],
    ),
    # An encoded slash, percent, `?` or `#`: decoded, each is another path, and
    # the scope took in a directory the target is not (#1434). Nothing is
    # listed inside: by `_node_name`, ZAP's active scan names these pages
    # decoded, outside the target, which the row's warning says.
    (
        "http://h.test/files/a%2Fb/",
        [],
        ["http://h.test/files/a/b/x", "http://h.test/files/a/", "http://h.test/"],
    ),
    (
        "http://h.test/files/a%2fb/",
        [],
        ["http://h.test/files/a/b/x", "http://h.test/files/a/"],
    ),
    (
        "http://h.test/a%2541/",
        [],
        ["http://h.test/a%41/x", "http://h.test/aA/x", "http://h.test/"],
    ),
    (
        "http://h.test/a%3Fb/",
        [],
        ["http://h.test/a/x", "http://h.test/"],
    ),
    (
        "http://h.test/a%23b/",
        [],
        ["http://h.test/a/x", "http://h.test/"],
    ),
]


@pytest.mark.parametrize(("target", "inside", "outside"), SCOPES)
def test_the_context_is_the_target_as_typed_and_no_wider(target, inside, outside):
    """Under 73e80aca the context was `urls: [target]`: `/search?q=hello`
    put its own target out of scope (1 request, nothing attacked, rc 0),
    `q=(x` did not compile (rc 1, "Invalid URL"), and `http://example.com`
    also took in `http://example.com.evil.test/`. Each URL is judged as the
    spider requests it and as the active scan names it (`_node_name`)."""
    context = _context(target)

    assert [u for u in inside if not _in_scope(context, u)] == []
    assert [u for u in outside if not _out_of_scope(context, u)] == []


@pytest.mark.parametrize(
    "target", ["http://h.test:80/app/", "https://h.test:443/", "http://h.test/a%20b/"]
)
def test_the_spider_and_the_import_keep_a_target_zap_would_respell(target):
    """Only the scope takes ZAP's spelling too: the spider's seed and the
    import's `targetUrl` are what the user typed."""
    assert _jobs(zap_plan(target, REPORT, 900))["spider"]["parameters"]["url"] == target
    spec = _jobs(zap_plan(target, REPORT, 900, api_spec="/specs/openapi.json"))
    assert spec["openapi"]["parameters"]["targetUrl"] == target


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
            # zap.sh passes it to java; without it zap.sh takes a quarter of
            # RAM (#1422).
            "-Xmx512m",
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


class TestZapsFlagsReachJava:
    """On Windows zap resolves to `zap.bat`, which JMo never starts: it runs the
    java line `zap.bat` holds (`zap_java`), so cmd.exe never reads zap's
    arguments. `tool_flags` was handed `zap.bat` and dropped a `-config` value
    holding `&` with a WARNING saying zap runs through zap.bat (#1427)."""

    def test_a_metacharacter_flag_reaches_java_whole(
        self, tmp_path, monkeypatch, caplog
    ):
        zap_dir = tmp_path / "zap"
        zap_dir.mkdir()
        (zap_dir / "zap.bat").write_bytes(b"")
        (zap_dir / "zap-2.17.0.jar").write_bytes(b"")
        java = str(tmp_path / "jre" / "bin" / "java.exe")
        real = tool_utils.find_tool
        monkeypatch.setattr(
            tool_utils, "find_tool", lambda name: java if name == "java" else real(name)
        )
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
        out = tmp_path / "out"
        out.mkdir()
        flags = ["-config", "spider.userAgent=a&b%c"]

        with caplog.at_level(logging.WARNING):
            rows = tool_loop.run_tools(
                tools=["zap"],
                target_type="url",
                target=TARGET,
                target_label=TARGET,
                out_dir=out,
                timeout=600,
                retries=0,
                per_tool_config={"zap": {"flags": flags}},
                allow_missing_tools=False,
                runner_cls=_Recording,
                find_tool_func=lambda name: str(zap_dir / "zap.bat"),
                write_stub_func=lambda tool, path: None,
            )

        assert rows["zap"].state is State.RAN, rows["zap"]
        (definition,) = _Recording.definitions
        assert definition.command[0] == java
        assert definition.command[-2:] == flags
        assert not [r for r in caplog.records if "zap.bat" in r.getMessage()]


class TestZapsHeap:
    """zap's heap is `per_tool.zap.heap`, 512m by default, on every OS (#1422,
    Decided 2026-11-05). Left to itself zap.sh took a quarter of RAM
    (`-Xmx7008m` on a 28 GB machine), which the memory gate could not count;
    and 512m ran out after about 13,000 requests on a wide site, so a wide
    site raises it. The gate reserves the heap plus 90 MB: a 2g zap admitted
    as a 600 MB run could take the budget three times over."""

    @staticmethod
    def _zap_bat(tmp_path, monkeypatch):
        zap_dir = tmp_path / "zap"
        zap_dir.mkdir()
        (zap_dir / "zap.bat").write_bytes(b"")
        (zap_dir / "zap-2.17.0.jar").write_bytes(b"")
        monkeypatch.setattr(
            tool_utils,
            "find_tool",
            lambda name: "C:/jre/bin/java.exe" if name == "java" else None,
        )
        return zap_dir / "zap.bat"

    def test_by_default_zap_sh_gets_512m_and_the_gate_reserves_602(
        self, tmp_path, monkeypatch
    ):
        rows, _, defs = _run(tmp_path, monkeypatch, ["zap"])

        assert rows["zap"].state is State.RAN, rows["zap"]
        assert defs["zap"].command[1] == "-Xmx512m"
        assert defs["zap"].memory_mb == 512 + 90

    def test_a_wide_sites_heap_reaches_zap_sh_and_the_gate(self, tmp_path, monkeypatch):
        _, _, defs = _run(
            tmp_path, monkeypatch, ["zap"], per_tool_config={"zap": {"heap": "2g"}}
        )

        assert defs["zap"].command[1] == "-Xmx2g"
        assert defs["zap"].memory_mb == 2048 + 90

    def test_on_windows_the_java_line_takes_the_same_heap(self, tmp_path, monkeypatch):
        zap_bat = self._zap_bat(tmp_path, monkeypatch)
        ctx = _ctx(tmp_path, binary=str(zap_bat), tool_config={"heap": "1536M"})

        (inv,) = DESCRIPTORS["zap"].invocations["url"](ctx)

        assert inv.command[:3] == ("C:/jre/bin/java.exe", "-Xmx1536M", "-jar")
        assert inv.memory_mb == 1536 + 90

    @pytest.mark.parametrize(
        ("heap", "mb"), [("524288k", 512), ("768m", 768), ("1G", 1024)]
    )
    def test_each_unit_java_reads_counts_in_mb(self, tmp_path, heap, mb):
        (inv,) = DESCRIPTORS["zap"].invocations["url"](
            _ctx(tmp_path, tool_config={"heap": heap})
        )

        assert inv.command[1] == f"-Xmx{heap}"
        assert inv.memory_mb == mb + 90

    @pytest.mark.parametrize("heap", [1024, "1024", "2 g", "-Xmx2g", "lots"])
    def test_a_size_java_would_not_read_is_refused_by_name(
        self, tmp_path, caplog, heap
    ):
        """A bare `1024` is 1024 bytes to java, and zap would not start: the
        default runs instead, and the warning names the key."""
        with caplog.at_level(logging.WARNING):
            (inv,) = DESCRIPTORS["zap"].invocations["url"](
                _ctx(tmp_path, tool_config={"heap": heap})
            )

        assert inv.command[1] == "-Xmx512m"
        assert inv.memory_mb == 512 + 90
        assert any("per_tool.zap.heap" in r.getMessage() for r in caplog.records)


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

    def test_a_home_that_cannot_be_made_fails_zap_alone(self, tmp_path, monkeypatch):
        """The plan is written, and the home readied, in the scan loop, before
        any tool runs: a `~/.jmo/zap-home` that is a file raised out of the
        loop and failed every tool on the URL target, nuclei included, which
        never ran (measured through `jmo scan`)."""
        home = tmp_path / "home"
        (home / ".jmo").mkdir(parents=True)
        (home / ".jmo" / "zap-home").write_bytes(b"not a dir")

        rows, out, defs = _run(tmp_path, monkeypatch, ["zap", "nuclei"])

        assert rows["zap"].state is State.FAILED
        assert rows["zap"].reason is Reason.COULD_NOT_RUN
        assert "zap-home" in rows["zap"].detail
        assert list(defs) == ["nuclei"]
        assert rows["nuclei"].state is State.RAN
        assert not (out / ZAP_PLAN).exists()

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
    if they drifted, the import would list operations the server lacks.

    Compared as parsed JSON: a Windows checkout with autocrlf holds the
    tracked file with CRLF line endings, which are not drift."""
    from tests.fixtures.samples.zap import fixture_server as fx

    tracked = Path(fx.__file__).resolve().parent
    fx.write_specs(tmp_path)

    for name in ("openapi.json", "openapi-v1.json"):
        written = json.loads((tmp_path / name).read_bytes())
        assert written == json.loads((tracked / name).read_bytes())


# --- a redirect out of the scope (#1431) ----------------------------------------


@pytest.fixture
def redirecting(tmp_path):
    """The fixture's `redirect` site: `/app/` asked as 127.0.0.1 moves to
    localhost, `/moved/` to another host."""
    f = fx.start("redirect", tmp_path / "requests.jsonl")
    yield f
    f.close()


def _probed(tmp_path: Path, target: str, api_spec: str = "") -> dict[str, str]:
    plan = tmp_path / ZAP_PLAN
    plan.write_bytes(zap_plan(target, tmp_path / "zap.json", 900, api_spec).encode())
    partly_read = DESCRIPTORS["zap"].partly_read
    assert partly_read is not None
    return partly_read(_ctx(tmp_path, target=target))


def _ops(tmp_path: Path, expected: int) -> list[tuple[str, int]]:
    """The fixture's log, once it holds `expected` lines: it writes a line
    after its answer is sent, so the probe can return first."""
    log = tmp_path / "requests.jsonl"
    deadline = time.monotonic() + 5
    while len(fx.read_log(log)) < expected and time.monotonic() < deadline:
        time.sleep(0.02)
    return [(r["op"], r["status"]) for r in fx.read_log(log)]


class TestAnEncodedPathIsNamed:
    """ZAP's active scan names a page by its decoded path (`_node_name`). A
    path holding `%2F` or `%25` decodes to another path, and one holding `%3F`
    or `%23` is cut at the decoded `?` or `#`: the scan may attack nothing
    under the target, and the row read a plain `ran` (#1434, not measured
    against ZAP). The scope keeps such a path as typed; the row says why."""

    @pytest.mark.parametrize(
        ("target", "held"),
        [
            ("http://h.test/files/a%2Fb/", "%2F"),
            ("http://h.test/files/a%2fb/", "%2F"),
            ("http://h.test/a%2541/", "%25"),
            ("http://h.test/a%3Fb/", "%3F"),
            ("http://h.test/a%23b/x", "%23"),
            ("http://h.test/a%2Fb%3Fc/", "%2F, %3F"),
        ],
    )
    def test_the_row_names_what_the_path_holds(self, tmp_path, target, held):
        said = _probed(tmp_path, target)

        assert list(said) == [target]
        assert f"its path holds {held}" in said[target], said

    @pytest.mark.parametrize(
        "target",
        [TARGET, "http://h.test/my%20app/", "http://h.test/a?q=%2F", "http://h%2F/"],
    )
    def test_a_path_that_decodes_harmlessly_gets_no_note(self, tmp_path, target):
        """The control: an encoded space, and `%2F` outside the path."""
        assert _probed(tmp_path, target) == {}

    def test_a_spec_scan_is_named_too(self, tmp_path):
        """The active scan attacks what the import found, by node name too."""
        target = "http://h.test/files/a%2Fb/"
        said = _probed(tmp_path, target, api_spec="/specs/openapi.json")

        assert "its path holds %2F" in said[target], said

    def test_a_redirect_out_of_the_scope_is_named_beside_it(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "scripts.core.tool_descriptors.url_redirect",
            lambda url, timeout=10.0: "http://elsewhere.test/x?state=1",
        )
        target = "http://h.test/files/a%2Fb/"

        (note,) = _probed(tmp_path, target).values()

        assert note.startswith("its path holds %2F"), note
        assert "; it redirects to http://elsewhere.test/x, outside" in note, note


class TestARedirectOutOfTheScopeIsNamed:
    """A URL that redirects off the scan's scope was spidered to the 301 and
    attacked by nothing, and the row read a plain `ran`, rc 0 (#1431,
    measured on ZAP 2.17.0). JMo asks the URL once, without following, and
    names a redirect the scope leaves out."""

    def test_a_site_that_moved_to_another_host_is_named(
        self, tmp_path, real_url_probe, redirecting
    ):
        target = redirecting.url + "/moved/"

        said = _probed(tmp_path, target)

        assert list(said) == [target]
        assert "http://zap-fixture.test/app/" in said[target]
        assert _ops(tmp_path, 1) == [("moved_redirect", 301)]

    def test_the_question_names_who_asks(self, tmp_path, real_url_probe, redirecting):
        """`http.client` sends no User-Agent, and a site behind a CDN or a WAF
        may answer a request without one with a 403 instead of its redirect,
        so the probe would miss the very redirect it asks about."""
        _probed(tmp_path, redirecting.url + "/moved/")

        _ops(tmp_path, 1)
        (request,) = fx.read_log(tmp_path / "requests.jsonl")
        assert "jmo-security" in request["ua"], request

    def test_the_other_loopback_spelling_is_in_the_scope_so_nothing_is_said(
        self, tmp_path, real_url_probe, redirecting
    ):
        assert _probed(tmp_path, redirecting.url + "/app/") == {}
        assert _ops(tmp_path, 1) == [("app_loopback_redirect", 301)]

    def test_a_redirect_inside_the_target_is_not_named(
        self, tmp_path, real_url_probe, redirecting
    ):
        """`/app` to `/app/`, as a static server answers for a directory."""
        assert _probed(tmp_path, redirecting.url + "/app") == {}
        assert _ops(tmp_path, 1) == [("app_redirect", 301)]

    def test_a_spec_scan_is_not_asked(self, tmp_path, real_url_probe, redirecting):
        """An `--api-spec` scan imports its operations and crawls nothing."""
        target = redirecting.url + "/moved/"

        assert _probed(tmp_path, target, api_spec="/specs/openapi.json") == {}
        assert _ops(tmp_path, 0) == []

    def test_a_target_that_does_not_answer_gets_no_note(self, tmp_path, real_url_probe):
        """zap says what it could not reach; the probe adds nothing to it."""
        closed = fx.start("redirect", tmp_path / "requests.jsonl")
        closed.close()

        assert _probed(tmp_path, closed.url + "/moved/") == {}

    def test_the_row_and_the_log_name_it(
        self, tmp_path, monkeypatch, caplog, real_url_probe, redirecting
    ):
        target = redirecting.url + "/moved/"

        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_jobs.tool_loop"):
            rows, _, _ = _run(tmp_path, monkeypatch, ["zap"], target=target)

        assert rows["zap"].state is State.RAN
        assert "http://zap-fixture.test/app/" in (rows["zap"].detail or "")
        assert "http://zap-fixture.test/app/" in caplog.text


# --- the probe reads what zap reads (review of #1431) ---------------------------


def _cased(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc.upper(), parts.path.upper(), parts.query, "")
    )


@pytest.mark.parametrize(("target", "inside", "outside"), SCOPES)
def test_the_probe_reads_the_scope_as_zap_does(target, inside, outside):
    """The probe and the plan's context share `_zap_scope`, but the probe does
    its own matching, and ZAP's ignores case (`_in_context`): matched with case,
    a redirect from `/Shop` to `/shop/` was named as unattacked though ZAP
    attacked it. Every row of the table, and each URL with its host and path
    upper-cased, reads the same to both."""
    for url in [*inside, *outside, *(_cased(u) for u in [*inside, *outside])]:
        assert _in_zap_scope(target, url) == _in_scope(_context(target), url), url


@pytest.mark.parametrize(
    ("target", "url"),
    [
        ("http://h.test/Shop", "http://h.test/shop/"),
        ("http://h.test/app/", "http://H.TEST/app/x"),
        ("http://localhost:8080/", "http://LOCALHOST:8080/x"),
    ],
)
def test_a_redirect_that_only_changes_case_is_inside(target, url):
    assert _in_scope(_context(target), url), "the model of ZAP disagrees"
    assert _in_zap_scope(target, url)


def _self_signed(directory: Path) -> tuple[Path, Path]:
    """A certificate for 127.0.0.1 and its key, minted here: a committed key
    would trip the detect-private-key hook."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


SSO = "https://sso.test/login?SAMLRequest=fixture-request&state=fixture-state"


@pytest.fixture
def self_signed_redirect(tmp_path):
    """An HTTPS site no CA vouches for, as a staging host's often is, that
    sends every request to a single sign-on page with its request in the
    query. Yields its URL."""

    class Moved(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", SSO)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*_self_signed(tmp_path))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Moved)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/app/"
    finally:
        server.shutdown()
        server.server_close()


def test_a_site_with_a_certificate_no_ca_signed_is_asked(
    real_url_probe, self_signed_redirect
):
    """JMo passes ZAP no certificate setting, and the probe verified the
    certificate, so on a self-signed staging host it saw nothing and the row
    read a plain `ran` again (review of #1431). It reads one header and sends
    nothing secret, so a certificate it cannot verify costs nothing."""
    assert url_redirect(self_signed_redirect) == SSO


def test_the_note_names_where_the_site_went_without_its_query(
    tmp_path, real_url_probe, self_signed_redirect
):
    """A sign-on redirect carries its request and state in the query, and the
    row's detail reaches `scan-timings.json`, which people paste into issues.
    The scope ignores the query; so does the note."""
    said = _probed(tmp_path, self_signed_redirect)

    (note,) = said.values()
    assert "https://sso.test/login" in note
    assert "fixture-request" not in note and "state=" not in note


@pytest.mark.parametrize(
    ("url", "port"), [("http://[::1]/", 80), ("https://[::1]/", 443)]
)
def test_an_ipv6_literal_is_asked_at_its_schemes_port(
    monkeypatch, real_url_probe, url, port
):
    """Handed no port, `http.client` reads the last `:1` of `::1` as one."""
    asked = []

    class Recording:
        def __init__(self, host, port=None, **kwargs):
            asked.append((host, port))
            raise OSError("recorded")

    monkeypatch.setattr(http.client, "HTTPConnection", Recording)
    monkeypatch.setattr(http.client, "HTTPSConnection", Recording)

    assert url_redirect(url) is None
    assert asked == [("::1", port)]
