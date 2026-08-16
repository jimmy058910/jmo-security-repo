import types
from pathlib import Path

from scripts.cli import jmo


def test_iter_repos_variants(tmp_path: Path):
    # repo path
    r1 = tmp_path / "r1"
    r1.mkdir()
    args = types.SimpleNamespace(repo=str(r1), repos_dir=None, targets=None)
    out = jmo._iter_repos(args)
    assert [p.name for p in out] == ["r1"]

    # repos_dir path with two repos
    base = tmp_path / "repos"
    (base / "a").mkdir(parents=True)
    (base / "b").mkdir(parents=True)
    args = types.SimpleNamespace(repo=None, repos_dir=str(base), targets=None)
    out = sorted([p.name for p in jmo._iter_repos(args)])
    assert out == ["a", "b"]

    # targets file
    r2 = tmp_path / "r2"
    r2.mkdir()
    tf = tmp_path / "targets.txt"
    tf.write_text(str(r1) + "\n" + str(r2) + "\n# comment\n\n", encoding="utf-8")
    args = types.SimpleNamespace(repo=None, repos_dir=None, targets=str(tf))
    out = sorted([p.name for p in jmo._iter_repos(args)])
    assert out == ["r1", "r2"]


def test_effective_scan_settings_merge(tmp_path: Path, monkeypatch):
    # Create config with defaults and a profile override
    cfg = tmp_path / "jmo.yml"
    cfg.write_text(
        """
tools: [gitleaks, trufflehog]
threads: 3
timeout: 111
include: [app-*]
exclude: [test-*]
log_level: DEBUG
retries: 2
per_tool:
  trivy:
    flags: ["--offline-scan"]
profiles:
  fast:
    tools: [semgrep]
    threads: 1
    retries: 0
    include: [app-1]
    per_tool:
      semgrep:
        flags: ["--severity", "ERROR"]
default_profile: fast
        """,
        encoding="utf-8",
    )
    args = types.SimpleNamespace(
        config=str(cfg), profile_name=None, tools=None, threads=None, timeout=None
    )
    eff = jmo._effective_scan_settings(args)
    # From default_profile 'fast' - tools come from PROFILE_TOOLS registry (single source of truth),
    # NOT from jmo.yml profiles section. Other settings (threads, retries, etc.) still merge from config.
    from scripts.core.tool_registry import PROFILE_TOOLS

    assert eff["tools"] == PROFILE_TOOLS["fast"]
    assert eff["threads"] == 1
    assert eff["timeout"] == 111  # inherited from base config
    assert eff["retries"] == 0
    assert eff["include"] == ["app-1"]
    assert isinstance(eff["per_tool"], dict) and "semgrep" in eff["per_tool"]


def test_log_json_and_human(capsys):
    # JSON logs at INFO and above
    args = types.SimpleNamespace(config=None, log_level="INFO", human_logs=False)
    jmo._log(args, "INFO", "hello json")
    err = capsys.readouterr().err
    assert "hello json" in err and err.strip().startswith("{")

    # Human logs with color
    args = types.SimpleNamespace(config=None, log_level="DEBUG", human_logs=True)
    jmo._log(args, "DEBUG", "hello human")
    err = capsys.readouterr().err
    assert "hello human" in err and "\x1b[" in err


def _skip_tools_args(tmp_path: Path, **overrides):
    """A namespace with NO `log_level`, so the default floor is what is tested."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_text("tools: [bandit]\n", encoding="utf-8")
    base = {
        "config": str(cfg),
        "profile_name": None,
        "tools": ["bandit", "semgrep"],
        "threads": None,
        "timeout": None,
        "skip_tools": ["semgrep"],
    }
    base.update(overrides)
    return types.SimpleNamespace(**base)


def test_skip_tools_notice_is_visible_at_the_DEFAULT_log_level(tmp_path, capsys):
    """#871: the notice existed and a normal run could not see it.

    It was emitted with `logging.getLogger(...).info(...)`, and
    `configure_scan_logging()` floors the stdlib `scripts` logger at **WARN**
    while `_log` floors at **INFO**. Measured before the fix, on a real scan:
    default **0** records, `--log-level INFO` 1, `WARN` 0, `DEBUG` 1.

    So this asserts at the *default* level deliberately. Asserting at INFO is
    what let the silence survive -- the record was always there, just never
    where a user would be standing.
    """
    args = _skip_tools_args(tmp_path)
    eff = jmo._effective_scan_settings(args)

    assert eff["tools"] == ["bandit"], "the skipped tool must actually be dropped"
    err = capsys.readouterr().err
    assert (
        "semgrep" in err
    ), f"nothing named the skipped tool at the default level: {err!r}"
    assert "--skip-tools" in err


def test_skip_tools_notice_is_emitted_exactly_once(tmp_path, capsys):
    """`_log` and `logging` both reach stderr; emitting on both duplicates.

    That is the trap chunk 10 measured -- `_log` writes JSON to `sys.stderr`
    directly and never touches `logging`, so raising the module logger to the
    user-facing level alongside it prints every line twice. The stdlib record
    is kept at DEBUG as a breadcrumb.
    """
    jmo._effective_scan_settings(_skip_tools_args(tmp_path))
    lines = [ln for ln in capsys.readouterr().err.splitlines() if "semgrep" in ln]
    assert len(lines) == 1, f"expected one record, got {len(lines)}: {lines}"


def test_no_skip_tools_is_silent(tmp_path, capsys):
    """Negative control -- without the flag the line must not fire at all."""
    jmo._effective_scan_settings(_skip_tools_args(tmp_path, skip_tools=[]))
    assert "--skip-tools" not in capsys.readouterr().err


def test_skip_tools_that_matches_nothing_is_silent(tmp_path, capsys):
    """The *second* negative control, and the one that was missing.

    There are two guards here, not one: an outer `if skip_tools and tools` and
    an inner `if dropped`. Passing `skip_tools=[]` only exercises the outer one,
    so a mutation removing the inner guard survived the test above -- it was
    unreachable from it.

    This is the case the inner guard exists for: the user names a tool that is
    not in the effective list, so `skip_tools` is truthy and `dropped` is empty.
    Without it the run reports `Skipping 0 tool(s) at user request
    (--skip-tools):` with nothing after the colon.
    """
    args = _skip_tools_args(tmp_path, tools=["bandit"], skip_tools=["not-a-tool"])
    eff = jmo._effective_scan_settings(args)

    assert eff["tools"] == ["bandit"], "nothing should have been dropped"
    err = capsys.readouterr().err
    assert "--skip-tools" not in err, f"reported a skip that did not happen: {err!r}"
    assert "0 tool(s)" not in err


def test_skip_tools_notice_names_every_dropped_tool(tmp_path, capsys):
    """A count without the names is the silence it replaced, one step removed."""
    args = _skip_tools_args(
        tmp_path,
        tools=["bandit", "semgrep", "trivy"],
        skip_tools=["semgrep", "trivy"],
    )
    eff = jmo._effective_scan_settings(args)
    assert eff["tools"] == ["bandit"]
    err = capsys.readouterr().err
    assert "2 tool(s)" in err
    assert "semgrep" in err and "trivy" in err
