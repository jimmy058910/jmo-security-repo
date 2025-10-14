import json
import types
from pathlib import Path

from scripts.cli import jmo


def _repo(tmp_path: Path, name: str) -> Path:
    r = tmp_path / "repos" / name
    r.mkdir(parents=True, exist_ok=True)
    return r


def test_include_exclude_filters(tmp_path: Path):
    _repo(tmp_path, "app-1")
    _repo(tmp_path, "test-1")
    out_base = tmp_path / "results"

    # Only include app-* and exclude test-*; with allow_missing_tools stubs
    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(tmp_path / "repos"),
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=["gitleaks"],
        timeout=10,
        threads=1,
        allow_missing_tools=True,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )

    # Monkeypatch effective settings to inject include/exclude
    def fake_eff(_):
        return {
            "tools": ["gitleaks"],
            "threads": 1,
            "timeout": 10,
            "include": ["app-*"],
            "exclude": ["test-*"],
            "retries": 0,
            "per_tool": {},
        }

    # Force tool missing to trigger stub
    def no_tools(_name: str) -> bool:
        return False

    jmo._effective_scan_settings, orig_eff = fake_eff, jmo._effective_scan_settings
    jmo._tool_exists, orig_te = no_tools, jmo._tool_exists
    try:
        rc = jmo.cmd_scan(args)
        assert rc == 0
        # app-1 should have stubbed output
        assert (out_base / "individual-repos" / "app-1" / "gitleaks.json").exists()
        # test-1 should be excluded
        assert not (out_base / "individual-repos" / "test-1" / "gitleaks.json").exists()
    finally:
        jmo._effective_scan_settings = orig_eff
        jmo._tool_exists = orig_te


def test_retries_attempts_logging(tmp_path: Path, monkeypatch):
    r = _repo(tmp_path, "rep")
    out_base = tmp_path / "results"

    # Configure retries=2 to ensure attempts>1
    def fake_eff(_):
        return {
            "tools": ["trufflehog"],
            "threads": 1,
            "timeout": 10,
            "include": [],
            "exclude": [],
            "retries": 2,
            "per_tool": {},
        }

    # Pretend tool exists
    monkeypatch.setattr(jmo, "_tool_exists", lambda name: name == "trufflehog")

    # First two runs non-ok rc=2, third ok rc=1 (acceptable for trufflehog)
    state = {"n": 0}

    def run_cmd(cmd, timeout, retries=0, capture_stdout=False, ok_rcs=None):  # noqa: ARG001
        state["n"] += 1
        rc = 2 if state["n"] < 3 else 1
        return rc, json.dumps({}), "", 1

    monkeypatch.setattr(jmo, "_run_cmd", run_cmd)
    jmo._effective_scan_settings, orig_eff = fake_eff, jmo._effective_scan_settings
    try:
        args = types.SimpleNamespace(
            cmd="scan",
            repo=str(r),
            repos_dir=None,
            targets=None,
            results_dir=str(out_base),
            config=str(tmp_path / "cfg.yml"),
            tools=None,
            timeout=None,
            threads=1,
            allow_missing_tools=False,
            profile_name=None,
            log_level=None,
            human_logs=False,
        )
        rc = jmo.cmd_scan(args)
        assert rc == 0
        # Output exists from acceptable rc=1
        assert (out_base / "individual-repos" / r.name / "trufflehog.json").exists()
    finally:
        jmo._effective_scan_settings = orig_eff


def test_semgrep_rc2_and_trivy_rc1_accepted(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, "rep2")
    out_base = tmp_path / "results"

    # Configure both tools
    def eff(_):
        return {
            "tools": ["semgrep", "trivy"],
            "threads": 1,
            "timeout": 10,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    def run_cmd(cmd, timeout, retries=0, capture_stdout=False, ok_rcs=None):  # noqa: ARG001
        prog = cmd[0]
        if prog == "semgrep":
            # rc=2 acceptable; write output file
            p = Path(cmd[cmd.index("--output") + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"results": []}), encoding="utf-8")
            return 2, "", "", 1
        if prog == "trivy":
            # rc=1 acceptable; write output file
            p = Path(cmd[cmd.index("-o") + 1])
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps({"Results": []}), encoding="utf-8")
            return 1, "", "", 1
        return 0, "", "", 1

    monkeypatch.setattr(jmo, "_effective_scan_settings", eff)
    monkeypatch.setattr(jmo, "_tool_exists", lambda n: n in {"semgrep", "trivy"})
    monkeypatch.setattr(jmo, "_run_cmd", run_cmd)
    args = types.SimpleNamespace(
        cmd="scan",
        repo=str(repo),
        repos_dir=None,
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=None,
        timeout=None,
        threads=1,
        allow_missing_tools=False,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
    assert (out_base / "individual-repos" / repo.name / "semgrep.json").exists()
    assert (out_base / "individual-repos" / repo.name / "trivy.json").exists()


def test_allow_missing_tools_stubs_all(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, "rep3")
    out_base = tmp_path / "results"

    def eff(_):
        return {
            "tools": [
                "gitleaks",
                "trufflehog",
                "semgrep",
                "noseyparker",
                "syft",
                "trivy",
                "hadolint",
                "checkov",
                "bandit",
                "tfsec",
            ],
            "threads": 1,
            "timeout": 5,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    monkeypatch.setattr(jmo, "_effective_scan_settings", eff)
    monkeypatch.setattr(jmo, "_tool_exists", lambda n: False)
    args = types.SimpleNamespace(
        cmd="scan",
        repo=str(repo),
        repos_dir=None,
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=None,
        timeout=None,
        threads=1,
        allow_missing_tools=True,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
    for t in [
        "gitleaks",
        "trufflehog",
        "semgrep",
        "noseyparker",
        "syft",
        "trivy",
        "hadolint",
        "checkov",
        "bandit",
        "tfsec",
    ]:
        assert (out_base / "individual-repos" / repo.name / f"{t}.json").exists()


def test_bad_jmo_threads_fallback(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, "rep4")
    out_base = tmp_path / "results"

    def eff(_):
        return {
            "tools": ["gitleaks"],
            "threads": None,
            "timeout": 5,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    class Cfg:
        threads = None

    monkeypatch.setattr(jmo, "_effective_scan_settings", eff)
    monkeypatch.setattr(jmo, "load_config", lambda p: Cfg())
    monkeypatch.setattr(jmo, "_tool_exists", lambda n: False)
    # Set bad env value
    monkeypatch.setenv("JMO_THREADS", "not-an-int")
    args = types.SimpleNamespace(
        cmd="scan",
        repo=str(repo),
        repos_dir=None,
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=None,
        timeout=None,
        threads=None,
        allow_missing_tools=True,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
