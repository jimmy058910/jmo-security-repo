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
    # From default_profile 'fast'
    assert eff["tools"] == ["semgrep"]
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
