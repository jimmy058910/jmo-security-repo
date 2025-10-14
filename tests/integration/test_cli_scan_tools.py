import json
import types
from pathlib import Path

from scripts.cli import jmo


def _repo(tmp_path: Path) -> Path:
    r = tmp_path / "repos" / "one"
    r.mkdir(parents=True, exist_ok=True)
    # Add a minimal Dockerfile to exercise hadolint path
    (r / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
    return r


def test_scan_each_tool_happy_paths(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path)
    out_base = tmp_path / "results"

    # Tools to exercise
    tools = [
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
    ]

    # Pretend only the current tool exists
    def tool_exists_factory(current: str):
        def _tool_exists(name: str) -> bool:
            return name == current

        return _tool_exists

    class Fake:
        def __init__(self):
            self.calls = []

        def run_cmd(
            self, cmd, timeout, retries=0, capture_stdout=False, ok_rcs=None
        ):  # noqa: D401
            self.calls.append(cmd)
            prog = cmd[0]
            # Create out files for flags-based outputs
            if prog == "semgrep":
                if "--output" in cmd:
                    p = Path(cmd[cmd.index("--output") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"results": []}), encoding="utf-8")
                return 0, "", "", 1
            if prog == "trivy":
                if "-o" in cmd:
                    p = Path(cmd[cmd.index("-o") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"Results": []}), encoding="utf-8")
                return 0, "", "", 1
            if prog == "gitleaks":
                # Simulate gitleaks writing the report to --report-path
                if "--report-path" in cmd:
                    p = Path(cmd[cmd.index("--report-path") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps([]), encoding="utf-8")
                return 1, "", "", 1  # gitleaks returns 0 or 1
            if prog == "noseyparker":
                # two invocations in local flow: scan, then report --format json
                if "report" in cmd:
                    return 0, json.dumps({"matches": []}), "", 1
                return 0, "", "", 1
            if prog == "hadolint":
                return 0, json.dumps([]), "", 1
            if prog == "checkov":
                return 0, json.dumps({"results": {"failed_checks": []}}), "", 1
            if prog == "bandit":
                return 0, json.dumps({"results": []}), "", 1
            if prog == "tfsec":
                return 0, json.dumps({"results": []}), "", 1
            if prog == "syft":
                return 0, json.dumps({"artifacts": []}), "", 1
            return 0, "", "", 1

    for t in tools:
        fake = Fake()
        monkeypatch.setattr(jmo, "_tool_exists", tool_exists_factory(t))
        monkeypatch.setattr(jmo, "_run_cmd", fake.run_cmd)
        args = types.SimpleNamespace(
            cmd="scan",
            repo=str(repo),
            repos_dir=None,
            targets=None,
            results_dir=str(out_base),
            config=str(tmp_path / "no.yml"),
            tools=[t],
            timeout=10,
            threads=1,
            allow_missing_tools=False,
            profile_name=None,
            log_level=None,
            human_logs=False,
        )
        rc = jmo.cmd_scan(args)
        assert rc == 0
        out = out_base / "individual-repos" / repo.name / f"{t}.json"
        assert out.exists(), f"expected output for {t} to exist: {out}"


def test_noseyparker_docker_fallback(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path)
    out_base = tmp_path / "results"

    # Local NP present but fails; docker present
    def fake_tool_exists(name: str) -> bool:
        return name in {"noseyparker", "docker"}

    class Fake:
        def __init__(self):
            self.phase = 0

        def run_cmd(self, cmd, timeout, retries=0, capture_stdout=False, ok_rcs=None):
            prog = cmd[0]
            if prog == "noseyparker":
                # Fail local operations to trigger docker fallback
                return 1, "", "fail", 1
            if prog == "bash":
                # docker fallback runner writes out json; emulate success
                # output path is argument after --out
                if "--out" in cmd:
                    p = Path(cmd[cmd.index("--out") + 1])
                    p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_text(json.dumps({"matches": []}), encoding="utf-8")
                return 0, "", "", 1
            return 0, "", "", 1

    fake = Fake()
    monkeypatch.setattr(jmo, "_tool_exists", fake_tool_exists)
    monkeypatch.setattr(jmo, "_run_cmd", fake.run_cmd)

    args = types.SimpleNamespace(
        cmd="scan",
        repo=str(repo),
        repos_dir=None,
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "no.yml"),
        tools=["noseyparker"],
        timeout=10,
        threads=1,
        allow_missing_tools=False,
        profile_name=None,
        log_level=None,
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)
    assert rc == 0
    out = out_base / "individual-repos" / repo.name / "noseyparker.json"
    assert out.exists()
