import json
import types
from pathlib import Path

from scripts.cli import jmo


def test_cmd_report_yaml_missing_debug_path(tmp_path: Path, monkeypatch):
    # Prepare results with one finding
    results = tmp_path / "results"
    indiv = results / "individual-repos" / "r1"
    indiv.mkdir(parents=True, exist_ok=True)
    (indiv / "trufflehog.json").write_text(
        json.dumps([{"RuleID": "R", "File": "a", "StartLine": 1}]), encoding="utf-8"
    )

    # Ensure config requests yaml output; simulate PyYAML missing in reporter
    (tmp_path / "jmo.yml").write_text(
        "outputs: [json, md, yaml, html]\n", encoding="utf-8"
    )
    import scripts.core.reporters.yaml_reporter as ymod

    monkeypatch.setattr(ymod, "yaml", None, raising=False)

    args = types.SimpleNamespace(
        cmd="report",
        results_dir=None,
        results_dir_pos=str(results),
        results_dir_opt=None,
        out=None,
        config=str(tmp_path / "jmo.yml"),
        fail_on=None,
        profile=False,
        threads=None,
        log_level="DEBUG",
        human_logs=False,
        allow_missing_tools=True,
    )
    rc = jmo.cmd_report(args)
    assert rc == 0
    # JSON/MD/HTML still generated; YAML skipped
    out_dir = results / "summaries"
    assert (out_dir / "findings.json").exists()
    assert (out_dir / "SUMMARY.md").exists()
    assert (out_dir / "dashboard.html").exists()
    assert not (out_dir / "findings.yaml").exists()


def test_cmd_report_suppression_report(tmp_path: Path, monkeypatch):
    # Prepare results + a suppression file
    results = tmp_path / "results"
    indiv = results / "individual-repos" / "r1"
    indiv.mkdir(parents=True, exist_ok=True)
    (indiv / "trufflehog.json").write_text(
        json.dumps([{"RuleID": "R", "File": "a", "StartLine": 1}]), encoding="utf-8"
    )

    # Find the generated finding id by running a quick report without suppressions first
    args0 = types.SimpleNamespace(
        cmd="report",
        results_dir=None,
        results_dir_pos=str(results),
        results_dir_opt=None,
        out=None,
        config=str(tmp_path / "no.yml"),
        fail_on=None,
        profile=False,
        threads=None,
        log_level=None,
        human_logs=False,
        allow_missing_tools=True,
    )
    jmo.cmd_report(args0)
    out_dir = results / "summaries"
    data = (out_dir / "findings.json").read_text(encoding="utf-8")
    import json as _json

    fid = _json.loads(data)[0]["id"]

    # Write suppressions file and re-run
    (results / "jmo.suppress.yml").write_text(
        f"suppress:\n  - id: {fid}\n    reason: test\n    expires: 2999-01-01\n",
        encoding="utf-8",
    )

    args = types.SimpleNamespace(
        cmd="report",
        results_dir=None,
        results_dir_pos=str(results),
        results_dir_opt=None,
        out=None,
        config=str(tmp_path / "no.yml"),
        fail_on=None,
        profile=False,
        threads=None,
        log_level=None,
        human_logs=False,
        allow_missing_tools=True,
    )
    rc = jmo.cmd_report(args)
    assert rc == 0
    # Ensure suppression report exists and mentions the fingerprint
    sup = (results / "summaries" / "SUPPRESSIONS.md").read_text(encoding="utf-8")
    assert fid in sup and "Suppressions Applied" in sup
