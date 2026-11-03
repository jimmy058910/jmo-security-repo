"""yara-x reports a canary under node_modules through the scan loop (v2.0.0
Phase 6, PR Y, Task Y5).

signature-base's npm supply-chain rules can match nowhere but `node_modules`,
so yara-x is the one tool that reads vendored trees (decision 4). This drives
the yara-x row through `tool_loop.run_tools`, as `jmo scan` does, with the real
engine (a dependency of JMo, so always present; it runs on the interpreter, so
no scanner binary is spawned) and a rule JMo wrote: never EICAR, never a real
sample (decision 7).

The canary sits in source, in `node_modules`, in `.git` and in JMo's own
results directory inside the tree, and only the first two may be reported
(Review Focus 3). Each finding names the rule's author, as DRL 1.1 requires
of every match (decision 5).
"""

from __future__ import annotations

from pathlib import Path

from scripts.cli.scan_jobs import tool_loop
from scripts.core.adapters.common import normalize_finding_path
from scripts.core.adapters.yara_x_adapter import YaraXAdapter
from scripts.core.scan_timings import State
from scripts.core.tool_runner import ToolRunner

CANARY = "jmo-yara-x-canary-7d3f9a: a test marker, not malware"
AUTHOR = "JMo Security test suite"
RULE = f"""
rule JMO_Canary_Test {{
    meta:
        author = "{AUTHOR}"
        description = "A string only JMo's tests write"
    strings:
        $canary = "{CANARY}"
    condition:
        $canary
}}
"""

PLANTED = {
    "src/index.js": True,
    "node_modules/left-pad/index.js": True,
    # A git object store is never source.
    ".git/objects/canary.js": False,
    # JMo's results directory inside the tree, from an earlier scan.
    "results/individual-repos/old/canary.js": False,
}


def _scan(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    for relative in PLANTED:
        (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (repo / relative).write_bytes(f"// {CANARY}\n".encode())
    rules = tmp_path / "canary.yar"
    rules.write_bytes(RULE.encode())
    out = tmp_path / "out"
    out.mkdir()

    row = tool_loop.run_tools(
        tools=["yara-x"],
        target_type="repo",
        target=repo,
        target_label="canary",
        out_dir=out,
        timeout=120,
        retries=0,
        per_tool_config={"yara-x": {"rules_path": str(rules)}},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
        results_name="results",
        results_tree=repo / "results",
    )["yara-x"]

    assert row.state is State.RAN, row
    return repo, out


def _relative(path: str, repo: Path) -> str:
    # The runner names each file absolutely; both sides are resolved so a
    # Windows temp directory spelled short (RUNNER~1) on one side still matches.
    found = Path(path)
    if found.is_absolute():
        found = found.resolve().relative_to(repo.resolve())
    return normalize_finding_path(found.as_posix())


def test_the_canary_is_reported_in_source_and_node_modules_only(tmp_path) -> None:
    repo, out = _scan(tmp_path)

    findings = YaraXAdapter().parse(out / "yara-x.json")

    assert sorted(_relative(f.location["path"], repo) for f in findings) == sorted(
        path for path, reported in PLANTED.items() if reported
    )
    assert {f.ruleId for f in findings} == {"JMO_Canary_Test"}


def test_each_canary_finding_names_the_rules_author(tmp_path) -> None:
    _, out = _scan(tmp_path)

    findings = YaraXAdapter().parse(out / "yara-x.json")

    assert findings, "no canary finding to read an author from"
    for finding in findings:
        assert finding.context is not None
        assert finding.context["author"] == AUTHOR
        assert AUTHOR in finding.message
