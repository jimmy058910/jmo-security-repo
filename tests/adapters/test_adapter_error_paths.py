import json
from pathlib import Path


from scripts.core.adapters.bandit_adapter import BanditAdapter
from scripts.core.adapters.semgrep_adapter import SemgrepAdapter
from scripts.core.adapters.syft_adapter import SyftAdapter
from scripts.core.adapters.checkov_adapter import CheckovAdapter
from scripts.core.adapters.hadolint_adapter import HadolintAdapter


def _write(p: Path, obj):
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_empty_and_malformed_inputs(tmp_path: Path):
    # Verify adapters gracefully handle empty and malformed payloads
    adapters_map = {
        "bandit.json": BanditAdapter(),
        "semgrep.json": SemgrepAdapter(),
        "syft.json": SyftAdapter(),
        "checkov.json": CheckovAdapter(),
        "hadolint.json": HadolintAdapter(),
    }
    # empty files
    for name, adapter in adapters_map.items():
        p = tmp_path / name
        p.write_text("", encoding="utf-8")
        assert adapter.parse(p) == []
    # malformed files
    for name, adapter in adapters_map.items():
        p = tmp_path / name
        p.write_text("{not json}", encoding="utf-8")
        assert adapter.parse(p) == []


def test_severity_translation_paths(tmp_path: Path):
    # Semgrep severity mapping
    sem = {
        "results": [
            {
                "check_id": "a.b.c",
                "path": "x",
                "start": {"line": 1},
                "extra": {"message": "m", "severity": "WARNING"},
            },
            {
                "check_id": "a.b.c",
                "path": "x",
                "start": {"line": 2},
                "extra": {"message": "m", "severity": "INFO"},
            },
        ],
        "version": "1",
    }
    p = tmp_path / "semgrep.json"
    _write(p, sem)
    adapter = SemgrepAdapter()
    findings = adapter.parse(p)
    assert [f.severity for f in findings] == ["MEDIUM", "LOW"]

    # Hadolint level mapping
    h = [
        {"code": "DL", "file": "D", "line": 1, "level": "error"},
        {"code": "DL", "file": "D", "line": 2, "level": "warning"},
    ]
    p = tmp_path / "hadolint.json"
    _write(p, h)
    adapter = HadolintAdapter()
    adapter = HadolintAdapter()
    findings = adapter.parse(p)
    assert [i.severity for i in findings] == ["HIGH", "MEDIUM"]


def test_adapter_missing_arrays_handled(tmp_path: Path):
    # checkov with unexpected shape (null failed_checks)
    p = tmp_path / "checkov.json"
    _write(p, {"results": {"failed_checks": None}})
    adapter = CheckovAdapter()
    adapter = CheckovAdapter()
    assert adapter.parse(p) == []

    # checkov with missing results entirely
    p = tmp_path / "checkov2.json"
    _write(p, {})
    adapter = CheckovAdapter()
    adapter = CheckovAdapter()
    assert adapter.parse(p) == []
