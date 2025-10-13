import json
from pathlib import Path


from scripts.core.adapters.bandit_adapter import load_bandit
from scripts.core.adapters.semgrep_adapter import load_semgrep
from scripts.core.adapters.syft_adapter import load_syft
from scripts.core.adapters.tfsec_adapter import load_tfsec
from scripts.core.adapters.checkov_adapter import load_checkov
from scripts.core.adapters.hadolint_adapter import load_hadolint


def _write(p: Path, obj):
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_empty_and_malformed_inputs(tmp_path: Path):
    # Verify adapters gracefully handle empty and malformed payloads
    files = {
        "bandit.json": load_bandit,
        "semgrep.json": load_semgrep,
        "syft.json": load_syft,
        "tfsec.json": load_tfsec,
        "checkov.json": load_checkov,
        "hadolint.json": load_hadolint,
    }
    # empty files
    for name, loader in files.items():
        p = tmp_path / name
        p.write_text("", encoding="utf-8")
        assert loader(p) == []
    # malformed files
    for name, loader in files.items():
        p = tmp_path / name
        p.write_text("{not json}", encoding="utf-8")
        assert loader(p) == []


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
    out = load_semgrep(p)
    assert [i["severity"] for i in out] == ["MEDIUM", "LOW"]

    # Hadolint level mapping
    h = [
        {"code": "DL", "file": "D", "line": 1, "level": "error"},
        {"code": "DL", "file": "D", "line": 2, "level": "warning"},
    ]
    p = tmp_path / "hadolint.json"
    _write(p, h)
    out = load_hadolint(p)
    assert [i["severity"] for i in out] == ["HIGH", "MEDIUM"]


def test_adapter_missing_arrays_handled(tmp_path: Path):
    # tfsec with unexpected shape
    p = tmp_path / "tfsec.json"
    _write(p, {"results": None})
    assert load_tfsec(p) == []

    # checkov with unexpected shape
    p = tmp_path / "checkov.json"
    _write(p, {"results": {"failed_checks": None}})
    assert load_checkov(p) == []
