from pathlib import Path
import json

from scripts.core import normalize_and_report as nr


def _write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_safe_load_adapter_failure_isolated(tmp_path: Path, monkeypatch):
    # Create minimal results dir with a repo and one tool JSON
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"
    _write(repo / "gitleaks.json", [])

    # Monkeypatch one loader to raise
    def boom(_path):
        raise RuntimeError("boom")

    monkeypatch.setattr(nr, "load_trufflehog", boom)

    out = nr.gather_results(root)
    # Should still return a list (adapter failure ignored)
    assert isinstance(out, list)