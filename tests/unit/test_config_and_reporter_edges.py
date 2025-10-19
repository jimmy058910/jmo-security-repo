from pathlib import Path

import pytest

from scripts.core.config import load_config
from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.cli.report_orchestrator import fail_code


def test_load_config_missing_file(tmp_path: Path):
    cfg = load_config(str(tmp_path / "does-not-exist.yml"))
    # Defaults should be applied
    assert isinstance(cfg.tools, list) and cfg.tools
    assert cfg.outputs and "json" in cfg.outputs


def test_load_config_without_yaml(monkeypatch, tmp_path: Path):
    # Simulate PyYAML not installed inside config module
    import scripts.core.config as cfgmod

    monkeypatch.setattr(cfgmod, "yaml", None, raising=False)
    cfg = load_config(str(tmp_path / "jmo.yml"))
    assert cfg.tools and isinstance(cfg.tools, list)


def test_yaml_reporter_raises_without_pyyaml(monkeypatch, tmp_path: Path):
    # Simulate PyYAML not installed inside yaml_reporter module
    import scripts.core.reporters.yaml_reporter as ymod

    monkeypatch.setattr(ymod, "yaml", None, raising=False)
    with pytest.raises(RuntimeError):
        write_yaml([], tmp_path / "x.yaml")


def test_fail_code_edges():
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 0}
    # Unknown threshold returns 0
    assert fail_code("unknown", counts) == 0
    # None threshold returns 0
    assert fail_code(None, counts) == 0
    # MEDIUM threshold yields 1 (since MEDIUM count > 0)
    assert fail_code("MEDIUM", counts) == 1
