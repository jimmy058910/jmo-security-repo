"""A secret an opengrep rule matches reaches no file under results/, nor history (#1585).

Measured 2026-11-05 at cc6c44a6 with `jmo ci --tools opengrep` on these planted
secrets: they reached opengrep.json, opengrep's log, findings.json/.yaml, the
dashboard, PCI_DSS_COMPLIANCE.md and history.db; two through the finding's message.
The real binary runs here, so the module is `requires_tools`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_utils import find_tool

pytestmark = pytest.mark.requires_tools

JWT = "planted-jwt-1585-aa11bb22"
K8S = "cGxhbnRlZDE1ODVrOHNzZWNyZXRlZTU1ZmY2Ng=="
DEFAULT_PASSWORD = "planted-pydefault-1585-gg77"
LOGGED = "planted-logtoken-1585-hh88"
PLANTED = (JWT, K8S, DEFAULT_PASSWORD, LOGGED)


def _repo(root: Path) -> Path:
    repo = root / "app"
    (repo / "k8s").mkdir(parents=True)
    (repo / "index.js").write_bytes(
        f'const jwt = require("jsonwebtoken");\n'
        f'const token = jwt.sign({{ user: 1 }}, "{JWT}");\n'
        f"module.exports = token;\n".encode()
    )
    (repo / "k8s" / "secret.yaml").write_bytes(
        f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
        f"data:\n  password: {K8S}\n".encode()
    )
    (repo / "app.py").write_bytes(
        f"import logging\nlogger = logging.getLogger(__name__)\n\n"
        f'def connect(host, password="{DEFAULT_PASSWORD}"):\n'
        f'    logger.info("token={LOGGED} for %s", host)\n'
        f"    return host\n".encode()
    )
    return repo


def test_no_planted_secret_survives_jmo_ci(tmp_path: Path, monkeypatch) -> None:
    opengrep = find_tool("opengrep")
    if not opengrep:
        pytest.skip("not installed: opengrep")
    cfg = tmp_path / "jmo.yml"
    cfg.write_bytes(
        yaml.safe_dump({"outputs": ["json", "md", "yaml", "html", "sarif"]}).encode()
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool",
        lambda name, *a, **k: opengrep if name == "opengrep" else None,
    )
    repo = _repo(tmp_path)
    results = tmp_path / "results"
    history = tmp_path / "history.db"
    argv = [
        "jmo", "ci", "--repo", str(repo), "--tools", "opengrep",
        "--results-dir", str(results), "--config", str(cfg), "--history-db", str(history),
    ]  # fmt: skip

    with patch.object(sys, "argv", argv):
        assert jmo.cmd_ci(jmo.parse_args()) == 0

    rules = {
        f["ruleId"].rsplit(".", 1)[-1]
        for f in json.loads((results / "summaries" / "findings.json").read_bytes())[
            "findings"
        ]
    }
    # Meta-guard: the rules fired, so their findings were there to leak.
    assert {
        "hardcoded-jwt-secret",
        "secrets-in-config-file",
        "hardcoded-password-default-argument",
        "python-logger-credential-disclosure",
    } <= rules, rules
    left = {
        p.relative_to(tmp_path).as_posix(): [
            s for s in PLANTED if s.encode() in p.read_bytes()
        ]
        for p in [*results.rglob("*"), history]
        if p.is_file()
    }
    assert {k: v for k, v in left.items() if v} == {}
