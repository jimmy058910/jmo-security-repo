"""A secret an opengrep rule matches reaches no file under results/, nor history (#1585).

Measured 2026-11-05 at cc6c44a6 with `jmo ci --tools opengrep` on these planted
secrets: they reached opengrep.json, opengrep's log, findings.json/.yaml, the
dashboard, PCI_DSS_COMPLIANCE.md and history.db; two through the finding's message.
The review of the fix measured more paths: other rules' results over the same
code, a nearby finding's snippet, and the logger rule's message for a `%` call.
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

# Every value here is planted: what each test asserts is that none of them
# reaches a file. Each shape is one that leaked, measured by #1585 or its review.
PLANTED = {
    "jwt_top": "planted-jwt-1585-aa11bb22",
    "jwt_inline": "planted-inline-jwt-u7y6t5",
    "session": "planted-session-l1k2j3",
    "k8s_a": "cGxhbnRlZGZsb3dvbmVhYWE=",
    "k8s_b": "cGxhbnRlZGZsb3d0d29iYmI=",
    "default_password": "planted-pydefault-1585-gg77",
    "logged": "planted-logtoken-1585-hh88",
    "rds": "planted-rds-pass-a1s2d3",
    "keyvault": "planted-kv-value-q1w2e3r4",
    "basic_auth": "planted-reqauth-c2v3b4",
    "set_password": "planted-setpw-n7m8q9",
    "bicep": "planted-bicep-pw-f5g6h7",
    "entropy": "planted-centropy-Xq7Lm2Pz9Rt4Wv8Ks3",
}


def _repo(root: Path) -> Path:
    p = PLANTED
    repo = root / "app"
    (repo / "k8s").mkdir(parents=True)
    files = {
        "index.js": (
            'const jwt = require("jsonwebtoken");\n'
            'const session = require("express-session");\n'
            'const express = require("express");\n'
            "const app = express();\n"
            f'const token = jwt.sign({{ user: 1 }}, "{p["jwt_top"]}");\n'
            "function issue(user) {\n"
            f'  return jwt.sign(user, "{p["jwt_inline"]}");\n'
            "}\n"
            "app.use(session({\n"
            f"  secret: '{p['session']}',\n"
            "  resave: false,\n"
            "  saveUninitialized: true\n"
            "}));\n"
            "module.exports = { token, issue };\n"
        ),
        "k8s/secret.yaml": (
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
            f"data: {{password: {p['k8s_a']}, token: {p['k8s_b']}}}\n"
        ),
        "app.py": (
            "import logging\nimport requests\n"
            "from django.contrib.auth.models import User\n\n"
            "logger = logging.getLogger(__name__)\n\n"
            f'def connect(host, password="{p["default_password"]}"):\n'
            f'    logger.info("token={p["logged"]} for %s" % host)\n'
            "    return host\n\n"
            f'requests.get("http://example.com/api", auth=("bob", "{p["basic_auth"]}"))\n'
            "u = User()\n"
            f'u.set_password("{p["set_password"]}")\n'
            "u.save()\n"
        ),
        "main.tf": (
            'resource "azurerm_key_vault_secret" "example" {\n'
            '  name         = "secret-sauce"\n'
            f'  value        = "{p["keyvault"]}"\n'
            "  key_vault_id = azurerm_key_vault.example.id\n"
            "}\n\n"
            'resource "aws_db_instance" "default" {\n'
            "  allocated_storage = 10\n"
            '  engine            = "mysql"\n'
            '  username          = "foo"\n'
            f'  password          = "{p["rds"]}"\n'
            "}\n"
        ),
        "main.bicep": (
            "param location string = resourceGroup().location\n"
            f"param adminPassword string = '{p['bicep']}'\n"
        ),
        "hi.c": (
            f'int main(void) {{\n  char *k;\n  k = "{p["entropy"]}";\n  return 0;\n}}\n'
        ),
    }
    for name, text in files.items():
        (repo / name).write_bytes(text.encode())
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
    # Meta-guard: the rules fired, and rules that are not secret-class fired
    # over the same code, so their findings were there to leak.
    assert {
        "hardcoded-jwt-secret",
        "express-session-hardcoded-secret",
        "secrets-in-config-file",
        "hardcoded-password-default-argument",
        "python-logger-credential-disclosure",
        "rds-insecure-password-storage-in-source-code",
        "raptor-high-entropy-assignment",
        "aws-db-instance-no-logging",
    } <= rules, rules
    left = {
        path.relative_to(tmp_path).as_posix(): [
            name
            for name, value in PLANTED.items()
            if value.encode() in path.read_bytes()
        ]
        for path in [*results.rglob("*"), history]
        if path.is_file()
    }
    assert {k: v for k, v in left.items() if v} == {}
