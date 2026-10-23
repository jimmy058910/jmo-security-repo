"""Unit tests for classify_bump() in scripts/dev/update_versions.py.

Locks in the semver classification rules used by the tool-version automation
layer: patch/minor are auto-merge candidates; major/unknown require human
review. Getting these wrong lets a risky bump slip into auto-merge, which is
exactly what the classifier exists to prevent.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load_module():
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "dev" / "update_versions.py"
    )
    spec = importlib.util.spec_from_file_location("update_versions", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


update_versions = _load_module()
classify_bump = update_versions.classify_bump


@pytest.mark.parametrize(
    ("current", "latest", "expected"),
    [
        # Standard semver bumps
        ("1.9.3", "1.9.4", "patch"),
        ("1.151.0", "1.151.1", "patch"),
        ("1.151.0", "1.159.0", "minor"),
        ("3.0.47", "4.0.5", "major"),
        ("1.0.0", "2.0.0", "major"),
        # v-prefix stripping
        ("v2.0.0", "2.0.1", "patch"),
        ("v1.0.0", "v1.1.0", "minor"),
        # Identical versions
        ("1.0.0", "1.0.0", "patch"),
        ("v1.0.0", "v1.0.0", "patch"),
        # 0.x pre-release territory — always risky
        ("0.0.0", "0.43.1", "major"),
        ("0.69.3", "0.70.0", "major"),
        ("0.104.0", "0.111.0", "major"),
        ("1.0.0", "0.9.0", "major"),  # regression-ish, still major
        # Rebrand / lossy normalization → unknown
        ("mini-testing-1.53.7", "1.98.0", "unknown"),
        ("4.5.4", "4.5.5-stable", "unknown"),
        ("2.16.1", "2.17.0-rc1", "unknown"),
    ],
)
def test_classify_bump(current: str, latest: str, expected: str) -> None:
    assert classify_bump(current, latest) == expected


def test_classify_bump_handles_garbage() -> None:
    """Non-numeric garbage strings never raise — they return 'unknown'."""
    assert classify_bump("not-a-version", "1.0.0") == "unknown"
    assert classify_bump("1.0.0", "bananas") == "unknown"
    assert classify_bump("", "1.0.0") == "unknown"


def test_classify_writes_only_json_to_stdout(monkeypatch, capsys) -> None:
    """`--classify` prints the JSON alone on stdout; its progress goes to stderr.

    maintenance.yml writes stdout to `classify_before.json` and pastes that file
    into the weekly PR inside a JSON fence. The version checks report progress
    with print(), and those lines, colour codes included, used to land in the
    same file ahead of the JSON, so nothing could parse it (#1467's body).
    """

    def checks_that_log() -> dict[str, tuple[str, str, bool]]:
        update_versions.log("Checking latest versions for binary tools...")
        update_versions.warn("trivy: Failed to check latest version")
        update_versions.ok("yara: 4.5.4 (latest)")
        return {"ruff": ("0.16.5", "0.17.2", True)}

    monkeypatch.setattr(update_versions, "check_latest_versions", checks_that_log)
    monkeypatch.setattr(
        update_versions,
        "load_versions",
        lambda: {"python_tools": {"ruff": {"critical": False}}},
    )

    assert update_versions._print_classification_json() == 0
    out, err = capsys.readouterr()

    assert json.loads(out) == {
        "ruff": {
            "current": "0.16.5",
            "latest": "0.17.2",
            "level": classify_bump("0.16.5", "0.17.2"),
            "critical": False,
        }
    }
    assert "trivy: Failed to check latest version" in err
