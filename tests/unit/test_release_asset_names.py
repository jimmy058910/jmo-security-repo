"""Every download names an asset its pinned release has, on every platform.

`jmo tools install` builds each URL from a template per platform. Rendering all
of them through the installer for six platform and architecture pairs, on
2026-11-05, found 53 of 66 names in their release: trivy, nuclei and hadolint
asked for `Darwin` names their releases do not have (trivy and nuclei say
`macOS`, hadolint `macos`), and trivy, nuclei and opa asked for a Windows arm64
build none of them publishes. Each failed with a 404 on that platform.

The names are tests/fixtures/release_asset_names.json, read from GitHub at the
pins with the version replaced by `{version}`, so a version bump does not stale
it; an upstream rename does, and is found when it is refreshed:

    gh api repos/<repo>/releases/tags/v<version> --jq '[.assets[].name]'
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.cli.tool_installer import ToolInstaller
from scripts.core.install_config import BINARY_URLS
from scripts.core.tool_registry import ToolRegistry

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "release_asset_names.json"
ASSETS = json.loads(FIXTURE.read_bytes())
DOWNLOADED = sorted([*BINARY_URLS, "zap"])
PLATFORMS = [
    ("linux", "x86_64"),
    ("linux", "aarch64"),
    ("macos", "x86_64"),
    ("macos", "arm64"),
    ("windows", "AMD64"),
    ("windows", "ARM64"),
]


def _rendered_asset(
    tool: str, platform: str, machine: str, monkeypatch, tmp_path
) -> str:
    """The asset name `jmo tools install <tool>` downloads on that platform."""
    installer = ToolInstaller(manager=MagicMock(), install_dir=tmp_path / "bin")
    installer.platform = platform
    monkeypatch.setattr("platform.machine", lambda: machine)
    urls: list[str] = []

    def record(url: str, _out: Path, timeout: int = 0) -> None:
        urls.append(url)
        return None  # "no download tool": the installer stops before any I/O

    monkeypatch.setattr(installer, "_download", record)
    info = ToolRegistry().get_tool(tool)
    assert info is not None, tool
    if tool == "zap":
        installer._install_extract_app(tool, info, 0.0)
    else:
        installer._install_binary(tool, info, 0.0)
    assert len(urls) == 1, (tool, platform, machine, urls)
    return urls[0].rsplit("/", 1)[1].replace(info.version, "{version}")


def test_the_names_cover_every_downloaded_tool() -> None:
    assert sorted(ASSETS) == DOWNLOADED


@pytest.mark.parametrize(("platform", "machine"), PLATFORMS)
@pytest.mark.parametrize("tool", DOWNLOADED)
def test_each_download_names_an_asset_its_release_has(
    tool: str, platform: str, machine: str, monkeypatch, tmp_path
) -> None:
    asset = _rendered_asset(tool, platform, machine, monkeypatch, tmp_path)

    assert asset in ASSETS[tool]["assets"], (
        f"{tool} on {platform}/{machine} downloads {asset}, which its release "
        f"does not have"
    )
