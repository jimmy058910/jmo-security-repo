"""opengrep installs as a static binary (v2.0.0 Phase 5, PR B, task B1).

Measured before any of this was written:

- The release names its assets `opengrep_<flavour>_<arch>` with no version in
  the name and no archive around them, and spells the architecture three ways:
  `x86` for Intel, `aarch64` on Linux, `arm64` on macOS. The installer's
  `{arch}` is `arm64` for both ARM spellings, so the URL takes its own
  placeholder, `{arch_x86}`, read from the platform's own machine name.
- It ships no Windows arm64 build: the x86 `.exe` is fetched there, as it is
  for hadolint, shellcheck and zizmor.
- Its checksum is a cosign `.sig` and `.cert` beside each asset, not a file of
  sums; the download is made without one, as zizmor's is.
- The first run unpacks 255,465,660 bytes (104 files) into
  `$XDG_CACHE_HOME/opengrep/v1.32.0/` and takes 1.1 s, the same as the second
  (v1.32.0, x86_64, fresh `HOME`, 2026-10-29), so the Dockerfile has no
  warm-up step.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolManager
from scripts.core.tool_registry import ToolInfo

# opengrep v1.32.0's release assets, listed with `gh release view v1.32.0 -R
# opengrep/opengrep --json assets --jq '.assets[].name'` on 2026-10-29. A URL
# the installer builds must be one of these, or it downloads a 404 page.
RELEASE_ASSETS_1_32_0 = frozenset(
    {
        "opengrep-core_linux_aarch64.tar.gz",
        "opengrep-core_linux_x86.tar.gz",
        "opengrep-core_osx_aarch64.tar.gz",
        "opengrep-core_osx_x86.tar.gz",
        "opengrep-core_windows_x86.zip",
        "opengrep_manylinux_aarch64",
        "opengrep_manylinux_aarch64.cert",
        "opengrep_manylinux_aarch64.sig",
        "opengrep_manylinux_x86",
        "opengrep_manylinux_x86.cert",
        "opengrep_manylinux_x86.sig",
        "opengrep_musllinux_aarch64",
        "opengrep_musllinux_aarch64.cert",
        "opengrep_musllinux_aarch64.sig",
        "opengrep_musllinux_x86",
        "opengrep_musllinux_x86.cert",
        "opengrep_musllinux_x86.sig",
        "opengrep_osx_arm64",
        "opengrep_osx_arm64.cert",
        "opengrep_osx_arm64.sig",
        "opengrep_osx_x86",
        "opengrep_osx_x86.cert",
        "opengrep_osx_x86.sig",
        "opengrep_windows_x86.exe",
        "opengrep_windows_x86.exe.cert",
        "opengrep_windows_x86.exe.sig",
    }
)


class TestInstallUrl:
    """Through `ToolInstaller._install_binary`, the path `jmo tools install`
    takes, stopped at the download so nothing is fetched."""

    @pytest.mark.parametrize(
        ("platform_key", "machine", "asset"),
        [
            ("linux", "x86_64", "opengrep_manylinux_x86"),
            ("linux", "aarch64", "opengrep_manylinux_aarch64"),
            ("macos", "x86_64", "opengrep_osx_x86"),
            ("macos", "arm64", "opengrep_osx_arm64"),
            ("windows", "AMD64", "opengrep_windows_x86.exe"),
            # No Windows arm64 build exists: the x86 one is fetched there.
            ("windows", "ARM64", "opengrep_windows_x86.exe"),
        ],
    )
    def test_the_url_names_a_real_asset(
        self, tmp_path, platform_key, machine, asset
    ) -> None:
        installer = ToolInstaller(install_dir=tmp_path)
        installer.platform = platform_key
        urls: list[str] = []

        def capture(url: str, dest: Path) -> None:
            urls.append(url)
            return None  # "no download tool": _install_binary stops here

        info = ToolInfo(
            name="opengrep", version="1.32.0", description="", category="binary_tools"
        )
        with (
            patch("platform.machine", return_value=machine),
            patch.object(installer, "_get_download_command", side_effect=capture),
        ):
            installer._install_binary("opengrep", info, time.time())

        assert urls == [
            "https://github.com/opengrep/opengrep/releases/download/v1.32.0/" + asset
        ]
        assert asset in RELEASE_ASSETS_1_32_0


def test_jmo_tools_check_says_there_is_no_windows_arm64_build() -> None:
    """The hint `jmo tools check` prints for a missing opengrep."""
    manager = ToolManager()
    with patch.object(manager, "_find_binary", return_value=None):
        status = manager.check_tool("opengrep")

    assert status.installed is False
    # versions.yaml's pin, read rather than restated: the weekly update moves it.
    pin = yaml.safe_load(Path("versions.yaml").read_text(encoding="utf-8"))
    assert status.expected_version == pin["binary_tools"]["opengrep"]["version"]
    assert status.install_hint.startswith("jmo tools install opengrep")
    assert "no Windows arm64 build" in status.install_hint
