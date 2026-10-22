"""`ToolInstaller._install_extract_app`, the path that installs ZAP.

`jmo tools install` first asks `check_tool` which tools are missing, and the
manager memoises each answer. The extract path then verified its own install
with that same manager, so on a first install it read the memoised "not
installed" and failed a ZAP it had just put on disk: "Extraction succeeded but
tool not detected" (measured 2026-10-21, the first `jmo tools install` on a
Debian host). The binary and pip paths are not exposed to this: they report
success from the install command's exit code.

The download and every subprocess are patched; nothing reaches the network.
"""

from __future__ import annotations

import time
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.cli.tool_installer import ToolInstaller


def test_a_first_install_is_not_judged_by_the_status_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    install_dir = tmp_path / ".jmo" / "bin"
    install_dir.mkdir(parents=True)
    installer = ToolInstaller(install_dir=install_dir)
    info = installer.registry.get_tool("zap")
    assert info is not None and info.version

    # The pre-install question `jmo tools install` asks, memoised.
    with patch("scripts.cli.tool_manager.find_tool", return_value=None):
        assert installer.manager.check_tool("zap").installed is False

    def fake_run(cmd, **kwargs):
        if cmd[0] == "curl":
            with zipfile.ZipFile(cmd[cmd.index("-o") + 1], "w") as archive:
                for name in ("zap.sh", "zap.bat", f"zap-{info.version}.jar"):
                    archive.writestr(f"ZAP_{info.version}/{name}", "")
            return MagicMock(returncode=0, stdout="", stderr="")
        # The version probe zap's verification runs.
        return MagicMock(returncode=0, stdout=f"{info.version}\n", stderr="")

    monkeypatch.setattr(
        installer,
        "_get_download_command",
        lambda url, out: ["curl", "-fsSL", "-o", str(out), url],
    )
    with patch("subprocess.run", side_effect=fake_run):
        result = installer._install_extract_app("zap", info, time.time())

    assert result.success, result.message
    assert (install_dir / "zap" / "zap.sh").is_file()
