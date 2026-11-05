"""Where `jmo tools install` puts a downloaded binary, and under what name.

On Windows every installed binary is named `<tool>.exe`, whatever the release
packed: trufflehog ships a .tar.gz whose binary has no extension, and installed
without `.exe` it was never found, so it silently never scanned (measured).
Keyed on the platform JMo installs for, not on the archive. These tests guarded
the BinaryInstaller copy of this logic until that class, which nothing ran, was
deleted; they now run ToolInstaller._install_binary, the code that ships.
"""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.cli.tool_installer import ToolInstaller
from scripts.core.tool_registry import ToolRegistry

BINARY = b"MZ a scanner, as released"


@pytest.fixture
def installer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ToolInstaller:
    inst = ToolInstaller(manager=MagicMock(), install_dir=tmp_path / "bin")
    monkeypatch.setattr(inst, "_get_arch", lambda: "x86_64")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    return inst


def _serve(installer: ToolInstaller, asset: str, body: bytes, sums: str | None) -> None:
    """Serve the asset, and its release's checksum file under `sums`."""
    files = {asset: body}
    if sums:
        files[sums] = f"{hashlib.sha256(body).hexdigest()}  {asset}\n".encode()

    def download(
        url: str, out: Path, timeout: int = 0
    ) -> subprocess.CompletedProcess[str]:
        name = url.rsplit("/", 1)[1]
        if name not in files:
            return subprocess.CompletedProcess([url], 22, "", "curl: (22) 404")
        out.write_bytes(files[name])
        return subprocess.CompletedProcess([url], 0, "", "")

    installer._download = download  # type: ignore[method-assign]


def _tar(name: str, mode: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        info = tarfile.TarInfo(name)
        info.size = len(BINARY)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(BINARY))
    return buf.getvalue()


def _install(installer: ToolInstaller, tool: str):
    return installer._install_binary(tool, ToolRegistry().get_tool(tool), 0.0)


def test_a_windows_binary_packed_without_exe_is_installed_as_exe(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    installer.platform = "windows"
    version = ToolRegistry().get_tool("trufflehog").version
    _serve(
        installer,
        f"trufflehog_{version}_windows_amd64.tar.gz",
        _tar("trufflehog", "w:gz"),
        f"trufflehog_{version}_checksums.txt",
    )

    result = _install(installer, "trufflehog")

    assert result.success, result.message
    assert (tmp_path / "bin" / "trufflehog.exe").read_bytes() == BINARY
    assert not (tmp_path / "bin" / "trufflehog").exists()


def test_a_zip_is_extracted_and_its_exe_installed(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    installer.platform = "windows"
    version = ToolRegistry().get_tool("gitleaks").version
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("LICENSE", "MIT")
        zf.writestr("gitleaks.exe", BINARY)
    _serve(
        installer,
        f"gitleaks_{version}_windows_x64.zip",
        buf.getvalue(),
        f"gitleaks_{version}_checksums.txt",
    )

    result = _install(installer, "gitleaks")

    assert result.success, result.message
    assert (tmp_path / "bin" / "gitleaks.exe").read_bytes() == BINARY


def test_a_raw_windows_exe_keeps_its_exe_name(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    installer.platform = "windows"
    _serve(installer, "hadolint-windows-x86_64.exe", BINARY, "checksums.sha256")

    result = _install(installer, "hadolint")

    assert result.success, result.message
    assert (tmp_path / "bin" / "hadolint.exe").read_bytes() == BINARY


def test_a_linux_tar_xz_is_extracted_to_a_bare_name(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    installer.platform = "linux"
    version = ToolRegistry().get_tool("shellcheck").version
    body = _tar(f"shellcheck-v{version}/shellcheck", "w:xz")
    _serve(installer, f"shellcheck-v{version}.linux.x86_64.tar.xz", body, None)

    result = _install(installer, "shellcheck")

    assert result.success, result.message
    installed = tmp_path / "bin" / "shellcheck"
    assert installed.read_bytes() == BINARY
    assert not (tmp_path / "bin" / "shellcheck.exe").exists()
