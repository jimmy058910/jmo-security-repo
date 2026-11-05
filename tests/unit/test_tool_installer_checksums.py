"""`jmo tools install` checks each binary against its release's sha256 (#1374).

The image and CI verified osv-scanner's download; the product's own installer
verified nothing, so an interrupted, redirected or tampered download was
installed and run as it was. Where a project publishes a checksum file, the
download is checked before anything is extracted or installed, and a mismatch
fails without touching the binary already installed. Where it publishes none,
the install says so instead of implying a check.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.cli.tool_installer import ToolInstaller
from scripts.core.checksums import parse_sha256sums
from scripts.core.install_config import BINARY_URLS, CHECKSUM_URLS, UNCHECKSUMMED
from scripts.core.tool_registry import ToolRegistry

# Lines as each release format writes them, read at the pinned tags.
GORELEASER = (
    "bdbea0508e439b144f49de14e775908de5f902f3d14ea7ae8354bae72b0b72ef  "
    "trufflehog_3.99.7_linux_amd64.tar.gz\n"
)
HADOLINT = (
    "c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507 "
    "*hadolint-linux-x86_64\n"
)
OPA = "5ae411b3ae2cb093ac1f70cc20df4b372eead7be61f7de989b33a3dbd6cbe09b  opa_linux_amd64\n"


@pytest.mark.parametrize(
    ("text", "name", "digest"),
    [
        (GORELEASER, "trufflehog_3.99.7_linux_amd64.tar.gz", "bdbea050"),
        (HADOLINT, "hadolint-linux-x86_64", "c7187db9"),
        (OPA, "opa_linux_amd64", "5ae411b3"),
    ],
)
def test_each_release_format_is_read(text: str, name: str, digest: str) -> None:
    sums = parse_sha256sums(text)

    assert list(sums) == [name]
    assert sums[name].startswith(digest)


def test_every_downloaded_tool_is_checked_or_says_why_not() -> None:
    """A tool added to BINARY_URLS has to choose: a checksum source, or the
    reason its project publishes none, which the install then prints."""
    assert set(CHECKSUM_URLS) | set(UNCHECKSUMMED) >= set(BINARY_URLS) | {"zap"}
    assert not set(CHECKSUM_URLS) & set(UNCHECKSUMMED)


@pytest.fixture
def installer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ToolInstaller:
    inst = ToolInstaller(manager=MagicMock(), install_dir=tmp_path / "bin")
    inst.platform = "linux"
    monkeypatch.setattr(inst, "_get_arch", lambda: "x86_64")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    return inst


def _serve(installer: ToolInstaller, files: dict[str, bytes]) -> list[str]:
    """Answer each download from `files`, keyed by the URL's last segment."""
    fetched: list[str] = []

    def download(
        url: str, out: Path, timeout: int = 0
    ) -> subprocess.CompletedProcess[str]:
        name = url.rsplit("/", 1)[1]
        fetched.append(name)
        if name not in files:
            return subprocess.CompletedProcess([url], 22, "", "curl: (22) 404")
        out.write_bytes(files[name])
        return subprocess.CompletedProcess([url], 0, "", "")

    installer._download = download  # type: ignore[method-assign]
    return fetched


def _sums(name: str, body: bytes) -> bytes:
    return f"{hashlib.sha256(body).hexdigest()}  {name}\n".encode()


BINARY = b"\x7fELF osv-scanner, as released"


def test_a_download_matching_its_published_sha256_installs(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    asset = "osv-scanner_linux_amd64"
    fetched = _serve(
        installer, {asset: BINARY, "osv-scanner_SHA256SUMS": _sums(asset, BINARY)}
    )

    result = installer._install_binary(
        "osv-scanner", ToolRegistry().get_tool("osv-scanner"), 0.0
    )

    assert result.success, result.message
    assert (tmp_path / "bin" / "osv-scanner").read_bytes() == BINARY
    assert fetched == [asset, "osv-scanner_SHA256SUMS"]
    assert result.warning is None


def test_a_mismatch_fails_and_leaves_the_installed_binary(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    asset = "osv-scanner_linux_amd64"
    installed = tmp_path / "bin" / "osv-scanner"
    installed.parent.mkdir(parents=True)
    installed.write_bytes(b"the version installed before")
    _serve(
        installer,
        {asset: b"tampered", "osv-scanner_SHA256SUMS": _sums(asset, BINARY)},
    )

    result = installer._install_binary(
        "osv-scanner", ToolRegistry().get_tool("osv-scanner"), 0.0
    )

    assert not result.success
    assert "sha256" in result.message
    assert hashlib.sha256(BINARY).hexdigest() in result.message
    assert installed.read_bytes() == b"the version installed before"


def test_an_asset_its_checksum_file_does_not_list_fails(
    installer: ToolInstaller,
) -> None:
    asset = "osv-scanner_linux_amd64"
    _serve(installer, {asset: BINARY, "osv-scanner_SHA256SUMS": _sums("other", BINARY)})

    result = installer._install_binary(
        "osv-scanner", ToolRegistry().get_tool("osv-scanner"), 0.0
    )

    assert not result.success
    assert asset in result.message


def test_a_checksum_file_that_cannot_be_fetched_fails(installer: ToolInstaller) -> None:
    _serve(installer, {"osv-scanner_linux_amd64": BINARY})

    result = installer._install_binary(
        "osv-scanner", ToolRegistry().get_tool("osv-scanner"), 0.0
    )

    assert not result.success
    assert "osv-scanner_SHA256SUMS" in result.message


def test_a_per_asset_checksum_file_is_read(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    # opa publishes one `<asset>.sha256` beside each asset.
    asset = "opa_linux_amd64"
    _serve(installer, {asset: BINARY, f"{asset}.sha256": _sums(asset, BINARY)})

    result = installer._install_binary("opa", ToolRegistry().get_tool("opa"), 0.0)

    assert result.success, result.message
    assert (tmp_path / "bin" / "opa").read_bytes() == BINARY


def test_zap_installs_and_says_it_was_not_verified(
    installer: ToolInstaller, tmp_path: Path
) -> None:
    # ZAP is an app archive, installed by its own path, with its checksums
    # only in its release notes.
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("ZAP_2.17.0/zap.sh", "#!/bin/sh\n")
        zf.writestr("ZAP_2.17.0/zap.bat", "@echo off\n")
    asset = "ZAP_2.17.0_Crossplatform.zip"
    fetched = _serve(installer, {asset: buf.getvalue()})
    installer.manager.check_tool.return_value = MagicMock(
        installed=True, installed_version="2.17.0"
    )

    result = installer._install_extract_app("zap", ToolRegistry().get_tool("zap"), 0.0)

    assert result.success, result.message
    assert result.warning and "not verified" in result.warning
    assert fetched == [asset]


def test_a_project_with_no_checksum_installs_and_says_it_was_not_verified(
    installer: ToolInstaller,
) -> None:
    fetched = _serve(installer, {"opengrep_manylinux_x86": BINARY})

    result = installer._install_binary(
        "opengrep", ToolRegistry().get_tool("opengrep"), 0.0
    )

    assert result.success, result.message
    assert result.warning and "not verified" in result.warning
    assert fetched == ["opengrep_manylinux_x86"]
