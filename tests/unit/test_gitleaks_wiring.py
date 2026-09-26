"""gitleaks wired as a descriptor row (v2.0.0 Phase 3, PR C).

Measured before any of this was written (the task plan's C1):

- The release names amd64 `x64`, which no installer placeholder produced, and
  ships a `.zip` on Windows only.
- Given an absolute target, gitleaks writes that path into every message, and
  a finding's id hashes the message: the same secret got a different id in
  every checkout. Run from the repository with target `.`, paths and messages
  are repository-relative, which is how the Phase 1 golden was made.
- gitleaks has no exclude flag. Its exclusions are a config file.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import segment_regex, write_gitleaks_config
from scripts.cli.tool_installer import ToolInstaller
from scripts.core.tool_descriptors import DESCRIPTORS, VENDORED_DIRS, ExclusionStyle
from scripts.core.tool_registry import ToolInfo

# gitleaks v8.30.1's release assets, listed with `gh release view v8.30.1 -R
# gitleaks/gitleaks` on 2026-09-26. A URL the installer builds must be one of
# these, or it downloads a 404 page.
RELEASE_ASSETS_8_30_1 = frozenset(
    {
        "gitleaks_8.30.1_darwin_arm64.tar.gz",
        "gitleaks_8.30.1_darwin_x64.tar.gz",
        "gitleaks_8.30.1_linux_arm64.tar.gz",
        "gitleaks_8.30.1_linux_armv6.tar.gz",
        "gitleaks_8.30.1_linux_armv7.tar.gz",
        "gitleaks_8.30.1_linux_x32.tar.gz",
        "gitleaks_8.30.1_linux_x64.tar.gz",
        "gitleaks_8.30.1_windows_arm64.zip",
        "gitleaks_8.30.1_windows_x32.zip",
        "gitleaks_8.30.1_windows_x64.zip",
    }
)


class TestInstallUrl:
    """Through `ToolInstaller._install_binary`, the path `jmo tools install`
    takes, stopped at the download so nothing is fetched."""

    @pytest.mark.parametrize(
        ("platform_key", "machine", "asset"),
        [
            ("linux", "x86_64", "gitleaks_8.30.1_linux_x64.tar.gz"),
            ("linux", "aarch64", "gitleaks_8.30.1_linux_arm64.tar.gz"),
            ("macos", "x86_64", "gitleaks_8.30.1_darwin_x64.tar.gz"),
            ("macos", "arm64", "gitleaks_8.30.1_darwin_arm64.tar.gz"),
            ("windows", "AMD64", "gitleaks_8.30.1_windows_x64.zip"),
            ("windows", "ARM64", "gitleaks_8.30.1_windows_arm64.zip"),
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
            name="gitleaks",
            version="8.30.1",
            description="",
            category="binary_tools",
        )
        with (
            patch("platform.machine", return_value=machine),
            patch.object(installer, "_get_download_command", side_effect=capture),
        ):
            installer._install_binary("gitleaks", info, time.time())

        assert urls == [
            "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/" + asset
        ]
        assert asset in RELEASE_ASSETS_8_30_1


class TestConfig:
    def test_it_renders_the_one_exclusion_list(self, tmp_path) -> None:
        path = write_gitleaks_config(tmp_path, results_dir_name="results")

        config = tomllib.loads(path.read_text(encoding="utf-8"))
        # gitleaks' own rules still apply; the file only adds exclusions.
        assert config["extend"] == {"useDefault": True}
        (allowlist,) = config["allowlists"]
        # trufflehog's list: JMo's own state directory too, which holds
        # history.db and so every finding a previous scan stored.
        assert allowlist["paths"] == [
            segment_regex(name)
            for name in dict.fromkeys((".git", ".jmo", *VENDORED_DIRS, "results"))
        ]

    def test_it_is_scratch_beside_the_outputs_and_absolute(
        self, tmp_path, monkeypatch
    ) -> None:
        """Dot-prefixed: the out_dir holds tool outputs and dot-prefixed
        scratch, and an undotted file reads as a tool that ran. Absolute:
        gitleaks runs from the repository, so a relative path resolves there."""
        monkeypatch.chdir(tmp_path)
        Path("out").mkdir()  # run_tools' out_dir always exists
        path = write_gitleaks_config(Path("out"))

        assert path.name == ".gitleaks.toml"
        assert path.is_absolute()
        assert path == (tmp_path / "out" / ".gitleaks.toml").resolve()

    def test_a_quote_in_the_results_name_does_not_break_the_file(
        self, tmp_path
    ) -> None:
        path = write_gitleaks_config(tmp_path, results_dir_name="it's '''odd\"")

        (allowlist,) = tomllib.loads(path.read_text(encoding="utf-8"))["allowlists"]
        assert allowlist["paths"][-1] == segment_regex("it's '''odd\"")

    def test_it_is_written_with_lf_endings(self, tmp_path) -> None:
        assert b"\r\n" not in write_gitleaks_config(tmp_path).read_bytes()


def test_the_descriptor_declares_the_config_style() -> None:
    d = DESCRIPTORS["gitleaks"]
    assert (d.exclusion_style, d.exclusion_flag) == (
        ExclusionStyle.CONFIG_FILE,
        "--config",
    )
    assert d.excluded_vendored == VENDORED_DIRS


def _recorded_definitions(repo: Path, out: Path, results_name: str | None = None):
    captured: list = []

    class Recorder:
        def __init__(self, tools, progress_callback=None):
            captured.extend(tools)

        def run_all_parallel(self):
            return []

    tool_loop.run_tools(
        tools=["gitleaks"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=Recorder,
        find_tool_func=lambda name: "/bin/gitleaks" if name == "gitleaks" else None,
        repo_root=repo,
        results_name=results_name,
    )
    return captured


def test_it_scans_the_repository_from_inside_it(tmp_path, monkeypatch) -> None:
    """A relative out_dir, so every path the command carries must survive the
    change of working directory."""
    monkeypatch.chdir(tmp_path)
    repo = Path("repo")
    repo.mkdir()
    (repo / "a.py").write_bytes(b"x = 1\n")
    out = Path("results") / "individual-repos" / "repo"
    out.mkdir(parents=True)

    (definition,) = _recorded_definitions(repo, out, results_name="results")

    report = (tmp_path / out / "gitleaks.json").resolve()
    config = (tmp_path / out / ".gitleaks.toml").resolve()
    assert definition.command == [
        "/bin/gitleaks",
        "dir",
        ".",
        "--report-format",
        "sarif",
        "--report-path",
        str(report),
        "--no-banner",
        "--exit-code",
        "0",
        "--config",
        str(config),
    ]
    assert definition.cwd == (tmp_path / "repo").resolve()
    assert definition.output_file == out / "gitleaks.json"
    assert definition.capture_stdout is False
    # `--exit-code 0`: a leak is not an error. Anything else is.
    assert definition.ok_return_codes == (0,)
    # The results directory sits inside nothing here, but was named, so the
    # config carries it.
    paths = tomllib.loads(config.read_text(encoding="utf-8"))["allowlists"][0]["paths"]
    assert segment_regex("results") in paths


# --- the real binary ------------------------------------------------------------


def _rsa_pem() -> bytes:
    """A key generated now, never a checked-in one: Defender and the
    repository's own secret scanning both act on a committed key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


@pytest.mark.requires_tools
def test_real_gitleaks_skips_every_excluded_directory_at_any_depth(tmp_path) -> None:
    """Measured against the binary, not the config text: an allowlist regex
    that never matches reads exactly like one that does, until a secret in
    `node_modules` is reported. The repository sits under a `vendor`
    directory of its own, the root-anchoring trap trufflehog fell into (B5)."""
    from scripts.core.tool_runner import ToolRunner

    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks is not on PATH")
    repo = tmp_path / "vendor" / "app"
    planted = {
        "kept.pem": True,
        "node_modules/pkg/k.pem": False,
        "src/vendor/k.pem": False,
        ".venv/lib/k.pem": False,
        "a/b/venv/k.pem": False,
        ".jmo/k.pem": False,
        "results/k.pem": False,
        "src/vendored/k.pem": True,  # a name that only starts like one
    }
    for rel in planted:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(_rsa_pem())
    out = tmp_path / "out"
    out.mkdir()

    rows = tool_loop.run_tools(
        tools=["gitleaks"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=120,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
        results_name="results",
    )

    assert rows["gitleaks"].state.value == "ran", rows["gitleaks"]
    sarif = json.loads((out / "gitleaks.json").read_bytes())
    found = sorted(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif["runs"][0]["results"]
    )
    assert found == sorted(rel for rel, kept in planted.items() if kept)


@pytest.mark.requires_tools
def test_real_gitleaks_exits_nonzero_on_a_broken_config(tmp_path) -> None:
    """Why `ok_return_codes` is `(0,)`: with `--exit-code 0` a leak is 0, and a
    run that could not scan is not (measured before relying on it)."""
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks is not on PATH")
    (tmp_path / "bad.toml").write_bytes(b"[[allowlists]\n")
    result = subprocess.run(
        [
            "gitleaks",
            "dir",
            ".",
            "--report-format",
            "sarif",
            "--report-path",
            str(tmp_path / "r.json"),
            "--no-banner",
            "--exit-code",
            "0",
            "--config",
            str(tmp_path / "bad.toml"),
        ],
        cwd=tmp_path,
        capture_output=True,
        timeout=60,
        env={**os.environ},
    )
    assert result.returncode != 0
