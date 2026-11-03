"""The rule-bundle fetch behind `jmo tools install` (v2.0.0 Phase 6, PR Y,
Task Y1).

The bundle is pinned by commit *and* by the tarball's sha256, checked before
anything is extracted; what lands is only what `scripts.core.yara_rules`
lets through, with a manifest of what it dropped and why; and a bundle the
filter refuses leaves the rules already installed where they were.

The download is a real subprocess that copies a local tarball, so nothing
here touches the network.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.installers.models import InstallResult
from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolStatus
from scripts.core.install_config import YARA_RULES_BUNDLE

DRL = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
CC_BY_NC = "https://creativecommons.org/licenses/by-nc/4.0/"
ENGINE = InstallResult(
    tool_name="yara-x", success=True, method="dependency", version_installed="1.22.1"
)


def _rule(name: str, license: str | None = None) -> str:
    meta = f'        license = "{license}"\n' if license else ""
    return f'rule {name} {{\n    meta:\n{meta}        author = "a"\n    condition:\n        true\n}}\n'


def _bundle(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    root = tmp_path / "src" / "signature-base-abc"
    (root / "yara").mkdir(parents=True)
    (root / "LICENSE").write_bytes(b"# Detection Rule License (DRL) 1.1\n")
    for name, text in files.items():
        (root / "yara" / name).write_bytes(text.encode("utf-8"))
    tarball = tmp_path / "bundle.tar.gz"
    with tarfile.open(tarball, "w:gz") as tar:
        tar.add(root, arcname=root.name)
    return tarball, hashlib.sha256(tarball.read_bytes()).hexdigest()


def _install(
    tmp_path: Path, tarball: Path, sha256: str, reviewed: dict | None = None
) -> tuple[InstallResult, Path]:
    # The home, not the destination function, is redirected: where the fetch
    # writes is part of what these tests check (Task Y4).
    home = tmp_path / "home"
    rules_dir = home / ".jmo" / "yara-rules"
    installer = ToolInstaller(manager=MagicMock())
    bundle = {
        "repo": "Neo23x0/signature-base",
        "ref": "abc",
        "url": "https://example.invalid/bundle.tar.gz",
        "sha256": sha256,
        "subdir": "yara",
        "license": "DRL 1.1",
    }

    def copy(url: str, out: Path) -> list[str]:
        script = "import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])"
        return [sys.executable, "-c", script, str(tarball), str(out)]

    with (
        patch.dict("scripts.cli.tool_installer.YARA_RULES_BUNDLE", bundle, clear=True),
        patch("scripts.cli.tool_installer.YARA_RULES_REVIEWED", reviewed or {}),
        patch.object(Path, "home", staticmethod(lambda: home)),
        patch.object(installer, "_get_download_command", side_effect=copy),
    ):
        return installer._install_yara_rules(ENGINE), rules_dir


def test_a_bundle_whose_sha256_differs_is_refused(tmp_path: Path) -> None:
    tarball, _ = _bundle(tmp_path, {"a.yar": _rule("Mine", DRL)})

    result, rules_dir = _install(tmp_path, tarball, "0" * 64)

    assert not result.success
    assert "sha256" in result.message
    assert not rules_dir.exists()


def test_only_redistributable_rules_land_with_a_manifest(tmp_path: Path) -> None:
    tarball, sha256 = _bundle(
        tmp_path, {"a.yar": _rule("Mine", DRL) + _rule("NonCommercial", CC_BY_NC)}
    )

    result, rules_dir = _install(tmp_path, tarball, sha256)

    assert result.success, result.message
    text = (rules_dir / "a.yar").read_bytes().decode("utf-8")
    assert "rule Mine" in text
    assert "NonCommercial" not in text
    assert (rules_dir / "LICENSE").is_file()
    manifest = json.loads((rules_dir / "manifest.json").read_bytes())
    assert manifest["ref"] == "abc"
    assert manifest["sha256"] == sha256
    assert manifest["kept_rules"] == 1
    assert manifest["dropped"] == [
        {"file": "a.yar", "rule": "NonCommercial", "reason": CC_BY_NC}
    ]


def test_an_unreviewed_rule_file_fails_and_keeps_the_installed_rules(
    tmp_path: Path,
) -> None:
    tarball, sha256 = _bundle(
        tmp_path, {"gpl.yar": "/*\n License: GPL\n*/\n" + _rule("Mine", DRL)}
    )
    installed = tmp_path / "home" / ".jmo" / "yara-rules"
    installed.mkdir(parents=True)
    (installed / "old.yar").write_bytes(_rule("Old").encode("utf-8"))

    result, rules_dir = _install(tmp_path, tarball, sha256)

    assert not result.success
    assert "gpl.yar" in result.message
    assert (rules_dir / "old.yar").is_file()


# Task Y2: the engine is a dependency of JMo, so `install` provides the rules.


def _routed(tmp_path: Path, *, pinned: bool, force: bool = False) -> tuple:
    installer = ToolInstaller(manager=MagicMock())
    # Never "already installed" by the manager: only the pinned rules may skip.
    installer.manager.check_tool.return_value = ToolStatus(
        name="yara-x", installed=False
    )
    fetched = InstallResult(tool_name="yara-x", success=True, method="dependency")
    with (
        patch("scripts.cli.tool_installer.pinned_rules_installed", return_value=pinned),
        patch.object(installer, "_install_yara_rules", return_value=fetched) as fetch,
    ):
        result = installer.install_tool("yara-x", force=force)
    return result, fetch


def test_yara_x_installs_its_rules_with_no_versions_yaml_row(tmp_path: Path) -> None:
    result, fetch = _routed(tmp_path, pinned=False)

    assert result.success, result.message
    fetch.assert_called_once()
    engine = fetch.call_args.args[0]
    assert engine.method == "dependency"
    assert engine.version_installed == importlib.metadata.version("yara-x")


def test_a_second_install_at_the_pin_fetches_nothing(tmp_path: Path) -> None:
    result, fetch = _routed(tmp_path, pinned=True)

    assert result.success
    assert result.method == "existing"
    fetch.assert_not_called()


def test_force_fetches_the_rules_again(tmp_path: Path) -> None:
    _, fetch = _routed(tmp_path, pinned=True, force=True)

    fetch.assert_called_once()


# Task Y4: the image carries pinned rules outside ~/.jmo (#1282), so in a
# container what a scan reads and where an install writes are two paths.


def _pinned(where: Path, ref: str) -> Path:
    where.mkdir(parents=True)
    (where / "a.yar").write_bytes(_rule("Image").encode("utf-8"))
    (where / "manifest.json").write_bytes(json.dumps({"ref": ref}).encode())
    return where


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }


def test_an_unforced_install_takes_the_images_rules_as_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The wizard and `jmo scan`'s offer to install missing tools call
    # install_tool without force; in the image a scan already reads the
    # pinned rules, so there is nothing to fetch.
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    image = _pinned(tmp_path / "opt" / "yara-rules", YARA_RULES_BUNDLE["ref"])
    monkeypatch.setattr("scripts.core.paths.IMAGE_YARA_RULES_DIR", image)
    installer = ToolInstaller(manager=MagicMock())

    with patch.object(
        installer,
        "_get_download_command",
        side_effect=AssertionError("fetched rules the image already carries"),
    ):
        result = installer.install_tool("yara-x")

    assert result.success, result.message
    assert result.method == "existing"
    assert not home.exists()


def test_a_forced_install_writes_under_home_and_leaves_the_images_rules_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fallback a scan reads is not where an install writes. The image's
    # tree is root's (the container user cannot replace it) and would not
    # outlive a `--rm` container; the user's own install lands under ~/.jmo,
    # the persistence mount, which is also the path that wins on read.
    image = _pinned(tmp_path / "opt" / "yara-rules", "the-images-pin")
    monkeypatch.setattr("scripts.core.paths.IMAGE_YARA_RULES_DIR", image)
    before = _tree(image)
    tarball, sha256 = _bundle(tmp_path, {"a.yar": _rule("Mine", DRL)})

    result, rules_dir = _install(tmp_path, tarball, sha256)

    assert result.success, result.message
    assert json.loads((rules_dir / "manifest.json").read_bytes())["ref"] == "abc"
    assert _tree(image) == before
