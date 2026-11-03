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
import json
import sys
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.cli.installers.models import InstallResult
from scripts.cli.tool_installer import ToolInstaller

DRL = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
CC_BY_NC = "https://creativecommons.org/licenses/by-nc/4.0/"
ENGINE = InstallResult(
    tool_name="yara", success=True, method="pip", version_installed="4.5.4"
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
    rules_dir = tmp_path / "home" / ".jmo" / "yara-rules"
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
        patch("scripts.cli.tool_installer.get_yara_rules_dir", return_value=rules_dir),
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
