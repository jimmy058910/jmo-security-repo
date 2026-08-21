#!/usr/bin/env python3
"""Tests for scripts/cli/build_commands.py module.

This test suite validates Docker build functionality:
1. Architecture detection
2. Docker availability checking
3. Repository root finding
4. Version validation
5. Image building
6. CLI argument handling

Target Coverage: >= 85%
"""

import argparse
import platform
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.cli.build_commands import VARIANTS

# ========== Category 1: Constants ==========


def test_variants_contains_expected_entries():
    """Test VARIANTS contains all expected Docker variants."""
    from scripts.cli.build_commands import VARIANTS

    expected = {"fast", "slim", "balanced", "deep"}
    assert set(VARIANTS.keys()) == expected


def test_variants_has_correct_dockerfiles():
    """Test VARIANTS maps to correct Dockerfile names."""
    from scripts.cli.build_commands import VARIANTS

    assert VARIANTS["fast"] == "Dockerfile.fast"
    assert VARIANTS["slim"] == "Dockerfile.slim"
    assert VARIANTS["balanced"] == "Dockerfile.balanced"
    assert VARIANTS["deep"] == "Dockerfile.deep"


def test_default_registry():
    """Test DEFAULT_REGISTRY has expected value."""
    from scripts.cli.build_commands import DEFAULT_REGISTRY

    assert DEFAULT_REGISTRY == "ghcr.io"


def test_default_org_matches_what_release_publishes():
    """The push target must be the namespace release.yml actually pushes to.

    This asserted `DEFAULT_ORG == "jmosecurity"`, restating the constant it was
    testing. The value was wrong -- `release.yml` publishes to
    `${{ github.repository_owner }}/jmo-security`, i.e. `jimmy058910` -- so
    `jmo build --push` aimed at a namespace this project does not own and
    `jmo build test` pulled from it. A test that repeats the constant cannot
    notice that; this one reads the workflow.
    """
    from scripts.cli.build_commands import DEFAULT_ORG

    workflow = (
        Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"
    ).read_text(encoding="utf-8")

    match = re.search(r"IMAGE_NAME_GHCR:.*?#\s*GitHub:\s*(\S+)/", workflow)
    assert match, "release.yml no longer records the GHCR owner in a comment"
    assert match.group(1) == DEFAULT_ORG


def test_default_image():
    """Test DEFAULT_IMAGE has expected value."""
    from scripts.cli.build_commands import DEFAULT_IMAGE

    assert DEFAULT_IMAGE == "jmo-security"


# ========== Category 2: Architecture Detection ==========


def test_detect_arch_x86_64():
    """Test _detect_arch returns amd64 for x86_64."""
    from scripts.cli.build_commands import _detect_arch

    with patch.object(platform, "machine", return_value="x86_64"):
        assert _detect_arch() == "amd64"


def test_detect_arch_amd64():
    """Test _detect_arch returns amd64 for amd64."""
    from scripts.cli.build_commands import _detect_arch

    with patch.object(platform, "machine", return_value="amd64"):
        assert _detect_arch() == "amd64"


def test_detect_arch_aarch64():
    """Test _detect_arch returns arm64 for aarch64."""
    from scripts.cli.build_commands import _detect_arch

    with patch.object(platform, "machine", return_value="aarch64"):
        assert _detect_arch() == "arm64"


def test_detect_arch_arm64():
    """Test _detect_arch returns arm64 for arm64."""
    from scripts.cli.build_commands import _detect_arch

    with patch.object(platform, "machine", return_value="arm64"):
        assert _detect_arch() == "arm64"


def test_detect_arch_unknown_defaults_to_amd64():
    """Test _detect_arch defaults to amd64 for unknown architectures."""
    from scripts.cli.build_commands import _detect_arch

    with patch.object(platform, "machine", return_value="unknown_arch"):
        assert _detect_arch() == "amd64"


# ========== Category 3: Docker Availability Checking ==========


def test_check_docker_not_in_path():
    """Test _check_docker returns False when Docker not in PATH."""
    from scripts.cli.build_commands import _check_docker

    with patch("shutil.which", return_value=None):
        assert _check_docker() is False


def test_check_docker_daemon_not_running():
    """Test _check_docker returns False when daemon not running."""
    from scripts.cli.build_commands import _check_docker

    mock_result = MagicMock()
    mock_result.returncode = 1

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", return_value=mock_result):
            assert _check_docker() is False


def test_check_docker_timeout():
    """Test _check_docker returns False on timeout."""
    from scripts.cli.build_commands import _check_docker

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker info", timeout=10),
        ),
    ):
        assert _check_docker() is False


def test_check_docker_exception():
    """Test _check_docker returns False on general exception."""
    from scripts.cli.build_commands import _check_docker

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", side_effect=Exception("Unexpected error")):
            assert _check_docker() is False


def test_check_docker_success():
    """Test _check_docker returns True when Docker is available."""
    from scripts.cli.build_commands import _check_docker

    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", return_value=mock_result):
            assert _check_docker() is True


# ========== Category 4: Repository Root Finding ==========


def _make_repo(root: Path) -> Path:
    """Build the marker set a real checkout has: versions.yaml + variant files.

    These tests used to `touch` a bare file named `Dockerfile`, which is the
    filesystem `_find_repo_root` expected and **not** the one the repo ships:
    #303 renamed it to `Dockerfile.deep` on 2026-04-19. The tests fabricated
    the missing file, passed, and the command was broken for seven releases --
    while `test_variants_mapping` in this same file asserted the real name.
    """
    (root / "versions.yaml").touch()
    for dockerfile in VARIANTS.values():
        (root / dockerfile).touch()
    return root


def test_find_repo_root_in_current_dir(tmp_path):
    """Test _find_repo_root finds repo when in root directory."""
    from scripts.cli.build_commands import _find_repo_root

    _make_repo(tmp_path)

    with patch.object(Path, "cwd", return_value=tmp_path):
        result = _find_repo_root()
        assert result == tmp_path


def test_find_repo_root_in_subdirectory(tmp_path):
    """Test _find_repo_root finds repo when in subdirectory."""
    from scripts.cli.build_commands import _find_repo_root

    _make_repo(tmp_path)

    # Create subdirectory
    subdir = tmp_path / "scripts" / "cli"
    subdir.mkdir(parents=True)

    with patch.object(Path, "cwd", return_value=subdir):
        result = _find_repo_root()
        assert result == tmp_path


def test_find_repo_root_not_found(tmp_path):
    """Test _find_repo_root returns None when not in a repo."""
    from scripts.cli.build_commands import _find_repo_root

    # Empty directory, no Dockerfile or versions.yaml
    with patch.object(Path, "cwd", return_value=tmp_path):
        result = _find_repo_root()
        assert result is None


def test_find_repo_root_missing_versions_yaml(tmp_path):
    """Test _find_repo_root returns None when versions.yaml missing."""
    from scripts.cli.build_commands import _find_repo_root

    for dockerfile in VARIANTS.values():
        (tmp_path / dockerfile).touch()

    with patch.object(Path, "cwd", return_value=tmp_path):
        result = _find_repo_root()
        assert result is None


def test_find_repo_root_finds_the_real_checkout():
    """The repository this test runs from must be findable.

    The regression guard for #303. Every test above builds its own fixture, so
    all four passed against a predicate that could not be satisfied anywhere in
    the actual tree. This one has no fixture to get wrong: it asserts that the
    real repo, with the real filenames, is what `_find_repo_root` locates.
    """
    from scripts.cli.build_commands import _find_repo_root

    repo = Path(__file__).resolve().parents[2]
    assert (repo / "versions.yaml").is_file(), "test is not running from a checkout"

    with patch.object(Path, "cwd", return_value=repo):
        assert _find_repo_root() == repo


def test_no_bare_dockerfile_exists_in_the_repo():
    """Pin the fact that made #303 invisible: there is no bare `Dockerfile`.

    If one is ever reintroduced, `_find_repo_root` keeps working either way --
    but the fixtures above would silently start describing reality again, and
    the reason this guard exists would be lost.
    """
    repo = Path(__file__).resolve().parents[2]
    assert not (repo / "Dockerfile").exists()
    for dockerfile in VARIANTS.values():
        assert (repo / dockerfile).is_file(), f"missing {dockerfile}"


# ========== Category 5: Version Validation ==========


def test_validate_versions_script_not_found(tmp_path):
    """Test _validate_versions returns True when script not found."""
    from scripts.cli.build_commands import _validate_versions

    # No validation script
    result = _validate_versions(tmp_path)
    assert result is True


def test_validate_versions_success(tmp_path):
    """Test _validate_versions returns True on successful validation."""
    from scripts.cli.build_commands import _validate_versions

    # Create validation script
    script_dir = tmp_path / "scripts" / "dev"
    script_dir.mkdir(parents=True)
    (script_dir / "update_versions.py").touch()

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "All versions valid"
    mock_result.stderr = ""

    with patch("subprocess.run", return_value=mock_result):
        result = _validate_versions(tmp_path)
        assert result is True


def test_validate_versions_failure(tmp_path):
    """Test _validate_versions returns False on validation failure."""
    from scripts.cli.build_commands import _validate_versions

    # Create validation script
    script_dir = tmp_path / "scripts" / "dev"
    script_dir.mkdir(parents=True)
    (script_dir / "update_versions.py").touch()

    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "Version mismatch"

    with patch("subprocess.run", return_value=mock_result):
        result = _validate_versions(tmp_path)
        assert result is False


def test_validate_versions_timeout(tmp_path):
    """Test _validate_versions returns True on timeout (proceeds anyway)."""
    from scripts.cli.build_commands import _validate_versions

    # Create validation script
    script_dir = tmp_path / "scripts" / "dev"
    script_dir.mkdir(parents=True)
    (script_dir / "update_versions.py").touch()

    with patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="test", timeout=120)
    ):
        result = _validate_versions(tmp_path)
        assert result is True


def test_validate_versions_exception(tmp_path):
    """Test _validate_versions returns True on exception (proceeds anyway)."""
    from scripts.cli.build_commands import _validate_versions

    # Create validation script
    script_dir = tmp_path / "scripts" / "dev"
    script_dir.mkdir(parents=True)
    (script_dir / "update_versions.py").touch()

    with patch("subprocess.run", side_effect=Exception("Error")):
        result = _validate_versions(tmp_path)
        assert result is True


# ========== Category 6: Image Building ==========


def test_build_image_unknown_variant(tmp_path):
    """Test _build_image returns 1 for unknown variant."""
    from scripts.cli.build_commands import _build_image

    result = _build_image(
        variant="nonexistent",
        tag="v1.0.0",
        repo_root=tmp_path,
        registry="ghcr.io",
        org="test",
        image_name="test-image",
    )
    assert result == 1


def test_build_image_dockerfile_not_found(tmp_path):
    """Test _build_image returns 1 when Dockerfile doesn't exist."""
    from scripts.cli.build_commands import _build_image

    result = _build_image(
        variant="balanced",
        tag="v1.0.0",
        repo_root=tmp_path,
        registry="ghcr.io",
        org="test",
        image_name="test-image",
    )
    assert result == 1


def test_build_image_local_tag(tmp_path):
    """Test _build_image uses local tag format."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.balanced").touch()

    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        _build_image(
            variant="balanced",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="test",
            image_name="jmo-security",
            local=True,
        )

        # Verify local tag format was used
        call_args = mock_run.call_args_list[0]
        cmd = call_args[0][0]
        assert "jmo-security:local-balanced" in cmd


def test_build_image_remote_tag(tmp_path):
    """Test _build_image uses remote tag format."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.balanced").touch()

    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        _build_image(
            variant="balanced",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="jmosecurity",
            image_name="jmo-security",
            local=False,
        )

        # Verify remote tag format was used
        call_args = mock_run.call_args_list[0]
        cmd = call_args[0][0]
        assert "ghcr.io/jmosecurity/jmo-security:v1.0.0-balanced" in cmd


def test_build_image_no_cache(tmp_path):
    """Test _build_image adds --no-cache when requested."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.fast").touch()

    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        _build_image(
            variant="fast",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="test",
            image_name="jmo-security",
            no_cache=True,
        )

        # Verify --no-cache was added
        call_args = mock_run.call_args_list[0]
        cmd = call_args[0][0]
        assert "--no-cache" in cmd


def test_build_image_failure(tmp_path):
    """Test _build_image returns failure code on build error."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.fast").touch()

    mock_result = MagicMock()
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        result = _build_image(
            variant="fast",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="test",
            image_name="jmo-security",
        )
        assert result == 1


def test_build_image_exception(tmp_path):
    """Test _build_image returns 1 on exception."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.fast").touch()

    with patch("subprocess.run", side_effect=Exception("Docker error")):
        result = _build_image(
            variant="fast",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="test",
            image_name="jmo-security",
        )
        assert result == 1


def test_build_image_platform_override(tmp_path):
    """Test _build_image uses platform override when provided."""
    from scripts.cli.build_commands import _build_image

    # Create Dockerfile
    (tmp_path / "Dockerfile.fast").touch()

    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        _build_image(
            variant="fast",
            tag="v1.0.0",
            repo_root=tmp_path,
            registry="ghcr.io",
            org="test",
            image_name="jmo-security",
            platform_target="arm64",
        )

        # Verify architecture was set
        call_args = mock_run.call_args_list[0]
        cmd = call_args[0][0]
        assert "TARGETARCH=arm64" in " ".join(cmd)


# ========== Category 7: cmd_build Function ==========


def test_cmd_build_docker_unavailable():
    """Test cmd_build returns 1 when Docker is unavailable."""
    from scripts.cli.build_commands import cmd_build

    args = argparse.Namespace()

    with patch("scripts.cli.build_commands._check_docker", return_value=False):
        result = cmd_build(args)
        assert result == 1


def test_cmd_build_repo_not_found():
    """Test cmd_build returns 1 when repo root not found."""
    from scripts.cli.build_commands import cmd_build

    args = argparse.Namespace()

    with patch("scripts.cli.build_commands._check_docker", return_value=True):
        with patch("scripts.cli.build_commands._find_repo_root", return_value=None):
            result = cmd_build(args)
            assert result == 1


def test_cmd_build_validate_subcommand(tmp_path):
    """Test cmd_build handles validate subcommand."""
    from scripts.cli.build_commands import cmd_build

    args = argparse.Namespace(build_command="validate")

    with patch("scripts.cli.build_commands._check_docker", return_value=True):
        with patch("scripts.cli.build_commands._find_repo_root", return_value=tmp_path):
            with patch(
                "scripts.cli.build_commands._validate_versions", return_value=True
            ):
                result = cmd_build(args)
                assert result == 0


def test_cmd_build_validation_failure(tmp_path):
    """Test cmd_build returns 1 when validation fails."""
    from scripts.cli.build_commands import cmd_build

    args = argparse.Namespace(
        build_command=None,
        skip_validate=False,
        all=False,
        variant="balanced",
        tag="latest",
        registry="ghcr.io",
        org="test",
        local=False,
        no_cache=False,
        push=False,
        platform=None,
    )

    with patch("scripts.cli.build_commands._check_docker", return_value=True):
        with patch("scripts.cli.build_commands._find_repo_root", return_value=tmp_path):
            with patch(
                "scripts.cli.build_commands._validate_versions", return_value=False
            ):
                result = cmd_build(args)
                assert result == 1


# ========== Category 8: add_build_args Function ==========


def test_add_build_args_creates_parser():
    """Test add_build_args creates a proper subparser."""
    from scripts.cli.build_commands import add_build_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    build_parser = add_build_args(subparsers)

    assert build_parser is not None
    assert isinstance(build_parser, argparse.ArgumentParser)


def test_add_build_args_has_variant_choices():
    """Test add_build_args includes variant choices."""
    from scripts.cli.build_commands import add_build_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    add_build_args(subparsers)

    # Parse a valid variant
    args = parser.parse_args(["build", "--variant", "deep"])
    assert args.variant == "deep"


def test_add_build_args_has_all_flag():
    """Test add_build_args includes --all flag."""
    from scripts.cli.build_commands import add_build_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    add_build_args(subparsers)

    args = parser.parse_args(["build", "--all"])
    assert args.all is True


def test_add_build_args_has_local_flag():
    """Test add_build_args includes --local flag."""
    from scripts.cli.build_commands import add_build_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    add_build_args(subparsers)

    args = parser.parse_args(["build", "--local"])
    assert args.local is True


def test_add_build_args_default_values():
    """Test add_build_args has correct default values."""
    from scripts.cli.build_commands import DEFAULT_ORG, DEFAULT_REGISTRY, add_build_args

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    add_build_args(subparsers)

    args = parser.parse_args(["build"])
    assert args.variant == "balanced"
    assert args.registry == DEFAULT_REGISTRY
    assert args.org == DEFAULT_ORG
    assert args.local is False
    assert args.push is False


# ========== Category 8: Image references and flag precedence (chunk 18) ==========


def test_image_ref_uses_the_published_bare_variant_tags():
    """`latest` maps to the bare variant tag, which is what release.yml pushes.

    Both the build path and the `test` path used `<tag>-<variant>`
    unconditionally, so the default run named `:latest-balanced` -- a tag
    family the project never publishes. `release.yml` pushes bare `:fast` /
    `:slim` / `:balanced` / `:deep` (with `:latest` pointing at deep) and
    versioned `:1.0.2-<variant>`.
    """
    from scripts.cli.build_commands import (
        DEFAULT_IMAGE,
        DEFAULT_ORG,
        DEFAULT_REGISTRY,
        _image_ref,
    )

    ref = _image_ref(
        "balanced", "latest", DEFAULT_REGISTRY, DEFAULT_ORG, DEFAULT_IMAGE, False
    )
    assert ref == f"{DEFAULT_REGISTRY}/{DEFAULT_ORG}/{DEFAULT_IMAGE}:balanced"
    assert "latest-balanced" not in ref


def test_image_ref_versioned_tag_keeps_the_variant_suffix():
    from scripts.cli.build_commands import (
        DEFAULT_IMAGE,
        DEFAULT_ORG,
        DEFAULT_REGISTRY,
        _image_ref,
    )

    ref = _image_ref(
        "deep", "1.0.9", DEFAULT_REGISTRY, DEFAULT_ORG, DEFAULT_IMAGE, False
    )
    assert ref.endswith(":1.0.9-deep")


def test_image_ref_local():
    from scripts.cli.build_commands import (
        DEFAULT_IMAGE,
        DEFAULT_ORG,
        DEFAULT_REGISTRY,
        _image_ref,
    )

    ref = _image_ref(
        "slim", "latest", DEFAULT_REGISTRY, DEFAULT_ORG, DEFAULT_IMAGE, True
    )
    assert ref == f"{DEFAULT_IMAGE}:local-slim"


def test_test_subparser_does_not_clobber_parent_flags():
    """`jmo build --variant deep test` silently tested `balanced`.

    argparse applies a subparser's defaults *after* the parent has parsed, so a
    subparser re-declaring a flag overwrites the value the user gave the
    parent. rc 0, no warning, the wrong image. `default=argparse.SUPPRESS`
    leaves the attribute alone when the flag is absent.
    """
    import sys as _sys

    from scripts.cli.jmo import parse_args

    saved = _sys.argv
    try:
        _sys.argv = ["jmo", "build", "--variant", "deep", "test"]
        args = parse_args()
        assert args.build_command == "test"
        assert args.variant == "deep"

        _sys.argv = ["jmo", "build", "--local", "test"]
        args = parse_args()
        assert args.local is True

        _sys.argv = ["jmo", "build", "--tag", "1.0.9", "test"]
        assert parse_args().tag == "1.0.9"
    finally:
        _sys.argv = saved


def test_explicit_subparser_flag_still_wins():
    """The fix must not make `jmo build test --variant deep` a no-op."""
    import sys as _sys

    from scripts.cli.jmo import parse_args

    saved = _sys.argv
    try:
        _sys.argv = ["jmo", "build", "test", "--variant", "deep"]
        assert parse_args().variant == "deep"
        _sys.argv = ["jmo", "build", "test"]
        assert parse_args().variant == "balanced"
    finally:
        _sys.argv = saved
