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
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    assert VARIANTS["deep"] == "Dockerfile"  # Base Dockerfile


def test_default_registry():
    """Test DEFAULT_REGISTRY has expected value."""
    from scripts.cli.build_commands import DEFAULT_REGISTRY

    assert DEFAULT_REGISTRY == "ghcr.io"


def test_default_org():
    """Test DEFAULT_ORG has expected value."""
    from scripts.cli.build_commands import DEFAULT_ORG

    assert DEFAULT_ORG == "jmosecurity"


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

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker info", timeout=10),
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


def test_find_repo_root_in_current_dir(tmp_path):
    """Test _find_repo_root finds repo when in root directory."""
    from scripts.cli.build_commands import _find_repo_root

    # Create required files
    (tmp_path / "Dockerfile").touch()
    (tmp_path / "versions.yaml").touch()

    with patch.object(Path, "cwd", return_value=tmp_path):
        result = _find_repo_root()
        assert result == tmp_path


def test_find_repo_root_in_subdirectory(tmp_path):
    """Test _find_repo_root finds repo when in subdirectory."""
    from scripts.cli.build_commands import _find_repo_root

    # Create required files in root
    (tmp_path / "Dockerfile").touch()
    (tmp_path / "versions.yaml").touch()

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

    # Only Dockerfile, no versions.yaml
    (tmp_path / "Dockerfile").touch()

    with patch.object(Path, "cwd", return_value=tmp_path):
        result = _find_repo_root()
        assert result is None


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
    from scripts.cli.build_commands import add_build_args, DEFAULT_REGISTRY, DEFAULT_ORG

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    add_build_args(subparsers)

    args = parser.parse_args(["build"])
    assert args.variant == "balanced"
    assert args.registry == DEFAULT_REGISTRY
    assert args.org == DEFAULT_ORG
    assert args.local is False
    assert args.push is False
