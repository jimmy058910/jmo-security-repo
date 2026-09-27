"""Unit tests for wizard command building utilities.

Tests cover:
- Repository arguments (repo, repos-dir, targets, tsv modes)
- Container image arguments (single, batch)
- IaC arguments (terraform, cloudformation, k8s-manifest)
- URL arguments (single, batch, api)
- GitLab arguments (repo, group)
- Kubernetes arguments (single namespace, all namespaces)
- Complete command building for native and Docker modes

Architecture Note:
- Uses MagicMock for TargetConfig and WizardConfig objects
- Tests both native and Docker execution modes
- Verifies volume mounting for Docker mode
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scripts.cli.jmo import build_parser
from scripts.cli.wizard_flows.command_builder import (
    build_command_parts,
    build_gitlab_args,
    build_iac_args,
    build_image_args,
    build_k8s_args,
    build_repo_args,
    build_url_args,
)
from scripts.cli.wizard_flows.config_models import WizardConfig
from scripts.cli.wizard_generators import JMO_DOCKER_IMAGE_FULL

# ========== Category 1: Repository Arguments ==========


def test_build_repo_args_repo_mode_native():
    """Test build_repo_args with --repo in native mode."""
    target = MagicMock()
    target.repo_mode = "repo"
    target.repo_path = "/path/to/repo"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--repo", "/path/to/repo"]


def test_build_repo_args_repos_dir_mode_native():
    """Test build_repo_args with --repos-dir in native mode."""
    target = MagicMock()
    target.repo_mode = "repos-dir"
    target.repo_path = "/path/to/repos"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--repos-dir", "/path/to/repos"]


def test_build_repo_args_targets_mode_native():
    """Test build_repo_args with --targets in native mode."""
    target = MagicMock()
    target.repo_mode = "targets"
    target.repo_path = "/path/to/targets.txt"

    args = build_repo_args(target, use_docker=False)

    assert args == ["--targets", "/path/to/targets.txt"]


def test_build_repo_args_tsv_mode_native():
    """The tsv command, parsed by `jmo scan`'s own parser.

    This asserted `"--tsv" in args` for as long as `jmo scan` rejected the
    command outright (#1299). `--dest` is always named: `jmo scan --tsv` has no
    default destination, and the wizard's own default is `repos-tsv`.
    """
    target = WizardConfig().target
    target.type = "repo"
    target.repo_mode = "tsv"
    target.tsv_path = "./repos.tsv"

    parsed = build_parser().parse_args(
        ["scan", *build_repo_args(target, use_docker=False)]
    )

    assert (parsed.tsv, parsed.dest) == ("./repos.tsv", "repos-tsv")


def test_build_repo_args_docker_mode(tmp_path):
    """Test build_repo_args with Docker volume mounting."""
    target = MagicMock()
    target.repo_mode = "repos-dir"
    target.repo_path = str(tmp_path / "repos")

    args = build_repo_args(target, use_docker=True)

    assert "-v" in args
    assert any("/scan" in arg for arg in args)
    assert "--repos-dir" in args


# ========== Category 2: Image Arguments ==========


def test_build_image_args_single_image():
    """Test build_image_args with single image."""
    target = MagicMock()
    target.image_name = "nginx:latest"
    target.images_file = None

    args = build_image_args(target, use_docker=False)

    assert args == ["--image", "nginx:latest"]


def test_build_image_args_batch_native():
    """Test build_image_args with images file in native mode."""
    target = MagicMock()
    target.image_name = None
    target.images_file = "./images.txt"

    args = build_image_args(target, use_docker=False)

    assert args == ["--images-file", "./images.txt"]


def test_build_image_args_batch_docker(tmp_path):
    """Test build_image_args with images file in Docker mode."""
    target = MagicMock()
    target.image_name = None
    target.images_file = str(tmp_path / "images.txt")

    args = build_image_args(target, use_docker=True)

    assert "-v" in args
    assert "--images-file" in args
    assert "/images.txt" in args


# ========== Category 3: IaC Arguments ==========


def test_build_iac_args_terraform_native():
    """Test build_iac_args with Terraform in native mode."""
    target = MagicMock()
    target.iac_type = "terraform"
    target.iac_path = "./infrastructure.tfstate"

    args = build_iac_args(target, use_docker=False)

    assert "--terraform" in args
    assert "./infrastructure.tfstate" in args


def test_build_iac_args_cloudformation_native():
    """Test build_iac_args with CloudFormation in native mode."""
    target = MagicMock()
    target.iac_type = "cloudformation"
    target.iac_path = "./template.yaml"

    args = build_iac_args(target, use_docker=False)

    assert "--cloudformation" in args
    assert "./template.yaml" in args


def test_build_iac_args_k8s_manifest_native():
    """Test build_iac_args with Kubernetes manifest in native mode."""
    target = MagicMock()
    target.iac_type = "k8s-manifest"
    target.iac_path = "./deployment.yaml"

    args = build_iac_args(target, use_docker=False)

    assert "--k8s-manifest" in args
    assert "./deployment.yaml" in args


def test_build_iac_args_docker_mode(tmp_path):
    """Test build_iac_args with Docker volume mounting."""
    target = MagicMock()
    target.iac_type = "terraform"
    target.iac_path = str(tmp_path / "infrastructure.tfstate")

    args = build_iac_args(target, use_docker=True)

    assert "-v" in args
    assert any("/scan/iac-file" in arg for arg in args)
    assert "--terraform" in args


# ========== Category 4: URL Arguments ==========


def test_build_url_args_single_url():
    """Test build_url_args with single URL."""
    target = MagicMock()
    target.url = "https://example.com"
    target.urls_file = None
    target.api_spec = None

    args = build_url_args(target, use_docker=False)

    assert args == ["--url", "https://example.com"]


def test_build_url_args_batch_native():
    """Test build_url_args with URLs file in native mode."""
    target = MagicMock()
    target.url = None
    target.urls_file = "./urls.txt"
    target.api_spec = None

    args = build_url_args(target, use_docker=False)

    assert args == ["--urls-file", "./urls.txt"]


def test_build_url_args_batch_docker(tmp_path):
    """Test build_url_args with URLs file in Docker mode."""
    target = MagicMock()
    target.url = None
    target.urls_file = str(tmp_path / "urls.txt")
    target.api_spec = None

    args = build_url_args(target, use_docker=True)

    assert "-v" in args
    assert "--urls-file" in args
    assert "/urls.txt" in args


def test_build_url_args_api_spec():
    """Test build_url_args with OpenAPI spec."""
    target = MagicMock()
    target.url = None
    target.urls_file = None
    target.api_spec = "./openapi.yaml"

    args = build_url_args(target, use_docker=False)

    assert args == ["--api-spec", "./openapi.yaml"]


# ========== Category 5: GitLab Arguments ==========


def test_build_gitlab_args_repo_mode():
    """Test build_gitlab_args with repository mode."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = "token123"
    target.gitlab_repo = "mygroup/myrepo"
    target.gitlab_group = None

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "https://gitlab.com" in args
    # The token travels as GITLAB_TOKEN in the environment, never in argv
    assert "--gitlab-token" not in args
    assert "token123" not in args
    assert "--gitlab-repo" in args
    assert "mygroup/myrepo" in args


def test_build_gitlab_args_group_mode():
    """Test build_gitlab_args with group mode."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = "token123"
    target.gitlab_repo = None
    target.gitlab_group = "mygroup"

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "--gitlab-token" not in args
    assert "--gitlab-group" in args
    assert "mygroup" in args
    assert "--gitlab-repo" not in args


def test_build_gitlab_args_minimal():
    """Test build_gitlab_args with minimal config (no token)."""
    target = MagicMock()
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = None
    target.gitlab_repo = "mygroup/myrepo"
    target.gitlab_group = None

    args = build_gitlab_args(target, use_docker=False)

    assert "--gitlab-url" in args
    assert "--gitlab-token" not in args
    assert "--gitlab-repo" in args


# ========== Category 6: Kubernetes Arguments ==========


def test_build_k8s_args_single_namespace():
    """Test build_k8s_args with single namespace."""
    target = MagicMock()
    target.k8s_context = "minikube"
    target.k8s_namespace = "default"
    target.k8s_all_namespaces = False

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "minikube" in args
    assert "--k8s-namespace" in args
    assert "default" in args
    assert "--k8s-all-namespaces" not in args


def test_build_k8s_args_all_namespaces():
    """Test build_k8s_args with all namespaces flag."""
    target = MagicMock()
    target.k8s_context = "prod-cluster"
    target.k8s_namespace = None
    target.k8s_all_namespaces = True

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "prod-cluster" in args
    assert "--k8s-all-namespaces" in args
    assert "--k8s-namespace" not in args


def test_build_k8s_args_minimal():
    """Test build_k8s_args with minimal config (context only)."""
    target = MagicMock()
    target.k8s_context = "minikube"
    target.k8s_namespace = None
    target.k8s_all_namespaces = False

    args = build_k8s_args(target, use_docker=False)

    assert "--k8s-context" in args
    assert "minikube" in args


# ========== Category 7: Complete Command Building ==========


def test_build_command_parts_native_repo(tmp_path):
    """Test build_command_parts for native repo scan."""
    config = MagicMock()
    config.use_docker = False
    config.results_dir = str(tmp_path / "results")
    config.threads = 4
    config.timeout = 600
    config.fail_on = "high"
    config.allow_missing_tools = True
    config.human_logs = True

    target = MagicMock()
    target.type = "repo"
    target.repo_mode = "repos-dir"
    target.repo_path = str(tmp_path)
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "jmo"
    # A severity threshold makes it `jmo ci`: `jmo scan` defines no --fail-on
    # (it abbreviates to --fail-on-store-error and HIGH is left unrecognised).
    assert cmd[1] == "ci"
    assert "--repos-dir" in cmd
    assert "--results-dir" in cmd
    assert "--threads" in cmd
    assert "--timeout" in cmd
    assert cmd[cmd.index("--fail-on") + 1] == "HIGH"
    assert "--allow-missing-tools" in cmd
    assert "--human-logs" in cmd
    assert "--profile-name" not in cmd


def test_build_command_parts_docker_repo(tmp_path):
    """Test build_command_parts for Docker repo scan."""
    config = WizardConfig()  # a MagicMock's attributes are truthy: all set
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")
    config.target.type = "repo"
    config.target.repo_mode = "repos-dir"
    config.target.repo_path = str(tmp_path / "myrepo")

    cmd = build_command_parts(config)

    assert cmd[:3] == ["docker", "run", "--rm"]
    assert cmd[cmd.index(JMO_DOCKER_IMAGE_FULL) + 1] == "scan"
    assert cmd[cmd.index("--results-dir") + 1] == "/results"
    assert "--profile-name" not in cmd


def test_build_command_parts_native_image():
    """Test build_command_parts for native image scan."""
    config = MagicMock()
    config.use_docker = False
    config.results_dir = "./results"
    config.threads = None
    config.timeout = None
    config.fail_on = None
    config.allow_missing_tools = False
    config.human_logs = False

    target = MagicMock()
    target.type = "image"
    target.image_name = "nginx:latest"
    target.images_file = None
    config.target = target

    cmd = build_command_parts(config)

    # No threshold: a plain `jmo scan`, and nothing selects a profile
    assert cmd == [
        "jmo",
        "scan",
        "--image",
        "nginx:latest",
        "--results-dir",
        "./results",
    ]


def test_build_command_parts_docker_volumes(tmp_path):
    """Test build_command_parts includes correct volume mounts for Docker."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "repo"
    target.repo_path = str(tmp_path / "myrepo")
    config.target = target

    cmd = build_command_parts(config)

    # Should have volume mounts (-v flags)
    assert "-v" in cmd
    # Should have results mount
    assert any("/results" in arg for arg in cmd)


# ========== Category 8: Docker Mode Extended Tests ==========


def test_build_command_parts_docker_image(tmp_path):
    """Test build_command_parts for Docker mode with image target."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "image"
    target.image_name = "nginx:latest"
    target.images_file = None
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "run" in cmd
    assert "--rm" in cmd
    assert JMO_DOCKER_IMAGE_FULL in cmd
    assert "--image" in cmd
    assert "nginx:latest" in cmd


def test_build_command_parts_docker_iac(tmp_path):
    """Test build_command_parts for Docker mode with IaC target."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "iac"
    target.iac_type = "terraform"
    target.iac_path = str(tmp_path / "main.tf")
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "-v" in cmd
    assert "--terraform" in cmd
    assert "/scan/iac-file" in cmd


def test_build_command_parts_docker_url(tmp_path):
    """Test build_command_parts for Docker mode with URL target."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "url"
    target.url = "https://example.com"
    target.urls_file = None
    target.api_spec = None
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "--url" in cmd
    assert "https://example.com" in cmd


def test_build_command_parts_docker_gitlab(tmp_path):
    """Test build_command_parts for Docker mode with GitLab target."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "gitlab"
    target.gitlab_url = "https://gitlab.com"
    target.gitlab_token = "secret"
    target.gitlab_repo = "org/repo"
    target.gitlab_group = None
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "--gitlab-url" in cmd
    assert "--gitlab-token" not in cmd
    assert "secret" not in cmd
    assert "--gitlab-repo" in cmd


def test_build_command_parts_docker_k8s(tmp_path):
    """Test build_command_parts for Docker mode with Kubernetes target."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "k8s"
    target.k8s_context = "minikube"
    target.k8s_namespace = "default"
    target.k8s_all_namespaces = False
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "docker"
    assert "--k8s-context" in cmd
    assert "--k8s-namespace" in cmd


def test_build_command_parts_docker_unknown_target_type(tmp_path):
    """Test build_command_parts for Docker mode with unknown target type."""
    config = MagicMock()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")

    target = MagicMock()
    target.type = "unknown_type"
    config.target = target

    cmd = build_command_parts(config)

    # Should still build base docker command
    assert cmd[0] == "docker"
    assert JMO_DOCKER_IMAGE_FULL in cmd


def test_build_command_parts_native_no_results_dir():
    """Test build_command_parts native mode without results_dir."""
    config = MagicMock()
    config.use_docker = False
    config.results_dir = None  # No results dir
    config.threads = None
    config.timeout = None
    config.fail_on = None
    config.allow_missing_tools = False
    config.human_logs = False

    target = MagicMock()
    target.type = "repo"
    target.repo_mode = "repo"
    target.repo_path = "/path/to/repo"
    config.target = target

    cmd = build_command_parts(config)

    assert cmd[0] == "jmo"
    assert "--results-dir" not in cmd
    assert "--repo" in cmd


# ========== Category 9: Edge Cases ==========


def test_build_repo_args_docker_mode_no_repo_path():
    """Test build_repo_args Docker mode when repo_path is None."""
    target = MagicMock()
    target.repo_path = None

    args = build_repo_args(target, use_docker=True)

    # Should return empty list when no repo_path
    assert args == []


def test_build_image_args_no_image_or_file():
    """Test build_image_args when neither image_name nor images_file set."""
    target = MagicMock()
    target.image_name = None
    target.images_file = None

    args = build_image_args(target, use_docker=False)

    assert args == []


def test_build_iac_args_docker_mode_no_iac_path():
    """Test build_iac_args Docker mode when iac_path is None."""
    target = MagicMock()
    target.iac_path = None
    target.iac_type = "terraform"

    args = build_iac_args(target, use_docker=True)

    # Should return empty when no iac_path
    assert args == []


def test_build_url_args_no_url_or_file():
    """Test build_url_args when neither url, urls_file, nor api_spec set."""
    target = MagicMock()
    target.url = None
    target.urls_file = None
    target.api_spec = None

    args = build_url_args(target, use_docker=False)

    assert args == []


def test_build_gitlab_args_no_url():
    """Test build_gitlab_args when gitlab_url is None."""
    target = MagicMock()
    target.gitlab_url = None
    target.gitlab_token = None
    target.gitlab_repo = None
    target.gitlab_group = None

    args = build_gitlab_args(target, use_docker=False)

    assert args == []


def test_build_k8s_args_no_context():
    """Test build_k8s_args when k8s_context is None."""
    target = MagicMock()
    target.k8s_context = None
    target.k8s_namespace = None
    target.k8s_all_namespaces = False

    args = build_k8s_args(target, use_docker=False)

    assert args == []


def test_build_repo_args_unknown_mode_native():
    """Test build_repo_args with unknown repo_mode returns empty args.

    This tests the implicit else branch when repo_mode doesn't match
    any known mode (repo, repos-dir, targets, tsv).
    """
    target = MagicMock()
    target.repo_mode = "unknown_mode"
    target.repo_path = "/path/to/something"

    args = build_repo_args(target, use_docker=False)

    # Unknown mode should return empty args (no match in if/elif chain)
    assert args == []


# ========== Category 10: The Docker branch, through the real parser ==========
#
# Every assertion here parses the argv the image's `jmo` entrypoint receives.
# Membership checks cannot tell a flag that parses from one that does not:
# `"--tsv" in args` passed for a command `jmo scan` never accepted, and the
# Docker branch passed `--repos-dir /scan` for a single repository, which scans
# each subdirectory as its own repository and never the root's own files.


def _docker_config(tmp_path: Path, repo_mode: str, fail_on: str = "") -> WizardConfig:
    config = WizardConfig()
    config.use_docker = True
    config.results_dir = str(tmp_path / "results")
    config.fail_on = fail_on
    config.target.type = "repo"
    config.target.repo_mode = repo_mode
    config.target.repo_path = str(tmp_path / "repo")
    return config


def _entrypoint_argv(cmd: list[str]) -> list[str]:
    """What follows the image name: the argv `jmo` itself parses."""
    return cmd[cmd.index(JMO_DOCKER_IMAGE_FULL) + 1 :]


def _mounts(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "-v"]


def test_docker_repo_mode_scans_the_mount_as_one_repository(tmp_path):
    config = _docker_config(tmp_path, "repo")

    cmd = build_command_parts(config)
    parsed = build_parser().parse_args(_entrypoint_argv(cmd))

    assert parsed.repo == "/scan"
    assert parsed.repos_dir is None
    assert f"{(tmp_path / 'repo').resolve()}:/scan" in _mounts(cmd)


def test_docker_repos_dir_mode_keeps_repos_dir(tmp_path):
    config = _docker_config(tmp_path, "repos-dir")

    parsed = build_parser().parse_args(_entrypoint_argv(build_command_parts(config)))

    assert parsed.repos_dir == "/scan"
    assert parsed.repo is None


def test_docker_targets_mode_is_refused_with_the_reason(tmp_path):
    """A targets file lists host paths, and the container sees only its mounts."""
    config = _docker_config(tmp_path, "targets")

    with pytest.raises(ValueError, match="targets") as err:
        build_command_parts(config)

    assert "container" in str(err.value)


def test_docker_tsv_mode_clones_into_the_asked_for_destination(tmp_path):
    """The Docker branch passed no target at all for tsv mode (#1299).

    The TSV is mounted read-only. Clones go to the destination the wizard
    asked for, mounted at /repos-tsv, so they persist between runs and a
    second run fast-forwards them; not under /results, which a CI job
    uploads whole.
    """
    config = _docker_config(tmp_path, "tsv")
    config.target.tsv_path = str(tmp_path / "repos.tsv")
    config.target.tsv_dest = str(tmp_path / "clones")

    cmd = build_command_parts(config)
    parsed = build_parser().parse_args(_entrypoint_argv(cmd))

    assert (parsed.tsv, parsed.dest) == ("/repos.tsv", "/repos-tsv")
    assert f"{(tmp_path / 'repos.tsv').resolve()}:/repos.tsv:ro" in _mounts(cmd)
    assert f"{(tmp_path / 'clones').resolve()}:/repos-tsv" in _mounts(cmd)


def test_docker_threshold_runs_jmo_ci(tmp_path):
    """`jmo scan` has no --fail-on; the Docker branch dropped the threshold."""
    config = _docker_config(tmp_path, "repo", fail_on="high")

    parsed = build_parser().parse_args(_entrypoint_argv(build_command_parts(config)))

    assert parsed.cmd == "ci"
    assert parsed.fail_on == "HIGH"
    assert parsed.repo == "/scan"


def test_docker_without_a_threshold_stays_a_scan(tmp_path):
    config = _docker_config(tmp_path, "repo")

    parsed = build_parser().parse_args(_entrypoint_argv(build_command_parts(config)))

    assert parsed.cmd == "scan"


def test_docker_carries_the_advanced_settings(tmp_path):
    """The Docker branch dropped all four; only the native one emitted them."""
    config = _docker_config(tmp_path, "repo")
    config.threads = 4
    config.timeout = 600
    config.allow_missing_tools = True
    config.human_logs = True

    parsed = build_parser().parse_args(_entrypoint_argv(build_command_parts(config)))

    assert (parsed.threads, parsed.timeout) == (4, 600)
    assert parsed.allow_missing_tools is True
    assert parsed.human_logs is True


def _gitlab_config(tmp_path: Path, use_docker: bool) -> WizardConfig:
    config = WizardConfig()
    config.use_docker = use_docker
    config.results_dir = str(tmp_path / "results")
    config.target.type = "gitlab"
    config.target.gitlab_repo = "group/project"
    config.target.gitlab_token = "glpat-SECRET"
    return config


@pytest.mark.parametrize("use_docker", [False, True], ids=["native", "docker"])
def test_the_gitlab_token_is_never_on_the_command_line(tmp_path, use_docker):
    """The wizard printed it, and `--emit-script`/`--emit-make` wrote it to disk.

    `jmo` reads GITLAB_TOKEN from the environment, so the command needs only
    the name: Docker forwards it with a bare `-e GITLAB_TOKEN`.
    """
    cmd = build_command_parts(_gitlab_config(tmp_path, use_docker))

    assert not any("glpat-SECRET" in part for part in cmd)
    assert "--gitlab-token" not in cmd
    if use_docker:
        image = cmd.index(JMO_DOCKER_IMAGE_FULL)
        assert ["-e", "GITLAB_TOKEN"] in [cmd[i : i + 2] for i in range(image)]
