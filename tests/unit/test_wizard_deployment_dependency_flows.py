"""Unit tests for deployment and dependency security audit workflows.

Tests cover:
- DeploymentFlow: Pre-deployment security checklist
- DependencyFlow: SBOM and dependency vulnerability scanning

Architecture Note:
- Uses tmp_path and monkeypatch fixtures
- Mocks PromptHelper for user interaction
- Tests environment auto-detection from env vars and files
"""

from pathlib import Path
from unittest.mock import patch


from scripts.cli.wizard_flows.dependency_flow import DependencyFlow
from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow


# ========== Category 1: DeploymentFlow - Target Detection ==========


def test_deployment_detect_targets(tmp_path, monkeypatch):
    """Test DeploymentFlow detect_targets finds deployment resources."""
    monkeypatch.chdir(tmp_path)

    # Create test files
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:latest"
    )
    (tmp_path / "main.tf").touch()
    (tmp_path / "package.json").write_text('{"name": "app"}')

    flow = DeploymentFlow()
    targets = flow.detect_targets()

    assert "images" in targets
    assert "iac" in targets
    assert "web" in targets
    assert "environment" in targets


def test_deployment_detect_environment_from_env_var(monkeypatch):
    """Test _detect_environment from ENVIRONMENT variable."""
    flow = DeploymentFlow()

    monkeypatch.setenv("ENVIRONMENT", "production")
    env = flow._detect_environment()
    assert env == "production"


def test_deployment_detect_environment_from_node_env(monkeypatch):
    """Test _detect_environment from NODE_ENV variable."""
    flow = DeploymentFlow()

    monkeypatch.setenv("NODE_ENV", "staging")
    env = flow._detect_environment()
    assert env == "staging"


def test_deployment_detect_environment_from_env_file(tmp_path, monkeypatch):
    """Test _detect_environment from .env file."""
    monkeypatch.chdir(tmp_path)

    (tmp_path / ".env").write_text("ENVIRONMENT=production\nAPI_KEY=secret")

    flow = DeploymentFlow()
    env = flow._detect_environment()
    assert env == "production"


def test_deployment_detect_environment_from_k8s_manifest(tmp_path, monkeypatch):
    """Test _detect_environment from Kubernetes namespace."""
    monkeypatch.chdir(tmp_path)

    k8s_dir = tmp_path / "k8s"
    k8s_dir.mkdir()
    (k8s_dir / "deployment.yml").write_text("namespace: production\nkind: Deployment")

    flow = DeploymentFlow()
    env = flow._detect_environment()
    assert env == "production"


def test_deployment_detect_environment_default_staging(tmp_path, monkeypatch):
    """Test _detect_environment defaults to staging."""
    monkeypatch.chdir(tmp_path)

    flow = DeploymentFlow()
    env = flow._detect_environment()
    assert env == "staging"


def test_deployment_detect_environment_handles_file_errors(tmp_path, monkeypatch):
    """Test _detect_environment handles file read errors gracefully."""
    monkeypatch.chdir(tmp_path)

    # Create .env file that will raise UnicodeDecodeError
    (tmp_path / ".env").write_bytes(b"\x80\x81\x82")

    flow = DeploymentFlow()
    env = flow._detect_environment()
    # Should not crash, should return default
    assert env == "staging"


# ========== Category 2: DeploymentFlow - User Prompting ==========


def test_deployment_prompt_user_staging():
    """Test prompt_user for staging deployment."""
    flow = DeploymentFlow()
    flow.detected_targets = {
        "images": ["nginx:latest"],
        "iac": [],
        "web": [],
        "environment": "staging",
    }

    with patch.object(flow.prompter, "prompt_choice") as mock_choice:
        mock_choice.side_effect = ["staging", "balanced", "HIGH"]

        options = flow.prompt_user()

        assert options["environment"] == "staging"
        assert options["profile"] == "balanced"
        assert options["fail_on"] == "HIGH"


def test_deployment_prompt_user_production(capsys):
    """Test prompt_user for production deployment shows requirements."""
    flow = DeploymentFlow()
    flow.detected_targets = {
        "images": [],
        "iac": [],
        "web": [],
        "environment": "production",
    }

    with patch.object(flow.prompter, "prompt_choice") as mock_choice:
        mock_choice.side_effect = ["production", "deep", "CRITICAL"]

        options = flow.prompt_user()

        assert options["environment"] == "production"
        assert options["profile"] == "deep"
        assert options["fail_on"] == "CRITICAL"

        # Verify production requirements were printed
        captured = capsys.readouterr()
        assert "Production Deployment Requirements" in captured.out


# ========== Category 3: DeploymentFlow - Target Summary ==========


def test_deployment_print_detected_targets_with_images(capsys):
    """Test _print_detected_deployment_targets with images."""
    flow = DeploymentFlow()
    targets = {"images": ["nginx:latest", "postgres:14", "redis:alpine"]}

    flow._print_detected_deployment_targets(targets)

    captured = capsys.readouterr()
    assert "Container images: 3 detected" in captured.out
    assert "nginx:latest" in captured.out


def test_deployment_print_detected_targets_with_iac(capsys):
    """Test _print_detected_deployment_targets with IaC files."""
    flow = DeploymentFlow()
    targets = {
        "iac": [
            Path("main.tf"),
            Path("variables.tf"),
            Path("outputs.tf"),
            Path("providers.tf"),
        ]
    }

    flow._print_detected_deployment_targets(targets)

    captured = capsys.readouterr()
    assert "IaC files: 4 detected" in captured.out
    assert "main.tf" in captured.out
    assert "... and 1 more" in captured.out


def test_deployment_print_detected_targets_with_web(capsys):
    """Test _print_detected_deployment_targets with web URLs."""
    flow = DeploymentFlow()
    targets = {"web": ["http://localhost:3000", "http://localhost:8080"]}

    flow._print_detected_deployment_targets(targets)

    captured = capsys.readouterr()
    assert "Web URLs: 2 detected for DAST" in captured.out
    assert "http://localhost:3000" in captured.out


def test_deployment_print_detected_targets_no_targets(capsys):
    """Test _print_detected_deployment_targets with no targets."""
    flow = DeploymentFlow()
    targets = {}

    flow._print_detected_deployment_targets(targets)

    captured = capsys.readouterr()
    assert "No deployment targets detected" in captured.out


# ========== Category 4: DeploymentFlow - Command Building ==========


def test_deployment_build_command_with_images():
    """Test build_command includes container images."""
    flow = DeploymentFlow()
    targets = {
        "images": ["nginx:latest", "postgres:14", "redis:alpine", "mongo:5"],
        "iac": [],
        "web": [],
    }
    options = {"profile": "deep", "fail_on": "CRITICAL"}

    cmd = flow.build_command(targets, options)

    assert "jmo" in cmd
    assert "ci" in cmd
    assert "--profile" in cmd
    assert "deep" in cmd
    assert "--fail-on" in cmd
    assert "CRITICAL" in cmd
    assert "--image" in cmd
    # Should limit to 3 images
    assert cmd.count("--image") == 3


def test_deployment_build_command_with_iac():
    """Test build_command includes IaC files."""
    flow = DeploymentFlow()
    targets = {
        "images": [],
        "iac": [Path("main.tf"), Path("variables.tf")],
        "web": [],
    }
    options = {"profile": "balanced", "fail_on": "HIGH"}

    cmd = flow.build_command(targets, options)

    assert "--terraform-state" in cmd


def test_deployment_build_command_with_web():
    """Test build_command includes web URL for DAST."""
    flow = DeploymentFlow()
    targets = {
        "images": [],
        "iac": [],
        "web": ["http://localhost:3000", "http://localhost:8080"],
    }
    options = {"profile": "balanced", "fail_on": "HIGH"}

    cmd = flow.build_command(targets, options)

    assert "--url" in cmd
    # Should only include first URL
    assert "http://localhost:3000" in cmd


# ========== Category 5: DependencyFlow - Target Detection ==========


def test_dependency_detect_targets(tmp_path, monkeypatch):
    """Test DependencyFlow detect_targets finds package files and images."""
    monkeypatch.chdir(tmp_path)

    # Create package files
    (tmp_path / "package.json").write_text('{"name": "app"}')
    (tmp_path / "requirements.txt").write_text("flask==2.0.0")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 2}')
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: python:3.10"
    )

    flow = DependencyFlow()
    targets = flow.detect_targets()

    assert "package_files" in targets
    assert "lock_files" in targets
    assert "images" in targets
    assert len(targets["package_files"]) >= 2
    assert len(targets["lock_files"]) >= 1


# ========== Category 6: DependencyFlow - User Prompting ==========


def test_dependency_prompt_user_all_yes():
    """Test prompt_user with all options selected."""
    flow = DependencyFlow()

    with patch.object(flow.prompter, "prompt_yes_no", side_effect=[True, True, True]):
        options = flow.prompt_user()

        assert options["generate_sbom"] is True
        assert options["scan_vulns"] is True
        assert options["check_licenses"] is True


def test_dependency_prompt_user_minimal():
    """Test prompt_user with minimal options."""
    flow = DependencyFlow()

    with patch.object(flow.prompter, "prompt_yes_no", side_effect=[True, True, False]):
        options = flow.prompt_user()

        assert options["generate_sbom"] is True
        assert options["scan_vulns"] is True
        assert options["check_licenses"] is False


# ========== Category 7: DependencyFlow - Command Building ==========


def test_dependency_build_command_basic(tmp_path, monkeypatch):
    """Test build_command with basic repository scan."""
    monkeypatch.chdir(tmp_path)

    flow = DependencyFlow()
    targets = {"package_files": [], "lock_files": [], "images": []}
    options = {"generate_sbom": True, "scan_vulns": True, "check_licenses": False}

    cmd = flow.build_command(targets, options)

    assert "jmo" in cmd
    assert "scan" in cmd
    assert "--profile" in cmd
    assert "balanced" in cmd
    assert "--tools" in cmd
    assert "syft" in cmd
    assert "trivy" in cmd
    assert "--repo" in cmd


def test_dependency_build_command_with_images(tmp_path, monkeypatch):
    """Test build_command includes images file."""
    monkeypatch.chdir(tmp_path)

    flow = DependencyFlow()
    targets = {
        "package_files": [],
        "lock_files": [],
        "images": ["python:3.10", "node:18"],
    }
    options = {"generate_sbom": True, "scan_vulns": True, "check_licenses": False}

    cmd = flow.build_command(targets, options)

    assert "--images-file" in cmd
    assert "dependency-images.txt" in cmd
    # Verify file was created
    assert (tmp_path / "dependency-images.txt").exists()


# ========== Category 8: DependencyFlow - Target Summary ==========


def test_dependency_print_detected_dependencies_with_packages(capsys):
    """Test _print_detected_dependencies with package files."""
    flow = DependencyFlow()
    targets = {
        "package_files": [
            Path("package.json"),
            Path("requirements.txt"),
            Path("go.mod"),
        ],
        "lock_files": [Path("package-lock.json")],
        "images": [],
    }

    flow._print_detected_dependencies(targets)

    captured = capsys.readouterr()
    assert "Package manifests: 3 detected" in captured.out
    assert "package.json" in captured.out
    assert "Lock files: 1 detected" in captured.out


def test_dependency_print_detected_dependencies_many_files(capsys):
    """Test _print_detected_dependencies with many files (shows '... and N more')."""
    flow = DependencyFlow()
    targets = {
        "package_files": [Path(f"pkg{i}.json") for i in range(10)],
        "lock_files": [Path(f"lock{i}.json") for i in range(5)],
        "images": ["python:3.10"],
    }

    flow._print_detected_dependencies(targets)

    captured = capsys.readouterr()
    assert "Package manifests: 10 detected" in captured.out
    assert "... and 5 more" in captured.out
    assert "Lock files: 5 detected" in captured.out
    assert "... and 2 more" in captured.out
    assert "Container images: 1 detected" in captured.out


def test_dependency_print_detected_dependencies_no_dependencies(capsys):
    """Test _print_detected_dependencies with no dependencies."""
    flow = DependencyFlow()
    targets = {"package_files": [], "lock_files": [], "images": []}

    flow._print_detected_dependencies(targets)

    captured = capsys.readouterr()
    assert "No dependency files detected" in captured.out
