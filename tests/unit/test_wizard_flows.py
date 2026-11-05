#!/usr/bin/env python3
"""Tests for the wizard's shared helpers: TargetDetector and PromptHelper."""

from scripts.cli.wizard_flows import PromptHelper, TargetDetector


class TestTargetDetector:
    """Tests for TargetDetector class."""

    def test_detect_repos(self, tmp_path):
        """Test repository detection."""
        # Create test repo
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        (repo_dir / ".git").mkdir()

        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert len(repos) == 1
        assert repos[0].name == "test-repo"

    def test_detect_repos_no_repos(self, tmp_path):
        """Test repository detection with no repos."""
        detector = TargetDetector()
        repos = detector.detect_repos(tmp_path)

        assert repos == []

    def test_detect_package_files_python(self, tmp_path):
        """Test Python package file detection."""
        # Create Python package files
        (tmp_path / "requirements.txt").touch()
        (tmp_path / "pyproject.toml").touch()
        (tmp_path / "setup.py").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 3
        file_names = [f.name for f in package_files]
        assert "requirements.txt" in file_names
        assert "pyproject.toml" in file_names
        assert "setup.py" in file_names

    def test_detect_package_files_javascript(self, tmp_path):
        """Test JavaScript package file detection."""
        (tmp_path / "package.json").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "package.json"

    def test_detect_package_files_go(self, tmp_path):
        """Test Go package file detection."""
        (tmp_path / "go.mod").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "go.mod"

    def test_detect_package_files_rust(self, tmp_path):
        """Test Rust package file detection."""
        (tmp_path / "Cargo.toml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "Cargo.toml"

    def test_detect_package_files_java_maven(self, tmp_path):
        """Test Java Maven package file detection."""
        (tmp_path / "pom.xml").touch()

        detector = TargetDetector()
        package_files = detector.detect_package_files(tmp_path)

        assert len(package_files) == 1
        assert package_files[0].name == "pom.xml"

    def test_detect_lock_files_python(self, tmp_path):
        """Test Python lock file detection."""
        (tmp_path / "poetry.lock").touch()
        (tmp_path / "Pipfile.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 2
        file_names = [f.name for f in lock_files]
        assert "poetry.lock" in file_names
        assert "Pipfile.lock" in file_names

    def test_detect_lock_files_javascript(self, tmp_path):
        """Test JavaScript lock file detection."""
        (tmp_path / "package-lock.json").touch()
        (tmp_path / "yarn.lock").touch()

        detector = TargetDetector()
        lock_files = detector.detect_lock_files(tmp_path)

        assert len(lock_files) == 2
        file_names = [f.name for f in lock_files]
        assert "package-lock.json" in file_names
        assert "yarn.lock" in file_names

    def test_detect_images_from_compose(self, tmp_path):
        """Test image detection from docker-compose.yml."""
        compose_content = """version: '3'
services:
  web:
    image: nginx:latest
  db:
    image: postgres:14
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        images = detector.detect_images(tmp_path)

        assert len(images) == 2
        assert "nginx:latest" in images
        assert "postgres:14" in images

    def test_detect_iac_terraform(self, tmp_path):
        """Test Terraform IaC detection."""
        (tmp_path / "main.tf").touch()
        (tmp_path / "terraform.tfstate").touch()

        detector = TargetDetector()
        iac_files = detector.detect_iac(tmp_path)

        assert len(iac_files) == 2

    def test_detect_web_apps_from_compose(self, tmp_path):
        """Test web app detection from docker-compose ports."""
        compose_content = """version: '3'
services:
  web:
    ports:
      - "8080:80"
"""
        (tmp_path / "docker-compose.yml").write_text(compose_content)

        detector = TargetDetector()
        urls = detector.detect_web_apps(tmp_path)

        assert "http://localhost:8080" in urls


class TestPromptHelper:
    """Tests for PromptHelper class."""

    def test_colorize(self):
        """Test text colorization."""
        import scripts.cli.wizard_flows.base_flow as bf

        orig = bf._ANSI_SUPPORTED
        bf._ANSI_SUPPORTED = True
        try:
            helper = PromptHelper()
            colored = helper.colorize("test", "blue")
            assert "\x1b[36m" in colored
            assert "test" in colored
            assert "\x1b[0m" in colored
        finally:
            bf._ANSI_SUPPORTED = orig

    def test_prompt_choice_with_default(self, monkeypatch):
        """Test choice prompt with default."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        helper = PromptHelper()

        choice = helper.prompt_choice("Test?", ["a", "b"], default="a")

        assert choice == "a"

    def test_prompt_yes_no_default_yes(self, monkeypatch):
        """Test yes/no prompt with default yes."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        helper = PromptHelper()

        result = helper.prompt_yes_no("Test?", default=True)

        assert result is True

    def test_prompt_yes_no_explicit_no(self, monkeypatch):
        """Test yes/no prompt with explicit no."""
        monkeypatch.setattr("builtins.input", lambda _: "n")
        helper = PromptHelper()

        result = helper.prompt_yes_no("Test?", default=True)

        assert result is False
