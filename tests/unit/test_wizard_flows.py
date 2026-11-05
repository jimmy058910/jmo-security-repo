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
