"""Unit tests for base wizard flow classes and utilities.

Tests cover:
- TargetDetector.detect_repos
- PromptHelper colored output and prompting

Architecture Note:
- Uses tmp_path fixture for file operations
- Mocks input() for user prompts
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.cli.wizard_flows.base_flow import PromptHelper, TargetDetector

# ========== Category 1: TargetDetector ==========


def test_detect_repos_with_git_repos(tmp_path):
    """Test detect_repos finds Git repositories."""
    detector = TargetDetector()

    # Create directories with .git
    (tmp_path / "repo1" / ".git").mkdir(parents=True)
    (tmp_path / "repo2" / ".git").mkdir(parents=True)
    (tmp_path / "notrepo").mkdir()

    repos = detector.detect_repos(tmp_path)

    assert len(repos) == 2
    assert tmp_path / "repo1" in repos
    assert tmp_path / "repo2" in repos


def test_detect_repos_no_repos(tmp_path):
    """Test detect_repos with no repositories."""
    detector = TargetDetector()
    repos = detector.detect_repos(tmp_path)
    assert len(repos) == 0


def test_detect_repos_nonexistent_directory():
    """Test detect_repos with non-existent directory."""
    detector = TargetDetector()
    repos = detector.detect_repos(Path("/nonexistent"))
    assert len(repos) == 0


# ========== Category 2: PromptHelper ==========


def test_prompter_colorize():
    """Test PromptHelper colorize applies ANSI codes."""
    import scripts.cli.wizard_flows.base_flow as bf

    orig = bf._ANSI_SUPPORTED
    bf._ANSI_SUPPORTED = True
    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "green")
        assert result == "\x1b[32mtest\x1b[0m"
    finally:
        bf._ANSI_SUPPORTED = orig


def test_prompter_colorize_invalid_color():
    """Test PromptHelper colorize with invalid color (fallback to reset)."""
    import scripts.cli.wizard_flows.base_flow as bf

    orig = bf._ANSI_SUPPORTED
    bf._ANSI_SUPPORTED = True
    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "invalid")
        assert result == "test\x1b[0m"
    finally:
        bf._ANSI_SUPPORTED = orig


def test_prompter_print_header(capsys):
    """Test PromptHelper print_header outputs formatted header."""
    prompter = PromptHelper()
    prompter.print_header("Test Header", "rocket")

    captured = capsys.readouterr()
    assert "Test Header" in captured.out
    assert "╔" in captured.out
    assert "╚" in captured.out


def test_prompter_print_step(capsys):
    """Test PromptHelper print_step outputs progress bar."""
    prompter = PromptHelper()
    prompter.print_step(2, 5, "Running scan")

    captured = capsys.readouterr()
    assert "Step 2/5" in captured.out
    assert "Running scan" in captured.out
    assert "40%" in captured.out


def test_prompter_prompt_choice_numeric():
    """Test PromptHelper prompt_choice with numeric input."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B", "Option C"]

    with patch("builtins.input", return_value="2"):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option B"


def test_prompter_prompt_choice_default():
    """Test PromptHelper prompt_choice with default."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B"]

    with patch("builtins.input", return_value=""):
        result = prompter.prompt_choice("Select:", choices, default="Option A")
        assert result == "Option A"


def test_prompter_prompt_choice_invalid_then_valid():
    """Test PromptHelper prompt_choice retries on invalid input."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B"]

    with patch("builtins.input", side_effect=["invalid", "99", "1"]):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option A"


def test_prompter_prompt_yes_no_yes():
    """Test PromptHelper prompt_yes_no with 'yes' input."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="y"):
        result = prompter.prompt_yes_no("Continue?")
        assert result is True


def test_prompter_prompt_yes_no_no():
    """Test PromptHelper prompt_yes_no with 'no' input."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value="n"):
        result = prompter.prompt_yes_no("Continue?")
        assert result is False


def test_prompter_prompt_yes_no_default():
    """Test PromptHelper prompt_yes_no with default."""
    prompter = PromptHelper()

    with patch("builtins.input", return_value=""):
        result = prompter.prompt_yes_no("Continue?", default=True)
        assert result is True


def test_prompter_prompt_choice_text_input():
    """Test PromptHelper prompt_choice with text input (case-insensitive)."""
    prompter = PromptHelper()
    choices = ["Option A", "Option B", "Option C"]

    with patch("builtins.input", return_value="option b"):
        result = prompter.prompt_choice("Select:", choices)
        assert result == "Option B"


def test_prompter_prompt_yes_no_retry():
    """Test PromptHelper prompt_yes_no retries on invalid input."""
    prompter = PromptHelper()

    with patch("builtins.input", side_effect=["maybe", "possibly", "y"]):
        result = prompter.prompt_yes_no("Continue?")
        assert result is True


def test_prompter_print_header_long_title(capsys):
    """Test PromptHelper print_header truncates long titles."""
    prompter = PromptHelper()

    # Very long header that should be truncated
    long_title = "A" * 200
    prompter.print_header(long_title, "star")

    captured = capsys.readouterr()
    # Should contain truncation ellipsis
    assert "…" in captured.out


def test_prompter_colorize_no_color_env(monkeypatch):
    """Test PromptHelper colorize respects NO_COLOR environment variable."""
    prompter = PromptHelper()

    monkeypatch.setenv("NO_COLOR", "1")
    result = prompter.colorize("test", "green")

    # Should return plain text without ANSI codes
    assert result == "test"


def test_target_detector_defaults_to_cwd(tmp_path, monkeypatch):
    """With no directory, detect_repos searches the current working directory."""
    (tmp_path / "app" / ".git").mkdir(parents=True)
    (tmp_path / "notes").mkdir()
    monkeypatch.chdir(tmp_path)

    assert TargetDetector().detect_repos(None) == [tmp_path / "app"]


# ========== Category 4: ANSI Support Detection ==========


def test_supports_ansi_no_color_env(monkeypatch):
    """Test _supports_ansi respects NO_COLOR environment variable."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.setenv("NO_COLOR", "1")

    # Call the function directly
    result = base_flow._supports_ansi()

    assert result is False


def test_supports_ansi_windows_terminal_env(monkeypatch):
    """Test _supports_ansi detects Windows Terminal via WT_SESSION."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("WT_SESSION", "some-session-id")

    result = base_flow._supports_ansi()

    assert result is True


def test_supports_ansi_xterm_env(monkeypatch):
    """Test _supports_ansi detects xterm from TERM variable."""
    from scripts.cli.wizard_flows import base_flow

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("WT_SESSION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")

    result = base_flow._supports_ansi()

    assert result is True


def test_get_terminal_width_fallback():
    """Test _get_terminal_width returns safe default on exception."""
    from scripts.cli.wizard_flows import base_flow

    with patch("shutil.get_terminal_size", side_effect=Exception("test")):
        result = base_flow._get_terminal_width()

    assert result == 80


def test_get_terminal_width_clamping():
    """Test _get_terminal_width clamps to min/max bounds."""
    from scripts.cli.wizard_flows import base_flow

    # Test minimum clamping
    with patch("shutil.get_terminal_size") as mock_size:
        mock_size.return_value = MagicMock(columns=20)
        result = base_flow._get_terminal_width()
        assert result == 40  # Minimum

    # Test maximum clamping
    with patch("shutil.get_terminal_size") as mock_size:
        mock_size.return_value = MagicMock(columns=200)
        result = base_flow._get_terminal_width()
        assert result == 120  # Maximum


def test_prompter_colorize_ansi_not_supported(monkeypatch):
    """Test PromptHelper colorize when ANSI not supported."""
    from scripts.cli.wizard_flows import base_flow

    # Set the module-level flag to False
    original_flag = base_flow._ANSI_SUPPORTED
    base_flow._ANSI_SUPPORTED = False
    monkeypatch.delenv("NO_COLOR", raising=False)

    try:
        prompter = PromptHelper()
        result = prompter.colorize("test", "green")
        assert result == "test"  # No ANSI codes
    finally:
        base_flow._ANSI_SUPPORTED = original_flag
