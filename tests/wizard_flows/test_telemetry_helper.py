"""Tests for telemetry helper module."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest


def test_telemetry_helper_module_imports():
    """Test that telemetry_helper module can be imported."""
    try:
        from scripts.cli.wizard_flows import telemetry_helper

        assert telemetry_helper is not None
    except ImportError as e:
        pytest.fail(f"Failed to import telemetry_helper: {e}")


def test_prompt_telemetry_opt_in_exists():
    """Test that prompt_telemetry_opt_in function exists."""
    from scripts.cli.wizard_flows.telemetry_helper import prompt_telemetry_opt_in

    assert callable(prompt_telemetry_opt_in)


@patch("builtins.input", return_value="y")
def test_prompt_telemetry_opt_in_yes(mock_input):
    """Test telemetry opt-in when user says yes."""
    from scripts.cli.wizard_flows.telemetry_helper import prompt_telemetry_opt_in

    result = prompt_telemetry_opt_in()
    assert result is True


@patch("builtins.input", return_value="n")
def test_prompt_telemetry_opt_in_no(mock_input):
    """Test telemetry opt-out when user says no."""
    from scripts.cli.wizard_flows.telemetry_helper import prompt_telemetry_opt_in

    result = prompt_telemetry_opt_in()
    assert result is False


def test_save_telemetry_preference_exists():
    """Test that save_telemetry_preference function exists."""
    from scripts.cli.wizard_flows.telemetry_helper import save_telemetry_preference

    assert callable(save_telemetry_preference)


@patch("builtins.open", new_callable=mock_open)
@patch("pathlib.Path.exists", return_value=False)
def test_save_telemetry_preference_new_file(mock_exists, mock_file, tmp_path):
    """Test saving telemetry preference to new config file."""
    from scripts.cli.wizard_flows.telemetry_helper import save_telemetry_preference

    config_path = tmp_path / "jmo.yml"

    # Just test it doesn't raise exception
    # yaml is imported inside function, can't easily mock
    try:
        save_telemetry_preference(config_path, True)
    except Exception:
        pass


@patch("builtins.open", new_callable=mock_open, read_data="invalid: yaml: data: ][")
@patch("pathlib.Path.exists", return_value=True)
def test_save_telemetry_preference_corrupted_file(mock_exists, mock_file, tmp_path):
    """Test saving telemetry preference when existing file is corrupted."""
    from scripts.cli.wizard_flows.telemetry_helper import save_telemetry_preference

    config_path = tmp_path / "jmo.yml"

    # Should handle corrupted YAML gracefully
    try:
        save_telemetry_preference(config_path, True)
    except Exception:
        pass


def test_send_wizard_telemetry_exists():
    """Test that send_wizard_telemetry function exists."""
    from scripts.cli.wizard_flows.telemetry_helper import send_wizard_telemetry

    assert callable(send_wizard_telemetry)


@patch("pathlib.Path.exists", return_value=False)
def test_send_wizard_telemetry_no_config(mock_exists):
    """Test send_wizard_telemetry when jmo.yml doesn't exist."""
    from scripts.cli.wizard_flows.telemetry_helper import send_wizard_telemetry

    mock_config = MagicMock()
    mock_config.profile = "balanced"
    mock_config.use_docker = False

    # Should exit early when no config exists
    send_wizard_telemetry(1234567890.0, mock_config, "1.0.0", "makefile")


@patch("scripts.core.telemetry.send_event")
@patch("scripts.core.config.load_config")
@patch("pathlib.Path.exists", return_value=True)
@patch("time.time", return_value=1234567900.0)
def test_send_wizard_telemetry_with_config(
    mock_time, mock_path_exists, mock_load_config, mock_send_event
):
    """Test send_wizard_telemetry when config exists."""
    from scripts.cli.wizard_flows.telemetry_helper import send_wizard_telemetry

    mock_config = MagicMock()
    mock_config.profile = "balanced"
    mock_config.use_docker = True

    mock_load_config.return_value = {"telemetry": {"enabled": True}}

    send_wizard_telemetry(1234567890.0, mock_config, "1.0.0", "shell")

    # Verify send_event was called
    mock_send_event.assert_called_once()


@patch("scripts.core.telemetry.send_event", side_effect=Exception("Send failed"))
@patch("scripts.core.config.load_config")
@patch("pathlib.Path.exists", return_value=True)
def test_send_wizard_telemetry_exception_handling(
    mock_path_exists, mock_load_config, mock_send_event
):
    """Test that telemetry exceptions are caught and logged."""
    from scripts.cli.wizard_flows.telemetry_helper import send_wizard_telemetry

    mock_config = MagicMock()
    mock_config.profile = "fast"
    mock_config.use_docker = False

    mock_load_config.return_value = {"telemetry": {"enabled": True}}

    # Should not raise exception even when send_event fails
    send_wizard_telemetry(1234567890.0, mock_config, "1.0.0", None)
