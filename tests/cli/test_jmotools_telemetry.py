#!/usr/bin/env python3
"""
Tests for jmotools telemetry CLI commands.

Tests:
- jmotools telemetry status
- jmotools telemetry enable
- jmotools telemetry disable
- jmotools telemetry info
"""

import subprocess
import yaml


def test_telemetry_status(tmp_path):
    """Test telemetry status command."""
    # Create minimal jmo.yml with telemetry enabled
    config_path = tmp_path / "jmo.yml"
    config_path.write_text(yaml.dump({"telemetry": {"enabled": True}}))

    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "status"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert "Telemetry Status" in result.stdout
    assert "Enabled" in result.stdout


def test_telemetry_disable(tmp_path):
    """Test telemetry disable command."""
    # Create minimal jmo.yml with telemetry enabled
    config_path = tmp_path / "jmo.yml"
    config_path.write_text(yaml.dump({"telemetry": {"enabled": True}}))

    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "disable"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert "Telemetry disabled" in result.stdout

    # Verify jmo.yml was updated
    config_data = yaml.safe_load(config_path.read_text())
    assert config_data["telemetry"]["enabled"] is False


def test_telemetry_enable(tmp_path):
    """Test telemetry enable command."""
    # Create minimal jmo.yml with telemetry disabled
    config_path = tmp_path / "jmo.yml"
    config_path.write_text(yaml.dump({"telemetry": {"enabled": False}}))

    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "enable"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert "Telemetry enabled" in result.stdout

    # Verify jmo.yml was updated
    config_data = yaml.safe_load(config_path.read_text())
    assert config_data["telemetry"]["enabled"] is True


def test_telemetry_info(tmp_path):
    """Test telemetry info command."""
    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "info"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert "Telemetry Information" in result.stdout
    assert "What we collect" in result.stdout
    assert "What we DON'T collect" in result.stdout
    assert "Privacy policy" in result.stdout
    assert "Opt-out commands" in result.stdout


def test_telemetry_enable_creates_config_if_missing(tmp_path):
    """Test that telemetry enable creates jmo.yml if it doesn't exist."""
    config_path = tmp_path / "jmo.yml"
    assert not config_path.exists()

    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "enable"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert config_path.exists()

    config_data = yaml.safe_load(config_path.read_text())
    assert config_data["telemetry"]["enabled"] is True


def test_telemetry_disable_creates_config_if_missing(tmp_path):
    """Test that telemetry disable creates jmo.yml if it doesn't exist."""
    config_path = tmp_path / "jmo.yml"
    assert not config_path.exists()

    result = subprocess.run(
        ["python3", "-m", "scripts.cli.jmotools", "telemetry", "disable"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0
    assert config_path.exists()

    config_data = yaml.safe_load(config_path.read_text())
    assert config_data["telemetry"]["enabled"] is False
