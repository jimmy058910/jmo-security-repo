"""Telemetry helper functions for wizard workflows."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def prompt_telemetry_opt_in() -> bool:
    """
    Prompt user to enable telemetry on first run.

    Returns:
        True if user opts in, False otherwise
    """
    print("\n" + "=" * 70)
    print("📊 Help Improve JMo Security")
    print("=" * 70)
    print("We'd like to collect anonymous usage stats to prioritize features.")
    print()
    print("✅ What we collect:")
    print("   • Tool usage (which tools ran)")
    print("   • Scan duration (fast/slow)")
    print("   • Execution mode (CLI/Docker/Wizard)")
    print("   • Platform (Linux/macOS/Windows)")
    print()
    print("❌ What we DON'T collect:")
    print("   • Repository names or paths")
    print("   • Finding details or secrets")
    print("   • IP addresses or user info")
    print()
    print("📄 Privacy policy: https://jmotools.com/privacy")
    print("📖 Full details: docs/TELEMETRY_IMPLEMENTATION_GUIDE.md")
    print("💡 You can change this later in jmo.yml")
    print()

    response = input("Enable anonymous telemetry? [y/N]: ").strip().lower()
    return response == "y"


def save_telemetry_preference(config_path: Path, enabled: bool) -> None:
    """
    Save telemetry preference to jmo.yml.

    Args:
        config_path: Path to jmo.yml
        enabled: Whether telemetry is enabled
    """
    import yaml

    # Load existing config or create new one
    if config_path.exists():
        try:
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
        except Exception:
            config_data = {}
    else:
        config_data = {}

    # Update telemetry section
    config_data["telemetry"] = {"enabled": enabled}

    # Write back to file
    with open(config_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    status = "enabled" if enabled else "disabled"
    print(f"\n✅ Telemetry {status}. You can change this later in {config_path}\n")


def send_wizard_telemetry(
    wizard_start_time: float,
    config: Any,
    version: str,
    artifact_type: str | None = None,
) -> None:
    """
    Send wizard.completed telemetry event.

    Args:
        wizard_start_time: Time when wizard started (from time.time())
        config: WizardConfig object
        version: Tool version string
        artifact_type: Type of artifact generated ("makefile", "shell", "gha", or None)
    """
    import time

    from scripts.core.config import load_config
    from scripts.core.telemetry import send_event

    try:
        cfg = load_config("jmo.yml") if Path("jmo.yml").exists() else None
        if cfg:
            wizard_duration = int(time.time() - wizard_start_time)
            execution_mode = "docker" if config.use_docker else "native"

            send_event(
                "wizard.completed",
                {
                    "profile_selected": config.profile,
                    "execution_mode": execution_mode,
                    "artifact_generated": artifact_type,
                    "duration_seconds": wizard_duration,
                },
                {},
                version=version,
            )
    except Exception as e:
        # Never let telemetry errors break the wizard
        logger.debug(f"Telemetry send failed: {e}")
