#!/usr/bin/env python3
"""
JMo Security Telemetry Module

Privacy-first, opt-in anonymous usage telemetry using GitHub Gist backend.

Reference: docs/TELEMETRY_IMPLEMENTATION_GUIDE.md
"""

import json
import os
import platform
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib import request
from urllib.error import URLError, HTTPError

# Telemetry endpoint (GitHub Gist API for MVP)
GIST_ID = os.environ.get("JMO_TELEMETRY_GIST_ID", "")
GITHUB_TOKEN = os.environ.get("JMO_TELEMETRY_GITHUB_TOKEN", "")
TELEMETRY_ENDPOINT = f"https://api.github.com/gists/{GIST_ID}" if GIST_ID else ""

# Telemetry file (JSONL format)
TELEMETRY_FILE = "jmo-telemetry-events.jsonl"

# Anonymous ID storage
TELEMETRY_ID_FILE = Path.home() / ".jmo-security" / "telemetry-id"

# Scan count tracking (for frequency inference)
SCAN_COUNT_FILE = Path.home() / ".jmo-security" / "scan-count"


def get_anonymous_id() -> str:
    """
    Get or create anonymous UUID (stored locally).

    Returns:
        UUID v4 string (e.g., "a7f3c8e2-4b1d-4f9e-8c3a-2d5e7f9b1a3c")
    """
    if TELEMETRY_ID_FILE.exists():
        return TELEMETRY_ID_FILE.read_text().strip()

    # Generate new UUID
    anon_id = str(uuid.uuid4())
    TELEMETRY_ID_FILE.parent.mkdir(parents=True, exist_ok=True)
    TELEMETRY_ID_FILE.write_text(anon_id)
    return anon_id


def is_telemetry_enabled(config: Dict[str, Any]) -> bool:
    """
    Check if telemetry is enabled in config or environment variable.

    Environment variable override (for CI/CD):
        JMO_TELEMETRY_DISABLE=1 → Force disable

    Config check:
        telemetry.enabled: true → Enable
        telemetry.enabled: false → Disable
        (missing) → Default: false (opt-in only)

    Args:
        config: JMo configuration dict (from jmo.yml)

    Returns:
        True if telemetry is enabled, False otherwise
    """
    # Environment variable override (CI/CD)
    if os.environ.get("JMO_TELEMETRY_DISABLE") == "1":
        return False

    # Config check (default: False, opt-in only)
    enabled: bool = bool(config.get("telemetry", {}).get("enabled", False))
    return enabled


def send_event(
    event_type: str,
    metadata: Dict[str, Any],
    config: Dict[str, Any],
    version: str = "0.7.0",
) -> None:
    """
    Send telemetry event (non-blocking, fire-and-forget).

    This function returns immediately and sends the event in a background thread.
    Network failures never interrupt the user's workflow.

    Args:
        event_type: Event name (e.g., "scan.started", "tool.failed")
        metadata: Event-specific metadata dict
        config: JMo configuration dict (to check if telemetry enabled)
        version: JMo Security version string
    """
    if not is_telemetry_enabled(config):
        return

    # Validate Gist endpoint is configured
    if not TELEMETRY_ENDPOINT or not GITHUB_TOKEN:
        # Silently skip if endpoint not configured (don't break user workflow)
        return

    # Fire-and-forget in background thread
    threading.Thread(
        target=_send_event_async, args=(event_type, metadata, version), daemon=True
    ).start()


def _send_event_async(event_type: str, metadata: Dict[str, Any], version: str) -> None:
    """
    Send event to telemetry endpoint (background thread).

    This function runs in a daemon thread and fails silently on errors.
    It should NEVER raise exceptions that could interrupt the main thread.

    Args:
        event_type: Event name
        metadata: Event-specific metadata dict
        version: JMo Security version string
    """
    try:
        # Build event payload
        event = {
            "event": event_type,
            "version": version,
            "platform": platform.system(),  # "Linux", "Darwin", "Windows"
            "python_version": f"{platform.python_version_tuple()[0]}.{platform.python_version_tuple()[1]}",
            "anonymous_id": get_anonymous_id(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata,
        }

        # Read current Gist content (to append, not overwrite)
        current_content = _get_gist_content()

        # Append new event (JSONL format: one JSON object per line)
        new_content = current_content + json.dumps(event) + "\n"

        # Update Gist via PATCH request
        data = json.dumps({"files": {TELEMETRY_FILE: {"content": new_content}}}).encode(
            "utf-8"
        )

        req = request.Request(
            TELEMETRY_ENDPOINT,
            data=data,
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": f"JMo-Security/{version}",
            },
            method="PATCH",
        )

        # Send request with 2-second timeout (don't block scans)
        with request.urlopen(
            req, timeout=2
        ) as response:  # nosec B310 - hardcoded GitHub Gist API URL
            if response.status not in (200, 201):
                # Gist API returned error, but don't crash (fail silently)
                pass

    except (URLError, HTTPError, TimeoutError, Exception):
        # Silently fail on any error (network, timeout, JSON parsing, etc.)
        # NEVER break the user's workflow due to telemetry issues
        pass


def _get_gist_content() -> str:
    """
    Fetch current Gist content to append new events.

    Returns:
        Current Gist content (JSONL format) or empty string if fetch fails
    """
    try:
        req = request.Request(
            TELEMETRY_ENDPOINT,
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "User-Agent": "JMo-Security",
            },
        )

        with request.urlopen(
            req, timeout=2
        ) as response:  # nosec B310 - hardcoded GitHub Gist API URL
            gist_data = json.loads(response.read().decode("utf-8"))
            content: str = str(
                gist_data.get("files", {}).get(TELEMETRY_FILE, {}).get("content", "")
            )
            return content

    except Exception:
        # If fetch fails, return empty string (will create new content)
        return ""


def bucket_duration(seconds: float) -> str:
    """
    Bucket scan duration for privacy (prevents fingerprinting).

    Args:
        seconds: Scan duration in seconds

    Returns:
        Bucketed duration string: "<5min", "5-15min", "15-30min", ">30min"
    """
    if seconds < 300:
        return "<5min"
    elif seconds < 900:
        return "5-15min"
    elif seconds < 1800:
        return "15-30min"
    else:
        return ">30min"


def bucket_findings(count: int) -> str:
    """
    Bucket finding count for privacy (prevents fingerprinting).

    Args:
        count: Number of findings

    Returns:
        Bucketed count string: "0", "1-10", "10-100", "100-1000", ">1000"
    """
    if count == 0:
        return "0"
    elif count <= 10:
        return "1-10"
    elif count <= 100:
        return "10-100"
    elif count <= 1000:
        return "100-1000"
    else:
        return ">1000"


def bucket_targets(count: int) -> str:
    """
    Bucket target count for privacy (prevents fingerprinting).

    Args:
        count: Total number of scan targets

    Returns:
        Bucketed count string: "1", "2-5", "6-10", "11-50", ">50"
    """
    if count == 1:
        return "1"
    elif count <= 5:
        return "2-5"
    elif count <= 10:
        return "6-10"
    elif count <= 50:
        return "11-50"
    else:
        return ">50"


def detect_ci_environment() -> bool:
    """
    Detect if running in CI/CD environment.

    Checks for common CI/CD environment variables:
    - GitHub Actions: GITHUB_ACTIONS, CI
    - GitLab CI: GITLAB_CI
    - Jenkins: JENKINS_URL, BUILD_ID
    - CircleCI: CIRCLECI
    - Travis CI: TRAVIS
    - Azure Pipelines: TF_BUILD
    - Bitbucket Pipelines: BITBUCKET_PIPELINE_UUID
    - Generic: CI=true

    Returns:
        True if running in CI/CD, False otherwise
    """
    ci_vars = [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "JENKINS_URL",
        "BUILD_ID",
        "CIRCLECI",
        "TRAVIS",
        "TF_BUILD",
        "BITBUCKET_PIPELINE_UUID",
    ]

    return any(os.environ.get(var) for var in ci_vars)


def infer_scan_frequency() -> Optional[str]:
    """
    Infer scan frequency based on local scan count.

    Reads/updates scan count file and infers frequency:
    - 1 scan → "first_time"
    - 2-10 scans → "weekly" (assumed)
    - 11+ scans → "daily" (assumed)

    Returns:
        Frequency hint: "first_time", "weekly", "daily", or None (if count unavailable)
    """
    try:
        # Read current scan count
        if SCAN_COUNT_FILE.exists():
            count = int(SCAN_COUNT_FILE.read_text().strip())
        else:
            count = 0

        # Increment scan count
        count += 1
        SCAN_COUNT_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCAN_COUNT_FILE.write_text(str(count))

        # Infer frequency
        if count == 1:
            return "first_time"
        elif count <= 10:
            return "weekly"
        else:
            return "daily"

    except Exception:
        # If file operations fail, return None (don't break scan)
        return None


# For testing purposes
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 scripts/core/telemetry.py <test|check>")
        sys.exit(1)

    command = sys.argv[1]

    if command == "test":
        # Test sending a telemetry event
        config = {"telemetry": {"enabled": True}}
        print("Sending test telemetry event...")
        send_event(
            "test.event",
            {"message": "Test telemetry event from CLI"},
            config,
            version="0.7.0-dev",
        )
        print("✅ Event sent (check Gist in a few seconds)")

    elif command == "check":
        # Check telemetry configuration
        print(f"GIST_ID: {GIST_ID or '(not set)'}")
        print(
            f"GITHUB_TOKEN: {'***' + GITHUB_TOKEN[-4:] if GITHUB_TOKEN else '(not set)'}"
        )
        print(f"TELEMETRY_ENDPOINT: {TELEMETRY_ENDPOINT or '(not configured)'}")
        print(f"Anonymous ID: {get_anonymous_id()}")
        print(f"CI Detected: {detect_ci_environment()}")
        print(f"Scan Frequency: {infer_scan_frequency() or '(none)'}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
