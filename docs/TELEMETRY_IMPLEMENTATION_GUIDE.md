# JMo Security — Telemetry Implementation Guide

**Version:** 1.0.0
**Target Release:** v0.7.0
**Status:** Ready for Implementation
**Privacy Policy:** <https://jmotools.com/privacy>

---

## Table of Contents

- [Overview](#overview)
- [Privacy-First Principles](#privacy-first-principles)
- [What We Track](#what-we-track)
- [What We NEVER Track](#what-we-never-track)
- [Architecture Overview](#architecture-overview)
- [Step-by-Step Implementation](#step-by-step-implementation)
  - [Phase 1: GitHub Gist Backend Setup](#phase-1-github-gist-backend-setup)
  - [Phase 2: Core Telemetry Module](#phase-2-core-telemetry-module)
  - [Phase 3: Wizard Integration](#phase-3-wizard-integration)
  - [Phase 4: CLI Integration](#phase-4-cli-integration)
  - [Phase 5: Docker Integration](#phase-5-docker-integration)
  - [Phase 6: Configuration Schema](#phase-6-configuration-schema)
  - [Phase 7: Testing & Verification](#phase-7-testing--verification)
- [Data Analysis Guide](#data-analysis-guide)
- [Troubleshooting](#troubleshooting)
- [Future: Cloudflare Workers Migration](#future-cloudflare-workers-migration)

---

## Overview

JMo Security implements **opt-in, anonymous, privacy-respecting telemetry** to help prioritize features, identify common failures, and improve user experience.

### Key Characteristics

- **Disabled by default** — Requires explicit user consent
- **100% anonymous** — No personally identifiable information (PII)
- **Open source** — Collection and storage code is public and auditable
- **User-controlled** — Can be disabled at any time via config or environment variable
- **Minimal** — Only essential usage data, no sensitive findings
- **Non-blocking** — Network failures never interrupt scans (fire-and-forget)

### Goals

1. **Understand tool usage** — Which tools are most popular? Which fail most often?
2. **Profile optimization** — Is "balanced" too slow? Is "fast" missing critical tools?
3. **Execution mode adoption** — CLI vs Docker vs Wizard usage patterns
4. **Platform support** — Linux/macOS/Windows usage distribution
5. **Feature prioritization** — Multi-target scanning adoption, compliance usage, etc.
6. **Business intelligence** — CI/CD adoption, enterprise usage patterns, regulated industry signals

---

## Privacy-First Principles

### Core Tenets

1. **Opt-In Only** — Telemetry is disabled by default. Users must explicitly enable it.
2. **Anonymous by Design** — No user names, IP addresses, repository names, or finding details.
3. **Minimal Collection** — Only data necessary to improve the tool and understand adoption patterns.
4. **Transparent Storage** — Data stored in privacy-respecting infrastructure (GitHub Gist → Cloudflare D1).
5. **Continuous Transparency** — Regular transparency reports with aggregated statistics (target: quarterly, minimum: bi-annually, published when statistically significant data available).
6. **User Control** — Easy to disable, no hidden trackers.

### Compliance

- ✅ **GDPR compliant** — Anonymous UUIDs are not personal data under GDPR Article 4(1)
- ✅ **CCPA compliant** — No sale of data, anonymous collection
- ✅ **SOC 2 compliant** — GitHub infrastructure meets security standards
- ✅ **HIPAA compliant** — No protected health information (PHI) collected

---

## What We Track

### 5 Core Events

#### 1. `scan.started`

**When:** User runs `jmo scan` or `jmotools {fast,balanced,full}`

**Metadata Collected:**

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `mode` | string | `"wizard"` | Execution mode: `cli`, `docker`, `wizard` |
| `profile` | string | `"balanced"` | Profile name: `fast`, `balanced`, `deep`, `custom` |
| `tools` | array | `["trufflehog", "semgrep"]` | List of tools enabled (no outputs) |
| `target_types.repos` | int | `3` | Count of repository targets |
| `target_types.images` | int | `1` | Count of container image targets |
| `target_types.urls` | int | `0` | Count of web URL targets |
| `target_types.iac` | int | `0` | Count of IaC file targets |
| `target_types.gitlab` | int | `0` | Count of GitLab repo targets |
| `target_types.k8s` | int | `0` | Count of Kubernetes context targets |
| **`ci_detected`** | **boolean** | **`true`** | **Running in CI/CD environment (GitHub Actions, GitLab CI, Jenkins, etc.)** |
| **`multi_target_scan`** | **boolean** | **`true`** | **Scanning more than one target type (e.g., repos + images + URLs)** |
| **`compliance_usage`** | **boolean** | **`true`** | **Compliance framework enrichment enabled (v0.5.1+ feature)** |
| **`total_targets_bucket`** | **string** | **`"10-50"`** | **Total target count bucketed: `"1"`, `"2-5"`, `"6-10"`, `"11-50"`, `">50"`** |
| **`scan_frequency_hint`** | **string** | **`"daily"`** | **Inferred scan frequency: `"first_time"`, `"weekly"`, `"daily"`, or `null`** |

**Privacy:** No repository names, file paths, or URLs. Only **counts** per target type. Business metrics are all boolean or bucketed.

**Use Case (Product Improvement):**

- Identify most popular profiles
- Understand multi-target adoption (are users scanning containers/IaC?)
- Detect execution mode preferences (CLI vs Docker vs Wizard)

**Use Case (Business Intelligence):**

- **CI/CD adoption:** "45% of scans run in CI/CD" → Enterprise market penetration
- **Advanced features:** "30% use multi-target scanning" → v0.6.0 feature success
- **Regulated industries:** "25% use compliance frameworks" → Finance/healthcare adoption
- **Team usage:** "Top 20% scan 50+ targets" → Enterprise team indicators
- **User engagement:** "60% are daily users" → High retention signal

---

#### 2. `scan.completed`

**When:** Scan finishes successfully or with errors

**Metadata Collected:**

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `mode` | string | `"cli"` | Execution mode |
| `profile` | string | `"fast"` | Profile name |
| `duration_bucket` | string | `"5-15min"` | Bucketed scan duration: `<5min`, `5-15min`, `15-30min`, `>30min` |
| `tools_succeeded` | int | `8` | Number of tools that ran successfully |
| `tools_failed` | int | `0` | Number of tools that failed/timed out |
| `total_findings_bucket` | string | `"10-100"` | Bucketed finding count: `0`, `1-10`, `10-100`, `100-1000`, `>1000` |

**Privacy:** Duration and finding counts are **bucketed** to prevent fingerprinting.

**Use Case:**
- Detect performance issues (too many `>30min` scans)
- Identify tool reliability (high `tools_failed` indicates problems)
- Understand typical finding volumes

---

#### 3. `tool.failed`

**When:** A specific tool times out, crashes, or returns non-zero exit code

**Metadata Collected:**

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `tool` | string | `"trivy"` | Tool name that failed |
| `failure_type` | string | `"timeout"` | Failure type: `timeout`, `crash`, `non_zero_exit` |
| `exit_code` | int/null | `null` | Exit code (if available, null for timeouts) |
| `profile` | string | `"balanced"` | Profile being used |

**Privacy:** No error messages, stack traces, or file paths. Only tool name and failure type.

**Use Case:**
- Prioritize tool reliability fixes (e.g., "trivy times out 15% of the time")
- Adjust default timeouts based on real-world data
- Detect tool version incompatibilities

---

#### 4. `wizard.completed`

**When:** User completes interactive wizard (with or without running scan)

**Metadata Collected:**

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `profile_selected` | string | `"balanced"` | Profile chosen in wizard |
| `execution_mode` | string | `"docker"` | Execution mode: `docker`, `native` |
| `artifact_generated` | string/null | `"makefile"` | Artifact type: `makefile`, `shell`, `gha`, or `null` |
| `duration_seconds` | int | `120` | Time spent in wizard (seconds) |

**Privacy:** No wizard inputs, target paths, or configuration values.

**Use Case:**
- Measure wizard adoption and completion rate
- Understand which artifacts users generate most
- Detect wizard UX issues (long durations = confusion?)

---

#### 5. `report.generated`

**When:** User runs `jmo report` or `jmo ci`

**Metadata Collected:**

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `output_formats` | array | `["json", "md", "html", "sarif"]` | List of output formats generated |
| `findings_bucket` | string | `"100-1000"` | Bucketed finding count |
| `suppressions_used` | boolean | `true` | Whether suppressions were applied |
| `compliance_enabled` | boolean | `true` | Whether compliance enrichment ran |

**Privacy:** No finding details, suppression rules, or compliance mappings.

**Use Case:**
- Understand which output formats are popular (HTML vs SARIF vs JSON)
- Measure suppression adoption
- Track compliance feature usage

---

### Common Fields (All Events)

Every telemetry event includes these standard fields:

| Field | Type | Example | Purpose |
|-------|------|---------|---------|
| `event` | string | `"scan.started"` | Event type identifier |
| `version` | string | `"0.7.0"` | JMo Security version |
| `platform` | string | `"Linux"` | OS platform: `Linux`, `Darwin` (macOS), `Windows` |
| `python_version` | string | `"3.11"` | Python version (major.minor) |
| `anonymous_id` | string | `"a7f3c8e2-..."` | Random UUID (stored in `~/.jmo-security/telemetry-id`) |
| `timestamp` | string | `"2025-10-19T14:32:00Z"` | ISO 8601 timestamp (UTC) |

---

### Anonymous ID

**Storage Location:** `~/.jmo-security/telemetry-id`

**Generation:** Random UUID v4 created on first telemetry-enabled scan

**Purpose:** Differentiate unique users from repeated scans by the same user

**Privacy Guarantees:**

- ✅ Random UUID — no correlation to user identity
- ✅ Stored locally — never transmitted to third parties
- ✅ Not linked to email, username, or IP address
- ✅ Rotating IDs — users can regenerate at any time

**Regeneration:**

```bash
rm ~/.jmo-security/telemetry-id
# New ID created on next scan
```

---

## What We NEVER Track

**NEVER collected:**

- ❌ Repository names, paths, or URLs
- ❌ Finding details (secrets, vulnerabilities, code snippets)
- ❌ File names or directory structures
- ❌ Suppression rules or exclusion patterns
- ❌ IP addresses or network information
- ❌ User names, email addresses, or identifiers
- ❌ Configuration values (API tokens, endpoints)
- ❌ Error messages or stack traces
- ❌ Environment variables
- ❌ Git commit history or branch names
- ❌ Exact scan durations (only bucketed: `<5min`, `5-15min`, etc.)
- ❌ Exact finding counts (only bucketed: `0`, `1-10`, `10-100`, etc.)

**Example of what we DON'T send:**

```json
// ❌ NEVER SENT
{
  "repo_name": "company-backend",
  "repo_path": "/home/user/projects/api",
  "finding": "AWS_SECRET_ACCESS_KEY found in config.py:42",
  "secret_value": "AKIAIOSFODNN7EXAMPLE",
  "file_path": "/home/user/projects/api/config.py",
  "user_email": "user@company.com",
  "ip_address": "192.168.1.100",
  "error_message": "Traceback (most recent call last)..."
}
```

**What we DO send (from same scan):**

```json
// ✅ ACTUALLY SENT
{
  "event": "scan.started",
  "version": "0.7.0",
  "platform": "Linux",
  "python_version": "3.11",
  "anonymous_id": "a7f3c8e2-4b1d-4f9e-8c3a-2d5e7f9b1a3c",
  "timestamp": "2025-10-19T14:32:00Z",
  "metadata": {
    "mode": "cli",
    "profile": "balanced",
    "tools": ["trufflehog", "semgrep", "trivy", "syft", "checkov", "hadolint", "zap", "nuclei"],
    "target_types": {
      "repos": 3,
      "images": 1,
      "urls": 0,
      "iac": 0,
      "gitlab": 0,
      "k8s": 0
    },
    "ci_detected": false,
    "multi_target_scan": true,
    "compliance_usage": true,
    "total_targets_bucket": "2-5",
    "scan_frequency_hint": "daily"
  }
}
```

---

## Architecture Overview

### Phase 1: GitHub Gist Backend (MVP for v0.7.0)

```text
┌─────────────┐         ┌─────────────────┐         ┌───────────────┐
│ jmo CLI     │ ──POST──▶ GitHub Gist API │ ──────▶ │ Private Gist  │
│ (telemetry) │         │ (HTTP POST)     │         │ (JSON Lines)  │
└─────────────┘         └─────────────────┘         └───────────────┘
                                                            │
                                                            ▼
                                                     ┌──────────────┐
                                                     │ Analysis     │
                                                     │ (jq/Python)  │
                                                     └──────────────┘
```

**How it works:**

1. User enables telemetry in `jmo.yml` (opt-in during wizard or manual edit)
2. Tool sends `POST https://api.github.com/gists/{gist_id}` with event JSON
3. Gist appends event to JSONL file (one event per line)
4. Maintainer downloads Gist periodically and analyzes with `jq` or Python

**Pros:**

- ✅ 100% free (GitHub Gists have no rate limits for authenticated writes)
- ✅ Zero infrastructure (no servers to maintain)
- ✅ Simple implementation (stdlib `urllib` only, no dependencies)
- ✅ Private by default (Gist visibility controlled by maintainer)

**Cons:**

- ⚠️ Not designed for high-volume writes (but fine for telemetry)
- ⚠️ Manual analysis (no real-time dashboards)

---

## Step-by-Step Implementation

### Phase 1: GitHub Gist Backend Setup

#### Step 1.1: Create SECRET Gist (Private)

**IMPORTANT: Use a SECRET Gist, not a public one.**

**Why SECRET?**

- ✅ Privacy & security (anonymous UUIDs remain private, not searchable)
- ✅ Business intelligence protection (usage patterns, adoption rates stay private)
- ✅ GDPR/CCPA compliance (access control, no third-party scraping)
- ✅ You can always make it public later (for transparency reports), but cannot make public Gists private

**Steps:**

1. Go to <https://gist.github.com/> (logged in as maintainer)
2. Click **"New gist"**
3. Set filename: `jmo-telemetry-events.jsonl`
4. Add initial content:

   ```json
   {"event": "telemetry.initialized", "timestamp": "2025-10-19T00:00:00Z", "message": "JMo Security Telemetry Backend"}
   ```

5. Set visibility: **"Create secret gist"** (NOT "Create public gist")
6. Click **"Create secret gist"**
7. Copy the Gist ID from URL: `https://gist.github.com/{username}/{GIST_ID}`

   Example: `https://gist.github.com/jimmy058910/fc897ef9a7f7ed40d001410fa369a1e1` → Gist ID = `fc897ef9a7f7ed40d001410fa369a1e1`

#### Step 1.2: Generate GitHub Personal Access Token (PAT)

1. Go to <https://github.com/settings/tokens>
2. Click **"Generate new token (classic)"**
3. Set note: `JMo Security Telemetry (Gist Write)`
4. Set expiration: `No expiration` (or `1 year` with renewal reminder)
5. Select scopes:
   - ✅ `gist` — Create and update gists
6. Click **"Generate token"**
7. Copy the token (starts with `ghp_...`)

**IMPORTANT:** Store token securely. It will only be shown once.

#### Step 1.3: Configure Gist Endpoint

Create environment variable with Gist ID and token:

```bash
# Add to ~/.bashrc or ~/.zshrc
export JMO_TELEMETRY_GIST_ID="abc123def456"
export JMO_TELEMETRY_GITHUB_TOKEN="ghp_YOUR_TOKEN_HERE"

# Reload shell
source ~/.bashrc
```

**For production:** Store token in GitHub Secrets for CI/CD, or use environment-specific config.

#### Step 1.4: Test Gist Write Access

```bash
# Test appending to Gist
curl -X PATCH "https://api.github.com/gists/$JMO_TELEMETRY_GIST_ID" \
  -H "Authorization: token $JMO_TELEMETRY_GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "files": {
      "jmo-telemetry-events.jsonl": {
        "content": "{\"event\": \"test\", \"timestamp\": \"2025-10-19T12:00:00Z\"}\n"
      }
    }
  }'
```

**Expected Response:** HTTP 200 with Gist metadata JSON

**Verify:**

```bash
# View Gist contents
gh gist view $JMO_TELEMETRY_GIST_ID
# Should show test event appended
```

---

### Phase 2: Core Telemetry Module

#### Step 2.1: Create `scripts/core/telemetry.py`

**File:** `scripts/core/telemetry.py`

**Complete Implementation:**

```python
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
    return config.get("telemetry", {}).get("enabled", False)


def send_event(
    event_type: str,
    metadata: Dict[str, Any],
    config: Dict[str, Any],
    version: str = "0.7.0"
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
        target=_send_event_async,
        args=(event_type, metadata, version),
        daemon=True
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
            "metadata": metadata
        }

        # Read current Gist content (to append, not overwrite)
        current_content = _get_gist_content()

        # Append new event (JSONL format: one JSON object per line)
        new_content = current_content + json.dumps(event) + "\n"

        # Update Gist via PATCH request
        data = json.dumps({
            "files": {
                TELEMETRY_FILE: {
                    "content": new_content
                }
            }
        }).encode("utf-8")

        req = request.Request(
            TELEMETRY_ENDPOINT,
            data=data,
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Content-Type": "application/json",
                "User-Agent": f"JMo-Security/{version}"
            },
            method="PATCH"
        )

        # Send request with 2-second timeout (don't block scans)
        with request.urlopen(req, timeout=2) as response:
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
                "User-Agent": "JMo-Security"
            }
        )

        with request.urlopen(req, timeout=2) as response:
            gist_data = json.loads(response.read().decode("utf-8"))
            return gist_data.get("files", {}).get(TELEMETRY_FILE, {}).get("content", "")

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
            version="0.7.0-dev"
        )
        print("✅ Event sent (check Gist in a few seconds)")

    elif command == "check":
        # Check telemetry configuration
        print(f"GIST_ID: {GIST_ID or '(not set)'}")
        print(f"GITHUB_TOKEN: {'***' + GITHUB_TOKEN[-4:] if GITHUB_TOKEN else '(not set)'}")
        print(f"TELEMETRY_ENDPOINT: {TELEMETRY_ENDPOINT or '(not configured)'}")
        print(f"Anonymous ID: {get_anonymous_id()}")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
```

#### Step 2.2: Test Telemetry Module

```bash
# Check configuration
python3 scripts/core/telemetry.py check

# Expected output:
# GIST_ID: abc123def456
# GITHUB_TOKEN: ***4567
# TELEMETRY_ENDPOINT: https://api.github.com/gists/abc123def456
# Anonymous ID: a7f3c8e2-4b1d-4f9e-8c3a-2d5e7f9b1a3c

# Send test event
python3 scripts/core/telemetry.py test

# Expected output:
# Sending test telemetry event...
# ✅ Event sent (check Gist in a few seconds)

# Verify in Gist
gh gist view $JMO_TELEMETRY_GIST_ID
# Should show test event appended
```

---

### Phase 3: Wizard Integration

#### Step 3.1: Add Telemetry Opt-In Prompt to Wizard

**File:** `scripts/cli/wizard.py`

**Location:** After profile selection, before scan execution

**Add Function:**

```python
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
```

**Update `run_wizard()` Function:**

```python
def run_wizard(args):
    """Interactive wizard main flow."""
    import yaml
    from pathlib import Path
    from scripts.core.telemetry import send_event
    from scripts.core.config import load_config

    wizard_start_time = time.time()

    # ... existing wizard logic (profile selection, target configuration) ...

    # Check if telemetry preference already set
    config_path = Path("jmo.yml")
    if config_path.exists():
        config = load_config(str(config_path))
        telemetry_set = "telemetry" in config and "enabled" in config.get("telemetry", {})
    else:
        telemetry_set = False
        config = {}

    # Prompt for telemetry on first run
    if not telemetry_set:
        telemetry_enabled = prompt_telemetry_opt_in()

        # Update config with telemetry preference
        config["telemetry"] = {"enabled": telemetry_enabled}

        # Write to jmo.yml
        if config_path.exists():
            config.update(load_config(str(config_path)))

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        print(f"\n✅ Telemetry {'enabled' if telemetry_enabled else 'disabled'}.")
        print(f"   You can change this later in {config_path}\n")

    # ... existing wizard logic (execution, artifact generation) ...

    # Send wizard.completed event (if telemetry enabled)
    wizard_duration = int(time.time() - wizard_start_time)
    send_event(
        "wizard.completed",
        {
            "profile_selected": selected_profile,
            "execution_mode": execution_mode,  # "docker" or "native"
            "artifact_generated": artifact_type,  # "makefile", "shell", "gha", or None
            "duration_seconds": wizard_duration
        },
        config,
        version=__version__
    )
```

---

### Phase 4: CLI Integration

#### Step 4.1: Instrument `jmo scan` Command

**File:** `scripts/cli/jmo.py`

**Import Telemetry Module:**

```python
from scripts.core.telemetry import send_event, bucket_duration, bucket_findings
```

**Update `cmd_scan()` Function:**

```python
def cmd_scan(args, config):
    """Main scan command with telemetry instrumentation."""
    import time

    # Detect execution mode
    mode = "wizard" if getattr(args, "from_wizard", False) else "cli"
    if os.environ.get("DOCKER_CONTAINER") == "1":
        mode = "docker"

    # Collect all targets (repos, images, URLs, IaC, GitLab, K8s)
    repos = _iter_repos(args)
    images = _iter_images(args)
    urls = _iter_urls(args)
    iac_files = _iter_iac(args)
    gitlab_repos = _iter_gitlab(args)
    k8s_contexts = _iter_k8s(args)

    # Get profile configuration
    profile_name = args.profile_name or config.get("default_profile", "balanced")
    profile_config = config.get("profiles", {}).get(profile_name, {})
    tools = profile_config.get("tools", config.get("tools", []))

    # Send scan.started event
    send_event("scan.started", {
        "mode": mode,
        "profile": profile_name,
        "tools": tools,
        "target_types": {
            "repos": len(repos),
            "images": len(images),
            "urls": len(urls),
            "iac": len(iac_files),
            "gitlab": len(gitlab_repos),
            "k8s": len(k8s_contexts)
        }
    }, config, version=__version__)

    # Run scan
    scan_start_time = time.time()
    tool_statuses = {}  # {tool_name: success_bool}

    # ... existing scan logic (tool invocation, parallel execution) ...

    # Track tool failures
    for tool_name, success in tool_statuses.items():
        if not success:
            send_event("tool.failed", {
                "tool": tool_name,
                "failure_type": "timeout",  # or "crash" or "non_zero_exit"
                "exit_code": None,  # or actual exit code
                "profile": profile_name
            }, config, version=__version__)

    # Calculate scan metrics
    scan_duration = time.time() - scan_start_time
    total_findings = 0  # Count findings from all tools (if available)

    # Send scan.completed event
    send_event("scan.completed", {
        "mode": mode,
        "profile": profile_name,
        "duration_bucket": bucket_duration(scan_duration),
        "tools_succeeded": sum(1 for s in tool_statuses.values() if s),
        "tools_failed": sum(1 for s in tool_statuses.values() if not s),
        "total_findings_bucket": bucket_findings(total_findings)
    }, config, version=__version__)
```

#### Step 4.2: Instrument `jmo report` Command

**Update `cmd_report()` Function:**

```python
def cmd_report(args, config):
    """Report generation with telemetry instrumentation."""
    from scripts.core.normalize_and_report import gather_results

    # ... existing report logic ...

    # Gather results to count findings
    findings = gather_results(args.results_dir, config)
    findings_count = len(findings)

    # Detect output formats
    output_formats = []
    if args.json or config.get("outputs", {}).get("json", True):
        output_formats.append("json")
    if args.md or config.get("outputs", {}).get("md", True):
        output_formats.append("md")
    if args.html or config.get("outputs", {}).get("html", True):
        output_formats.append("html")
    if args.sarif or config.get("outputs", {}).get("sarif", False):
        output_formats.append("sarif")

    # Check if suppressions were used
    suppressions_used = (Path(args.results_dir) / "jmo.suppress.yml").exists()

    # Check if compliance enrichment is enabled
    compliance_enabled = True  # Always enabled in v0.5.1+

    # Send report.generated event
    send_event("report.generated", {
        "output_formats": output_formats,
        "findings_bucket": bucket_findings(findings_count),
        "suppressions_used": suppressions_used,
        "compliance_enabled": compliance_enabled
    }, config, version=__version__)
```

---

### Phase 5: Docker Integration

#### Step 5.1: Add Docker Environment Detection

**File:** `Dockerfile`, `Dockerfile.slim`, `Dockerfile.alpine`

**Add Environment Variable:**

```dockerfile
# Dockerfile (all variants)
ENV DOCKER_CONTAINER=1
```

This allows telemetry module to detect Docker execution mode via:

```python
if os.environ.get("DOCKER_CONTAINER") == "1":
    mode = "docker"
```

#### Step 5.2: Docker Telemetry Configuration

**Option 1: Mount Telemetry ID (Persistent Anonymous ID)**

```bash
docker run --rm \
  -v $(pwd):/scan \
  -v ~/.jmo-security:/root/.jmo-security \
  -e JMO_TELEMETRY_GIST_ID="$JMO_TELEMETRY_GIST_ID" \
  -e JMO_TELEMETRY_GITHUB_TOKEN="$JMO_TELEMETRY_GITHUB_TOKEN" \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

**Option 2: Disable Telemetry in Docker (CI/CD)**

```bash
docker run --rm \
  -v $(pwd):/scan \
  -e JMO_TELEMETRY_DISABLE=1 \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

---

### Phase 6: Configuration Schema

#### Step 6.1: Update `jmo.yml` Schema

**Add Telemetry Section:**

```yaml
# jmo.yml
default_profile: balanced

# Telemetry (opt-in, anonymous usage statistics)
telemetry:
  enabled: false  # Default: false (opt-in only)
  # Privacy policy: https://jmotools.com/privacy
  # Full details: docs/TELEMETRY_IMPLEMENTATION_GUIDE.md

tools:
  - trufflehog
  - semgrep
  - syft
  - trivy
  - checkov
  - hadolint
  - zap
  - nuclei

outputs:
  - json
  - md
  - html
  - sarif

profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]
    timeout: 300
    threads: 8
  # ... other profiles ...
```

#### Step 6.2: Document in USER_GUIDE.md

**File:** `docs/USER_GUIDE.md`

**Add Section:**

```markdown
## Telemetry Configuration

JMo Security supports **opt-in, anonymous telemetry** to help prioritize features and identify common failures.

### Enabling Telemetry

**Option 1: Via Wizard (Recommended)**

```bash
jmotools wizard
# Answer 'y' when prompted for telemetry
```

**Option 2: Manual Edit (jmo.yml)**

```yaml
telemetry:
  enabled: true
```

**Option 3: Environment Variable (Temporary)**

```bash
export JMO_TELEMETRY_DISABLE=0  # Enable
export JMO_TELEMETRY_DISABLE=1  # Disable
```

### What We Collect

- Tool usage (which tools ran)
- Scan duration (bucketed: <5min, 5-15min, etc.)
- Execution mode (CLI, Docker, Wizard)
- Platform (Linux, macOS, Windows)
- Target type counts (repos, images, URLs, etc.)

### What We DON'T Collect

- ❌ Repository names or paths
- ❌ Finding details or secrets
- ❌ IP addresses or user info
- ❌ Configuration values

**Privacy Policy:** <https://jmotools.com/privacy>

**Full Details:** [docs/TELEMETRY_IMPLEMENTATION_GUIDE.md](TELEMETRY_IMPLEMENTATION_GUIDE.md)
```

---

### Phase 7: Testing & Verification

#### Step 7.1: Local Testing Checklist

- [ ] **Gist backend configured** — `JMO_TELEMETRY_GIST_ID` and `JMO_TELEMETRY_GITHUB_TOKEN` set
- [ ] **Telemetry module tests pass** — `python3 scripts/core/telemetry.py test`
- [ ] **Wizard opt-in prompt displays** — `jmotools wizard` (first run)
- [ ] **Telemetry enabled in jmo.yml** — `telemetry.enabled: true`
- [ ] **CLI sends scan.started event** — `jmo scan --repo . --profile fast`
- [ ] **CLI sends scan.completed event** — Scan finishes successfully
- [ ] **CLI sends tool.failed event** — Tool timeout/crash occurs
- [ ] **Wizard sends wizard.completed event** — Wizard completes
- [ ] **Report sends report.generated event** — `jmo report ./results`
- [ ] **Events appear in Gist** — `gh gist view $JMO_TELEMETRY_GIST_ID`
- [ ] **Anonymous ID persists** — `cat ~/.jmo-security/telemetry-id`
- [ ] **Telemetry can be disabled** — `export JMO_TELEMETRY_DISABLE=1`

#### Step 7.2: Docker Testing Checklist

- [ ] **Docker detects execution mode** — `mode: "docker"` in events
- [ ] **Docker telemetry can be disabled** — `-e JMO_TELEMETRY_DISABLE=1`
- [ ] **Docker uses container-specific ID** — Different UUID per container (unless mounted)
- [ ] **Docker respects mounted telemetry ID** — `-v ~/.jmo-security:/root/.jmo-security`

#### Step 7.3: CI/CD Testing Checklist

- [ ] **CI telemetry disabled by default** — `JMO_TELEMETRY_DISABLE=1` in workflows
- [ ] **CI scans complete without telemetry** — No errors in logs

---

## Data Analysis Guide

### Download Telemetry Events

```bash
# Download JSONL from GitHub Gist
gh gist view $JMO_TELEMETRY_GIST_ID --raw > telemetry-events.jsonl

# Or via curl
curl -H "Authorization: token $JMO_TELEMETRY_GITHUB_TOKEN" \
  "https://api.github.com/gists/$JMO_TELEMETRY_GIST_ID" | \
  jq -r '.files["jmo-telemetry-events.jsonl"].content' > telemetry-events.jsonl
```

### Analysis Examples (jq)

```bash
# Count events by type
jq -r '.event' telemetry-events.jsonl | sort | uniq -c

# Most popular profiles
jq -r 'select(.event == "scan.started") | .metadata.profile' telemetry-events.jsonl | \
  sort | uniq -c | sort -rn

# Failure rate by tool
jq -r 'select(.event == "tool.failed") | .metadata.tool' telemetry-events.jsonl | \
  sort | uniq -c | sort -rn

# Platform distribution
jq -r '.platform' telemetry-events.jsonl | sort | uniq -c

# Execution mode popularity
jq -r 'select(.event == "scan.started") | .metadata.mode' telemetry-events.jsonl | \
  sort | uniq -c

# Average scan duration (bucketed)
jq -r 'select(.event == "scan.completed") | .metadata.duration_bucket' telemetry-events.jsonl | \
  sort | uniq -c

# Multi-target adoption (count of scans with >1 target type)
jq -r 'select(.event == "scan.started") |
  .metadata.target_types |
  to_entries |
  map(select(.value > 0)) |
  length' telemetry-events.jsonl | \
  awk '{if($1>1) multi++; else single++} END {print "Single:", single, "Multi:", multi}'

# Wizard artifact generation
jq -r 'select(.event == "wizard.completed") | .metadata.artifact_generated' telemetry-events.jsonl | \
  sort | uniq -c

# Output format popularity
jq -r 'select(.event == "report.generated") | .metadata.output_formats[]' telemetry-events.jsonl | \
  sort | uniq -c | sort -rn
```

### Python Analysis Script

```python
#!/usr/bin/env python3
"""Analyze telemetry events from JSONL file."""

import json
from collections import Counter
from pathlib import Path

def analyze_telemetry(jsonl_path: str):
    """Analyze telemetry events and print summary statistics."""
    events = []
    with open(jsonl_path) as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    print(f"Total Events: {len(events)}")
    print()

    # Event type distribution
    event_types = Counter(e["event"] for e in events)
    print("Event Types:")
    for event, count in event_types.most_common():
        print(f"  {event}: {count}")
    print()

    # Unique users
    unique_users = len(set(e["anonymous_id"] for e in events))
    print(f"Unique Users: {unique_users}")
    print()

    # Platform distribution
    platforms = Counter(e["platform"] for e in events)
    print("Platforms:")
    for platform, count in platforms.most_common():
        print(f"  {platform}: {count} ({count/len(events)*100:.1f}%)")
    print()

    # Profile popularity
    scan_events = [e for e in events if e["event"] == "scan.started"]
    profiles = Counter(e["metadata"]["profile"] for e in scan_events)
    print("Profiles:")
    for profile, count in profiles.most_common():
        print(f"  {profile}: {count} ({count/len(scan_events)*100:.1f}%)")
    print()

    # Tool failures
    fail_events = [e for e in events if e["event"] == "tool.failed"]
    if fail_events:
        tools_failed = Counter(e["metadata"]["tool"] for e in fail_events)
        print("Tool Failures:")
        for tool, count in tools_failed.most_common():
            print(f"  {tool}: {count}")
    print()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_telemetry.py telemetry-events.jsonl")
        sys.exit(1)
    analyze_telemetry(sys.argv[1])
```

---

## Troubleshooting

### Telemetry Not Sending

**Symptom:** No events appear in Gist after scans

**Check:**

```bash
# 1. Verify environment variables
echo $JMO_TELEMETRY_GIST_ID
echo $JMO_TELEMETRY_GITHUB_TOKEN

# 2. Check telemetry is enabled
grep -A1 "telemetry:" jmo.yml
# Should show: enabled: true

# 3. Verify anonymous ID exists
cat ~/.jmo-security/telemetry-id

# 4. Test module directly
python3 scripts/core/telemetry.py test

# 5. Check Gist permissions
curl -H "Authorization: token $JMO_TELEMETRY_GITHUB_TOKEN" \
  "https://api.github.com/gists/$JMO_TELEMETRY_GIST_ID"
```

### Gist API Rate Limiting

**Symptom:** HTTP 429 errors in logs

**Solution:** GitHub Gist API has no documented rate limits, but if you hit issues:

1. Reduce event frequency (batch events)
2. Migrate to Cloudflare Workers (Phase 2)

### Anonymous ID Not Persisting

**Symptom:** Different UUID on every scan

**Check:**

```bash
# Verify file permissions
ls -la ~/.jmo-security/

# Manually create directory
mkdir -p ~/.jmo-security
chmod 700 ~/.jmo-security
```

### Docker Telemetry Not Working

**Symptom:** No events from Docker scans

**Check:**

```bash
# Verify environment variables passed to container
docker run --rm \
  -e JMO_TELEMETRY_GIST_ID="$JMO_TELEMETRY_GIST_ID" \
  -e JMO_TELEMETRY_GITHUB_TOKEN="$JMO_TELEMETRY_GITHUB_TOKEN" \
  ghcr.io/jimmy058910/jmo-security:latest \
  python3 scripts/core/telemetry.py check
```

---

## Future: Cloudflare Workers Migration

When usage scales (10k+ users), migrate to Cloudflare Workers + D1 backend for:

- ✅ Real-time analytics dashboards
- ✅ Proper SQLite database storage
- ✅ 100k requests/day free tier
- ✅ Edge-optimized (fast globally)

**Setup Guide:** See [docs/TELEMETRY.md](TELEMETRY.md#cloudflare-worker-setup) lines 922-1058

**Migration Steps:**

1. Create Cloudflare D1 database
2. Deploy Worker function
3. Update `TELEMETRY_ENDPOINT` in `scripts/core/telemetry.py`
4. No client code changes required (same event format)

---

## Summary

### Implementation Checklist

**Phase 1: Backend Setup**

- [ ] Create private GitHub Gist
- [ ] Generate GitHub PAT with `gist` scope
- [ ] Set `JMO_TELEMETRY_GIST_ID` and `JMO_TELEMETRY_GITHUB_TOKEN` env vars
- [ ] Test Gist write access

**Phase 2: Core Module**

- [ ] Create `scripts/core/telemetry.py`
- [ ] Implement `send_event()`, `get_anonymous_id()`, bucketing functions
- [ ] Test module: `python3 scripts/core/telemetry.py test`

**Phase 3: Wizard Integration**

- [ ] Add `prompt_telemetry_opt_in()` function
- [ ] Update `run_wizard()` to prompt on first run
- [ ] Send `wizard.completed` event

**Phase 4: CLI Integration**

- [ ] Instrument `cmd_scan()` with `scan.started` and `scan.completed` events
- [ ] Instrument tool failures with `tool.failed` events
- [ ] Instrument `cmd_report()` with `report.generated` event

**Phase 5: Docker Integration**

- [ ] Add `ENV DOCKER_CONTAINER=1` to Dockerfiles
- [ ] Document telemetry configuration in Docker README

**Phase 6: Configuration**

- [ ] Update `jmo.yml` schema with `telemetry` section
- [ ] Document in `docs/USER_GUIDE.md`
- [ ] Update privacy policy

**Phase 7: Testing**

- [ ] Test local CLI telemetry
- [ ] Test wizard telemetry
- [ ] Test Docker telemetry
- [ ] Verify events in Gist
- [ ] Test opt-out mechanisms

---

**Document Version:** 1.0.0
**Last Updated:** 2025-10-19
**Next Review:** 2025-11-01 (pre-v0.7.0 release)
**Maintainer:** James Moceri (hello@jmotools.com)
