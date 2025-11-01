# JMo Security — Telemetry Implementation Guide

**Version:** 1.0.0 (Draft for v0.7.0)
**Status:** Implementation Pending
**Privacy Policy:** <https://jmotools.com/privacy>

---

## Table of Contents

- [Overview](#overview)
- [Privacy-First Philosophy](#privacy-first-philosophy)
- [What We Collect](#what-we-collect)
- [What We DON'T Collect](#what-we-dont-collect)
- [Opt-In/Opt-Out Guide](#opt-inopt-out-guide)
- [Technical Architecture](#technical-architecture)
- [Data Analysis and Usage](#data-analysis-and-usage)
- [Transparency Reports](#transparency-reports)
- [Frequently Asked Questions](#frequently-asked-questions)

---

## Overview

JMo Security implements **opt-out, anonymous, privacy-respecting telemetry** to help prioritize features, identify common failures, and improve user experience. Telemetry is:

- **Enabled by default** — Users can opt-out anytime (see below)
- **Auto-disabled in CI/CD** — Never collects in automation environments
- **100% anonymous** — No personally identifiable information (PII)
- **Open source** — Collection and storage code is public
- **User-controlled** — Easy opt-out via env var or config
- **Minimal** — Only essential usage data, no sensitive findings

**Inspiration:** We follow industry best practices from Homebrew, VS Code, npm, and pip.

**Goal:** Understand which tools users rely on, which profiles are popular, and where failures occur to build a better security toolkit.

---

## Privacy-First Philosophy

### Core Principles

1. **Opt-Out Model (v0.7.1+)** — Telemetry enabled by default, users can easily opt-out. Auto-disables in CI/CD.
2. **Anonymous by Design** — No user names, IP addresses, repository names, or finding details.
3. **Minimal Collection** — Only data necessary to improve the tool.
4. **Transparent Storage** — Data stored in privacy-respecting infrastructure (GitHub Gist → Cloudflare D1).
5. **Public Reports** — Quarterly transparency reports with aggregated statistics.
6. **User Control** — Easy opt-out via environment variable or config, no hidden trackers.

### Industry Benchmarks

| Tool | Telemetry Model | Default State |
|------|-----------------|---------------|
| Homebrew | Opt-out, anonymous | **Enabled** |
| VS Code | Opt-out, anonymous | **Enabled** (can disable) |
| npm | Opt-out, anonymous | **Enabled** |
| pip | No telemetry | N/A |
| **JMo Security** | Opt-out, anonymous | **Enabled** (v0.7.1+) |

**Rationale:** Opt-out provides better data for feature prioritization (80-90% vs 5-15% adoption) while respecting user privacy. Auto-disables in CI/CD environments. Users see informative banner on first 3 scans.

---

## What We Collect

### Event Types and Metadata

#### 1. `scan.started`

**When:** User runs `jmo scan` or `jmotools {fast,balanced,full}`

**Metadata:**

```json
{
  "event": "scan.started",
  "version": "0.7.0",
  "platform": "Linux",
  "python_version": "3.11",
  "anonymous_id": "uuid-v4-random",
  "timestamp": "2025-10-19T14:32:00Z",
  "metadata": {
    "mode": "wizard",                     // "cli" | "docker" | "wizard"
    "profile": "balanced",                // "fast" | "balanced" | "deep" | "custom"
    "tools": ["trufflehog", "semgrep"],   // Tool list (no outputs)
    "target_types": {
      "repos": 3,                         // Count only, no names
      "images": 1,
      "urls": 0,
      "iac": 0,
      "gitlab": 0,
      "k8s": 0
    }
  }
}
```

**Privacy:** No repository names, file paths, or URLs. Only **counts** per target type.

---

#### 2. `scan.completed`

**When:** Scan finishes successfully or fails

**Metadata:**

```json
{
  "event": "scan.completed",
  "version": "0.7.0",
  "platform": "macOS",
  "python_version": "3.12",
  "anonymous_id": "uuid-v4-random",
  "timestamp": "2025-10-19T14:48:00Z",
  "metadata": {
    "mode": "cli",
    "profile": "fast",
    "duration_bucket": "5-15min",          // "<5min" | "5-15min" | "15-30min" | ">30min"
    "tools_succeeded": 8,
    "tools_failed": 0,
    "total_findings_bucket": "10-100"      // "0" | "1-10" | "10-100" | "100-1000" | ">1000"
  }
}
```

**Privacy:** Duration and finding counts are **bucketed** to prevent fingerprinting.

---

#### 3. `tool.failed`

**When:** A tool times out, crashes, or returns non-zero exit code

**Metadata:**

```json
{
  "event": "tool.failed",
  "version": "0.7.0",
  "platform": "Linux",
  "python_version": "3.10",
  "anonymous_id": "uuid-v4-random",
  "timestamp": "2025-10-19T15:02:00Z",
  "metadata": {
    "tool": "trivy",
    "failure_type": "timeout",             // "timeout" | "crash" | "non_zero_exit"
    "exit_code": null,
    "profile": "balanced"
  }
}
```

**Privacy:** No error messages, stack traces, or file paths. Only tool name and failure type.

---

#### 4. `wizard.completed`

**When:** User completes interactive wizard

**Metadata:**

```json
{
  "event": "wizard.completed",
  "version": "0.7.0",
  "platform": "Linux",
  "python_version": "3.11",
  "anonymous_id": "uuid-v4-random",
  "timestamp": "2025-10-19T16:12:00Z",
  "metadata": {
    "profile_selected": "balanced",
    "execution_mode": "docker",            // "docker" | "native"
    "artifact_generated": "makefile",      // "makefile" | "shell" | "gha" | null
    "duration_seconds": 120
  }
}
```

**Privacy:** No wizard inputs, target paths, or configuration values.

---

#### 5. `report.generated`

**When:** User runs `jmo report` or `jmo ci`

**Metadata:**

```json
{
  "event": "report.generated",
  "version": "0.7.0",
  "platform": "macOS",
  "python_version": "3.12",
  "anonymous_id": "uuid-v4-random",
  "timestamp": "2025-10-19T17:00:00Z",
  "metadata": {
    "output_formats": ["json", "md", "html", "sarif"],  // Which reporters ran
    "findings_bucket": "100-1000",
    "suppressions_used": true,                          // Boolean only
    "compliance_enabled": true
  }
}
```

**Privacy:** No finding details, suppression rules, or compliance mappings.

---

### Anonymous ID

**What is it?**
A randomly generated UUID (version 4) created once per installation and stored locally:

```bash
~/.jmo-security/telemetry-id
```

**Example ID:**
`a7f3c8e2-4b1d-4f9e-8c3a-2d5e7f9b1a3c`

**Purpose:**
Differentiate unique users from repeated scans by the same user.

**Privacy:**

- ✅ Random UUID — no correlation to user identity
- ✅ Stored locally — never transmitted to third parties
- ✅ Not linked to email, username, or IP address
- ✅ Rotating IDs — users can regenerate at any time

**How to regenerate:**

```bash
rm ~/.jmo-security/telemetry-id
# New ID created on next scan
```

---

## What We DON'T Collect

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

**Example of what we DON'T send:**

```json
// ❌ NEVER SENT
{
  "repo_name": "company-backend",
  "finding": "AWS_SECRET_ACCESS_KEY found in config.py:42",
  "file_path": "/home/user/projects/api/config.py",
  "secret_value": "AKIAIOSFODNN7EXAMPLE",
  "user_email": "user@company.com"
}
```

**What we DO send (from same scan):**

```json
// ✅ ACTUALLY SENT
{
  "event": "scan.completed",
  "platform": "Linux",
  "profile": "balanced",
  "duration_bucket": "5-15min",
  "tools_succeeded": 8,
  "total_findings_bucket": "10-100"
}
```

---

## Opt-In/Opt-Out Guide

### Initial Setup (First Run)

#### Wizard Mode (Recommended)

When running `jmotools wizard` for the first time, you'll see:

```text
╔══════════════════════════════════════════════════════════════╗
║            📊 Help Improve JMo Security                      ║
╚══════════════════════════════════════════════════════════════╝

We'd like to collect anonymous usage stats to prioritize features.

✅ What we collect:
   • Tool usage (which tools ran)
   • Scan duration (fast/slow)
   • Execution mode (CLI/Docker/Wizard)
   • Platform (Linux/macOS/Windows)

❌ What we DON'T collect:
   • Repository names or paths
   • Finding details or secrets
   • IP addresses or user info

📄 Privacy policy: https://jmotools.com/privacy
💡 You can change this later in jmo.yml

Enable anonymous telemetry? [y/N]:
```

**Default:** `N` (No) — Telemetry disabled unless you type `y`.

---

#### Manual Configuration

Edit `jmo.yml` to enable/disable telemetry:

```yaml
# jmo.yml
telemetry:
  enabled: true   # Set to false to disable
  # Privacy: https://jmotools.com/privacy
```

---

### Opt-In After Installation

**Enable telemetry:**

```bash
# Option 1: Edit jmo.yml manually
vi jmo.yml
# Set: telemetry.enabled: true

# Option 2: Use wizard
jmotools wizard
# Answer 'y' when prompted
```

**Verify telemetry is enabled:**

```bash
grep -A1 "telemetry:" jmo.yml
# Should show:
#   telemetry:
#     enabled: true
```

---

### Opt-Out (Disable Telemetry)

**Disable telemetry:**

```bash
# Option 1: Edit jmo.yml
vi jmo.yml
# Set: telemetry.enabled: false

# Option 2: Delete telemetry section
# Remove the entire telemetry block from jmo.yml

# Option 3: Set environment variable (temporary)
export JMO_TELEMETRY_DISABLE=1
```

**Verify telemetry is disabled:**

```bash
jmotools balanced --repos-dir ~/repos
# No telemetry events will be sent
```

**Delete anonymous ID (optional):**

```bash
rm ~/.jmo-security/telemetry-id
# Prevents correlation of future scans if you re-enable
```

---

### Docker Mode

**Telemetry in Docker containers:**

```bash
# Telemetry enabled (if jmo.yml has telemetry.enabled: true)
docker run --rm -v $(pwd):/scan \
  -v $(pwd)/jmo.yml:/app/jmo.yml \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced

# Telemetry disabled (override with environment variable)
docker run --rm -v $(pwd):/scan \
  -e JMO_TELEMETRY_DISABLE=1 \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

**Note:** Docker containers use a container-specific anonymous ID unless you mount `~/.jmo-security/`.

---

### CI/CD Environments

**Disable telemetry in CI/CD:**

```yaml
# .github/workflows/security-scan.yml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    env:
      JMO_TELEMETRY_DISABLE: 1  # Disable telemetry in CI
    steps:
      - name: Run security scan
        run: jmotools balanced --repos-dir .
```

**Why disable in CI?**

- CI builds generate high-volume, repetitive events
- CI environments often prohibit outbound HTTP requests
- Opt-in telemetry should reflect user choices, not CI automation

---

## Technical Architecture

### Backend Architecture (v1.0 — GitHub Gist MVP)

#### Phase 1: GitHub Gist (v0.7.0 — MVP)

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

1. User enables telemetry in `jmo.yml`
2. Tool sends `POST https://api.github.com/gists/{gist_id}` with event JSON
3. Gist appends event to JSONL file (one event per line)
4. Maintainer downloads Gist periodically and analyzes with `jq` or Python

**Pros:**

- ✅ 100% free (GitHub Gists have no rate limits for authenticated writes)
- ✅ Zero infrastructure (no servers to maintain)
- ✅ Simple implementation (stdlib `urllib` only)
- ✅ Private by default (Gist visibility controlled by maintainer)

**Cons:**

- ⚠️ Not designed for high-volume writes (but fine for telemetry)
- ⚠️ Manual analysis (no real-time dashboards)

---

#### Phase 2: Cloudflare Workers + D1 (v0.8.0+)

When usage scales (10k+ users), upgrade to serverless backend:

```text
┌─────────────┐         ┌─────────────────────┐         ┌─────────────┐
│ jmo CLI     │ ──POST──▶ Cloudflare Worker   │ ──────▶ │ Cloudflare  │
│ (telemetry) │         │ (Edge Function)     │         │ D1 (SQLite) │
└─────────────┘         └─────────────────────┘         └─────────────┘
                                                                │
                                                                ▼
                                                         ┌──────────────┐
                                                         │ Analytics    │
                                                         │ Dashboard    │
                                                         └──────────────┘
```

**Benefits:**

- ✅ Still 100% free (100k requests/day free tier)
- ✅ Real-time analytics (Cloudflare Analytics built-in)
- ✅ Proper database (Cloudflare D1 SQLite)
- ✅ Edge-optimized (fast globally)

**Setup:** 30-minute one-time deployment (see [Cloudflare Worker Setup](#cloudflare-worker-setup)).

---

### Client Implementation (Python)

**File:** `scripts/core/telemetry.py`

```python
import json
import platform
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from urllib import request
from urllib.error import URLError
import threading

# Telemetry endpoint (Gist API for MVP, Cloudflare Worker later)
TELEMETRY_ENDPOINT = "https://api.github.com/gists/{gist_id}"


def get_anonymous_id() -> str:
    """Get or create anonymous UUID (stored locally)."""
    id_file = Path.home() / ".jmo-security" / "telemetry-id"
    if id_file.exists():
        return id_file.read_text().strip()

    anon_id = str(uuid.uuid4())
    id_file.parent.mkdir(parents=True, exist_ok=True)
    id_file.write_text(anon_id)
    return anon_id


def is_telemetry_enabled(config: Dict[str, Any]) -> bool:
    """Check if telemetry is enabled in config or env var."""
    # Environment variable override (for CI/CD)
    import os
    if os.environ.get("JMO_TELEMETRY_DISABLE") == "1":
        return False

    return config.get("telemetry", {}).get("enabled", False)


def send_event(
    event_type: str,
    metadata: Dict[str, Any],
    config: Dict[str, Any],
    version: str = "0.7.0"
) -> None:
    """Send telemetry event (non-blocking)."""
    if not is_telemetry_enabled(config):
        return

    # Fire-and-forget in background thread
    threading.Thread(
        target=_send_event_async,
        args=(event_type, metadata, version),
        daemon=True
    ).start()


def _send_event_async(event_type: str, metadata: Dict[str, Any], version: str) -> None:
    """Send event to telemetry endpoint (background thread)."""
    try:
        event = {
            "event": event_type,
            "version": version,
            "platform": platform.system(),
            "python_version": f"{platform.python_version_tuple()[0]}.{platform.python_version_tuple()[1]}",
            "anonymous_id": get_anonymous_id(),
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Send to telemetry endpoint
        data = json.dumps(event).encode("utf-8")
        req = request.Request(
            TELEMETRY_ENDPOINT,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        # Timeout after 2 seconds (don't block scans)
        with request.urlopen(req, timeout=2) as response:
            pass  # Fire-and-forget

    except (URLError, TimeoutError, Exception):
        # Silently fail (never break user's workflow)
        pass
```

**Key Features:**

- ✅ **Non-blocking** — Background thread, never delays scans
- ✅ **Fail-silent** — Network errors don't break user workflows
- ✅ **2-second timeout** — Don't wait for slow networks
- ✅ **Zero dependencies** — Uses stdlib only (`urllib`, `threading`)

---

### Wizard Integration

**File:** `scripts/cli/wizard.py`

```python
def prompt_telemetry_opt_in() -> bool:
    """Prompt user to enable telemetry on first run."""
    print("\n" + "=" * 60)
    print("📊 Help Improve JMo Security")
    print("=" * 60)
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
    print("💡 You can change this later in jmo.yml")
    print()

    response = input("Enable anonymous telemetry? [y/N]: ").strip().lower()
    return response == "y"


def run_wizard(args):
    """Interactive wizard main flow."""
    # ... existing wizard logic ...

    # Check if telemetry preference already set
    config_path = Path("jmo.yml")
    if config_path.exists():
        config = yaml.safe_load(config_path.read_text())
        telemetry_set = "telemetry" in config and "enabled" in config.get("telemetry", {})
    else:
        telemetry_set = False

    # Prompt for telemetry on first run
    if not telemetry_set:
        telemetry_enabled = prompt_telemetry_opt_in()

        # Update jmo.yml with telemetry preference
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text())
        else:
            config = {}

        config["telemetry"] = {"enabled": telemetry_enabled}
        config_path.write_text(yaml.dump(config, default_flow_style=False))

        print(f"\n✅ Telemetry {'enabled' if telemetry_enabled else 'disabled'}.")
        print(f"   You can change this later in {config_path}\n")

    # ... continue wizard ...
```

**User Experience:**

1. User runs `jmotools wizard` for the first time
2. Wizard prompts for telemetry consent **before** scanning
3. User response saved to `jmo.yml`
4. Future wizard runs **skip** the prompt (preference already set)

---

### Event Instrumentation

**File:** `scripts/cli/jmo.py`

```python
from scripts.core.telemetry import send_event

def cmd_scan(args, config):
    """Main scan command."""
    # Detect execution mode
    mode = "wizard" if getattr(args, "from_wizard", False) else "cli"
    if os.environ.get("DOCKER_CONTAINER"):
        mode = "docker"

    # Collect targets (repos, images, URLs, etc.)
    repos = _iter_repos(args)
    images = _iter_images(args)
    urls = _iter_urls(args)
    iac_files = _iter_iac(args)
    gitlab_repos = _iter_gitlab(args)
    k8s_contexts = _iter_k8s(args)

    # Send scan.started event
    send_event("scan.started", {
        "mode": mode,
        "profile": args.profile_name,
        "tools": config["profiles"][args.profile_name]["tools"],
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
    start_time = time.time()
    statuses = {}

    # ... scan logic ...

    # Calculate duration bucket
    elapsed = time.time() - start_time
    duration_bucket = _duration_bucket(elapsed)

    # Send scan.completed event
    send_event("scan.completed", {
        "mode": mode,
        "profile": args.profile_name,
        "duration_bucket": duration_bucket,
        "tools_succeeded": len([t for t in statuses if statuses[t]]),
        "tools_failed": len([t for t in statuses if not statuses[t]])
    }, config, version=__version__)


def _duration_bucket(seconds: float) -> str:
    """Bucket scan duration for privacy."""
    if seconds < 300:
        return "<5min"
    elif seconds < 900:
        return "5-15min"
    elif seconds < 1800:
        return "15-30min"
    else:
        return ">30min"
```

**Privacy:** No exact durations sent — bucketed to prevent fingerprinting.

---

## Data Analysis and Usage

### How Maintainers Analyze Telemetry

**Download Gist events:**

```bash
# Download JSONL from GitHub Gist
gh gist view {gist-id} --raw > telemetry-events.jsonl
```

**Example analysis:**

```bash
# Count events by type
jq -r '.event' telemetry-events.jsonl | sort | uniq -c

# Most popular profiles
jq -r 'select(.event == "scan.started") | .metadata.profile' telemetry-events.jsonl | sort | uniq -c | sort -rn

# Failure rate by tool
jq -r 'select(.event == "tool.failed") | .metadata.tool' telemetry-events.jsonl | sort | uniq -c | sort -rn

# Platform distribution
jq -r '.platform' telemetry-events.jsonl | sort | uniq -c

# Execution mode popularity
jq -r 'select(.event == "scan.started") | .metadata.mode' telemetry-events.jsonl | sort | uniq -c
```

**Example insights:**

- **Top profiles:** 65% balanced, 25% fast, 10% deep
- **Top failures:** Trivy timeout (12%), ZAP crash (8%)
- **Platform split:** 70% Linux, 20% macOS, 10% Windows/WSL
- **Wizard adoption:** 40% wizard, 35% CLI, 25% Docker

**Actions:**

- Optimize slow profiles (increase default timeout for Trivy)
- Fix common failures (investigate ZAP crashes)
- Prioritize wizard features (40% of users)

---

## Transparency Reports

### Quarterly Public Reports

**Location:** <https://jmotools.com/transparency>

**Example Report (Q1 2026):**

```markdown
# JMo Security Telemetry Transparency Report — Q1 2026

**Reporting Period:** January 1 - March 31, 2026
**Opt-In Rate:** 18% (1,200 users out of 6,500 total)

## Summary Statistics

- **Total Scans:** 45,000
- **Unique Users:** 1,200 (anonymous IDs)
- **Platforms:** 68% Linux, 22% macOS, 10% Windows
- **Most Popular Profile:** Balanced (62%)
- **Execution Modes:** 42% CLI, 35% Wizard, 23% Docker

## Top Insights

1. **Wizard is key onboarding tool** — 35% of scans use wizard mode
2. **Trivy timeout issues** — 15% of scans report trivy timeouts (→ increase default timeout to 1200s in v0.7.1)
3. **Docker adoption growing** — 23% Docker usage (up from 18% in Q4 2025)

## Privacy Compliance

- ✅ Zero PII collected
- ✅ No user-identifiable data retained
- ✅ All data anonymized
- ✅ Gist access restricted to maintainers only

## Raw Data Sample

See anonymized event samples: https://jmotools.com/transparency/q1-2026/sample-events.json
```

---

## Frequently Asked Questions

### General

**Q: Why does JMo Security need telemetry?**
A: Telemetry helps us understand which tools users rely on, which profiles are popular, and where failures occur. This helps us prioritize features (e.g., should we optimize the wizard or CLI?) and fix common issues (e.g., trivy timeouts).

**Q: Is telemetry required?**
A: No. Telemetry is **disabled by default** and requires explicit opt-in. All features work without telemetry.

**Q: Can I trust that telemetry is actually anonymous?**
A: Yes. The telemetry code is open source. You can audit `scripts/core/telemetry.py` to verify exactly what data is sent.

---

### Privacy

**Q: Do you collect IP addresses?**
A: No. The telemetry endpoint (GitHub Gist API or Cloudflare Worker) does not log IP addresses, and we explicitly strip IPs from all data.

**Q: Can you identify me from the anonymous ID?**
A: No. The anonymous ID is a random UUID with no correlation to your identity. It only differentiates unique users from repeated scans.

**Q: Do you collect repository names or finding details?**
A: No. We **never** collect repository names, file paths, finding details, secrets, or vulnerabilities. Only aggregated counts (e.g., "10-100 findings").

**Q: What if I accidentally enabled telemetry?**
A: Disable it in `jmo.yml` or delete `~/.jmo-security/telemetry-id`. Past events cannot be correlated to you.

---

### Technical

**Q: Does telemetry slow down scans?**
A: No. Telemetry runs in a background thread with a 2-second timeout and fails silently on network errors.

**Q: What if the telemetry endpoint is down?**
A: Telemetry fails silently. Your scan continues normally.

**Q: Can I self-host the telemetry backend?**
A: Yes (advanced). You can deploy your own Cloudflare Worker and point `TELEMETRY_ENDPOINT` to your instance.

**Q: Does telemetry work in air-gapped environments?**
A: Yes. If the telemetry endpoint is unreachable (e.g., corporate firewall), events fail silently and scans continue.

---

### Compliance

**Q: Is telemetry GDPR-compliant?**
A: Yes. Anonymous UUIDs are not considered personal data under GDPR Article 4(1). No IP addresses, names, or identifiers are collected.

**Q: Is telemetry HIPAA-compliant?**
A: Yes. No protected health information (PHI) is collected.

**Q: Is telemetry SOC 2-compliant?**
A: Yes. Data is stored in privacy-respecting infrastructure (GitHub → Cloudflare) with restricted access.

---

## Implementation Roadmap

### v0.7.0 (Target: November 2025)

- [ ] Implement `scripts/core/telemetry.py` (stdlib only)
- [ ] Add wizard opt-in prompt (`scripts/cli/wizard.py`)
- [ ] Instrument 5 core events (scan.started, scan.completed, tool.failed, wizard.completed, report.generated)
- [ ] Update `jmo.yml` schema to include `telemetry.enabled`
- [ ] Create GitHub Gist backend (private)
- [ ] Write privacy policy page (<https://jmotools.com/privacy>)
- [ ] Update [docs/USER_GUIDE.md](USER_GUIDE.md) with telemetry documentation
- [ ] Add telemetry FAQ to [docs/index.md](index.md)

### v0.7.1 (Target: December 2025)

- [ ] Publish first transparency report (Q4 2025)
- [ ] Optimize based on telemetry insights (e.g., trivy timeout increase)

### v0.8.0 (Target: Q1 2026)

- [ ] Migrate to Cloudflare Workers + D1 backend
- [ ] Add real-time analytics dashboard (Cloudflare Analytics)
- [ ] Public metrics page (<https://jmotools.com/metrics>)

---

## Cloudflare Worker Setup

### For Maintainers: Deploying the Telemetry Backend (v0.8.0+)

### Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### Create D1 Database

```bash
# Create SQLite database
wrangler d1 create jmo-telemetry

# Create events table
wrangler d1 execute jmo-telemetry --command "
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  version TEXT NOT NULL,
  platform TEXT NOT NULL,
  python_version TEXT,
  anonymous_id TEXT NOT NULL,
  metadata TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_event_type ON events(event_type);
CREATE INDEX idx_timestamp ON events(timestamp);
CREATE INDEX idx_anonymous_id ON events(anonymous_id);
"
```

### Deploy Worker

**File:** `wrangler.toml`

```toml
name = "jmo-telemetry"
main = "src/index.js"
compatibility_date = "2025-10-19"

[[d1_databases]]
binding = "DB"
database_name = "jmo-telemetry"
database_id = "your-database-id"
```

**File:** `src/index.js`

```javascript
export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    try {
      const event = await request.json();

      // Validate event structure
      if (!event.event || !event.version || !event.anonymous_id) {
        return new Response("Invalid event", { status: 400 });
      }

      // Insert into D1 database
      await env.DB.prepare(
        "INSERT INTO events (event_type, version, platform, python_version, anonymous_id, metadata, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(
        event.event,
        event.version,
        event.platform,
        event.python_version || null,
        event.anonymous_id,
        JSON.stringify(event.metadata),
        event.timestamp
      ).run();

      return new Response("OK", {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*"
        }
      });
    } catch (error) {
      console.error("Telemetry error:", error);
      return new Response("Internal error", { status: 500 });
    }
  }
};
```

**Deploy:**

```bash
wrangler publish
# Returns: https://jmo-telemetry.your-account.workers.dev
```

**Update telemetry endpoint:**

```python
# scripts/core/telemetry.py
TELEMETRY_ENDPOINT = "https://jmo-telemetry.your-account.workers.dev"
```

**Test:**

```bash
curl -X POST https://jmo-telemetry.your-account.workers.dev \
  -H "Content-Type: application/json" \
  -d '{
    "event": "scan.started",
    "version": "0.8.0",
    "platform": "Linux",
    "python_version": "3.11",
    "anonymous_id": "test-uuid",
    "metadata": {"profile": "balanced"},
    "timestamp": "2025-10-19T12:00:00Z"
  }'
```

---

## Conclusion

JMo Security's telemetry system is designed with **privacy first**, **user control**, and **transparency** as core principles. By collecting minimal, anonymous usage data, we can build a better security toolkit while respecting user trust.

**Key Takeaways:**

- ✅ **Opt-in by default** — disabled unless explicitly enabled
- ✅ **100% anonymous** — no PII, no secrets, no repository names
- ✅ **Open source** — audit the code yourself
- ✅ **Easy to disable** — edit `jmo.yml` or set environment variable
- ✅ **Transparent reports** — quarterly public summaries

**Questions?** Contact us at <general@jmogaming.com> or file an issue at <https://github.com/jimmy058910/jmo-security-repo/issues>.

---

**Document Version:** 1.0.0 (Draft)
**Last Updated:** 2025-10-19
**Next Review:** 2025-11-19 (monthly during v0.7.0 development)
