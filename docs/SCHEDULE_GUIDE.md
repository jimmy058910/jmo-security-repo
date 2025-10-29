# Schedule Management Guide

**Complete guide to automated scan scheduling with JMo Security (v0.8.0+)**

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Schedule Concepts](#schedule-concepts)
- [Creating Schedules](#creating-schedules)
- [Managing Schedules](#managing-schedules)
- [GitLab CI Integration](#gitlab-ci-integration)
- [Slack Notifications](#slack-notifications)
- [GitHub Actions Integration](#github-actions-integration)
- [Local Cron Integration](#local-cron-integration)
- [Advanced Configuration](#advanced-configuration)
- [Troubleshooting](#troubleshooting)

## Overview

JMo Security's schedule management system enables automated, recurring security scans with:

- **Kubernetes-inspired API**: Familiar patterns for DevOps teams (metadata, spec, status)
- **Cron-based scheduling**: Full cron syntax support with timezone awareness
- **Multiple backends**: GitLab CI, GitHub Actions, local cron
- **Slack notifications**: Success/failure alerts to team channels
- **Local persistence**: Schedules stored in `~/.jmo/schedules.json` with secure permissions

## Quick Start

### Basic Weekly Scan

```python
from scripts.core.schedule_manager import (
    ScheduleManager, ScanSchedule, ScheduleMetadata,
    ScheduleSpec, BackendConfig, JobTemplateSpec
)

# Initialize manager
manager = ScheduleManager()

# Create schedule
schedule = ScanSchedule(
    metadata=ScheduleMetadata(
        name="weekly-scan",
        labels={"team": "security", "environment": "production"}
    ),
    spec=ScheduleSpec(
        schedule="0 2 * * 1",  # Every Monday at 2 AM UTC
        timezone="UTC",
        backend=BackendConfig(type="gitlab-ci"),
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repos_dir": "/repos"},
            results={"dir": "/results"},
            options={"fail_on": "HIGH"},
            notifications={
                "enabled": True,
                "channels": [
                    {
                        "type": "slack",
                        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
                    }
                ]
            }
        )
    )
)

# Save schedule
manager.create(schedule)
print(f"✅ Created schedule: {schedule.metadata.name}")
print(f"Next run: {schedule.status.nextScheduleTime}")
```

### Export to GitLab CI

```bash
# Export schedule as GitLab CI YAML
jmo schedule export weekly-scan > .gitlab-ci.yml

# Or programmatically
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator

generator = GitLabCIGenerator()
schedule = manager.get("weekly-scan")
yaml_content = generator.generate(schedule)
print(yaml_content)
```

## Schedule Concepts

### Kubernetes-Inspired Architecture

Schedules follow Kubernetes CronJob patterns for familiarity:

```yaml
apiVersion: jmo.security/v1alpha1
kind: ScanSchedule
metadata:
  name: nightly-scan
  uid: 550e8400-e29b-41d4-a716-446655440000
  labels:
    team: security
    environment: prod
  annotations:
    description: "Nightly security scan for production repos"
  creationTimestamp: "2025-10-29T02:00:00Z"
  generation: 1
spec:
  schedule: "0 2 * * *"
  timezone: "UTC"
  suspend: false
  concurrencyPolicy: "Forbid"
  startingDeadlineSeconds: 300
  successfulJobsHistoryLimit: 30
  failedJobsHistoryLimit: 10
  backend:
    type: "gitlab-ci"
    config: {}
  jobTemplate:
    profile: "balanced"
    targets:
      repos_dir: "/repos"
    results:
      dir: "/results"
    options:
      fail_on: "HIGH"
    notifications:
      enabled: true
      channels:
        - type: "slack"
          url: "https://hooks.slack.com/services/..."
status:
  conditions:
    - type: "Ready"
      status: "True"
      lastTransitionTime: "2025-10-29T02:00:00Z"
      reason: "Created"
      message: "Schedule created successfully"
  nextScheduleTime: "2025-10-30T02:00:00Z"
  lastScheduleTime: null
  lastSuccessfulTime: null
  active: 0
  succeeded: 0
  failed: 0
```

### Cron Syntax

Standard cron format with 5 fields:

```text
┌───────────── minute (0 - 59)
│ ┌───────────── hour (0 - 23)
│ │ ┌───────────── day of month (1 - 31)
│ │ │ ┌───────────── month (1 - 12)
│ │ │ │ ┌───────────── day of week (0 - 7, Sunday = 0 or 7)
│ │ │ │ │
* * * * *
```

**Common patterns:**

```python
# Every day at 2 AM UTC
schedule="0 2 * * *"

# Every Monday at 2 AM UTC
schedule="0 2 * * 1"

# Every 6 hours
schedule="0 */6 * * *"

# Every weekday at 9 AM UTC
schedule="0 9 * * 1-5"

# First day of month at midnight
schedule="0 0 1 * *"

# Every 15 minutes (for testing)
schedule="*/15 * * * *"
```

### Concurrency Policies

Controls how concurrent scan jobs are handled:

- **`Forbid`** (default): Skip new job if previous still running
- **`Allow`**: Run multiple jobs concurrently
- **`Replace`**: Cancel running job and start new one

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    concurrencyPolicy="Forbid"  # Prevent overlapping scans
)
```

## Creating Schedules

### Basic Schedule

```python
from scripts.core.schedule_manager import *

manager = ScheduleManager()

schedule = ScanSchedule(
    metadata=ScheduleMetadata(name="basic-scan"),
    spec=ScheduleSpec(
        schedule="0 2 * * *",
        jobTemplate=JobTemplateSpec(
            profile="fast",
            targets={"repo": "/path/to/repo"},
            results={"dir": "/results"},
            options={}
        )
    )
)

manager.create(schedule)
```

### Multi-Target Schedule

Scan multiple target types in one schedule:

```python
schedule = ScanSchedule(
    metadata=ScheduleMetadata(name="comprehensive-scan"),
    spec=ScheduleSpec(
        schedule="0 3 * * 1",  # Weekly Monday 3 AM
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={
                "repos_dir": "/repos",
                "images": ["nginx:latest", "postgres:15"],
                "urls": ["https://api.example.com"],
                "k8s_context": "prod"
            },
            results={"dir": "/results/weekly"},
            options={"fail_on": "HIGH", "threads": 8}
        )
    )
)
```

### Schedule with Labels

Use labels for filtering and organization:

```python
schedule = ScanSchedule(
    metadata=ScheduleMetadata(
        name="prod-backend-scan",
        labels={
            "team": "backend",
            "environment": "production",
            "priority": "critical"
        },
        annotations={
            "owner": "security-team@example.com",
            "description": "Production backend services security scan"
        }
    ),
    spec=ScheduleSpec(schedule="0 1 * * *", ...)
)
```

## Managing Schedules

### List All Schedules

```python
manager = ScheduleManager()

# List all
schedules = manager.list()
for s in schedules:
    print(f"{s.metadata.name}: {s.spec.schedule} (next: {s.status.nextScheduleTime})")

# Filter by labels
prod_schedules = manager.list(labels={"environment": "production"})
```

### Get Specific Schedule

```python
schedule = manager.get("weekly-scan")
if schedule:
    print(f"Schedule: {schedule.metadata.name}")
    print(f"Cron: {schedule.spec.schedule}")
    print(f"Profile: {schedule.spec.jobTemplate.profile}")
    print(f"Next run: {schedule.status.nextScheduleTime}")
else:
    print("Schedule not found")
```

### Update Schedule

```python
# Get existing schedule
schedule = manager.get("weekly-scan")

# Modify schedule
schedule.spec.schedule = "0 3 * * *"  # Change to 3 AM
schedule.spec.jobTemplate.profile = "deep"  # Use deep profile
schedule.spec.suspend = True  # Temporarily suspend

# Save changes
manager.update(schedule)
print(f"✅ Updated schedule (generation {schedule.metadata.generation})")
```

### Delete Schedule

```python
success = manager.delete("weekly-scan")
if success:
    print("✅ Schedule deleted")
else:
    print("❌ Schedule not found")
```

### Suspend/Resume Schedule

```python
# Suspend
schedule = manager.get("weekly-scan")
schedule.spec.suspend = True
manager.update(schedule)

# Resume
schedule.spec.suspend = False
manager.update(schedule)
```

## GitLab CI Integration

### Generate GitLab CI YAML

```python
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator

manager = ScheduleManager()
generator = GitLabCIGenerator()

schedule = manager.get("weekly-scan")
yaml_content = generator.generate(schedule)

# Write to .gitlab-ci.yml
with open(".gitlab-ci.yml", "w") as f:
    f.write(yaml_content)
```

### Generated YAML Structure

The generator creates a complete GitLab CI pipeline:

```yaml
# Auto-generated by JMo Security Schedule Manager
# Schedule: weekly-scan
# Cron: 0 2 * * 1 (Every Monday at 2 AM UTC)
# Profile: balanced
# Export command: jmo schedule export weekly-scan > .gitlab-ci.yml

variables:
  JMO_PROFILE: "balanced"
  JMO_FAIL_ON: "HIGH"

stages:
  - scan
  - notify

jmo-security-scan:
  stage: scan
  image: ghcr.io/jimmy058910/jmo-security:latest
  script:
    - jmo scan --repos-dir /repos --profile balanced --fail-on HIGH
    - jmo report /results
  artifacts:
    paths:
      - results/
    reports:
      sast: results/summaries/findings.sarif
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'

notify-slack-success:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST 'https://hooks.slack.com/services/...' \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "✅ Security Scan Completed",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Security Scan: weekly-scan*\n*Status:* ✅ Success\n*Pipeline:* <'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>\n*Commit:* '"$CI_COMMIT_SHORT_SHA"' by '"$CI_COMMIT_AUTHOR"'\n*Duration:* '"$CI_JOB_DURATION"'s"
              }
            }
          ]
        }'
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
      when: on_success

notify-slack-failure:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST 'https://hooks.slack.com/services/...' \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "❌ Security Scan Failed",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Security Scan: weekly-scan*\n*Status:* ❌ Failed\n*Pipeline:* <'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>\n*Commit:* '"$CI_COMMIT_SHORT_SHA"' by '"$CI_COMMIT_AUTHOR"'\n*Error:* Check pipeline logs"
              }
            }
          ]
        }'
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
      when: on_failure
```

### Configure GitLab Pipeline Schedule

1. Navigate to **CI/CD > Schedules** in GitLab
2. Click **New schedule**
3. Configure:
   - **Description**: `Weekly Security Scan`
   - **Interval Pattern**: Custom (use cron syntax from schedule)
   - **Cron timezone**: `UTC`
   - **Target branch**: `main`
4. Save schedule
5. GitLab will run `.gitlab-ci.yml` on schedule

## Slack Notifications

### Setup Slack Webhook

1. Go to [Slack API: Incoming Webhooks](https://api.slack.com/messaging/webhooks)
2. Create new app or select existing app
3. Enable Incoming Webhooks
4. Add New Webhook to Workspace
5. Select channel (e.g., `#security-alerts`)
6. Copy webhook URL: `https://hooks.slack.com/services/T00/B00/XXX`

### Configure Notifications

```python
schedule = ScanSchedule(
    metadata=ScheduleMetadata(name="prod-scan"),
    spec=ScheduleSpec(
        schedule="0 2 * * *",
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repos_dir": "/repos"},
            results={"dir": "/results"},
            options={},
            notifications={
                "enabled": True,
                "channels": [
                    {
                        "type": "slack",
                        "url": "https://hooks.slack.com/services/T00/B00/XXX"
                    }
                ]
            }
        )
    )
)
```

### Multiple Slack Channels

```python
notifications={
    "enabled": True,
    "channels": [
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/T00/B00/XXX",  # #security
        },
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/T00/B01/YYY",  # #devops
        }
    ]
}
```

### Notification Message Format

Success notification includes:

- ✅ Success status
- Pipeline/job URL
- Commit SHA and author
- Scan duration
- Findings summary (if available)

Failure notification includes:

- ❌ Failure status
- Pipeline/job URL
- Commit SHA and author
- Error message
- Link to logs

### Security Best Practices

**DO NOT hardcode webhook URLs in code:**

```python
# ❌ BAD - Hardcoded secret
notifications={
    "channels": [{"type": "slack", "url": "https://hooks.slack.com/..."}]
}

# ✅ GOOD - Use environment variable
import os
notifications={
    "channels": [{"type": "slack", "url": os.environ["SLACK_WEBHOOK_URL"]}]
}

# ✅ GOOD - Use GitLab CI variable
# In .gitlab-ci.yml:
# SLACK_WEBHOOK_URL is configured as masked CI/CD variable
```

## GitHub Actions Integration

### Generate GitHub Actions Workflow

```python
# Coming soon - GitHub Actions generator planned for v0.9.0
# Current workaround: Manually create .github/workflows/security-scan.yml
```

### Manual GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'  # Every Monday at 2 AM UTC
  workflow_dispatch:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run security scan
        run: |
          jmo scan --repo . --profile balanced --fail-on HIGH
          jmo report ./results

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Notify Slack on success
        if: success()
        uses: slackapi/slack-github-action@v1
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
          payload: |
            {
              "text": "✅ Security Scan Completed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Security Scan: security-scan*\n*Status:* ✅ Success\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|#${{ github.run_number }}>\n*Commit:* ${{ github.sha }} by ${{ github.actor }}"
                  }
                }
              ]
            }

      - name: Notify Slack on failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
          payload: |
            {
              "text": "❌ Security Scan Failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Security Scan: security-scan*\n*Status:* ❌ Failed\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|#${{ github.run_number }}>\n*Commit:* ${{ github.sha }} by ${{ github.actor }}"
                  }
                }
              ]
            }
```

## Local Cron Integration

### Export Schedule as Shell Script

```python
# Coming soon - Shell script generator planned for v0.9.0
# Current workaround: Manually create scan script
```

### Manual Cron Setup

1. Create scan script:

```bash
#!/bin/bash
# /usr/local/bin/jmo-weekly-scan.sh

set -euo pipefail

# Configuration
REPOS_DIR="/path/to/repos"
RESULTS_DIR="/path/to/results/$(date +%Y-%m-%d)"
PROFILE="balanced"
SLACK_WEBHOOK="https://hooks.slack.com/services/..."

# Run scan
jmo scan --repos-dir "$REPOS_DIR" --results-dir "$RESULTS_DIR" --profile "$PROFILE" --fail-on HIGH

# Generate reports
jmo report "$RESULTS_DIR"

# Notify Slack on success
curl -X POST "$SLACK_WEBHOOK" \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"✅ Security scan completed: $RESULTS_DIR\"}"
```

2. Make executable:

```bash
chmod +x /usr/local/bin/jmo-weekly-scan.sh
```

3. Add to crontab:

```bash
# Edit crontab
crontab -e

# Add schedule (every Monday at 2 AM)
0 2 * * 1 /usr/local/bin/jmo-weekly-scan.sh >> /var/log/jmo-scan.log 2>&1
```

4. Verify cron job:

```bash
crontab -l
```

## Advanced Configuration

### History Limits

Control how many job results to retain:

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    successfulJobsHistoryLimit=30,  # Keep 30 successful runs
    failedJobsHistoryLimit=10       # Keep 10 failed runs
)
```

### Starting Deadline

Set deadline for starting jobs:

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    startingDeadlineSeconds=300  # Cancel if can't start within 5 minutes
)
```

### Backend-Specific Configuration

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    backend=BackendConfig(
        type="gitlab-ci",
        config={
            "image": "ghcr.io/jimmy058910/jmo-security:latest-slim",
            "tags": ["docker", "linux"],
            "timeout": "1h",
            "retry": {"max": 2, "when": ["runner_system_failure"]}
        }
    )
)
```

### Profile-Specific Options

```python
jobTemplate=JobTemplateSpec(
    profile="deep",
    targets={"repos_dir": "/repos"},
    results={"dir": "/results"},
    options={
        "fail_on": "MEDIUM",
        "threads": 4,
        "timeout": 1800,
        "allow_missing_tools": False,
        "human_logs": True
    }
)
```

## Troubleshooting

### Schedule Not Running

**Check schedule is not suspended:**

```python
schedule = manager.get("weekly-scan")
if schedule.spec.suspend:
    print("⚠️ Schedule is suspended")
    schedule.spec.suspend = False
    manager.update(schedule)
```

**Verify cron syntax:**

```python
from croniter import croniter
from datetime import datetime

try:
    cron = croniter("0 2 * * *", datetime.now())
    next_run = cron.get_next(datetime)
    print(f"✅ Valid cron, next run: {next_run}")
except ValueError as e:
    print(f"❌ Invalid cron: {e}")
```

### Slack Notifications Not Working

**Test webhook directly:**

```bash
curl -X POST 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' \
  -H 'Content-Type: application/json' \
  -d '{"text": "Test notification from JMo Security"}'
```

**Check GitLab CI variable:**

1. Go to **Settings > CI/CD > Variables**
2. Verify `SLACK_WEBHOOK_URL` exists and is not expired
3. Ensure variable is not protected/masked if needed in non-protected branches

### Permission Denied: schedules.json

```bash
# Fix permissions
chmod 600 ~/.jmo/schedules.json

# Verify
ls -la ~/.jmo/schedules.json
# Should show: -rw------- (owner read/write only)
```

### Next Run Time Not Updating

```python
from datetime import datetime, timezone
from croniter import croniter

schedule = manager.get("weekly-scan")
now = datetime.now(timezone.utc)
cron = croniter(schedule.spec.schedule, now)
schedule.status.nextScheduleTime = cron.get_next(datetime).isoformat()
manager.update(schedule)
print(f"✅ Updated next run: {schedule.status.nextScheduleTime}")
```

### GitLab CI YAML Not Generating Correctly

```python
# Enable debug mode in generator
generator = GitLabCIGenerator()
schedule = manager.get("weekly-scan")

# Generate with debug output
yaml_content = generator.generate(schedule)
print("=" * 80)
print("GENERATED YAML:")
print("=" * 80)
print(yaml_content)
```

## See Also

- [USER_GUIDE.md](USER_GUIDE.md) — Complete user guide with all CLI commands
- [Slack Integration Examples](examples/slack-notifications.md) — Real-world Slack integration patterns
- [GitLab CI Examples](examples/.gitlab-ci.yml) — Example GitLab CI configurations
- [ROADMAP.md](../ROADMAP.md) — Future schedule management features

## Need Help?

- **Bug reports**: [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Questions**: [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
- **Documentation**: [docs.jmotools.com](https://docs.jmotools.com)
