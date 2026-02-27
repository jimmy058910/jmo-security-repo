# Slack Notification Examples

**Real-world patterns for integrating Slack notifications with JMo Security scans**

## Table of Contents

- [Basic Setup](#basic-setup)
- [GitLab CI Integration](#gitlab-ci-integration)
- [GitHub Actions Integration](#github-actions-integration)
- [Custom Notification Messages](#custom-notification-messages)
- [Multi-Channel Notifications](#multi-channel-notifications)
- [Conditional Notifications](#conditional-notifications)
- [Rich Formatting](#rich-formatting)
- [Troubleshooting](#troubleshooting)

## Basic Setup

### Create Slack Incoming Webhook

1. Go to [Slack API: Incoming Webhooks](https://api.slack.com/messaging/webhooks)
2. Click **Create New App** → **From scratch**
3. Name your app (e.g., "JMo Security")
4. Select your workspace
5. Navigate to **Incoming Webhooks**
6. Toggle **Activate Incoming Webhooks** to **On**
7. Click **Add New Webhook to Workspace**
8. Select channel (e.g., `#security-alerts`)
9. Copy webhook URL: `https://hooks.slack.com/services/T00/B00/XXX`

### Test Webhook

```bash
curl -X POST 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' \
  -H 'Content-Type: application/json' \
  -d '{"text": "✅ Test notification from JMo Security"}'
```

## GitLab CI Integration

### Basic Notification

```yaml
# .gitlab-ci.yml
variables:
  SLACK_WEBHOOK_URL: $SLACK_WEBHOOK_URL  # Set in CI/CD variables

jmo-security-scan:
  stage: scan
  image: ghcr.io/jimmy058910/jmo-security:latest
  script:
    - jmo scan --repo . --profile balanced
    - jmo report ./results
  artifacts:
    paths:
      - results/
  after_script:
    - |
      if [ "$CI_JOB_STATUS" == "success" ]; then
        STATUS_EMOJI="✅"
        STATUS_TEXT="Success"
      else
        STATUS_EMOJI="❌"
        STATUS_TEXT="Failed"
      fi

      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d "{\"text\": \"$STATUS_EMOJI Security Scan $STATUS_TEXT\"}"
```

### Rich Formatted Notification

```yaml
notify-slack:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d '{
          "blocks": [
            {
              "type": "header",
              "text": {
                "type": "plain_text",
                "text": "🔒 Security Scan Results"
              }
            },
            {
              "type": "section",
              "fields": [
                {
                  "type": "mrkdwn",
                  "text": "*Status:*\n✅ Passed"
                },
                {
                  "type": "mrkdwn",
                  "text": "*Pipeline:*\n<'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>"
                },
                {
                  "type": "mrkdwn",
                  "text": "*Commit:*\n'"$CI_COMMIT_SHORT_SHA"'"
                },
                {
                  "type": "mrkdwn",
                  "text": "*Author:*\n'"$CI_COMMIT_AUTHOR"'"
                }
              ]
            },
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Branch:* '"$CI_COMMIT_REF_NAME"'\n*Duration:* '"$CI_JOB_DURATION"'s"
              }
            }
          ]
        }'
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
```

### Notification with Findings Summary

```yaml
notify-with-summary:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      # Extract findings count from results
      FINDINGS_COUNT=$(grep -oP 'Total findings: \K\d+' results/summaries/SUMMARY.md || echo "0")
      CRITICAL=$(grep -oP 'CRITICAL \(\K\d+' results/summaries/SUMMARY.md || echo "0")
      HIGH=$(grep -oP 'HIGH \(\K\d+' results/summaries/SUMMARY.md || echo "0")

      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "🔒 Security Scan Completed",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Security Scan Results*\n\n📊 *Findings:* '"$FINDINGS_COUNT"' total\n🔴 *CRITICAL:* '"$CRITICAL"'\n🟠 *HIGH:* '"$HIGH"'\n\n<'"$CI_PIPELINE_URL"'|View Pipeline> | <'"$CI_PROJECT_URL"'/-/jobs/'"$CI_JOB_ID"'/artifacts/browse/results/summaries|View Report>"
              }
            }
          ]
        }'
```

### Separate Success/Failure Jobs

```yaml
stages:
  - scan
  - notify

jmo-security-scan:
  stage: scan
  image: ghcr.io/jimmy058910/jmo-security:latest
  script:
    - jmo scan --repo . --profile balanced --fail-on HIGH
    - jmo report ./results
  artifacts:
    paths:
      - results/
    when: always

notify-success:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "✅ Security Scan Passed",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Security Scan:* ✅ Passed\n*Pipeline:* <'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>\n*Commit:* '"$CI_COMMIT_SHORT_SHA"' by '"$CI_COMMIT_AUTHOR"'"
              }
            }
          ]
        }'
  needs:
    - job: jmo-security-scan
      artifacts: true
  rules:
    - when: on_success

notify-failure:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "❌ Security Scan Failed",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Security Scan:* ❌ Failed\n*Pipeline:* <'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>\n*Commit:* '"$CI_COMMIT_SHORT_SHA"' by '"$CI_COMMIT_AUTHOR"'\n*Error:* High severity findings detected. Review report for details."
              }
            }
          ]
        }'
  needs:
    - job: jmo-security-scan
      artifacts: true
  rules:
    - when: on_failure
```

## GitHub Actions Integration

### Basic Notification with Slack GitHub Action

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * 1'
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run security scan
        uses: docker://ghcr.io/jimmy058910/jmo-security:latest
        with:
          args: scan --repo . --profile balanced

      - name: Generate report
        uses: docker://ghcr.io/jimmy058910/jmo-security:latest
        with:
          args: report ./results

      - name: Notify Slack
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
                    "text": "*Security Scan Results*\n*Status:* ✅ Success\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|#${{ github.run_number }}>\n*Commit:* ${{ github.sha }}\n*Author:* ${{ github.actor }}"
                  }
                }
              ]
            }
```

### Conditional Notifications (Success/Failure)

```yaml
- name: Notify Slack on success
  if: success()
  uses: slackapi/slack-github-action@v1
  with:
    webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
    payload: |
      {
        "text": "✅ Security Scan Passed",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Security Scan:* ✅ Passed\n*Repository:* ${{ github.repository }}\n*Branch:* ${{ github.ref_name }}\n*Commit:* ${{ github.sha }}\n*Author:* ${{ github.actor }}\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Details>"
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
              "text": "*Security Scan:* ❌ Failed\n*Repository:* ${{ github.repository }}\n*Branch:* ${{ github.ref_name }}\n*Commit:* ${{ github.sha }}\n*Author:* ${{ github.actor }}\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Logs>"
            }
          }
        ]
      }
```

### Notification with Findings Summary

```yaml
- name: Extract findings summary
  id: summary
  run: |
    TOTAL=$(grep -oP 'Total findings: \K\d+' results/summaries/SUMMARY.md || echo "0")
    CRITICAL=$(grep -oP 'CRITICAL \(\K\d+' results/summaries/SUMMARY.md || echo "0")
    HIGH=$(grep -oP 'HIGH \(\K\d+' results/summaries/SUMMARY.md || echo "0")
    echo "total=$TOTAL" >> $GITHUB_OUTPUT
    echo "critical=$CRITICAL" >> $GITHUB_OUTPUT
    echo "high=$HIGH" >> $GITHUB_OUTPUT

- name: Notify Slack with summary
  uses: slackapi/slack-github-action@v1
  with:
    webhook: ${{ secrets.SLACK_WEBHOOK_URL }}
    payload: |
      {
        "text": "🔒 Security Scan Results",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Security Scan Results*\n\n📊 *Total Findings:* ${{ steps.summary.outputs.total }}\n🔴 *CRITICAL:* ${{ steps.summary.outputs.critical }}\n🟠 *HIGH:* ${{ steps.summary.outputs.high }}\n\n*Repository:* ${{ github.repository }}\n*Branch:* ${{ github.ref_name }}\n*Run:* <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|View Report>"
            }
          }
        ]
      }
```

## Custom Notification Messages

### Thread Notifications

Reply to previous message to create thread:

```bash
# Send initial message and capture timestamp
RESPONSE=$(curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"text": "🔒 Security Scan Started"}')

# Extract thread_ts from response
THREAD_TS=$(echo "$RESPONSE" | jq -r '.ts')

# Reply in thread with results
curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{
    "text": "✅ Security Scan Completed",
    "thread_ts": "'"$THREAD_TS"'"
  }'
```

### Mentions and User Groups

```json
{
  "text": "<!here> Security scan completed",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "<!here> Critical findings detected\n\n<@U123456> Please review ASAP"
      }
    }
  ]
}
```

Mention patterns:

- `<!here>` - Notify all active users in channel
- `<!channel>` - Notify all users in channel
- `<@U123456>` - Mention specific user (use User ID)
- `<!subteam^S123456>` - Mention user group

### Attachments with Actions

```json
{
  "text": "Security Scan Results",
  "attachments": [
    {
      "color": "danger",
      "title": "Critical Findings Detected",
      "text": "5 CRITICAL and 12 HIGH severity findings",
      "fields": [
        {
          "title": "CRITICAL",
          "value": "5",
          "short": true
        },
        {
          "title": "HIGH",
          "value": "12",
          "short": true
        }
      ],
      "actions": [
        {
          "type": "button",
          "text": "View Report",
          "url": "https://gitlab.com/org/repo/-/jobs/123/artifacts/browse"
        },
        {
          "type": "button",
          "text": "View Pipeline",
          "url": "https://gitlab.com/org/repo/-/pipelines/456"
        }
      ]
    }
  ]
}
```

## Multi-Channel Notifications

### Route by Severity

```bash
# High priority findings → #security-alerts
if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 5 ]; then
  curl -X POST "$SLACK_WEBHOOK_SECURITY" \
    -H 'Content-Type: application/json' \
    -d '{"text": "🚨 HIGH PRIORITY: Critical security findings detected"}'
fi

# Regular updates → #security
curl -X POST "$SLACK_WEBHOOK_GENERAL" \
  -H 'Content-Type: application/json' \
  -d '{"text": "✅ Daily security scan completed"}'
```

### Team-Specific Channels

```python
# In schedule configuration
notifications={
    "enabled": True,
    "channels": [
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/T00/B00/XXX",  # #backend-team
            "filter": {"labels": {"team": "backend"}}
        },
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/T00/B01/YYY",  # #frontend-team
            "filter": {"labels": {"team": "frontend"}}
        }
    ]
}
```

## Conditional Notifications

### Only Notify on Failures

```yaml
notify-failure-only:
  stage: notify
  image: curlimages/curl:latest
  script:
    - |
      curl -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d '{
          "text": "❌ Security Scan Failed - Immediate Action Required",
          "blocks": [
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "<!here> *CRITICAL:* Security scan failed\n\n*Pipeline:* <'"$CI_PIPELINE_URL"'|#'"$CI_PIPELINE_ID"'>\n*Branch:* '"$CI_COMMIT_REF_NAME"'\n*Author:* '"$CI_COMMIT_AUTHOR"'"
              }
            }
          ]
        }'
  rules:
    - when: on_failure
```

### Only Notify on New Findings

```bash
# Compare with previous scan
PREVIOUS_COUNT=$(cat results/.previous-count 2>/dev/null || echo "0")
CURRENT_COUNT=$(grep -oP 'Total findings: \K\d+' results/summaries/SUMMARY.md)

if [ "$CURRENT_COUNT" -gt "$PREVIOUS_COUNT" ]; then
  NEW_FINDINGS=$((CURRENT_COUNT - PREVIOUS_COUNT))

  curl -X POST "$SLACK_WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d '{
      "text": "⚠️ New Security Findings Detected",
      "blocks": [
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*New Findings:* '"$NEW_FINDINGS"'\n*Previous:* '"$PREVIOUS_COUNT"'\n*Current:* '"$CURRENT_COUNT"'"
          }
        }
      ]
    }'
fi

# Save current count
echo "$CURRENT_COUNT" > results/.previous-count
```

### Time-Based Notifications

```yaml
# Only notify during business hours (9 AM - 5 PM UTC)
notify-business-hours:
  stage: notify
  script:
    - |
      HOUR=$(date -u +%H)
      if [ "$HOUR" -ge 9 ] && [ "$HOUR" -lt 17 ]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
          -H 'Content-Type: application/json' \
          -d '{"text": "Security scan completed"}'
      fi
```

## Rich Formatting

### Emoji Status Indicators

```json
{
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Scan Results by Severity*\n\n🔴 CRITICAL: 0\n🟠 HIGH: 3\n🟡 MEDIUM: 12\n⚪ LOW: 5\n🔵 INFO: 8"
      }
    }
  ]
}
```

### Progress Indicators

```json
{
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Scan Progress*\n\n▰▰▰▰▰▰▰▱▱▱ 70%\n\nScanning: `backend-api`\nCompleted: 7/10 repositories"
      }
    }
  ]
}
```

### Markdown Formatting

```json
{
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Security Scan Summary*\n\n```\nTotal Findings: 28\nCRITICAL:       0\nHIGH:           3\nMEDIUM:        12\nLOW:            5\nINFO:           8\n```\n\n*Top Issues:*\n• Missing authentication headers\n• Hardcoded API keys\n• Insecure dependencies"
      }
    }
  ]
}
```

## Troubleshooting

### Webhook Not Receiving Messages

**Check webhook URL:**

```bash
# Test webhook directly
curl -v -X POST 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' \
  -H 'Content-Type: application/json' \
  -d '{"text": "Test"}'

# Should return: HTTP/1.1 200 OK
# If 404: Webhook URL is invalid or revoked
# If 403: Webhook is disabled
```

**Verify webhook is active in Slack:**

1. Go to [Slack API: Your Apps](https://api.slack.com/apps)
2. Select your app
3. Navigate to **Incoming Webhooks**
4. Check webhook is listed and active

### Messages Not Appearing in Channel

**Check webhook channel:**

- Each webhook is tied to a specific channel
- Re-create webhook if you need to change channel
- Use multiple webhooks for multiple channels

### Rate Limiting

Slack rate limits: 1 message per second per webhook

**Solution: Batch notifications:**

```bash
# Instead of sending 10 separate messages
for repo in repo1 repo2 repo3; do
  curl -X POST "$SLACK_WEBHOOK_URL" -d "{\"text\": \"Scanned $repo\"}"
done

# Send one combined message
MESSAGE="Scan completed:\n"
for repo in repo1 repo2 repo3; do
  MESSAGE="$MESSAGE• $repo\n"
done

curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d "{\"text\": \"$MESSAGE\"}"
```

### Webhook URL Exposed in Logs

**Use masked CI/CD variables:**

GitLab:

1. Go to **Settings > CI/CD > Variables**
2. Add `SLACK_WEBHOOK_URL` variable
3. Check **Mask variable**
4. Check **Protect variable** (if only for protected branches)

GitHub:

1. Go to **Settings > Secrets and variables > Actions**
2. Add `SLACK_WEBHOOK_URL` secret
3. Secrets are automatically masked in logs

**Never hardcode webhook URLs in YAML:**

```yaml
# ❌ BAD
script:
  - curl -X POST 'https://hooks.slack.com/services/T00/B00/XXX' ...

# ✅ GOOD
script:
  - curl -X POST "$SLACK_WEBHOOK_URL" ...
```

## See Also

- [SCHEDULE_GUIDE.md](../SCHEDULE_GUIDE.md) — Complete schedule management guide
- [Slack Block Kit Builder](https://app.slack.com/block-kit-builder) — Visual message builder
- [Slack API: Incoming Webhooks](https://api.slack.com/messaging/webhooks) — Official documentation
- [GitLab CI Examples](../.gitlab-ci.yml) — Complete GitLab CI configurations
