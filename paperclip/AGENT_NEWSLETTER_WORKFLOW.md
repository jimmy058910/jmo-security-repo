# Agent Newsletter Workflow

How agents create newsletter broadcasts and how Jimmy publishes them.

## Overview

The newsletter stack is split into two halves:

| Half | Status | Code |
|------|--------|------|
| **Collection** (subscribe form → Resend audience) | Done | `scripts/api/subscribe_endpoint.js`, `scripts/core/email_service.py` |
| **Broadcast** (digest → Resend Broadcasts → Jimmy sends) | Done (this doc) | `scripts/core/newsletter_broadcast.py` |

Agents draft; Jimmy clicks Send. No agent ever fires a broadcast directly without the `--send` flag, and that flag is only used in testing or with explicit Jimmy approval.

## Environment Setup (one-time)

Set these in your shell or CI environment:

```bash
export RESEND_API_KEY="re_..."          # from https://resend.com/api-keys
export RESEND_AUDIENCE_ID="<uuid>"      # see "Find Your Audience ID" below
export JMO_FROM_EMAIL="marketing@jmotools.com"   # already verified domain
```

### Find Your Audience ID

```bash
python scripts/core/newsletter_broadcast.py --list-audiences
```

This prints all audiences associated with your API key. Copy the UUID for the JMo subscriber list and set `RESEND_AUDIENCE_ID`.

## Creating a Release Digest (standard agent workflow)

When a new version ships, the Content Manager agent runs:

```bash
python scripts/core/newsletter_broadcast.py --release-notes
```

This:
1. Reads the version from `pyproject.toml`
2. Extracts the matching section from `CHANGELOG.md`
3. Renders a styled HTML email
4. Creates a **draft** broadcast in Resend (no email sent yet)
5. Prints the broadcast URL

Output looks like:

```text
Creating broadcast draft…
  Subject:  JMo Security v1.0.5 — what's new
  Audience: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Draft ID: bcast_xxxxxxxxxxxxxxxxxxxxxxxx
  View at:  https://resend.com/broadcasts/bcast_xxx

Broadcast is in Draft state. Review at https://resend.com/broadcasts
then click Send when ready.
```

## Jimmy's Review Step

1. Open the URL from the output (or go to [resend.com/broadcasts](https://resend.com/broadcasts))
2. Preview the email — check subject, content, formatting
3. Send a test send to yourself: **Send test email** button
4. When satisfied: click **Send**

That's it. The broadcast goes to every subscriber in the audience.

## Override Options

```bash
# Override the version (useful if pyproject.toml hasn't been bumped yet):
python scripts/core/newsletter_broadcast.py --release-notes --version 1.0.6

# Custom subject:
python scripts/core/newsletter_broadcast.py --release-notes \
    --subject "JMo Security v1.0.5: CI stability + cleaner tool status"

# Custom HTML file (for non-release digests):
python scripts/core/newsletter_broadcast.py \
    --subject "April DevSecOps digest" \
    --html-file paperclip/content/blog/april-digest.html

# Preview HTML without calling Resend (useful during authoring):
python scripts/core/newsletter_broadcast.py --release-notes --dry-run
```

## Sending Immediately (bypass dashboard review)

Only use this with Jimmy's explicit approval:

```bash
python scripts/core/newsletter_broadcast.py --release-notes --send
```

The `--send` flag creates the draft then immediately fires it. There is no undo.

## Python API

For custom agent workflows:

```python
from scripts.core.newsletter_broadcast import create_broadcast, build_release_digest_html

# Build the digest HTML from CHANGELOG
subject, html = build_release_digest_html()  # reads pyproject.toml version

# Create the draft
broadcast_id = create_broadcast(
    subject=subject,
    html=html,
    audience_id="your-audience-uuid",
)

print(f"Draft: https://resend.com/broadcasts/{broadcast_id}")
```

## Timing

- **On release day**: Content Manager creates the draft immediately after the GitHub release tag is live
- **Jimmy sends**: same day or next morning — up to Jimmy
- **Frequency**: one digest per release; no fixed cadence

## Troubleshooting

| Error | Fix |
|-------|-----|
| `resend package not installed` | `pip install resend` |
| `RESEND_API_KEY not set` | Export the env var (see setup above) |
| `RESEND_AUDIENCE_ID not set` | Run `--list-audiences`, copy the UUID |
| `No changelog entry found for v1.0.x` | Check the version string in `pyproject.toml` matches CHANGELOG header exactly |
| HTML looks wrong in email client | Run `--dry-run` and paste HTML into [Litmus](https://litmus.com) or [Maizzle](https://maizzle.com) |
| Broadcast not appearing in Resend | Check API key has Broadcasts write permission |
