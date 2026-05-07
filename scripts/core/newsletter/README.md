# JMo newsletter content pipeline

Content-assembly pipeline for JMo Updates broadcasts. Builds a static HTML +
plain-text draft from three inputs that can be reviewed before being uploaded
to Resend.

## Layout

| Path | What it is |
|------|------------|
| `template.html` | Shared HTML email template. Mixes Python `${...}` build-time placeholders with Resend `{{{property\|fallback}}}` send-time placeholders. |
| `draft_generator.py` | Pulls release notes from `CHANGELOG.md`, optionally splices in a customer story, renders the template, and emits an `.html` + `.txt` pair. |
| `__init__.py` | Re-exports `generate_draft`, `NewsletterDraft`, `ReleaseEntry`. |

The companion module `scripts/core/newsletter_broadcast.py` (one level up)
owns the Resend upload step. Nothing in this package talks to Resend — review
the static files first, then hand them to `newsletter_broadcast`.

## Customer-story convention

Customer stories live at `dev-only/customer-stories/active.md`. The
`dev-only/` directory is gitignored so stories never enter source control —
agents draft them locally before each broadcast and archive them after the
send.

`active.md` is plain markdown. The first markdown blockquote (`> ...`) is
extracted as the subject-line tagline. Example:

```markdown
# Pipeline saved at SOC team

> JMo caught a hardcoded GCP service-account key in a Terraform module
> two days before our compliance audit.

— **Internal SOC engineer**, *enterprise team*
```

When `active.md` is missing, the customer-story section is silently omitted
and the subject-line falls back to the first `### subsection` heading from
the release notes.

## Subject-line formula

| Customer story present? | Subject line |
|-------------------------|--------------|
| Yes | `JMo v{version} released — {first_blockquote_line}` (truncated to ~60 chars) |
| No  | `JMo v{version} released — {first_release_subsection_title}` |

## Substitution layers

The template intentionally has two substitution layers:

- **Build-time** (`${name}`) — filled in by `draft_generator` when the static
  draft is assembled. Never touched by Resend.
- **Send-time** (`{{{property|fallback}}}`) — Resend hydrates these per
  recipient when the broadcast fires. Currently used for `first_name` and
  the standard `unsubscribe` link.

This separation keeps recipient personalization out of the agent flow:
`draft_generator` only touches build-time content, and Resend handles all
send-time hydration.

## CLI

```bash
# Most-recent CHANGELOG release, default customer-story path
python -m scripts.core.newsletter.draft_generator --output-dir ./drafts

# All releases inside a date window (e.g. monthly digest)
python -m scripts.core.newsletter.draft_generator \
  --start 2026-04-01 --end 2026-04-30 \
  --output-dir ./drafts

# Skip the customer-story section explicitly
python -m scripts.core.newsletter.draft_generator \
  --no-customer-story --output-dir ./drafts
```

## Programmatic use

```python
from pathlib import Path
from scripts.core.newsletter import generate_draft

draft = generate_draft(output_dir=Path("./drafts"))
print(draft.subject)
print(draft.html_path)  # ./drafts/newsletter-v1_0_5.html
print(draft.text_path)  # ./drafts/newsletter-v1_0_5.txt
```
