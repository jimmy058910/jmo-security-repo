# JMo Security — Brand Assets

This directory holds the brand identity spec and design tokens for JMo Security.

## Files

| File | Purpose |
|------|---------|
| `IDENTITY.md` | The brand spec — voice, color, typography, logo usage, do/don't |
| `tokens.css` | CSS custom properties (web consumers) |
| `tokens.py` | Python constants and ANSI codes (CLI/terminal consumers) |
| `templates/` | Reference HTML implementations (footer, email chrome) |

## Where consumers live

| Consumer | What it should pull |
|----------|---------------------|
| `scripts/dashboard/` | `tokens.css` for color, typography, surfaces |
| `scripts/cli/ui/` (CLI output) | `tokens.py` ANSI codes |
| jmotools.com | `tokens.css` + `templates/footer.html` |
| Newsletter ([JMOAA-53](/JMOAA/issues/JMOAA-53)) | `templates/email-chrome.html` |
| Signup form ([JMOAA-51](/JMOAA/issues/JMOAA-51)) | `tokens.css` + `templates/footer.html` |

## How to make changes

1. Read `IDENTITY.md` first. It explains *why* a token has the value it does.
2. If you're touching severity colors, brand primary, or voice principles, that's a material change. Open a PR, get CEO review, audit downstream consumers in the same change.
3. If you're adding a new token (e.g. a new shadow tier), add it to both `tokens.css` and `tokens.py` if it's relevant in both contexts. Drift between them is the bug we're trying to prevent.
4. Cosmetic clarifications (typo fixes, expanded examples) can ship as a normal commit.

## Versioning

Tokens are versioned alongside the codebase. There is no separate brand release schedule. The intent is that the spec follows the product — when we ship a new dashboard view, the brand doc captures the new patterns we adopted.

## Status

| Phase | Status |
|-------|--------|
| 1 — Foundation spec + tokens | done (this commit) |
| 2 — Reference templates (footer, email chrome) | done (this commit) |
| 3 — Logo system (SVG variants, favicon set, social) | pending — see [JMOAA-55](/JMOAA/issues/JMOAA-55) |
| 4 — Adoption (dashboard reads tokens, jmotools.com adopts) | pending — Tier 2/3 work |
