# JMo Security — Brand Assets

This directory holds the brand identity spec and design tokens for JMo Security.

## Files

| File | Purpose |
|------|---------|
| `IDENTITY.md` | The brand spec — voice, color, typography, logo usage, do/don't |
| `tokens.css` | CSS custom properties (web consumers) |
| `tokens.py` | Python constants and ANSI codes (CLI/terminal consumers) |
| `templates/` | Reference HTML implementations (footer, email chrome) |
| `logos/` | Logo system — SVG variants, favicon set, social-share image (see below) |

## Logo system (`logos/`)

All colors reference `tokens.css` — hex values are literal matches to token definitions, not orphan values.

### SVG variants

| File | Use case | Background |
|------|----------|------------|
| `jmo-mark.svg` | Primary lockup: JMO wordmark + tagline | Light / white |
| `jmo-mark-dark.svg` | Primary lockup inverted | Dark / navy |
| `jmo-mark-mono.svg` | Single-color: embossed/foil/laser print | Light (navy ink) |
| `jmo-icon.svg` | Icon-only square: favicon source, GitHub social preview | Transparent |
| `jmo-wordmark.svg` | JMO mark, no tagline: nav bars, inline mentions, footer | Light / white |
| `jmo-wordmark-vertical.svg` | Stacked: icon above text | Light / white |
| `social-share-1200x630.svg` | OG/Twitter card source (editable) | Navy fill |

### Raster output

| File | Size | Use case |
|------|------|----------|
| `favicon-16.png` | 16×16 | Browser tab favicon |
| `favicon-32.png` | 32×32 | HiDPI browser tab |
| `apple-touch-icon-180.png` | 180×180 | iOS home screen |
| `android-chrome-192.png` | 192×192 | Android home screen |
| `android-chrome-512.png` | 512×512 | Android splash / PWA |
| `social-share-1200x630.png` | 1200×630 | Open Graph / Twitter card |

### Usage rules (summary — full rules in `IDENTITY.md`)

- **Minimum size:** 24px tall for icon-only; 32px tall for horizontal lockup.
- **Clear space:** padding equal to the height of the "J" character on all sides.
- **Background:** use `jmo-mark.svg` on white/light; `jmo-mark-dark.svg` on navy/dark terminals. Never place either on a busy photographic background without a solid color block underneath.
- **Don't recolor.** All SVG color values map to tokens. Any edit must trace back to a token in `tokens.css`.
- **Regenerating PNGs:** `pip install cairosvg` then `cairosvg svg2png` from `jmo-icon.svg` at the target size. The social-share PNG regenerates from `social-share-1200x630.svg`.

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
| 3 — Logo system (SVG variants, favicon set, social) | done — [JMOAA-56](/JMOAA/issues/JMOAA-56) |
| 4 — Adoption (dashboard reads tokens, jmotools.com adopts) | pending — tracked at [JMOAA-57](/JMOAA/issues/JMOAA-57) (Tier 3) |
