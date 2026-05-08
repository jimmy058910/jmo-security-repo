# JMo Security — Brand Identity

This document is the source of truth for JMo Security's visual and verbal brand. Anything that ships on jmotools.com, in the dashboard, in marketing, in newsletters, or in tool output should resolve back to the decisions captured here.

If you're consuming the brand in code, use the token files instead of hardcoding values:

- `tokens.css` — CSS custom properties (web)
- `tokens.py` — Python constants and ANSI codes (CLI/terminal output)

## 1. Voice & tone

JMo Security speaks **developer-to-developer**. The voice belongs to a SOC engineer who got tired of stitching together five different tools and built one that works. It's technical, honest, and useful. It is not corporate, not breathless, not afraid to acknowledge tradeoffs.

### Core principles

- **Technically authoritative.** We know what we're talking about. Findings reference CWE/CVE/OWASP/MITRE by ID. We name the underlying scanners, we don't hide them.
- **Community-minded.** Open-source ethos. We credit the upstream tools we orchestrate. We engage on GitHub Discussions, not gated channels.
- **Security-serious but not stuffy.** Real risk gets real language. We don't dress up findings, but we also don't fearmonger to drive engagement.
- **Practitioner-grounded.** "Built by a SOC engineer at BAE Systems" beats "enterprise-grade". Lived experience over taglines.

### What we sound like

- "Run 28 scanners, get one deduplicated report. No SaaS, no telemetry, no API keys to leak."
- "v1.0.5 ships SQLite historical storage, machine-readable diffs, and a Mann-Kendall trend significance test. Local-first."
- "Cross-tool dedup typically removes 30–40% of duplicate findings. Your eyes thank you."

### What we never sound like

- "Revolutionary AI-powered enterprise security platform"
- "Empowering teams to leverage cutting-edge synergies"
- "Solutions that scale" (any sentence with "solutions" as the noun)
- Anything that hides what the underlying scanners actually do
- Anything implying findings are scarier than they are

### Specific copy rules

- Use the **active voice and the imperative mood** in CLI/docs ("Run", "Install", "Open"), not "the user can".
- Use **numbers, not adjectives** ("28 scanners", "30–40% noise reduction", "8,000+ tests"), never "many" or "lots of".
- **Name the tools.** When we orchestrate Trivy, Semgrep, Bandit, etc., name them. Hiding the wiring undermines trust.
- **Severity is severity.** Don't soften "critical" to "important" or escalate "low" to "needs review". Match the underlying scanner's call.
- **First person plural** in marketing ("we built this"), **second person** in docs ("you'll see"), **imperative** in CLI ("install the tools").

## 2. Logo system

The current primary mark lives at `assets/jmo-logo.png`: navy "JMO" wordmark with the "O" rendered as a magnifying glass containing a padlock, with "SECURITY AUDIT TOOL SUITE" as the tagline below.

### Variants needed (Phase 3 deliverable)

| Variant | Use case |
|---------|----------|
| Primary horizontal | README, docs header, jmotools.com hero |
| Primary vertical (stacked) | narrow contexts (sidebar, mobile splash) |
| Icon only (square) | favicon, social-share avatar, GitHub social preview |
| Light mode | dark text on light backgrounds (current default) |
| Dark mode | light text on dark backgrounds (terminals, dark dashboards) |
| Wordmark only | inline mentions, footer credits |

### Usage rules

- **Minimum size:** 24px tall for icon-only; 32px tall for horizontal lockup. Below that, illegibility kills the mark.
- **Clear space:** padding equal to the height of the "J" character on all sides.
- **Backgrounds:** sufficient contrast (WCAG AA — 4.5:1 against the navy). On busy photographic backgrounds, place the mark on a solid color block.
- **Don't:** stretch, recolor (outside palette), drop-shadow, outline, rotate, animate, place on top of other logos, or use the magnifying-glass-and-padlock element separately from the wordmark unless using the icon-only lockup.

### Tagline

The "SECURITY AUDIT TOOL SUITE" tagline is part of the primary lockup. In compact contexts, drop it. In long-form contexts (about pages, conference signage), keep it.

## 3. Color

The palette is severity-anchored. Severity colors are non-negotiable — they map to scanner output and changing them breaks the user's mental model. Everything else is a neutral or a UI semantic.

### Severity (load-bearing)

Used in dashboards, CLI output, dedup summaries, trend reports, compliance dashboards.

| Token | Hex | Use |
|-------|-----|-----|
| `severity-critical` | `#d32f2f` | CVSS 9.0–10.0, RCE, exposed secrets |
| `severity-high` | `#f57c00` | CVSS 7.0–8.9, auth bypass, SQLi |
| `severity-medium` | `#fbc02d` | CVSS 4.0–6.9, XSS, weak crypto |
| `severity-low` | `#7cb342` | CVSS 0.1–3.9, hardening recs |
| `severity-info` | `#757575` | informational, best-practice nudges |

These match the existing dashboard config (`scripts/dashboard/tailwind.config.js`) — kept stable on purpose.

### Brand primary

| Token | Hex | Use |
|-------|-----|-----|
| `brand-primary` | `#1976d2` | links, CTAs, active states, focus rings |
| `brand-primary-dark` | `#0d47a1` | logo navy, headers on light surfaces |
| `brand-accent` | `#42a5f5` | hover states, secondary CTAs |

The deep navy (`#0d47a1`) is the load-bearing brand color — it's what people remember from the logo.

### Neutrals

A 9-step gray scale for text, surfaces, and borders. These are tuned for both light and dark mode.

| Token | Hex | Light-mode use | Dark-mode use |
|-------|-----|----------------|---------------|
| `neutral-50` | `#fafafa` | page background | — |
| `neutral-100` | `#f5f5f5` | surface raised | — |
| `neutral-200` | `#eeeeee` | border subtle | — |
| `neutral-300` | `#e0e0e0` | border default | — |
| `neutral-500` | `#9e9e9e` | text muted | text muted |
| `neutral-700` | `#616161` | text secondary | border default |
| `neutral-800` | `#424242` | text primary | surface raised |
| `neutral-900` | `#212121` | — | page background |
| `neutral-950` | `#121212` | — | deepest (terminal-like) |

### Semantic UI (distinct from severity)

For UI states unrelated to security findings — form validation, system messages, etc.

| Token | Hex | Use |
|-------|-----|-----|
| `ui-success` | `#2e7d32` | scan completed, install succeeded |
| `ui-warning` | `#ed6c02` | deprecation notice, config drift |
| `ui-error` | `#c62828` | command failed, validation error |
| `ui-info` | `#0288d1` | tip, hint, neutral notification |

We deliberately do NOT reuse severity colors here. A UI success message is not a "low severity finding"; conflating them confuses operators.

### Accessibility

All text/background pairs in the spec meet WCAG AA (4.5:1 for body, 3:1 for large text). Tokens audited at https://webaim.org/resources/contrastchecker/ on creation. Re-verify after any edit.

## 4. Typography

### Hosting decision

**System font stack only. No external font CDNs.**

Rationale: a security tool that loads fonts from Google Fonts (or any third-party CDN) leaks every visitor's IP and User-Agent to that third party on every page view. For a brand whose differentiator is local-first, no-telemetry, no-SaaS-dependency, that's a credibility wound. System fonts also load instantly with zero render-blocking.

If we ever need a custom display face, the answer is **self-hosted woff2**, subset to the glyphs we use, served from jmotools.com. Never `<link rel="stylesheet" href="https://fonts.googleapis.com/...">`.

### Stacks

```css
/* Body & UI */
--font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
             'Ubuntu', 'Cantarell', 'Helvetica Neue', sans-serif;

/* Findings, CLI output, code */
--font-mono: ui-monospace, 'SF Mono', 'Cascadia Code', 'Roboto Mono',
             'Consolas', 'Liberation Mono', 'Menlo', monospace;

/* Display (currently unused; reserve for future hero treatments) */
--font-display: var(--font-sans);
```

### Scale

A modular scale at ratio 1.25, base 16px. Restraint matters — we render data, not magazine layouts.

| Token | Size | Line height | Use |
|-------|------|-------------|-----|
| `text-xs` | 12px | 1.4 | metadata, timestamps |
| `text-sm` | 14px | 1.5 | secondary text, table cells |
| `text-base` | 16px | 1.6 | body |
| `text-lg` | 20px | 1.4 | subheads |
| `text-xl` | 24px | 1.3 | section heads |
| `text-2xl` | 30px | 1.2 | page heads |
| `text-3xl` | 38px | 1.15 | hero |

### Weight

- 400 (regular) — body
- 500 (medium) — UI labels, table headers
- 600 (semibold) — section heads
- 700 (bold) — page heads, emphasis

### Monospace use

Use `--font-mono` for: CLI command examples, security finding identifiers (CVE-2024-1234), file paths, code blocks, scanner output, dashboard table cells rendering raw scanner output. Use it deliberately — when everything is monospace, monospace stops signaling "this is code".

## 5. Iconography

We don't ship a custom icon set. Use **Heroicons** (MIT, self-hostable as inline SVG). Keep stroke width consistent (1.5px outline for UI affordances, solid fill for severity indicators).

For severity icons, prefer:

- Critical: hexagon-exclamation
- High: shield-exclamation
- Medium: exclamation-triangle
- Low: information-circle
- Info: circle (or text label, no icon)

## 6. Imagery & illustration

We don't use stock photography of "diverse hands typing on keyboards". Visual content is either:

- Real screenshots of the product (preferred)
- Architecture/flow diagrams (mermaid in docs, hand-drawn-feeling SVG in marketing)
- Severity heatmaps and trend charts (live data from the dashboard)

If we ever need illustration, the aesthetic is **technical-diagram, monochromatic + 1 accent color**. Not Corporate Memphis.

## 7. Templates (Phase 2)

Reference implementations live in `docs/brand/templates/`:

- `footer.html` — site footer for jmotools.com
- `email-chrome.html` — header/footer wrapper for newsletter (consumed by [JMOAA-53](/JMOAA/issues/JMOAA-53))

Both consume `tokens.css` so palette changes propagate without edits.

## 8. Versioning

This document is versioned alongside the codebase. Material changes (palette, voice principles, typography stack) require:

1. Edit on a feature branch
2. CEO review
3. If consumers (dashboard, jmotools.com, email) rely on the changing token, audit them in the same PR

Cosmetic clarifications (typo fixes, expanded examples) can ship as a normal commit.

## Cross-references

- Existing dashboard tokens: `scripts/dashboard/tailwind.config.js`
- Existing voice doc: AGENTS.md (brand voice section in CEO instructions)
- Consumer issues: [JMOAA-51](/JMOAA/issues/JMOAA-51) signup form, [JMOAA-53](/JMOAA/issues/JMOAA-53) newsletter, [JMOAA-45](/JMOAA/issues/JMOAA-45) outbound system
