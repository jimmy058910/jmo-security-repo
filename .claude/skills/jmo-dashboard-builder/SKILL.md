---
name: jmo-dashboard-builder
description: Build JMo Security interactive React dashboard with charts, compliance visualization, and SBOM trees. Use when building or updating the HTML dashboard.
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Purpose

Build JMo Security's interactive React dashboard using modern frontend technologies (React, Tailwind CSS, shadcn/ui, Recharts). Creates self-contained HTML dashboards for security findings with charts, compliance visualization, and SBOM trees. Replaces legacy vanilla JS dashboard with component-based architecture.

**Target Output:** Self-contained HTML file (`dashboard.html`).

It does **not** load `findings.json`. `scripts/core/reporters/html_reporter.py`
picks one of two modes by finding count against `INLINE_THRESHOLD`:

| Mode | When | How the data arrives |
|---|---|---|
| Inline | `total <= INLINE_THRESHOLD` | JSON substituted into the `window.__FINDINGS__` placeholder — genuinely self-contained |
| External | above the threshold | `dashboard-data.json` written beside the HTML and `fetch()`ed, so a large scan does not produce a 50–100 MB file |

`src/hooks/useFindings.ts` reads embedded data first and falls back to the
fetch. Note the sibling file is `dashboard-data.json`, deliberately **not**
`findings.json` — that name belongs to `basic_reporter.write_json()`, whose
output is metadata-wrapped and a different shape.

> External mode needs an HTTP origin. Chrome gives every `file://` document a
> unique opaque origin, so the `fetch()` fails when the HTML is opened directly
> from disk. That is the cost of not shipping a 100 MB file, not an oversight —
> serve the directory, or stay under the threshold.

**Architecture:** React 18 + TypeScript + Vite + vite-plugin-singlefile + Tailwind CSS + shadcn/ui + Recharts

---

**Approach:** Build for offline-first reliability. Every component must work without network access.

## When to Use This Skill

**USE when:** Building the initial React dashboard prototype, adding new dashboard features (charts, compliance views, SBOM trees), updating dashboard UI components, implementing new visualizations.

**DON'T USE when:** Working on core security adapters or CLI code, creating simple HTML reports (use existing reporters in `scripts/core/reporters/`).

---

## Critical Constraints

1. **Self-Contained HTML** -- All JavaScript, CSS, fonts, images inlined. No CDN dependencies (offline-first). Works in file:// protocol.

2. **Bundle Size** -- TARGET: <2 MB. **This is the authoritative figure**; [references/troubleshooting.md](references/troubleshooting.md) defers to it rather than restating thresholds. Measured: the committed `scripts/dashboard/dist/index.html` is **0.93 MB**, so there is roughly 2x headroom today. Use production builds (minified, tree-shaken).

   Do **not** plan for route-level code splitting. `vite-plugin-singlefile`
   needs one file, so the real `vite.config.ts` sets `inlineDynamicImports: true`
   **and** `manualChunks: undefined` to switch splitting off. `React.lazy()` in
   `App.tsx` is still worth keeping for dev-server ergonomics and to express
   module boundaries, but every chunk is inlined at build time — it buys no
   bytes in the shipped artifact.

3. **Data Source** -- findings from `normalize_and_report.py`, CommonFinding schema v1.2.0 (6 compliance frameworks). Delivered inline or as `dashboard-data.json` — see **Target Output** above for which and why.

4. **Fallback Strategy** -- Legacy dashboard (`html_reporter.py`) remains as fallback. If React dashboard build fails, fall back to legacy.

5. **Security Headers** -- CSP + X-Frame-Options. Content-Security-Policy: script-src 'unsafe-inline' (required for inline bundles). X-Frame-Options: DENY. X-Content-Type-Options: nosniff.

---

## Design & Style Guidelines

### Design Principles

**DO:** Professional security tool aesthetic (not "AI slop"). System fonts: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`. Dark mode support. Severity-based color coding. Scannable tables. Copy-to-clipboard buttons.

**DON'T:** Centered layouts everywhere. Purple/pink gradients. Excessive rounded corners. Inter font. Marketing-style CTAs.

### Color Palette

```css
--critical: #d32f2f;   /* Red (Critical severity) */
--high: #f57c00;       /* Orange (High severity) */
--medium: #fbc02d;     /* Yellow (Medium severity) */
--low: #7cb342;        /* Green (Low severity) */
--info: #757575;       /* Gray (Info severity) */
--primary: #1976d2;    /* Blue (primary actions) */
--background: #ffffff; /* Light mode background */
--background-dark: #1e1e1e; /* Dark mode background */
```

---

## Project Structure

```text
scripts/
├── dashboard/                    # React dashboard source (scripts/dashboard/)
│   ├── src/
│   │   ├── main.tsx             # Entry point
│   │   ├── App.tsx              # Main app with routing
│   │   ├── pages/
│   │   │   ├── Overview.tsx     # Dashboard overview with charts
│   │   │   ├── Findings.tsx     # Filterable findings table
│   │   │   ├── Compliance.tsx   # Compliance framework viz
│   │   │   └── SBOM.tsx         # SBOM dependency tree
│   │   ├── components/
│   │   │   ├── FindingsTable.tsx
│   │   │   ├── FindingDetail.tsx
│   │   │   ├── SeverityChart.tsx
│   │   │   ├── ComplianceRadar.tsx
│   │   │   ├── DependencyTree.tsx
│   │   │   └── FilterPanel.tsx
│   │   ├── lib/
│   │   │   ├── utils.ts          # shadcn/ui utilities
│   │   │   └── findings-loader.ts # Load findings.json
│   │   └── types/
│   │       └── findings.ts       # TypeScript types for CommonFinding
│   ├── public/
│   │   └── findings.json         # Sample data for development
│   ├── index.html                # HTML entry point
│   ├── package.json
│   ├── vite.config.ts            # Vite + vite-plugin-singlefile
│   ├── tsconfig.json
│   └── src/index.css              # tailwind 4 config lives in CSS (#390)
└── core/
    └── reporters/
        └── html_reporter.py           # HTML dashboard generator (legacy + React)
```

---

## Quick Start: Building the Dashboard

### Prerequisites

- Node.js 18+ (LTS), npm 9+ or pnpm 8+, Git worktree (for parallel development)

### Step 1: Set Up Git Worktree

```bash
git worktree add -b feature/react-dashboard ../jmo-dashboard-worktree
cd ../jmo-dashboard-worktree
```

Work in a worktree so an in-progress dashboard build never blocks a scan or a
release on the main checkout.

### Step 2: Initialize Dashboard Project

```bash
cd scripts/dashboard
npm install  # Uses package.json (React 18, Vite, Recharts, Tailwind, etc.)
```

### Step 3: Configure Vite for Self-Contained HTML

Already configured — read [`scripts/dashboard/vite.config.ts`](../../../scripts/dashboard/vite.config.ts)
rather than reconstructing it here. The two settings that carry the
single-file guarantee, and that a well-meaning edit tends to undo:

- `inlineDynamicImports: true` **with** `manualChunks: undefined` — together
  these disable code splitting. A single-file build cannot emit chunks, so
  re-enabling `manualChunks` silently produces sibling `.js` files that the
  HTML then cannot find offline.
- `assetsInlineLimit` / `chunkSizeWarningLimit` set to 100 MB and
  `cssCodeSplit: false` — these force everything inline rather than emitting
  separate asset files.

### Step 4: Create TypeScript Types

```typescript
// src/types/findings.ts - CommonFinding schema v1.2.0
export interface CommonFinding {
  schemaVersion: string
  id: string
  ruleId: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  tool: { name: string; version: string }
  location: { path: string; startLine?: number; endLine?: number }
  message: string
  title?: string
  description?: string
  remediation?: string
  references?: string[]
  tags?: string[]
  cvss?: { version?: string; score: number; vector?: string }
  context?: { snippet?: string; lines?: string[] }
  compliance?: {
    owaspTop10_2021?: string[]
    cweTop25_2024?: Array<{ rank: number; id: string; category: string }>
    cisControlsV8_1?: Array<{ control: string; ig: string }>
    nistCsf2_0?: Array<{ function: string; category: string; subcategory: string }>
    pciDss4_0?: Array<{ requirement: string; priority: string }>
    mitreAttack?: Array<{ tactic: string; technique: string; subtechnique?: string }>
  }
  risk?: { cwe?: string; confidence?: number; likelihood?: string; impact?: string }
  raw?: any
}
```

### Step 5: Build Self-Contained HTML

```bash
npm run build         # Output: dist/index.html (self-contained, ~1-2MB)
du -h dist/index.html # Verify bundle size
npm run preview       # Test locally
```

---

## Integration with Python Reporter

**This is already built. Do not write a new reporter.**
[`scripts/core/reporters/html_reporter.py`](../../../scripts/core/reporters/html_reporter.py)
is the integration, `write_html` is its entry point, and the CLI already calls
it. There is no `write_html_react`.

Earlier revisions of this skill reproduced a prototype of that module here. The
copy fell behind the real one on three points that matter, which is the reason
it is now a citation instead of a snippet:

| The real module does | The prototype did |
|---|---|
| Verifies `window.__FINDINGS__ = []` is present and falls back with a logged warning if not (`html_reporter.py:64-75`) | Called `str.replace()` unconditionally — a template change yields a "successful" report showing zero findings |
| Escapes `</script>`, `<script`, `<!--` and backticks **after** `json.dumps` (`html_reporter.py:88-94`) | Interpolated raw JSON into an inline `<script>`, so a finding containing `</script>` breaks out of the tag (CWE-79) |
| Falls back to a test fixture, then to `_write_fallback_html()` | Imported `write_html` from its own module — a circular import that would never have run |

If you change the injection, change it there, and keep those three properties.
`json.dumps` alone is **not** sufficient escaping for an HTML `<script>`
context: it is valid JSON to emit the literal characters `</script>`.

---

## Common Development Tasks

### Add New Chart to Overview Page

```tsx
import { PieChart, Pie, Cell, ResponsiveContainer, Legend } from 'recharts'

const SeverityChart = ({ findings }) => {
  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})
  const data = Object.entries(severityCounts).map(([severity, count]) => ({
    name: severity, value: count
  }))
  const COLORS = {
    CRITICAL: '#d32f2f', HIGH: '#f57c00', MEDIUM: '#fbc02d',
    LOW: '#7cb342', INFO: '#757575'
  }
  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100}>
          {data.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />
          ))}
        </Pie>
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  )
}
```

### Add Compliance Radar Chart

```tsx
import { RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts'

export const ComplianceRadar = ({ findings }) => {
  const frameworkCounts = findings.reduce((acc, f) => {
    if (f.compliance?.owaspTop10_2021?.length) acc.owasp++
    if (f.compliance?.cweTop25_2024?.length) acc.cwe++
    if (f.compliance?.cisControlsV8_1?.length) acc.cis++
    if (f.compliance?.nistCsf2_0?.length) acc.nist++
    if (f.compliance?.pciDss4_0?.length) acc.pci++
    if (f.compliance?.mitreAttack?.length) acc.attack++
    return acc
  }, { owasp: 0, cwe: 0, cis: 0, nist: 0, pci: 0, attack: 0 })

  const data = [
    { framework: 'OWASP', count: frameworkCounts.owasp },
    { framework: 'CWE', count: frameworkCounts.cwe },
    { framework: 'CIS', count: frameworkCounts.cis },
    { framework: 'NIST', count: frameworkCounts.nist },
    { framework: 'PCI DSS', count: frameworkCounts.pci },
    { framework: 'ATT&CK', count: frameworkCounts.attack }
  ]

  return (
    <RadarChart width={500} height={400} data={data}>
      <PolarGrid />
      <PolarAngleAxis dataKey="framework" />
      <PolarRadiusAxis />
      <Radar name="Findings" dataKey="count" stroke="#1976d2" fill="#1976d2" fillOpacity={0.6} />
    </RadarChart>
  )
}
```

---

## Troubleshooting

For bundle size issues, findings not loading, dark mode styling problems, testing/QA procedures (bundle size check, cross-browser testing, Lighthouse), and external reference links, see [references/troubleshooting.md](references/troubleshooting.md).
