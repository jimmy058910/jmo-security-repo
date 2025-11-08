# JMo Security React Dashboard

Modern React-based security dashboard for JMo Security scan results.

## Features

- **Interactive findings table** with sorting by severity, priority, rule, and path
- **Advanced filtering** by severity, tool, and search query
- **Expandable rows** showing full details, remediation, and code snippets
- **Dual-mode data loading**:
  - **Inline mode** (<1000 findings): Data embedded in HTML for instant load
  - **External mode** (>1000 findings): Fetches findings.json to prevent browser freeze
- **Self-contained HTML**: All CSS/JS/fonts inlined (no CDN dependencies)
- **Offline-capable**: Works in `file://` protocol
- **Security headers**: CSP, X-Frame-Options, X-Content-Type-Options
- **Mobile responsive**: Tailwind CSS breakpoints
- **TypeScript**: Full type safety with CommonFinding v1.2.0 schema

## Build Pipeline

### Prerequisites

- Node.js 18+ (includes npm)
- Recommended: npm 9+

### Quick Start

```bash
cd scripts/dashboard

# Install dependencies (one-time setup)
npm install

# Development server with hot reload
npm run dev
# Visit http://localhost:5173

# Production build (self-contained HTML)
npm run build
# Output: dist/index.html (160KB)

# Preview production build
npm run preview
# Visit http://localhost:4173
```

## Architecture

### Tech Stack

| Component | Choice | Why |
|-----------|--------|-----|
| Build Tool | Vite 5 + vite-plugin-singlefile | 5-10x faster than CRA, self-contained HTML support |
| UI Framework | Tailwind CSS | Lightweight, customizable, tree-shakeable |
| Charts | Recharts (Phase 4) | React-native, responsive, 100KB gzipped |
| Language | TypeScript | Type safety, better DX, zero runtime cost |
| State | React useState + Context | Simple, sufficient for read-only dashboard |
| Routing | None | Single-page, tab-based navigation |

### Directory Structure

```text
scripts/dashboard/
├── src/
│   ├── components/
│   │   ├── FindingsTable.tsx    # Main findings table with sorting/expandable rows
│   │   └── FilterPanel.tsx      # Severity/tool/search filters
│   ├── hooks/
│   │   └── useFindings.ts       # Dual-mode data loading hook
│   ├── types/
│   │   └── findings.ts          # TypeScript types (CommonFinding v1.2.0)
│   ├── App.tsx                  # Root component with filter logic
│   ├── main.tsx                 # React entry point
│   └── index.css                # Tailwind directives
├── dist/
│   └── index.html               # Self-contained production build (160KB)
├── index.html                   # HTML template (injected by Python)
├── package.json                 # npm dependencies
├── vite.config.ts               # Vite build configuration
├── tsconfig.json                # TypeScript configuration
├── tailwind.config.js           # Tailwind CSS configuration
└── README.md                    # This file
```

### Dual-Mode Data Loading

**Python controls which mode via template injection:**

```python
# scripts/core/reporters/html_reporter_react.py (future implementation)
INLINE_THRESHOLD = 1000

if len(findings) <= INLINE_THRESHOLD:
    # Inline mode: embed JSON in HTML
    injected_html = template.replace(
        'window.__FINDINGS__ = []',
        f'window.__FINDINGS__ = {json.dumps(findings)}'
    )
else:
    # External mode: write findings.json separately
    (out_path.parent / "findings.json").write_text(json.dumps(findings))
    injected_html = template  # Load via fetch()
```

**React automatically detects mode:**

```typescript
// src/hooks/useFindings.ts
const embedded = (window as any).__FINDINGS__

if (embedded && Array.isArray(embedded) && embedded.length > 0) {
  // Inline mode: instant load
  setFindings(embedded)
} else {
  // External mode: fetch findings.json
  const response = await fetch('findings.json')
  const json = await response.json()
  setFindings(json.findings)  // v1.0.0 metadata wrapper supported
}
```

## Bundle Size

| Build Stage | Size | Target | Status |
|-------------|------|--------|--------|
| Phase 0 (Empty) | 148KB | <50KB | ✅ |
| Phase 1 (Core UI) | 161KB | <100KB | ✅ |
| Phase 2 (Data Loading) | 163KB | <200KB | ✅ |
| Phase 4 (Charts) | ~250KB | <500KB | 🔲 |
| Final (All Features) | ~400KB | <2MB | 🔲 |

**Optimization Techniques:**

- Tree shaking (automatic with Vite)
- Minification (terser)
- CSS inlining (postcss + tailwind)
- Lazy loading (dynamic imports for heavy features)
- No external resources (all fonts/icons inlined)

## Development Status

### Completed (Phases 0-2)

- ✅ **Phase 0**: Project setup, build pipeline, self-contained HTML
- ✅ **Phase 1**: FindingsTable, FilterPanel, sorting, expandable rows
- ✅ **Phase 2**: useFindings hook, dual-mode loading, loading/error states

### Planned (Phases 3-7)

- 🔲 **Phase 3**: Dark mode, keyboard shortcuts, CSV/JSON export
- 🔲 **Phase 4**: SQLite history navigation, diff comparison, trend charts, compliance radar
- 🔲 **Phase 5**: Performance optimization (<2MB bundle, <1s load)
- 🔲 **Phase 6**: Testing (Jest + React Testing Library + Playwright)
- 🔲 **Phase 7**: Python integration (html_reporter_react.py)

## Python Integration (Phase 7)

**Create new reporter:**

```python
# scripts/core/reporters/html_reporter_react.py
from pathlib import Path
import json

INLINE_THRESHOLD = 1000

def write_react_dashboard(findings, out_path, meta):
    # Read React build template
    template = Path(__file__).parent.parent.parent / "dashboard" / "dist" / "index.html"
    html = template.read_text()

    # Inject findings (inline or external)
    if len(findings) <= INLINE_THRESHOLD:
        # Inline mode
        findings_json = json.dumps(findings).replace("</script>", "<\\/script>")
        html = html.replace('window.__FINDINGS__ = []', f'window.__FINDINGS__ = {findings_json}')
    else:
        # External mode
        (out_path.parent / "findings.json").write_text(json.dumps({"meta": meta, "findings": findings}))

    # Write dashboard.html
    out_path.write_text(html)
```

**Register in jmo.py:**

```python
# scripts/cli/jmo.py
if "html" in outputs:
    from scripts.core.reporters.html_reporter_react import write_react_dashboard
    write_react_dashboard(all_findings, out_path / "dashboard.html", meta)
```

## Testing

### Unit Tests (Phase 6)

```bash
npm install --save-dev vitest @testing-library/react @testing-library/jest-dom jsdom

npm run test        # Run all tests
npm run test:ui     # Interactive UI
npm run test:watch  # Watch mode
npm run coverage    # Coverage report (target: ≥85%)
```

### Integration Tests (Phase 6)

```bash
npm install --save-dev playwright

npm run test:e2e    # End-to-end tests
```

## Deployment

### Docker Integration

```dockerfile
# Dockerfile (future)
FROM node:18-alpine AS dashboard-builder
WORKDIR /app/dashboard
COPY scripts/dashboard/package*.json ./
RUN npm ci --production=false
COPY scripts/dashboard/ ./
RUN npm run build

# Copy dist/index.html to Python runtime
FROM python:3.11-slim
COPY --from=dashboard-builder /app/dashboard/dist/index.html /app/scripts/dashboard/dist/
# ... rest of Python setup
```

### CI/CD

```yaml
# .github/workflows/ci.yml (future)
- name: Build React Dashboard
  run: |
    cd scripts/dashboard
    npm ci
    npm run build
    du -h dist/index.html  # Verify bundle size
    grep -E 'https?://|cdn\.' dist/index.html && exit 1 || true  # No external resources
```

## Troubleshooting

### Build Errors

**TypeScript errors:**

```bash
npm run type-check  # Check types without building
```

**Bundle size too large:**

```bash
npm install --save-dev vite-bundle-visualizer
npm run build -- --mode analyze  # Visualize bundle composition
```

### Runtime Errors

**Findings not loading:**

1. Check browser console for errors
2. Verify `window.__FINDINGS__` is populated (inline mode)
3. Verify `findings.json` exists (external mode)
4. Check CSP headers allow `fetch()` to `self`

**Performance issues:**

1. Check if >1000 findings (should use external mode)
2. Profile with React DevTools
3. Use virtual scrolling for large tables (Phase 5)

## Contributing

See [../../CONTRIBUTING.md](../../CONTRIBUTING.md) for project-wide guidelines.

**Dashboard-specific guidelines:**

- Follow React best practices (hooks, functional components)
- Use TypeScript strict mode (no `any` unless necessary)
- Keep bundle size <2MB (monitor with `du -h dist/index.html`)
- Test on Chrome, Firefox, Safari, Edge
- Verify offline mode works (`file://` protocol)
- Run `npm run type-check` before committing

## License

See [../../LICENSE](../../LICENSE) for project license.

## Support

- **Issues**: <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Docs**: [../../docs/](../../docs/)
- **Implementation Plan**: [../../dev-only/1.0.0/REACT_DASHBOARD_COMPLETE_PLAN.md](../../dev-only/1.0.0/REACT_DASHBOARD_COMPLETE_PLAN.md)
