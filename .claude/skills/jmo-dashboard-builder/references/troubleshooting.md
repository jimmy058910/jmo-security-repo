# Dashboard Builder Troubleshooting

Common issues, debugging tips, and solutions for the JMo Security React dashboard.

## Bundle Too Large

**Problem:** `dist/index.html` exceeds the target in
[SKILL.md](../SKILL.md) § Critical Constraints. That is the one authoritative
threshold — this file deliberately does not restate a number, because two
documents holding two thresholds is how contradictory build decisions happen.

**Solutions:**

1. Remove unused shadcn/ui components
2. Use production build: `NODE_ENV=production npm run build`
3. Disable source maps: `build.sourcemap: false`
4. Read `dist/stats.html` — `rollup-plugin-visualizer` already writes it on
   every build, with gzip and brotli sizes per module

> **Do not "lazy load Recharts" with `React.lazy(() => import('recharts'))`.**
> `React.lazy` requires a module whose **default** export is a component;
> Recharts has published only *named* exports since v2.0, so that call resolves
> to a namespace object and React throws at render. Lazy-load a local wrapper
> that default-exports instead — which is what `src/App.tsx` already does:
>
> ```tsx
> const ComplianceRadar = lazy(() => import('./components/ComplianceRadar'))
> ```
>
> Note this buys no bytes in the shipped artifact anyway: the single-file build
> inlines every dynamic import. It is a dev-server and code-organisation tool.

## Findings Not Loading

**Problem:** Dashboard shows empty state

**Check:**

1. Verify `window.__FINDINGS__` is populated in the HTML (inline mode)
2. If it is the empty placeholder, the reporter chose **external** mode — check
   that `dashboard-data.json` sits beside the HTML, and that you are serving
   over HTTP. Opened as `file://`, the `fetch()` cannot succeed: Chrome gives
   each local file a unique opaque origin, so siblings are cross-origin.
3. Check the browser console for JSON parse errors
4. Validate the data against the TypeScript types in `src/types/`

## Styling Issues in Dark Mode

**Problem:** Text not visible in dark mode

**Solution:** Use Tailwind dark mode utilities:

```tsx
<div className="bg-white dark:bg-gray-800 text-gray-900 dark:text-white">
```

## Testing & Quality Assurance

### Bundle Size Check

```bash
# After build (scripts/dashboard/ is the React source directory)
du -h scripts/dashboard/dist/index.html
```

Pass/fail is the single target in [SKILL.md](../SKILL.md) § Critical
Constraints — **<2 MB**. The committed build measures 0.93 MB, so a result near
or above the target means something new is being bundled; open `dist/stats.html`
before raising the threshold.

This file previously carried a second, looser ladder (acceptable <3 MB, too
large >5 MB) which disagreed with both the target and its own "Problem: exceeds
3 MB" heading, leaving the 3–5 MB band simultaneously failing and acceptable.

### Cross-Browser Testing

```bash
# Use Puppeteer to test in multiple browsers
npm install -D puppeteer

# Test script
node scripts/test-dashboard.js
```

### Lighthouse Performance

```bash
npx lighthouse scripts/dashboard/dist/index.html --output html --output-path lighthouse-report.html
```

## Reference Links

- **shadcn/ui components**: <https://ui.shadcn.com/docs/components>
- **Recharts documentation**: <https://recharts.org/en-US/>
- **Vite plugin singlefile**: <https://github.com/richardtallent/vite-plugin-singlefile>
- **JMo Security docs**: [docs/USER_GUIDE.md](../../../../docs/USER_GUIDE.md)
- **Dashboard output format**: [docs/RESULTS_GUIDE.md](../../../../docs/RESULTS_GUIDE.md)
