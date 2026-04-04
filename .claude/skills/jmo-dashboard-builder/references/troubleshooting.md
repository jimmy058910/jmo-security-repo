# Dashboard Builder Troubleshooting

Common issues, debugging tips, and solutions for the JMo Security React dashboard.

## Bundle Too Large

**Problem:** `dist/index.html` exceeds 3MB

**Solutions:**

1. Lazy load Recharts: `const Recharts = React.lazy(() => import('recharts'))`
2. Remove unused shadcn/ui components
3. Use production build: `NODE_ENV=production npm run build`
4. Disable source maps: `build.sourcemap: false`

## Findings Not Loading

**Problem:** Dashboard shows empty state

**Check:**

1. Verify `window.__FINDINGS__` is populated in HTML
2. Check browser console for JSON parse errors
3. Validate findings.json schema matches TypeScript types

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

# Target: <2MB
# Acceptable: <3MB
# Too large: >5MB (investigate)
```

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
- **Implementation guide**: [dev-only/REACT_DASHBOARD_IMPLEMENTATION_GUIDE.md](../../../../dev-only/REACT_DASHBOARD_IMPLEMENTATION_GUIDE.md)
