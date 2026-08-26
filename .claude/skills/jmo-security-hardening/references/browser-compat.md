# Browser Compatibility Considerations

Include this section in security reports for web-related fixes (CSP, headers, client-side validation).

---

## Feature Support Matrix

Support depends on **how the policy is delivered**, not only on the browser.
Some directives are ignored in a `<meta>` tag by every browser at every version.

| Feature | Works in `<meta>`? | Chrome | Firefox | Safari | Edge |
|---------|--------------------|--------|---------|--------|------|
| CSP (`script-src`, `default-src`, ...) | yes, `http-equiv` | 25+ (2013) | 23+ (2013) | 7+ (2013) | 12+ (2015) |
| CSP `frame-ancestors` | **no** -- header only | n/a | n/a | n/a | n/a |
| `X-Frame-Options` | **no** -- header only | n/a | n/a | n/a | n/a |
| `X-Content-Type-Options` | **no** -- header only | n/a | n/a | n/a | n/a |
| Referrer policy | yes, as `<meta name="referrer">` | 56+ (2016) | 50+ (2016) | 11.1+ (2018) | 79+ (2020) |

`frame-ancestors`, `report-uri` and `sandbox` are excluded from `<meta>`
delivery by the CSP spec: framing has to be decided before the document
renders, which only an HTTP header guarantees. `X-Frame-Options` was never a
pragma directive at all.

## Framing protection

- **Primary:** `Content-Security-Policy: frame-ancestors 'none'` **as a
  response header**
- **Fallback:** `X-Frame-Options: DENY` **as a response header** (legacy
  browsers)
- **Not a fallback:** either directive in a `<meta>` tag. It is inert, so a
  page that ships only the meta form has *no* clickjacking protection
  regardless of browser version.

JMo's dashboard is a static file, so it cannot set response headers on its own
— whatever serves it must. See `scripts/dashboard/index.html:8-10`.

## Testing Recommendations

Recommended browser testing targets:

- Chrome 90+ (current)
- Firefox 88+ (current)
- Safari 14+ (current)
- IE 11 (if business requires, test CSP degradation gracefully)
