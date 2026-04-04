# Browser Compatibility Considerations

Include this section in security reports for web-related fixes (CSP, headers, client-side validation).

---

## Feature Support Matrix

| Feature | Chrome | Firefox | Safari | Edge | Coverage |
|---------|--------|---------|--------|------|----------|
| CSP via meta tag | 25+ (2013) | 23+ (2013) | 7+ (2013) | 12+ (2015) | 95%+ |
| X-Content-Type-Options | 1+ (2008) | 50+ (2016) | 11+ (2017) | 12+ (2015) | 90%+ |
| Referrer-Policy | 56+ (2016) | 50+ (2016) | 11.1+ (2018) | 79+ (2020) | 85%+ |

## Fallback Strategies

- **Primary:** CSP `frame-ancestors 'none'` (broad support)
- **Fallback:** X-Frame-Options `DENY` (legacy browsers)
- **Result:** Dual protection ensures 95%+ browser coverage

## Testing Recommendations

Recommended browser testing targets:

- Chrome 90+ (current)
- Firefox 88+ (current)
- Safari 14+ (current)
- IE 11 (if business requires, test CSP degradation gracefully)
