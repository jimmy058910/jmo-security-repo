# Known Limitations and Edge Cases

---

## What This Skill Does NOT Do

1. **Find vulnerabilities:** Use security-auditor agent for discovery
2. **Fix 0-days:** Only handles known vulnerability patterns
3. **Crypto implementation:** Use established libraries (bcrypt, argon2)
4. **Network security:** Doesn't configure firewalls, TLS, etc.

## When to Use Manual Security Review Instead

- **Complex auth flows:** OAuth, SAML require expert review
- **Cryptographic code:** Never automate crypto fixes
- **Business logic bugs:** Require domain expertise
- **Compliance-specific:** HIPAA, PCI DSS need auditor review

## Troubleshooting

### "Fix introduces breaking changes"

**Cause:** Security fix changes API contract
**Fix:** Review --dry-run output, adjust API versioning

### "Security tests failing"

**Cause:** Generated tests too strict
**Fix:** Review test expectations, adjust to match business requirements

### "Bandit still reports issue after fix"

**Cause:** False positive or incomplete fix
**Fix:** Add `# nosec B602` comment with justification if false positive

### "Performance degradation after fix"

**Cause:** Validation overhead
**Fix:** Profile hotspots, optimize validation logic or cache results (see [rollback-performance.md](./rollback-performance.md))
