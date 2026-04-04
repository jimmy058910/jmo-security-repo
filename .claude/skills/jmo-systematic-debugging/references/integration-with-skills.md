# Integration with Other Skills

How systematic debugging integrates with the broader JMo skill ecosystem.

---

## Generic Skills (Required)

**This skill requires using:**

- **root-cause-tracing** - REQUIRED when error is deep in call stack (Phase 1, Step 5: Trace Data Flow)
- **test-driven-development** - REQUIRED for creating failing test case (Phase 4, Step 1)

**Complementary skills:**

- **defense-in-depth** - Add validation at multiple layers after finding root cause
- **condition-based-waiting** - Replace arbitrary timeouts identified in Phase 2
- **verification-before-completion** - Verify fix worked before claiming success

---

## JMo-Specific Skills

**This skill should be used BEFORE these skills:**

- **jmo-adapter-generator:** Before generating new adapter, debug why existing one fails
- **jmo-test-fabricator:** Before writing tests, debug why existing tests fail
- **jmo-ci-debugger:** Use systematic debugging when CI investigation needed

**Complementary JMo skills:**

- **jmo-profile-optimizer:** After fixing bugs, optimize performance
- **jmo-documentation-updater:** After fixing bugs, document troubleshooting steps

---

## Real-World Impact

From debugging sessions:

- Systematic approach: 15-30 minutes to fix
- Random fixes approach: 2-3 hours of thrashing
- First-time fix rate: 95% vs 40%
- New bugs introduced: Near zero vs common
