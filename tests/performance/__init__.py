"""Performance and benchmarking tests for JMo Security.

This module contains performance benchmarks for critical paths:
- SQLite operations (scan insert, query)
- Diff engine (fingerprint-based comparison)
- Trend analysis (statistical validation)
- Cross-tool deduplication (similarity clustering)
- HTML dashboard generation (React build)
- Memory usage (large scans)

All benchmarks establish baseline performance targets from CLAUDE.md:
- SQLite scan insert: <50ms
- History list (10k scans): <100ms
- Trend analysis (30 days): <200ms
- Diff (1000 findings): <500ms
- Deduplication (1000 findings): <2s
- Dashboard (5000 findings): <5s
- Memory usage (10k findings): <500MB
"""
