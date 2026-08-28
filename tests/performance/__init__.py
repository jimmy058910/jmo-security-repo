"""Performance and benchmarking tests for JMo Security.

This module contains performance benchmarks for critical paths:
- SQLite operations (scan insert, query)
- Diff engine (fingerprint-based comparison)
- Trend analysis (statistical validation)
- Cross-tool deduplication (similarity clustering)
- HTML dashboard generation (React build)
- Memory usage (large scans)

These are the targets this repository set for itself. **They do not come
from CLAUDE.md**, which has never contained a performance section --
`git log -S` finds no commit that ever added one. Thirteen citations across
three files said otherwise (#742), which made every number look externally
sourced when this docstring is the source:
- SQLite scan insert: <50ms
- History list (10k scans): <100ms
- Trend analysis (30 days): <200ms
- Diff (1000 findings): <500ms
- Deduplication (1000 findings): <2s
- Dashboard (5000 findings): <5s
- Memory usage (10k findings): <500MB
"""
