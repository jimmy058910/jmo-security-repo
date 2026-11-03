#!/usr/bin/env python3
"""
Security Testing Suite for JMo Security.

Tests security hardening and vulnerability resistance:
- SQL injection resistance (parameterized queries)
- Path traversal prevention (input validation)
- Secrets management (no hardcoded credentials)
- Dependency vulnerabilities (Trivy/OSV-Scanner)
- Docker security (non-root, minimal attack surface)
- Input validation (CLI args, YAML config, regex DoS)

These tests validate that JMo Security itself is secure and hardened
against common attack vectors.
"""
