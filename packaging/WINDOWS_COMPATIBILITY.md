# Windows Compatibility Guide

**IMPORTANT: Windows users should understand tool availability before choosing installation method.**

---

## Windows Tool Compatibility Matrix

JMo Security orchestrates **13 scanners**. Every one of them has a native Windows build that `jmo tools install` sets up; two carry a caveat (Semgrep and ZAP).

| Tool | Category | Native Windows Support | Notes |
|------|----------|------------------------|-------|
| **TruffleHog** | Secrets Scanning | Full support | Go binary; working tree and git history |
| **Gitleaks** | Secrets Scanning | Full support | Go binary; working tree and git history |
| **Semgrep** | Multi-Language SAST | Some rules require Linux | Use Docker for full coverage |
| **Syft** | SBOM Generation | Full support | Go binary, generates Software Bill of Materials |
| **Trivy** | Vulnerability Scanning | Full support | Go binary, scans containers/IaC/files |
| **Checkov** | IaC Security | Full support | Python, scans Terraform/CloudFormation/K8s |
| **Hadolint** | Dockerfile Linting | Full support | Windows `.exe` from upstream; runs only when Dockerfiles are present |
| **ShellCheck** | Shell Script Linting | Full support | Windows zip from upstream; runs only when shell scripts are present |
| **gosec** | Go SAST | Full support | Go binary; runs only when Go sources are present |
| **YARA** | Malware Pattern Matching | Full support | `yara-python` wheel; rules are fetched at install time |
| **Grype** | Vulnerability Scanning | Full support | Go binary |
| **OWASP ZAP** | DAST Web Scanning | Needs a Java runtime | Docker recommended; runs only on `--url` targets |
| **Nuclei** | Vulnerability Scanner | Full support | Go binary, 4000+ templates; runs only on `--url` targets |

OPA, the policy engine behind `jmo policy` and `jmo report --policy`, is not a scanner. `jmo tools install` installs it natively on Windows alongside the 13.

---

## Choosing What Runs

There are no scan profiles. `jmo scan` considers all 13 scanners, and the target's content decides which of them run. Narrow the list when a tool is not set up yet:

```powershell
# Everything that applies to the target
jmo scan --repos-dir C:\Projects

# Only some tools
jmo scan --repos-dir C:\Projects --tools trufflehog trivy semgrep

# Leave ZAP out when Java is not configured
jmo scan --url http://localhost:3000 --skip-tools zap

# Continue past tools that are not installed
jmo scan --repos-dir C:\Projects --allow-missing-tools
```

A top-level `tools:` list in `jmo.yml` narrows the list for every scan.

---

## 🎯 Recommended Installation Paths for Windows

### Path 1: WSL2 + Docker Desktop (BEST - All 13 Tools) ⭐

**Setup time:** 10 minutes (one-time)
**Tool coverage:** 100% (all 13 tools)

**Steps:**

1. **Install WSL2:**

   ```powershell
   # Run as Administrator
   wsl --install
   # Restart computer when prompted
   ```

2. **Install Docker Desktop:**
   - Download from: <https://www.docker.com/products/docker-desktop>
   - Enable WSL2 integration in Docker Desktop settings

3. **Install JMo Security (choose one):**

   **Option A: Winget (recommended)**

   ```powershell
   winget install jmo.jmo-security
   ```

   **Option B: pip (in WSL2)**

   ```bash
   pip install jmo-security
   ```

4. **Run scans with full tool suite:**

   ```powershell
   # From Windows PowerShell
   jmo wizard --docker

   # Or from WSL2 terminal
   jmo wizard --docker
   ```

**Why this is best:**

- ✅ All 13 security tools available
- ✅ Consistent with Linux/macOS experience
- ✅ Native Windows CLI with Docker backend
- ✅ Best performance and reliability

---

### Path 2: Native Windows

**Setup time:** a few minutes
**Tool coverage:** all 13 scanners once `jmo tools install` has run (ZAP also needs Java)

**Steps:**

1. **Install via Winget:**

   ```powershell
   winget install jmo.jmo-security
   ```

2. **Install the scanners:**

   ```powershell
   jmo tools install
   ```

3. **Run scans:**

   ```powershell
   jmo scan --repos-dir C:\Projects

   # ZAP will be skipped if Java is not configured
   jmo scan --repos-dir C:\Projects --allow-missing-tools
   ```

**Limitations:**

- No ZAP (DAST) unless Java is configured
- Some Semgrep rules skip on Windows

**When to use:**

- Quick validation scans
- Pre-commit hooks
- CI/CD where Docker is not available
- Learning JMo Security basics

---

## 🔧 Tool Installation (Optional for Native Windows)

If using **Path 2 (Native Windows)**, `jmo tools install` sets up every scanner. The package-manager commands below are an alternative for individual tools:

### Core Tools (Work on Windows)

**TruffleHog:**

```powershell
# Via scoop
scoop install trufflehog

# Or download from:
# https://github.com/trufflesecurity/trufflehog/releases
```

**Trivy:**

```powershell
# Via scoop
scoop install trivy

# Or download from:
# https://github.com/aquasecurity/trivy/releases
```

**Syft:**

```powershell
# Via scoop
scoop install syft

# Or download from:
# https://github.com/anchore/syft/releases
```

**Checkov:**

```powershell
pip install checkov
```

**Hadolint:**

```powershell
# Download from:
# https://github.com/hadolint/hadolint/releases
```

**Nuclei:**

```powershell
# Via go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Or download from:
# https://github.com/projectdiscovery/nuclei/releases
```

**After installing tools, verify:**

```powershell
jmo tools check
```

---

## ❓ FAQ: Windows Compatibility

### Q: Why do some tools need extra setup on Windows?

**A:** All 13 scanners have Windows builds, but two need more than the binary:

- **OWASP ZAP** needs a Java runtime
- **Semgrep** has rules that assume Linux

Windows is a secondary platform for most security tools, so Docker/WSL2 remains the simplest route to full coverage.

### Q: Can I use Windows Subsystem for Linux (WSL1)?

**A:** ❌ No. WSL1 lacks kernel features required by some tools. **Use WSL2 only.**

### Q: Does Winget install all 13 tools?

**A:** ❌ No. Winget installs **only the JMo Security CLI**. You must:

- Install the scanners with `jmo tools install`, OR
- Use Docker mode (all 13 tools included)

**Docker mode is recommended.**

### Q: Which tools should I run on native Windows?

**A:** All of them. There are no scan profiles: `jmo scan` runs whichever of the 13 scanners apply to the target. Add `--allow-missing-tools` while some are not installed yet:

```powershell
jmo scan --repos-dir C:\Projects --allow-missing-tools
```

### Q: Can I mix native tools and Docker?

**A:** ⚠️ Not recommended. JMo runs tools either:

- All native (local binaries)
- All Docker (containerized)

**Pick one mode per scan.**

---

## 🎓 Best Practices for Windows Users

### ✅ DO

1. **Use WSL2 + Docker Desktop** for production scans
2. **Run `jmo tools install`** once if running native Windows only
3. **Use `--allow-missing-tools`** flag to skip unavailable tools gracefully
4. **Check tool availability** before scanning:

   ```powershell
   jmo tools check
   ```

### ❌ DON'T

1. **Don't expect 100% tool parity** with Linux/macOS on native Windows
2. **Don't skip Docker** if you need comprehensive security coverage
3. **Don't ignore Windows Defender** - some tools may be flagged as false positives

---

## 📚 Additional Resources

- **Docker Desktop for Windows:** <https://docs.docker.com/desktop/install/windows-install/>
- **WSL2 Installation:** <https://learn.microsoft.com/en-us/windows/wsl/install>
- **Scoop Package Manager:** <https://scoop.sh/> (for tool installation)
- **JMo Security Docker Guide:** [../docs/DOCKER_README.md](../docs/DOCKER_README.md)

---

## 🆘 Troubleshooting

### Issue: "Tool not found" errors on native Windows

**Solution:**

```powershell
# Check which tools are available
jmo tools check

# Run with missing tools allowed
jmo scan --repos-dir C:\Projects --allow-missing-tools
```

### Issue: ZAP fails to start

**Solution:** ZAP requires Java. Either:

1. Install Java JRE 11+, OR
2. Use Docker mode:

   ```powershell
   jmo wizard --docker
   ```

### Issue: Semgrep rules fail

**Solution:** Some rules are Linux-specific. Use Docker for full Semgrep coverage:

```powershell
jmo wizard --docker
```

---

**Last Updated:** September 2026
**Maintainer:** Jimmy Moceri (@jimmy058910)
