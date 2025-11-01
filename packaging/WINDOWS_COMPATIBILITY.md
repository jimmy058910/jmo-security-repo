# Windows Compatibility Guide

**IMPORTANT: Windows users should understand tool availability before choosing installation method.**

---

## 🪟 Windows Tool Compatibility Matrix

JMo Security orchestrates **12 external security tools**. On Windows, only **7 of these tools** work natively. The other 5 require WSL2 or Docker.

### ✅ Works Natively on Windows (7/12)

| Tool | Category | Native Windows Support | Notes |
|------|----------|------------------------|-------|
| **TruffleHog** | Secrets Scanning | ✅ Full support | Go binary, verified secrets, 95% fewer false positives |
| **Trivy** | Vulnerability Scanning | ✅ Full support | Go binary, scans containers/IaC/files |
| **Syft** | SBOM Generation | ✅ Full support | Go binary, generates Software Bill of Materials |
| **Checkov** | IaC Security | ✅ Full support | Python, scans Terraform/CloudFormation/K8s |
| **Hadolint** | Dockerfile Linting | ✅ Full support | Haskell binary available for Windows |
| **Nuclei** | Vulnerability Scanner | ✅ Full support | Go binary, 4000+ templates, fast API security |
| **Bandit** | Python SAST | ✅ Full support | Python, static analysis for Python code |

### ❌ Requires WSL2 or Docker (5/12)

| Tool | Category | Windows Limitation | Workaround |
|------|----------|-------------------|------------|
| **Nosey Parker** | Deep Secrets Scanning | ❌ No Windows build (Rust) | Use Docker or WSL2 |
| **Semgrep** | Multi-Language SAST | ⚠️ Some rules require Linux | Use Docker for full coverage |
| **OWASP ZAP** | DAST Web Scanning | ⚠️ Complex Java setup | Docker recommended |
| **Falco** | Runtime Security | ❌ Linux kernel only (eBPF) | Docker/WSL2 required |
| **AFL++** | Fuzzing | ❌ Linux kernel required | Docker/WSL2 required |

---

## 📊 Profile Compatibility

### Fast Profile ✅ **Works on Native Windows**

**Time:** 5-8 minutes | **Tools:** 3 core tools

```powershell
jmotools fast --repos-dir C:\Projects
```

**Tools included:**

- ✅ TruffleHog (verified secrets)
- ✅ Trivy (vulnerabilities, misconfigs)
- ⚠️ Semgrep (90% of rules work, some Linux-specific rules skipped)

**Coverage:** Secrets, vulnerabilities, basic SAST

### Balanced Profile ⚠️ **Partially Works on Native Windows**

**Time:** 15-20 minutes | **Tools:** 8 tools (7 work natively, 1 requires Docker)

```powershell
jmotools balanced --repos-dir C:\Projects
```

**Tools included:**

- ✅ TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit (7/8 work)
- ⚠️ ZAP (requires Docker or complex Java setup)

**Coverage:** Secrets, SAST, SCA, containers, IaC, Dockerfiles, limited DAST

**Recommendation:** Use Docker for full balanced profile:
```powershell
jmotools wizard --docker --profile balanced
```

### Deep Profile ❌ **Requires Docker/WSL2**

**Time:** 30-60 minutes | **Tools:** 12 comprehensive tools

**Tools NOT available natively:**

- ❌ Nosey Parker (deep secrets)
- ❌ Falco (runtime security)
- ❌ AFL++ (fuzzing)

**Recommendation:** MUST use Docker:
```powershell
jmotools wizard --docker --profile deep
```

---

## 🎯 Recommended Installation Paths for Windows

### Path 1: WSL2 + Docker Desktop (BEST - All 12 Tools) ⭐

**Setup time:** 10 minutes (one-time)
**Tool coverage:** 100% (all 12 tools)

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
   jmotools wizard --docker

   # Or from WSL2 terminal
   jmotools wizard --docker
   ```

**Why this is best:**

- ✅ All 12 security tools available
- ✅ Consistent with Linux/macOS experience
- ✅ Native Windows CLI with Docker backend
- ✅ Best performance and reliability

---

### Path 2: Native Windows (LIMITED - 7/12 Tools)

**Setup time:** 1 minute
**Tool coverage:** 58% (7/12 tools)

**Steps:**

1. **Install via Winget:**
   ```powershell
   winget install jmo.jmo-security
   ```

2. **Run scans with limited tools:**
   ```powershell
   # Use fast profile (best for native Windows)
   jmotools fast --repos-dir C:\Projects

   # Or balanced profile (ZAP will be skipped)
   jmotools balanced --repos-dir C:\Projects --allow-missing-tools
   ```

**Limitations:**

- ❌ No Nosey Parker (deep secrets scanning)
- ❌ No Falco (runtime security)
- ❌ No AFL++ (fuzzing)
- ⚠️ No ZAP (DAST) unless Java configured
- ⚠️ Some Semgrep rules skip on Windows

**When to use:**

- Quick validation scans
- Pre-commit hooks (fast profile)
- CI/CD where Docker not available
- Learning JMo Security basics

**NOT recommended for:**

- Production security audits
- Compliance scanning
- Comprehensive vulnerability assessment

---

## 🔧 Tool Installation (Optional for Native Windows)

If using **Path 2 (Native Windows)**, you can install tools individually for better performance:

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

**Bandit:**
```powershell
pip install bandit
```

**After installing tools, verify:**
```powershell
jmotools setup --check
```

---

## ❓ FAQ: Windows Compatibility

### Q: Why don't all tools work on Windows?

**A:** Many security tools are built for Linux and rely on:

- Linux kernel features (eBPF for Falco)
- POSIX APIs (AFL++ fuzzing)
- Linux package ecosystems
- Rust/Go toolchains that prioritize Linux

Windows is a secondary platform for most security tools.

### Q: Will Windows support improve in the future?

**A:** Unlikely for some tools:

- **Falco:** Requires eBPF (Linux kernel only)
- **AFL++:** Requires Linux kernel for fuzzing
- **Nosey Parker:** Rust team prioritizes Linux/macOS

**Docker/WSL2 is the permanent solution for full tool coverage on Windows.**

### Q: Can I use Windows Subsystem for Linux (WSL1)?

**A:** ❌ No. WSL1 lacks kernel features required by some tools. **Use WSL2 only.**

### Q: Does Winget install all 12 tools?

**A:** ❌ No. Winget installs **only the JMo Security CLI**. You must:

- Install tools separately (7 work natively), OR
- Use Docker mode (all 12 tools included)

**Docker mode is recommended.**

### Q: Which profile should I use on native Windows?

**A:** Use **fast profile** for best experience:
```powershell
jmotools fast --repos-dir C:\Projects
```

**Avoid deep profile on native Windows** - it will fail due to missing tools.

### Q: Can I mix native tools and Docker?

**A:** ⚠️ Not recommended. JMo runs tools either:

- All native (local binaries)
- All Docker (containerized)

**Pick one mode per scan.**

---

## 🎓 Best Practices for Windows Users

### ✅ DO

1. **Use WSL2 + Docker Desktop** for production scans
2. **Use fast profile** if running native Windows only
3. **Use `--allow-missing-tools`** flag to skip unavailable tools gracefully
4. **Check tool availability** before choosing profile:
   ```powershell
   jmotools setup --check
   ```

### ❌ DON'T

1. **Don't use deep profile on native Windows** - will fail
2. **Don't expect 100% tool parity** with Linux/macOS on native Windows
3. **Don't skip Docker** if you need comprehensive security coverage
4. **Don't ignore Windows Defender** - some tools may be flagged as false positives

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
jmotools setup --check

# Run with missing tools allowed
jmotools fast --repos-dir C:\Projects --allow-missing-tools
```

### Issue: ZAP fails to start

**Solution:** ZAP requires Java. Either:

1. Install Java JRE 11+, OR
2. Use Docker mode:
   ```powershell
   jmotools wizard --docker
   ```

### Issue: Semgrep rules fail

**Solution:** Some rules are Linux-specific. Use Docker for full Semgrep coverage:
```powershell
jmotools wizard --docker
```

---

**Last Updated:** 2025-10-30
**Version:** v0.9.0
**Maintainer:** Jimmy Moceri (@jimmy058910)
