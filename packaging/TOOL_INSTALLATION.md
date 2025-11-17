# External Tool Installation Guide

**JMo Security orchestrates 12 external security tools. This guide shows you how to install them.**

---

## 🚀 Quick Install (Automated Scripts)

### macOS / Linux (Homebrew)

```bash
# One-command install for all Homebrew-compatible tools
curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

# Verify installation
jmotools setup --check
```

## One-command install for all Homebrew-compatible tools

curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

## Verify installation

jmotools setup --check

```text

**Installs:** TruffleHog, Semgrep, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit, ZAP (9/12 tools)

**Not included:** Nosey Parker, Falco, AFL++ (Docker-only)

---

### Linux (Native Package Managers)

```bash
# Automated installation for Ubuntu/Debian/Fedora/Arch
curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-linux.sh | bash

# Verify installation
jmotools setup --check
```

**Installs:** TruffleHog, Semgrep, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit, ZAP (9/12 tools)

**Not included:** Nosey Parker, Falco, AFL++ (Docker-only)

---

### Linux (Native Package Managers)

```bash
# Automated installation for Ubuntu/Debian/Fedora/Arch
curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-linux.sh | bash

# Verify installation
jmotools setup --check
```

## Automated installation for Ubuntu/Debian/Fedora/Arch

curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-linux.sh | bash

## Verify installation

jmotools setup --check

```text

**Installs:** All tools available for your distribution

---

### Windows (PowerShell)

```powershell
# Download and run automated installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1

# Verify installation
jmotools setup --check
```

**Installs:** All tools available for your distribution

---

### Windows (PowerShell)

```powershell
# Download and run automated installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1

# Verify installation
jmotools setup --check
```

## Download and run automated installer

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1

## Verify installation

jmotools setup --check

```text

**Installs:** 7/12 Windows-compatible tools (TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit)

**⚠️ Windows Limitation:** 5/12 tools require WSL2 or Docker. See [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md)

---

## 📋 Manual Installation (Individual Tools)

If automated scripts don't work, install tools individually:

### Secrets Scanning

**TruffleHog** (Verified secrets detection):
```bash
# macOS/Linux
brew install trufflesecurity/trufflehog/trufflehog

# Windows (Scoop)
scoop install trufflehog

# Manual download
https://github.com/trufflesecurity/trufflehog/releases
```

**Installs:** 7/12 Windows-compatible tools (TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit)

**⚠️ Windows Limitation:** 5/12 tools require WSL2 or Docker. See [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md)

---

## 📋 Manual Installation (Individual Tools)

If automated scripts don't work, install tools individually:

### Secrets Scanning

**TruffleHog** (Verified secrets detection):

```bash
# macOS/Linux
brew install trufflesecurity/trufflehog/trufflehog

# Windows (Scoop)
scoop install trufflehog

# Manual download
https://github.com/trufflesecurity/trufflehog/releases
```

## macOS/Linux

brew install trufflesecurity/trufflehog/trufflehog

## Windows (Scoop)

scoop install trufflehog

## Manual download

https://github.com/trufflesecurity/trufflehog/releases

```text

**Nosey Parker** (Deep secrets scanning - Docker only):
```bash
docker pull ghcr.io/praetorian-inc/noseyparker:latest
```

**Nosey Parker** (Deep secrets scanning - Docker only):

```bash
docker pull ghcr.io/praetorian-inc/noseyparker:latest
```

docker pull ghcr.io/praetorian-inc/noseyparker:latest

```text

---

### SAST (Static Analysis)

**Semgrep** (Multi-language SAST):
```bash
# macOS/Linux
brew install semgrep

# Python (all platforms)
pip install semgrep

# Manual download
https://github.com/semgrep/semgrep/releases
```

---

### SAST (Static Analysis)

**Semgrep** (Multi-language SAST):

```bash
# macOS/Linux
brew install semgrep

# Python (all platforms)
pip install semgrep

# Manual download
https://github.com/semgrep/semgrep/releases
```

## macOS/Linux

brew install semgrep

## Python (all platforms)

pip install semgrep

## Manual download

https://github.com/semgrep/semgrep/releases

```text

**Bandit** (Python security linter):
```bash
# All platforms
pip install bandit
```

**Bandit** (Python security linter):

```bash
# All platforms
pip install bandit
```

## All platforms

pip install bandit

```text

---

### Vulnerabilities + SBOM

**Trivy** (Comprehensive vulnerability scanner):
```bash
# macOS/Linux
brew install aquasecurity/trivy/trivy

# Windows (Scoop)
scoop install trivy

# Ubuntu/Debian
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Manual download
https://github.com/aquasecurity/trivy/releases
```

---

### Vulnerabilities + SBOM

**Trivy** (Comprehensive vulnerability scanner):

```bash
# macOS/Linux
brew install aquasecurity/trivy/trivy

# Windows (Scoop)
scoop install trivy

# Ubuntu/Debian
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# Manual download
https://github.com/aquasecurity/trivy/releases
```

## macOS/Linux

brew install aquasecurity/trivy/trivy

## Windows (Scoop)

scoop install trivy

## Ubuntu/Debian

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

## Manual download

https://github.com/aquasecurity/trivy/releases

```text

**Syft** (SBOM generation):
```bash
# macOS/Linux
brew install syft

# Windows (Scoop)
scoop install syft

# Manual download
https://github.com/anchore/syft/releases
```

**Syft** (SBOM generation):

```bash
# macOS/Linux
brew install syft

# Windows (Scoop)
scoop install syft

# Manual download
https://github.com/anchore/syft/releases
```

## macOS/Linux

brew install syft

## Windows (Scoop)

scoop install syft

## Manual download

https://github.com/anchore/syft/releases

```text

---

### IaC Security

**Checkov** (Infrastructure as Code security):
```bash
# All platforms
pip install checkov

# macOS/Linux
brew install checkov
```

---

### IaC Security

**Checkov** (Infrastructure as Code security):

```bash
# All platforms
pip install checkov

# macOS/Linux
brew install checkov
```

## All platforms

pip install checkov

## macOS/Linux

brew install checkov

```text

---

### Dockerfile Linting

**Hadolint** (Dockerfile best practices):
```bash
# macOS/Linux
brew install hadolint

# Windows
https://github.com/hadolint/hadolint/releases
# Download hadolint-Windows-x86_64.exe and add to PATH
```

---

### Dockerfile Linting

**Hadolint** (Dockerfile best practices):

```bash
# macOS/Linux
brew install hadolint

# Windows
https://github.com/hadolint/hadolint/releases
# Download hadolint-Windows-x86_64.exe and add to PATH
```

## macOS/Linux

brew install hadolint

## Windows

https://github.com/hadolint/hadolint/releases

## Download hadolint-Windows-x86_64.exe and add to PATH

```text

---

### DAST (Dynamic Analysis)

**OWASP ZAP** (Web application security):
```bash
# macOS
brew install --cask owasp-zap

# Linux
https://www.zaproxy.org/download/

# Windows
# Requires Java JRE 11+
https://www.zaproxy.org/download/
```

---

### DAST (Dynamic Analysis)

**OWASP ZAP** (Web application security):

```bash
# macOS
brew install --cask owasp-zap

# Linux
https://www.zaproxy.org/download/

# Windows
# Requires Java JRE 11+
https://www.zaproxy.org/download/
```

## macOS

brew install --cask owasp-zap

## Linux

https://www.zaproxy.org/download/

## Windows

## Requires Java JRE 11+

https://www.zaproxy.org/download/

```text

**Nuclei** (Fast vulnerability scanner):
```bash
# macOS/Linux
brew install nuclei

# Windows (Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Manual download
https://github.com/projectdiscovery/nuclei/releases
```

**Nuclei** (Fast vulnerability scanner):

```bash
# macOS/Linux
brew install nuclei

# Windows (Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Manual download
https://github.com/projectdiscovery/nuclei/releases
```

## macOS/Linux

brew install nuclei

## Windows (Go)

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

## Manual download

https://github.com/projectdiscovery/nuclei/releases

```text

---

### Runtime Security

**Falco** (Container/K8s monitoring - Docker only):
```bash
# Requires Docker or Kubernetes
https://falco.org/docs/getting-started/installation/
```

---

### Runtime Security

**Falco** (Container/K8s monitoring - Docker only):

```bash
# Requires Docker or Kubernetes
https://falco.org/docs/getting-started/installation/
```

## Requires Docker or Kubernetes

https://falco.org/docs/getting-started/installation/

```text

---

### Fuzzing

**AFL++** (Coverage-guided fuzzing - Docker only):
```bash
docker pull aflplusplus/aflplusplus
```

---

### Fuzzing

**AFL++** (Coverage-guided fuzzing - Docker only):

```bash
docker pull aflplusplus/aflplusplus
```

docker pull aflplusplus/aflplusplus

```text

---

## 🐳 Zero-Installation Alternative (Recommended)

**Don't want to install 12 tools?** Use Docker mode:

```bash
# All 12 tools included in Docker image
jmotools wizard --docker

# Or run scan directly
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced
```

---

## 🐳 Zero-Installation Alternative (Recommended)

**Don't want to install 12 tools?** Use Docker mode:

```bash
# All 12 tools included in Docker image
jmotools wizard --docker

# Or run scan directly
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced
```

## All 12 tools included in Docker image

jmotools wizard --docker

## Or run scan directly

docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced

```text

**Benefits:**

- ✅ All 12 security tools included
- ✅ Zero setup required
- ✅ Consistent environment across platforms
- ✅ Works identically on macOS, Linux, Windows

---

## 🔍 Verify Installation

After installing tools, verify they're detected:

```bash
jmotools setup --check
```

**Benefits:**

- ✅ All 12 security tools included
- ✅ Zero setup required
- ✅ Consistent environment across platforms
- ✅ Works identically on macOS, Linux, Windows

---

## 🔍 Verify Installation

After installing tools, verify they're detected:

```bash
jmotools setup --check
```

jmotools setup --check

```text

**Expected output:**

```text
✅ TruffleHog: v3.63.0 detected
✅ Semgrep: v1.45.0 detected
✅ Trivy: v0.49.0 detected
✅ Syft: v0.98.0 detected
✅ Checkov: v3.1.0 detected
✅ Hadolint: v2.12.0 detected
✅ Nuclei: v3.1.0 detected
✅ Bandit: v1.7.5 detected
⚠️  OWASP ZAP: Not detected (optional)
⚠️  Nosey Parker: Not detected (Docker only)
⚠️  Falco: Not detected (Docker only)
⚠️  AFL++: Not detected (Docker only)

8/12 tools detected. Use --allow-missing-tools or Docker mode.
```

**Expected output:**

```text
✅ TruffleHog: v3.63.0 detected
✅ Semgrep: v1.45.0 detected
✅ Trivy: v0.49.0 detected
✅ Syft: v0.98.0 detected
✅ Checkov: v3.1.0 detected
✅ Hadolint: v2.12.0 detected
✅ Nuclei: v3.1.0 detected
✅ Bandit: v1.7.5 detected
⚠️  OWASP ZAP: Not detected (optional)
⚠️  Nosey Parker: Not detected (Docker only)
⚠️  Falco: Not detected (Docker only)
⚠️  AFL++: Not detected (Docker only)

8/12 tools detected. Use --allow-missing-tools or Docker mode.
```

✅ TruffleHog: v3.63.0 detected
✅ Semgrep: v1.45.0 detected
✅ Trivy: v0.49.0 detected
✅ Syft: v0.98.0 detected
✅ Checkov: v3.1.0 detected
✅ Hadolint: v2.12.0 detected
✅ Nuclei: v3.1.0 detected
✅ Bandit: v1.7.5 detected
⚠️  OWASP ZAP: Not detected (optional)
⚠️  Nosey Parker: Not detected (Docker only)
⚠️  Falco: Not detected (Docker only)
⚠️  AFL++: Not detected (Docker only)

8/12 tools detected. Use --allow-missing-tools or Docker mode.

```text

---

## 📊 Tool Compatibility Matrix

| Tool | macOS | Linux | Windows | Docker |
|------|-------|-------|---------|--------|
| TruffleHog | ✅ | ✅ | ✅ | ✅ |
| Semgrep | ✅ | ✅ | ⚠️ | ✅ |
| Trivy | ✅ | ✅ | ✅ | ✅ |
| Syft | ✅ | ✅ | ✅ | ✅ |
| Checkov | ✅ | ✅ | ✅ | ✅ |
| Hadolint | ✅ | ✅ | ✅ | ✅ |
| Nuclei | ✅ | ✅ | ✅ | ✅ |
| Bandit | ✅ | ✅ | ✅ | ✅ |
| OWASP ZAP | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Nosey Parker | ❌ | ✅ | ❌ | ✅ |
| Falco | ❌ | ✅ | ❌ | ✅ |
| AFL++ | ❌ | ✅ | ❌ | ✅ |

**Legend:**

- ✅ Full native support
- ⚠️ Limited support (complex setup or some features unavailable)
- ❌ Not available natively (use Docker)

---

## 🎯 Recommended Installation Paths

### Path 1: Docker (Best for Everyone) ⭐

**Install:** Docker Desktop only
**Tools:** All 12 tools included
**Time:** 2 minutes

```bash
# Install Docker Desktop
https://www.docker.com/products/docker-desktop

# Start scanning immediately
jmotools wizard --docker
```

---

## 📊 Tool Compatibility Matrix

| Tool | macOS | Linux | Windows | Docker |
|------|-------|-------|---------|--------|
| TruffleHog | ✅ | ✅ | ✅ | ✅ |
| Semgrep | ✅ | ✅ | ⚠️ | ✅ |
| Trivy | ✅ | ✅ | ✅ | ✅ |
| Syft | ✅ | ✅ | ✅ | ✅ |
| Checkov | ✅ | ✅ | ✅ | ✅ |
| Hadolint | ✅ | ✅ | ✅ | ✅ |
| Nuclei | ✅ | ✅ | ✅ | ✅ |
| Bandit | ✅ | ✅ | ✅ | ✅ |
| OWASP ZAP | ⚠️ | ⚠️ | ⚠️ | ✅ |
| Nosey Parker | ❌ | ✅ | ❌ | ✅ |
| Falco | ❌ | ✅ | ❌ | ✅ |
| AFL++ | ❌ | ✅ | ❌ | ✅ |

**Legend:**

- ✅ Full native support
- ⚠️ Limited support (complex setup or some features unavailable)
- ❌ Not available natively (use Docker)

---

## 🎯 Recommended Installation Paths

### Path 1: Docker (Best for Everyone) ⭐

**Install:** Docker Desktop only
**Tools:** All 12 tools included
**Time:** 2 minutes

```bash
# Install Docker Desktop
https://www.docker.com/products/docker-desktop

# Start scanning immediately
jmotools wizard --docker
```

## Install Docker Desktop

https://www.docker.com/products/docker-desktop

## Start scanning immediately

jmotools wizard --docker

```text

---

### Path 2: Native + Automated Scripts (Best for Power Users)

**Install:** JMo CLI + automated tool installer
**Tools:** 8-9 tools (platform-dependent)
**Time:** 5-10 minutes

```bash
# macOS/Linux
curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

# Windows
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1
```

---

### Path 2: Native + Automated Scripts (Best for Power Users)

**Install:** JMo CLI + automated tool installer
**Tools:** 8-9 tools (platform-dependent)
**Time:** 5-10 minutes

```bash
# macOS/Linux
curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

# Windows
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1
```

## macOS/Linux

curl -fsSL https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-homebrew.sh | bash

## Windows

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/packaging/scripts/install-tools-windows.ps1" -OutFile install-tools.ps1
.\install-tools.ps1

```text

---

### Path 3: Native + Manual Installation (Maximum Control)

**Install:** Each tool individually
**Tools:** Choose which tools you need
**Time:** 15-30 minutes

See **Manual Installation** section above for each tool.

---

## 🆘 Troubleshooting

### Issue: `jmotools setup --check` shows tools not detected

**Solutions:**

1. **Check PATH:**
   ```bash
   echo $PATH  # Should include tool install directories
   ```

1. **Verify binary exists:**

   ```bash
   which trufflehog
   which trivy
   which semgrep
   ```

2. **Run with missing tools allowed:**

   ```bash
   jmotools fast --repos-dir ~/repos --allow-missing-tools
   ```

3. **Use Docker mode:**

   ```bash
   jmotools wizard --docker  # Bypasses all tool detection
   ```

---

### Issue: Permission denied when running tools

**Solution (macOS/Linux):**

```bash
# Make binaries executable
chmod +x $(which trufflehog)
chmod +x $(which trivy)
# ... etc
```

---

### Path 3: Native + Manual Installation (Maximum Control)

**Install:** Each tool individually
**Tools:** Choose which tools you need
**Time:** 15-30 minutes

See **Manual Installation** section above for each tool.

---

## 🆘 Troubleshooting

### Issue: `jmotools setup --check` shows tools not detected

**Solutions:**

1. **Check PATH:**

   ```bash
   echo $PATH  # Should include tool install directories
   ```

2. **Verify binary exists:**

   ```bash
   which trufflehog
   which trivy
   which semgrep
   ```

3. **Run with missing tools allowed:**

   ```bash
   jmotools fast --repos-dir ~/repos --allow-missing-tools
   ```

4. **Use Docker mode:**

   ```bash
   jmotools wizard --docker  # Bypasses all tool detection
   ```

---

### Issue: Permission denied when running tools

**Solution (macOS/Linux):**

```bash
# Make binaries executable
chmod +x $(which trufflehog)
chmod +x $(which trivy)
# ... etc
```

## Make binaries executable

chmod +x $(which trufflehog)
chmod +x $(which trivy)

## ... etc

```text

---

### Issue: Windows Defender flags tools as malicious

**Solution:**
Security tools are often flagged as false positives. Either:

1. **Add exclusion to Windows Defender:**
   - Windows Security → Virus & threat protection → Exclusions
   - Add folder: `C:\Users\<user>\scoop\apps\` (for Scoop installs)

2. **Use Docker mode (recommended):**
   ```powershell
   jmotools wizard --docker
   ```

---

## 📚 Additional Resources

- **Homebrew Installation Script:** [packaging/scripts/install-tools-homebrew.sh](scripts/install-tools-homebrew.sh)
- **Linux Installation Script:** [packaging/scripts/install-tools-linux.sh](scripts/install-tools-linux.sh)
- **Windows Installation Script:** [packaging/scripts/install-tools-windows.ps1](scripts/install-tools-windows.ps1)
- **Windows Compatibility Guide:** [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md)
- **Docker Guide:** [../docs/DOCKER_README.md](../docs/DOCKER_README.md)

---

**Last Updated:** 2025-10-30
**Version:** v0.9.0
**Maintainer:** Jimmy Moceri (@jimmy058910)


---

### Issue: Windows Defender flags tools as malicious

**Solution:**
Security tools are often flagged as false positives. Either:

1. **Add exclusion to Windows Defender:**
   - Windows Security → Virus & threat protection → Exclusions
   - Add folder: `C:\Users\<user>\scoop\apps\` (for Scoop installs)

2. **Use Docker mode (recommended):**

   ```powershell
   jmotools wizard --docker
   ```

---

## 📚 Additional Resources

- **Homebrew Installation Script:** [packaging/scripts/install-tools-homebrew.sh](scripts/install-tools-homebrew.sh)
- **Linux Installation Script:** [packaging/scripts/install-tools-linux.sh](scripts/install-tools-linux.sh)
- **Windows Installation Script:** [packaging/scripts/install-tools-windows.ps1](scripts/install-tools-windows.ps1)
- **Windows Compatibility Guide:** [WINDOWS_COMPATIBILITY.md](WINDOWS_COMPATIBILITY.md)
- **Docker Guide:** [../docs/DOCKER_README.md](../docs/DOCKER_README.md)

---

**Last Updated:** 2025-10-30
**Version:** v0.9.0
**Maintainer:** Jimmy Moceri (@jimmy058910)
