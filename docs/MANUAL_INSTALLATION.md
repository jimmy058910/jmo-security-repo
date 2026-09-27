# Installation Guide

Complete reference for installing JMo Security and its external security tools.

## Table of Contents

- [Quick Start](#quick-start)
- [JMo Security Installation](#jmo-security-installation)
- [External Tool Installation](#external-tool-installation)
- [Platform-Specific Guide](#platform-specific-guide)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

**Fastest option (Docker - zero installation):**

```bash
# All tools pre-installed, works on all platforms
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results
```

**Native installation:**

```bash
# 1. Install JMo Security
pip install jmo-security

# 2. Check tool status
jmo tools check

# 3. Install missing tools (cross-platform)
jmo tools install

# 4. Verify installation
jmo tools check
```

---

## JMo Security Installation

### pip (All Platforms)

```bash
pip install jmo-security
```

### Homebrew (macOS/Linux)

```bash
brew install jmo-security
```

### Winget (Windows)

```powershell
winget install jmo-security
```

### From Source

```bash
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo
pip install -e .
```

---

## External Tool Installation

JMo Security orchestrates the external security tools in the [tool matrix](TOOLS.md#the-tool-matrix), plus OPA for policy-as-code. Use the built-in tool manager or install manually.

### Automated Installation (Recommended)

**Using `jmo tools` (All Platforms):**

```bash
# Check what's installed and what's missing
jmo tools check

# Install missing tools (auto-detects platform)
jmo tools install

# Or install specific tools
jmo tools install trivy semgrep
```

**Installation methods by platform:**

| Platform | Methods (in priority order) |
|----------|----------------------------|
| Linux | apt, pip, npm, install script, binary download, brew |
| macOS | brew, pip, npm, install script, binary download |
| Windows | pip, npm, binary download, manual |

Semgrep and Checkov always go into isolated virtual environments, and ZAP is always an extracted archive, whatever the platform. [TOOLS.md](TOOLS.md#installation) lists where each tool ends up.

**Windows (PowerShell):**

```powershell
jmo tools install
```

### Manual Tool Installation

#### Secrets Scanning

**TruffleHog** (Verified secrets detection):

```bash
# macOS/Linux
brew install trufflesecurity/trufflehog/trufflehog

# Windows (Scoop)
scoop install trufflehog
```

#### SAST (Static Analysis)

**Semgrep** (Multi-language SAST):

```bash
# macOS/Linux
brew install semgrep

# Python (all platforms)
pip install semgrep
```

**Gosec** (Go security analyzer):

```bash
# macOS
brew install gosec

# Linux/Windows (Go)
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

#### Vulnerabilities + SBOM

**Trivy** (Comprehensive vulnerability scanner):

```bash
# macOS/Linux
brew install aquasecurity/trivy/trivy

# Windows (Scoop)
scoop install trivy

# Ubuntu/Debian
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

**Syft** (SBOM generation):

```bash
# macOS/Linux
brew install syft

# Windows (Scoop)
scoop install syft
```

**Grype** (Vulnerability scanner, Anchore database):

```bash
# macOS
brew install grype

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Windows (Chocolatey)
choco install grype -y
```

#### IaC Security

**Checkov** (Infrastructure as Code):

```bash
pip install checkov
# or
brew install checkov
```

#### Dockerfile Linting

**Hadolint** (Dockerfile best practices):

```bash
# macOS/Linux
brew install hadolint

# Windows: Download from https://github.com/hadolint/hadolint/releases
```

#### Shell Script Linting

**ShellCheck** (Shell script static analysis):

```bash
# macOS
brew install shellcheck

# Ubuntu/Debian
sudo apt install shellcheck -y

# Windows (Chocolatey)
choco install shellcheck -y
```

#### Malware Detection

**YARA** (Malware pattern matching):

```bash
pip install yara-python
```

`yara-python` is only the engine; it carries no rules, and YARA with no rules matches nothing. `jmo tools install yara` also downloads JMo's pinned rule bundle into `~/.jmo/yara-rules/`. If you install the engine by hand, point `per_tool.yara.rules_path` in `jmo.yml` at a rule set.

#### DAST (Dynamic Analysis)

**OWASP ZAP** (Web application security):

```bash
# macOS
brew install --cask owasp-zap

# Linux/Windows: https://www.zaproxy.org/download/
```

**Nuclei** (Fast vulnerability scanner):

```bash
# macOS/Linux
brew install nuclei

# Windows (Go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

#### Java for ZAP

**OWASP ZAP** requires **Java 17+**. It is the only tool in the matrix that needs Java; `jmo tools install zap` installs ZAP itself but not Java.

**Install Java:**

```bash
# Windows (Chocolatey)
choco install openjdk17 -y

# Windows (Winget)
winget install Microsoft.OpenJDK.17

# macOS
brew install openjdk@17

# Linux (Ubuntu/Debian)
sudo apt install openjdk-17-jre -y

# Linux (RHEL/CentOS)
sudo dnf install java-17-openjdk -y
```

**Verify Java installation:**

```bash
java -version
# Should show: openjdk version "17.x.x" or similar
```

> **Note:** The wizard will automatically detect if Java is missing and offer to **auto-install** it using your system's package manager (Chocolatey/winget on Windows, apt/dnf on Linux, Homebrew on macOS). If auto-install fails, it shows clear manual installation instructions.

### Tool Compatibility Matrix

| Tool | macOS | Linux | Windows | Docker |
|------|-------|-------|---------|--------|
| TruffleHog | ✅ | ✅ | ✅ | ✅ |
| Semgrep | ✅ | ✅ | ⚠️ | ✅ |
| Trivy | ✅ | ✅ | ✅ | ✅ |
| Syft | ✅ | ✅ | ✅ | ✅ |
| Checkov | ✅ | ✅ | ✅ | ✅ |
| Hadolint | ✅ | ✅ | ✅ | ✅ |
| ShellCheck | ✅ | ✅ | ✅ | ✅ |
| Gosec | ✅ | ✅ | ✅ | ✅ |
| Grype | ✅ | ✅ | ✅ | ✅ |
| YARA | ✅ | ✅ | ✅ | ✅ |
| Nuclei | ✅ | ✅ | ✅ | ✅ |
| OWASP ZAP | ✅ | ✅ | ✅ | ✅ |

**Legend:** ✅ Full support | ⚠️ Limited support

---

## Platform-Specific Guide

### macOS

**Prerequisites:**

- macOS 10.15+ (11.0 Big Sur recommended)
- Python 3.12+
- Homebrew

**Installation:**

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.12
brew install python@3.12

# Install JMo Security
pip3 install jmo-security
jmo setup
```

**M1/M2 Apple Silicon:**

Some tools require Rosetta 2:

```bash
softwareupdate --install-rosetta --agree-to-license
```

Tools with native ARM64 support: Trivy (v0.47.0+), Checkov, TruffleHog
Use Docker for: Semgrep, OWASP ZAP on M1/M2

**PATH Configuration:**

```bash
# Add to ~/.zshrc
export PATH="/opt/homebrew/bin:$PATH"
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$PATH"
```

### Windows (Native)

**Prerequisites:**

- Windows 10 version 1809+ or Windows 11
- Winget or Scoop package manager
- PowerShell 5.1+ (7.x recommended)

**Installation:**

```powershell
# Install Python 3.12
winget install Python.Python.3.12

# Install JMo Security
pip install jmo-security
jmo setup
```

**PATH Configuration:**

Add to Environment Variables:
`C:\Users\<username>\AppData\Local\Programs\Python\Python311\Scripts`

**Execution Policy:**

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Windows Defender:**

Security tools may be flagged as false positives. Add exclusion:

```powershell
Add-MpPreference -ExclusionPath "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts"
```

**Note:** Every tool in the [tool matrix](TOOLS.md#the-tool-matrix) installs natively on Windows. ZAP additionally needs Java 17+ (see [Java for ZAP](#java-for-zap)).

### Windows WSL

**Prerequisites:**

- Windows 10 version 2004+ or Windows 11
- WSL2 enabled
- Ubuntu 22.04 LTS recommended

**Installation:**

```bash
# Install WSL2 (from PowerShell as Administrator)
wsl --install -d Ubuntu-22.04

# From WSL Ubuntu terminal
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3-pip git
pip3 install jmo-security
jmo setup
```

**Docker Desktop Integration:**

Enable WSL2 integration: Docker Desktop → Settings → Resources → WSL Integration

**Accessing Windows Files:**

```bash
# Windows drives at /mnt/<drive-letter>
cd /mnt/c/Users/<username>/Projects/myrepo
jmo scan --repo .

# For better performance, copy to WSL2 native filesystem
cp -r /mnt/c/Users/<username>/Projects/myrepo ~/myrepo
```

**Memory Limits:**

Create `C:\Users\<username>\.wslconfig`:

```ini
[wsl2]
memory=4GB
processors=2
```

### Linux

**Ubuntu/Debian:**

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.11 python3-pip git curl
pip3 install jmo-security
jmo setup
```

**RHEL/CentOS/Fedora:**

```bash
sudo dnf update -y
sudo dnf install -y python3.11 python3-pip git curl
pip3 install jmo-security
jmo setup
```

**Alpine Linux:**

```bash
apk update && apk upgrade
apk add python3 py3-pip git curl bash
pip3 install jmo-security
```

**User vs System Installation:**

```bash
# User installation (recommended)
pip3 install --user jmo-security
export PATH="$HOME/.local/bin:$PATH"

# Virtual environment
python3 -m venv ~/.jmo-venv
source ~/.jmo-venv/bin/activate
pip install jmo-security
```

**SELinux (RHEL/CentOS):**

```bash
# Temporarily set permissive mode
sudo setenforce 0

# Or add policy
sudo ausearch -c 'jmo' --raw | audit2allow -M jmo-policy
sudo semodule -i jmo-policy.pp
```

**Docker Permissions:**

```bash
sudo usermod -aG docker $USER
newgrp docker
```

---

## Troubleshooting

### "jmo: command not found"

**All Platforms:**

```bash
# Verify installation
pip3 show jmo-security

# Check PATH
echo $PATH | grep -i python  # Linux/macOS
$env:Path -split ";" | Select-String "Python"  # Windows

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"  # Linux/macOS
```

### "Tool not found: trivy"

```bash
# Option 1: Check and install tools
jmo tools check
jmo tools install

# Option 2: Use Docker (all tools included)
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan

# Option 3: Allow missing tools
jmo scan --repo . --allow-missing-tools
```

### "Tool outdated" warnings

```bash
# Check outdated tools
jmo tools outdated

# Update all outdated tools
jmo tools update

# Update only critical tools
jmo tools update --critical-only
```

### Docker Permission Denied (Linux)

```bash
sudo usermod -aG docker $USER
newgrp docker
docker ps  # Should work without sudo
```

### Slow Scans on WSL2

```bash
# Copy to WSL2 native filesystem
cp -r /mnt/c/Users/<user>/Projects/myrepo ~/myrepo
jmo scan --repo ~/myrepo
```

### Windows Defender False Positives

```powershell
# Add exclusion
Add-MpPreference -ExclusionPath "$env:USERPROFILE\scoop\apps"

# Or use Docker mode
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
```

---

## Platform Comparison

| Feature | macOS | Windows | WSL | Linux | Docker |
|---------|-------|---------|-----|-------|--------|
| **Setup Time** | 5 min | 10 min | 15 min | 5 min | 2 min |
| **Tool Support** | All | All (Semgrep limited) | All | All | All |
| **Performance** | Fast | Fast | Fast | Fast | Fast |
| **CI/CD Ready** | Yes | Limited | Yes | Yes | Yes |
| **Recommended** | Local dev | Docker | Full tooling | Servers | All |

---

## Additional Resources

- **Docker Guide:** [DOCKER_README.md](DOCKER_README.md)
- **User Guide:** [USER_GUIDE.md](USER_GUIDE.md)
- **Quick Start:** [QUICKSTART.md](../QUICKSTART.md)

---

**Last Updated:** February 2026
