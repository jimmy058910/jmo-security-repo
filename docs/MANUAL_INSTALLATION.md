# Installation Guide

Complete reference for installing JMo Security and its external security tools.

## Table of Contents

- [Quick Start](#quick-start)
- [JMo Security Installation](#jmo-security-installation)
- [External Tool Installation](#external-tool-installation)
- [Platform-Specific Guide](#platform-specific-guide)
- [Manual Installation Tools](#manual-installation-tools)
  - [Windows-Specific Installation](#windows-specific-installation)
    - [Prowler (Windows)](#prowler-windows)
    - [Lynis (Windows)](#lynis-windows)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

**Fastest option (Docker - zero installation):**

```bash
# All tools pre-installed, works on all platforms
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:balanced \
  scan --repo /scan --results-dir /scan/results --profile-name balanced
```

**Native installation:**

```bash
# 1. Install JMo Security
pip install jmo-security

# 2. Check tool status for your profile
jmo tools check --profile balanced

# 3. Install missing tools (cross-platform)
jmo tools install --profile balanced

# 4. Verify installation
jmo tools check --profile balanced
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

JMo Security orchestrates 28+ external security tools. Use the built-in tool manager or install manually.

### Automated Installation (Recommended)

**Using `jmo tools` (All Platforms):**

```bash
# Check what's needed for your profile
jmo tools check --profile balanced

# Install missing tools (auto-detects platform)
jmo tools install --profile balanced

# Or install all tools for deep scanning
jmo tools install --profile deep
```

**Installation methods by platform:**

| Platform | Methods (in priority order) |
|----------|----------------------------|
| Linux | apt, pip, npm, binary download, brew |
| macOS | brew, pip, npm, binary download |
| Windows | pip, npm, binary download, manual |

**Windows (PowerShell):**

```powershell
jmo tools install --profile balanced
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

**Nosey Parker** (Deep secrets scanning - Docker only):

```bash
docker pull ghcr.io/praetorian-inc/noseyparker:latest
```

#### SAST (Static Analysis)

**Semgrep** (Multi-language SAST):

```bash
# macOS/Linux
brew install semgrep

# Python (all platforms)
pip install semgrep
```

**Bandit** (Python security linter):

```bash
pip install bandit
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

**Bearer** (Privacy/PII scanning - Linux/macOS only):

```bash
# macOS
brew install bearer/tap/bearer

# Linux
curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh

# Windows: Use Docker
docker run --rm -v "$PWD:/scan" bearer/bearer scan /scan
```

> **Note:** Bearer is not available natively on Windows. Use Docker mode or WSL2 for full support.

#### Java-Based Tools (Dependency-Check, ZAP)

Several tools require **Java 11+** (Java 17+ recommended):

- **OWASP Dependency-Check** - SCA/vulnerability scanner
- **OWASP ZAP** - Dynamic application security testing

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

**Install Dependency-Check:**

```bash
# All platforms (after Java is installed)
jmo tools install dependency-check

# Or manual download from:
# https://github.com/jeremylong/DependencyCheck/releases
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
| Nuclei | ✅ | ✅ | ✅ | ✅ |
| Bandit | ✅ | ✅ | ✅ | ✅ |
| OWASP ZAP | ✅ | ✅ | ✅ | ✅ |
| Bearer | ✅ | ✅ | ❌ | ✅ |
| Nosey Parker | ❌ | ✅ | ❌ | ✅ |
| Falco | ❌ | ✅ | ❌ | ✅ |
| AFL++ | ❌ | ✅ | ❌ | Manual |
| MobSF | ❌ | ❌ | ❌ | ✅ |
| Akto | ❌ | ❌ | ❌ | ✅ |

**Legend:** ✅ Full support | ⚠️ Limited support | ❌ Docker only | Manual = See [Manual Installation](#manual-installation-tools)

> **Wizard behavior:** When running `jmo wizard`, platform-incompatible tools are automatically skipped with explanatory messages. For example, on Windows:
>
> ```text
> ~ Skipped on windows (5 tools):
>   ~ falco: Requires Linux kernel module
>   ~ afl++: Requires Linux kernel features
>   ~ noseyparker: Rust binary not available for Windows
>   ~ bearer: Go binary not available for Windows
>   ~ mobsf: Complex setup (Docker recommended)
> ```

---

## Platform-Specific Guide

### macOS

**Prerequisites:**

- macOS 10.15+ (11.0 Big Sur recommended)
- Python 3.10+ (3.11 recommended)
- Homebrew

**Installation:**

```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.11
brew install python@3.11

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
export PATH="/opt/homebrew/opt/python@3.11/libexec/bin:$PATH"
```

### Windows (Native)

**Prerequisites:**

- Windows 10 version 1809+ or Windows 11
- Winget or Scoop package manager
- PowerShell 5.1+ (7.x recommended)

**Installation:**

```powershell
# Install Python 3.11
winget install Python.Python.3.11

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

**Limitation:** 5/12 tools require WSL2 or Docker. Use Docker mode for full coverage.

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

## Manual Installation Tools

Some tools require manual installation due to complex dependencies or platform-specific limitations.

### Windows-Specific Installation

The following tools have special requirements on Windows that prevent automatic installation:

#### Prowler (Windows) {#prowler-windows}

**Issue:** Prowler installation on Windows fails due to long path limitations (>260 characters). The AWS SDK and its dependencies create deeply nested paths that exceed Windows' default MAX_PATH limit.

**Solution:** Enable Windows Long Path Support (requires admin privileges and reboot):

1. **Enable via Registry (Recommended):**

   ```powershell
   # Run PowerShell as Administrator
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
     -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
   ```

2. **Enable via Group Policy (Alternative):**
   - Press Win+R, type `gpedit.msc`
   - Navigate to: Computer Configuration → Administrative Templates → System → Filesystem
   - Enable "Enable Win32 long paths"

3. **Reboot your system** (required for the change to take effect)

4. **Install Prowler:**

   ```powershell
   pip install prowler
   prowler -v  # Verify installation
   ```

**Alternative:** Use WSL2 or Docker mode for full Prowler support:

```powershell
# WSL2
wsl -d Ubuntu-22.04
pip install prowler

# Docker
docker run -v "$PWD:/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --profile balanced
```

#### Lynis (Windows) {#lynis-windows}

**Issue:** Lynis is a shell script that requires a Unix shell (bash) to run. It cannot run natively on Windows without a Unix-like environment.

**Solution Options:**

1. **Use WSL2 (Recommended):**

   ```powershell
   # Install WSL2 if not already installed
   wsl --install -d Ubuntu-22.04

   # From WSL2 terminal
   sudo apt update && sudo apt install lynis -y
   lynis show version
   ```

2. **Use Git Bash:**

   ```bash
   # Install Git for Windows (includes Git Bash)
   # https://git-scm.com/download/win

   # From Git Bash terminal
   git clone https://github.com/CISOfy/lynis.git ~/.lynis
   ~/.lynis/lynis show version
   ```

3. **Use Docker mode:**

   ```powershell
   docker run -v "$PWD:/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --profile balanced
   ```

**Note:** On Windows, JMo will skip Lynis if bash is not available. Use Docker mode for full tool coverage.

---

### Docker Image Tool Counts

| Variant | Docker-Ready | Manual Tools |
|---------|--------------|--------------|
| **Deep/Full** | 25 | 3 (MobSF, Akto, AFL++) |
| **Balanced** | 18 | 0 |
| **Slim** | 14 | 0 |
| **Fast** | 8 | 0 |

### AFL++ Installation (Fuzzing)

AFL++ is a powerful fuzzing framework but requires LLVM development headers for full compilation. It's optional for most security scanning workflows.

**Ubuntu/Debian:**

```bash
# Install build dependencies
sudo apt-get install -y build-essential clang llvm-14-dev libc++-dev \
  libc++abi-dev libunwind-dev libglib2.0-dev

# Clone and build
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make distrib
sudo make install

# Verify
afl-fuzz --help
```

**Docker (Easiest):**

```bash
# Use official AFL++ Docker image
docker pull aflplusplus/aflplusplus

# Run AFL++ from Docker
docker run -it -v $(pwd):/src aflplusplus/aflplusplus
```

**JMo Integration:**

AFL++ is primarily used for fuzz testing compiled binaries, not typical security scanning workflows. If you need fuzzing capabilities:

```bash
# Run AFL++ separately on compiled targets
afl-fuzz -i input/ -o findings/ -- ./target_binary @@
```

### MobSF Installation

**Prerequisites:** Python 3.10+, JDK 8+, 2 GB storage

```bash
# Install MobSF
pip install mobsf==4.2.0

# Install Android SDK tools
wget https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip
unzip commandlinetools-linux-9477386_latest.zip -d ~/android-sdk
export ANDROID_HOME=~/android-sdk

$ANDROID_HOME/cmdline-tools/bin/sdkmanager --sdk_root=$ANDROID_HOME \
  "build-tools;30.0.3" "platforms;android-30"

# Install APK tools
sudo apt-get install -y aapt
wget https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar
sudo mv apktool_2.10.0.jar /usr/local/bin/apktool.jar

# Verify
mobsf --version
```

**JMo Integration:**

```bash
jmo scan --repo ./mobile-app --profile deep --tools mobsf
```

### Akto Installation

**Prerequisites:** Docker 20.10+, Docker Compose 1.29+

```bash
# Deploy Akto
git clone https://github.com/akto-api-security/akto.git
cd akto
docker-compose up -d

# Configure JMo
mkdir -p ~/.jmo
cat > ~/.jmo/akto.yml << EOF
akto:
  endpoint: http://localhost:8080/api
  api_key: YOUR_API_KEY
EOF

# Get API key from Akto dashboard: http://localhost:8080
# Settings → API Keys → Generate
```

**JMo Integration:**

```bash
jmo scan --url https://api.example.com --profile deep --tools akto
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
jmo tools check --profile balanced
jmo tools install --profile balanced

# Option 2: Use Docker (all tools included)
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --repo /scan

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
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:balanced scan --repo /scan
```

---

## Platform Comparison

| Feature | macOS | Windows | WSL | Linux | Docker |
|---------|-------|---------|-----|-------|--------|
| **Setup Time** | 5 min | 10 min | 15 min | 5 min | 2 min |
| **Tool Support** | 90% | 50% | 100% | 100% | 100% |
| **Performance** | Fast | Fast | Fast | Fast | Fast |
| **CI/CD Ready** | Yes | Limited | Yes | Yes | Yes |
| **Recommended** | Local dev | Docker | Full tooling | Servers | All |

---

## Additional Resources

- **Docker Guide:** [DOCKER_README.md](DOCKER_README.md)
- **User Guide:** [USER_GUIDE.md](USER_GUIDE.md)
- **Quick Start:** [QUICKSTART.md](../QUICKSTART.md)

---

**Last Updated:** December 2025
