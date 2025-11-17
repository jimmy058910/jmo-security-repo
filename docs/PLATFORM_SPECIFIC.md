# Platform-Specific Installation Guide

**Last Updated:** 2025-11-16

**Purpose:** Platform-specific troubleshooting and considerations for macOS, Windows (native), Windows WSL, and Linux environments.

---

## 📚 Quick Navigation

| Platform | Best For | Installation Method | Troubleshooting |
|----------|----------|---------------------|-----------------|
| **[macOS](#macos)** | Local development | Native Python via Homebrew | [macOS Issues](#macos-troubleshooting) |
| **[Windows (Native)](#windows-native)** | Windows 10/11 users | Winget + pip | [Windows Issues](#windows-troubleshooting) |
| **[Windows WSL](#windows-wsl)** | Full Linux tooling on Windows | WSL2 + Ubuntu | [WSL Issues](#wsl-troubleshooting) |
| **[Linux](#linux)** | Servers, CI/CD | apt/dnf/yum + pip | [Linux Issues](#linux-troubleshooting) |
| **[Docker](#docker-all-platforms)** | Zero-installation, all platforms | Docker Desktop | [Docker Issues](#docker-troubleshooting) |

---

## macOS

### Prerequisites

- **macOS version:** 10.15 Catalina or later (11.0 Big Sur recommended)
- **Python:** 3.10+ (3.11 recommended)
- **Homebrew:** Package manager for macOS tools
- **Xcode Command Line Tools:** Required for some security tools

### Installation Steps

```bash
# 1. Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python 3.11 via Homebrew
brew install python@3.11

# 3. Verify Python version
python3 --version  # Should show 3.11.x

# 4. Install JMo Security
pip3 install jmo-security

# 5. Verify installation
jmo --help

# 6. Install external security tools (optional)
jmo setup
```

### macOS-Specific Considerations

#### **1. M1/M2 Apple Silicon (ARM64) Compatibility**

**Issue:** Some security tools are x86_64 only and require Rosetta 2.

**Solution:**

```bash
# Install Rosetta 2 (one-time setup)
softwareupdate --install-rosetta --agree-to-license

# Verify architecture
uname -m  # Should show "arm64"

# Use Docker for x86_64 tools (Semgrep, Trivy)
docker run --platform linux/amd64 -v "$(pwd):/scan" jmosecurity/jmo-security:balanced scan --repo /scan
```

**Tools with native ARM64 support:**

- ✅ Trivy (v0.47.0+)
- ✅ Checkov (all versions)
- ✅ TruffleHog (all versions)
- ⚠️ Semgrep (use Docker on M1/M2)
- ⚠️ OWASP ZAP (use Docker on M1/M2)

#### **2. Homebrew PATH Configuration**

**Issue:** `pip3 install` commands not found after installation.

**Solution:**

```bash
# Add Homebrew Python to PATH (add to ~/.zshrc or ~/.bash_profile)
export PATH="/opt/homebrew/bin:$PATH"
export PATH="/opt/homebrew/opt/python@3.11/libexec/bin:$PATH"

# Reload shell
source ~/.zshrc  # or source ~/.bash_profile
```

#### **3. pip3 vs pip on macOS**

**Issue:** macOS has system Python 2.7 (deprecated) and may conflict with Homebrew Python.

**Solution:**

```bash
# ALWAYS use pip3 on macOS (not pip)
pip3 install jmo-security

# Verify pip points to Python 3.11
pip3 --version  # Should show "pip 23.x.x from /opt/homebrew/..."
```

#### **4. Xcode Command Line Tools**

**Issue:** Some tools (Syft, Grype) require Xcode tools for compilation.

**Solution:**

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Verify installation
xcode-select -p  # Should show "/Library/Developer/CommandLineTools"
```

#### **5. macOS Gatekeeper Warnings**

**Issue:** "jmo cannot be opened because the developer cannot be verified."

**Solution:**

```bash
# Allow unsigned binaries (after verifying source)
sudo spctl --master-disable  # Temporarily disable Gatekeeper

# Re-enable after installation
sudo spctl --master-enable
```

---

## Windows (Native)

### Prerequisites

- **Windows version:** Windows 10 version 1809 or later, Windows 11
- **Winget:** Windows Package Manager ([install guide](https://aka.ms/getwinget))
- **PowerShell:** 5.1 or later (7.x recommended)

### Installation Steps

```powershell
# 1. Install Python 3.11 via winget
winget install Python.Python.3.11

# 2. Verify Python installation
python --version  # Should show Python 3.11.x

# 3. Install JMo Security
pip install jmo-security

# 4. Verify installation
jmo --help

# 5. Install external security tools (optional)
jmo setup
```

### Windows-Specific Considerations

#### **1. PowerShell vs CMD**

**Issue:** CMD has limited support for environment variables and path handling.

**Solution:**

```powershell
# ALWAYS use PowerShell (not CMD) for JMo commands
# PowerShell supports $PWD variable and better path handling

# PowerShell (recommended)
docker run --rm -v "${PWD}:/scan" jmosecurity/jmo-security:fast scan --repo /scan

# CMD (fallback, avoid if possible)
docker run --rm -v "%CD%:/scan" jmosecurity/jmo-security:fast scan --repo /scan
```

#### **2. PATH Configuration**

**Issue:** `jmo: command not found` after pip installation.

**Solution:**

```powershell
# Add Python Scripts directory to PATH
# 1. Open "Environment Variables" (Win+R → sysdm.cpl → Advanced → Environment Variables)
# 2. Edit "Path" under "User variables"
# 3. Add: C:\Users\<username>\AppData\Local\Programs\Python\Python311\Scripts

# Verify PATH
$env:Path -split ";" | Select-String "Python311"

# Reload PowerShell
# Close and reopen PowerShell after PATH change
```

#### **3. Execution Policy Restrictions**

**Issue:** "jmo.ps1 cannot be loaded because running scripts is disabled."

**Solution:**

```powershell
# Check current execution policy
Get-ExecutionPolicy

# Allow local scripts (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Verify
Get-ExecutionPolicy  # Should show "RemoteSigned"
```

#### **4. Windows Defender Warnings**

**Issue:** Windows Defender flags security tools as malware (false positives).

**Solution:**

```powershell
# Add JMo directory to exclusions (run as Administrator)
Add-MpPreference -ExclusionPath "$env:USERPROFILE\AppData\Local\Programs\Python\Python311\Scripts"
Add-MpPreference -ExclusionPath "$env:USERPROFILE\.jmo"

# Verify exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

#### **5. Limited Tool Support on Native Windows**

**Issue:** Some tools (Trivy, Semgrep, ZAP) have limited native Windows support.

**Solution:**

**Option 1: Use Docker (recommended)**

```powershell
# Install Docker Desktop for Windows
winget install Docker.DockerDesktop

# Use Docker-based scanning
docker run --rm -v "${PWD}:/scan" jmosecurity/jmo-security:balanced scan --repo /scan
```

**Option 2: Use WSL2 (full Linux tooling)**

See [Windows WSL](#windows-wsl) section below.

**Tools with native Windows support:**

- ✅ Checkov (via pip)
- ✅ Bandit (via pip)
- ✅ TruffleHog (via binary)
- ⚠️ Trivy (limited, use Docker)
- ⚠️ Semgrep (limited, use Docker)
- ❌ OWASP ZAP (use Docker)
- ❌ Prowler (use WSL/Docker)

---

## Windows WSL

### Prerequisites

- **Windows version:** Windows 10 version 2004+ (build 19041+) or Windows 11
- **WSL2:** Windows Subsystem for Linux 2 ([enable guide](https://docs.microsoft.com/en-us/windows/wsl/install))
- **Ubuntu:** Recommended distribution (20.04 LTS or 22.04 LTS)

### Installation Steps

```bash
# 1. Install WSL2 (from PowerShell as Administrator)
wsl --install -d Ubuntu-22.04

# 2. Restart computer (required for WSL2)

# 3. Launch Ubuntu from Start Menu, create user/password

# 4. Update package lists (from WSL Ubuntu terminal)
sudo apt update && sudo apt upgrade -y

# 5. Install Python 3.11 and pip
sudo apt install -y python3.11 python3-pip git

# 6. Install JMo Security
pip3 install jmo-security

# 7. Verify installation
jmo --help

# 8. Install external security tools
jmo setup
```

### WSL-Specific Considerations

#### **1. Docker Desktop Integration**

**Issue:** Docker not available in WSL2 after installing Docker Desktop.

**Solution:**

```bash
# 1. Enable WSL2 integration in Docker Desktop
# Settings → Resources → WSL Integration → Enable "Ubuntu-22.04"

# 2. Verify Docker works from WSL
docker --version  # Should show Docker version

# 3. Run Docker scan from WSL
docker run --rm -v "$(pwd):/scan" jmosecurity/jmo-security:fast scan --repo /scan
```

#### **2. Accessing Windows Files from WSL**

**Issue:** Need to scan repos on Windows C: drive.

**Solution:**

```bash
# Windows drives mounted at /mnt/<drive-letter>
cd /mnt/c/Users/<username>/Projects/myrepo

# Scan Windows repo from WSL
jmo scan --repo /mnt/c/Users/<username>/Projects/myrepo

# Docker volume mount for Windows paths
docker run --rm -v /mnt/c/Users/<username>/Projects/myrepo:/scan jmosecurity/jmo-security:fast scan --repo /scan
```

**Performance Note:** Accessing Windows files from WSL2 is slower than native WSL2 filesystem. For best performance:

```bash
# Copy repo to WSL2 filesystem
cp -r /mnt/c/Users/<username>/Projects/myrepo ~/myrepo
cd ~/myrepo

# Scan from WSL2 native filesystem (3-5x faster)
jmo scan --repo ~/myrepo
```

#### **3. WSL1 vs WSL2**

**Issue:** WSL1 has limited Docker support and slower I/O.

**Solution:**

```bash
# Check WSL version
wsl -l -v

# Upgrade to WSL2 if needed (from PowerShell as Administrator)
wsl --set-version Ubuntu-22.04 2

# Set WSL2 as default
wsl --set-default-version 2
```

**WSL1 limitations:**

- ❌ No Docker support (kernel incompatibility)
- ❌ Slower file I/O (9P protocol overhead)
- ❌ Limited syscall support (some tools fail)

**WSL2 benefits:**

- ✅ Full Docker Desktop integration
- ✅ Native Linux kernel (4.19+)
- ✅ 3-5x faster file I/O on native filesystem
- ✅ Full syscall compatibility

#### **4. Memory and CPU Limits**

**Issue:** WSL2 consumes excessive RAM (default: 50% of system memory).

**Solution:**

```bash
# Create .wslconfig in Windows user directory
# C:\Users\<username>\.wslconfig

[wsl2]
memory=4GB      # Limit WSL2 to 4GB RAM
processors=2    # Limit to 2 CPU cores
swap=2GB        # Swap file size

# Restart WSL after config change (from PowerShell)
wsl --shutdown
wsl
```

#### **5. Git Line Ending Conflicts**

**Issue:** Git converts LF to CRLF on Windows, breaking shell scripts.

**Solution:**

```bash
# Configure Git to preserve LF line endings in WSL
git config --global core.autocrlf input

# For repos cloned on Windows, fix line endings
git config core.autocrlf false
git rm --cached -r .
git reset --hard
```

---

## Linux

### Distribution-Specific Installation

#### Ubuntu/Debian (20.04+, 11+)

```bash
# Update package lists
sudo apt update && sudo apt upgrade -y

# Install Python 3.11 and dependencies
sudo apt install -y python3.11 python3-pip git curl

# Install JMo Security
pip3 install jmo-security

# Verify installation
jmo --help

# Install external security tools
jmo setup
```

#### RHEL/CentOS/Fedora (8+, 36+)

```bash
# Update package lists
sudo dnf update -y

# Install Python 3.11 and dependencies
sudo dnf install -y python3.11 python3-pip git curl

# Install JMo Security
pip3 install jmo-security

# Verify installation
jmo --help

# Install external security tools
jmo setup
```

#### Alpine Linux (3.17+)

```bash
# Update package lists
apk update && apk upgrade

# Install Python 3.11 and dependencies
apk add python3 py3-pip git curl bash

# Install JMo Security
pip3 install jmo-security

# Verify installation
jmo --help
```

### Linux-Specific Considerations

#### **1. Python 3.10+ Availability**

**Issue:** Older distributions (Ubuntu 18.04, CentOS 7) ship Python 3.6-3.9.

**Solution:**

```bash
# Option 1: Use deadsnakes PPA (Ubuntu/Debian)
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# Option 2: Use pyenv (all distributions)
curl https://pyenv.run | bash
pyenv install 3.11.7
pyenv global 3.11.7

# Option 3: Use Docker (no system Python changes)
docker run --rm -v "$(pwd):/scan" jmosecurity/jmo-security:balanced scan --repo /scan
```

#### **2. pip User vs System Installation**

**Issue:** Permission denied when installing with pip.

**Solution:**

```bash
# Option 1: User installation (recommended, no sudo)
pip3 install --user jmo-security
export PATH="$HOME/.local/bin:$PATH"  # Add to ~/.bashrc or ~/.zshrc

# Option 2: Virtual environment (isolated)
python3 -m venv ~/.jmo-venv
source ~/.jmo-venv/bin/activate
pip install jmo-security

# Option 3: System-wide (requires sudo, NOT recommended)
sudo pip3 install jmo-security
```

#### **3. SELinux Restrictions (RHEL/CentOS/Fedora)**

**Issue:** SELinux blocks JMo from accessing files or executing tools.

**Solution:**

```bash
# Check SELinux status
getenforce  # Should show "Enforcing" or "Permissive"

# Option 1: Set permissive mode temporarily (testing)
sudo setenforce 0

# Option 2: Add SELinux policy for JMo (production)
sudo ausearch -c 'jmo' --raw | audit2allow -M jmo-policy
sudo semodule -i jmo-policy.pp

# Option 3: Disable SELinux (NOT recommended for production)
# Edit /etc/selinux/config: SELINUX=disabled
```

#### **4. AppArmor Restrictions (Ubuntu/Debian)**

**Issue:** AppArmor blocks Docker or security tools from accessing files.

**Solution:**

```bash
# Check AppArmor status
sudo aa-status

# Option 1: Set complain mode for Docker
sudo aa-complain /etc/apparmor.d/docker

# Option 2: Disable AppArmor profile (testing only)
sudo ln -s /etc/apparmor.d/docker /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/docker

# Option 3: Add AppArmor exception for JMo
# (requires custom profile creation)
```

#### **5. Docker Permission Issues**

**Issue:** "permission denied while trying to connect to Docker daemon socket."

**Solution:**

```bash
# Add user to docker group (requires logout/login)
sudo usermod -aG docker $USER

# Logout and login (or use newgrp)
newgrp docker

# Verify Docker works without sudo
docker --version
docker ps
```

---

## Docker (All Platforms)

### Prerequisites

- **Docker Desktop:** macOS, Windows ([install guide](https://docs.docker.com/desktop/))
- **Docker Engine:** Linux ([install guide](https://docs.docker.com/engine/install/))
- **Docker version:** 20.10+ (24.0+ recommended)

### Platform-Specific Docker Setup

#### **macOS**

```bash
# Install Docker Desktop
brew install --cask docker

# Start Docker Desktop (from Applications folder)

# Verify Docker
docker --version
docker ps
```

#### **Windows (Native)**

```powershell
# Install Docker Desktop via winget
winget install Docker.DockerDesktop

# Start Docker Desktop (from Start Menu)

# Verify Docker (PowerShell)
docker --version
docker ps
```

#### **Windows WSL**

```bash
# Docker Desktop integration (Settings → Resources → WSL Integration)
# Enable "Ubuntu-22.04" integration

# Verify Docker from WSL
docker --version
docker ps
```

#### **Linux**

```bash
# Ubuntu/Debian
sudo apt install -y docker.io
sudo systemctl enable --now docker

# RHEL/CentOS/Fedora
sudo dnf install -y docker
sudo systemctl enable --now docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Docker-Specific Considerations

#### **1. Volume Mount Syntax by Platform**

**Issue:** Volume mount syntax differs across platforms.

**Solution:**

```bash
# Linux/macOS/WSL
docker run --rm -v "$(pwd):/scan" jmosecurity/jmo-security:fast scan --repo /scan

# Windows PowerShell
docker run --rm -v "${PWD}:/scan" jmosecurity/jmo-security:fast scan --repo /scan

# Windows CMD
docker run --rm -v "%CD%:/scan" jmosecurity/jmo-security:fast scan --repo /scan
```

#### **2. Line Ending Issues (Windows)**

**Issue:** Shell scripts fail with "^M: bad interpreter" on Windows-mounted volumes.

**Solution:**

```bash
# Configure Git to preserve LF line endings
git config --global core.autocrlf false

# Fix existing repo
git rm --cached -r .
git reset --hard

# Or run Docker with --platform linux/amd64
docker run --platform linux/amd64 -v "$(pwd):/scan" jmosecurity/jmo-security:fast scan --repo /scan
```

#### **3. Docker Desktop Resource Limits**

**Issue:** Docker Desktop runs out of memory during large scans.

**Solution:**

```bash
# Increase Docker Desktop memory limit
# macOS/Windows: Docker Desktop → Settings → Resources → Memory
# Recommended: 4-8 GB for balanced scans, 8-16 GB for full scans

# Verify resource limits
docker info | grep -i memory
```

#### **4. Image Pull Rate Limits (Docker Hub)**

**Issue:** "toomanyrequests: You have reached your pull rate limit."

**Solution:**

```bash
# Option 1: Authenticate to Docker Hub (free account = 200 pulls/6 hours)
docker login

# Option 2: Use GitHub Container Registry (unlimited pulls)
docker pull ghcr.io/jmosecurity/jmo-security:fast

# Option 3: Pull once, use cached image
docker images | grep jmo-security
```

---

## Common Troubleshooting

### Issue: "jmo: command not found"

**Platforms:** All

**Causes:**

1. JMo not installed
2. Python Scripts directory not in PATH
3. Virtual environment not activated

**Solutions:**

```bash
# 1. Verify installation
pip3 show jmo-security

# 2. Check PATH (macOS/Linux)
echo $PATH | grep -i python

# 3. Check PATH (Windows PowerShell)
$env:Path -split ";" | Select-String "Python"

# 4. Add to PATH manually
# macOS/Linux: Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/.local/bin:$PATH"

# Windows: Add to Environment Variables
# C:\Users\<username>\AppData\Local\Programs\Python\Python311\Scripts
```

### Issue: "No module named 'scripts'"

**Platforms:** All

**Cause:** JMo not installed correctly or virtual environment issue.

**Solution:**

```bash
# Uninstall and reinstall
pip3 uninstall jmo-security -y
pip3 install --no-cache-dir jmo-security

# Verify installation
pip3 show jmo-security
jmo --help
```

### Issue: "Tool not found: trivy"

**Platforms:** macOS, Windows, Linux

**Cause:** External security tools not installed.

**Solution:**

```bash
# Option 1: Install tools via jmo setup
jmo setup

# Option 2: Use Docker (zero installation)
docker run --rm -v "$(pwd):/scan" jmosecurity/jmo-security:balanced scan --repo /scan

# Option 3: Install specific tool manually
# Trivy (all platforms)
brew install trivy  # macOS
winget install Aqua.Trivy  # Windows
sudo apt install trivy  # Ubuntu/Debian
```

### Issue: "Permission denied" (Docker)

**Platforms:** Linux

**Cause:** User not in docker group.

**Solution:**

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout and login (or use newgrp)
newgrp docker

# Verify
docker ps  # Should work without sudo
```

### Issue: Slow scans on WSL2

**Platforms:** Windows WSL

**Cause:** Accessing Windows files from WSL2 (/mnt/c/) is 3-5x slower.

**Solution:**

```bash
# Option 1: Copy repo to WSL2 native filesystem
cp -r /mnt/c/Users/<username>/Projects/myrepo ~/myrepo
cd ~/myrepo
jmo scan --repo ~/myrepo

# Option 2: Use Docker Desktop (faster than /mnt/c/)
docker run --rm -v /mnt/c/Users/<username>/Projects/myrepo:/scan jmosecurity/jmo-security:fast scan --repo /scan
```

---

## Platform Comparison Matrix

| Feature | macOS | Windows (Native) | Windows WSL | Linux | Docker |
|---------|-------|------------------|-------------|-------|--------|
| **Setup Time** | 5 min | 10 min | 15 min | 5 min | 2 min |
| **Tool Support** | ✅ 90% native | ⚠️ 50% native | ✅ 100% | ✅ 100% | ✅ 100% |
| **Performance** | ⚡ Fast | ⚡ Fast | ⚡ Fast (native FS) | ⚡ Fast | ⚡ Fast |
| **Maintenance** | Low | Medium | Medium | Low | Very Low |
| **CI/CD Ready** | ✅ Yes | ⚠️ Limited | ✅ Yes | ✅ Yes | ✅ Yes |
| **Recommended For** | Local dev | Windows users | Full tooling | Servers | All use cases |

---

## Getting Help

### Platform-Specific Support Channels

- **macOS:** [GitHub Discussions - macOS](https://github.com/jimmy058910/jmo-security-repo/discussions/categories/macos)
- **Windows:** [GitHub Discussions - Windows](https://github.com/jimmy058910/jmo-security-repo/discussions/categories/windows)
- **WSL:** [GitHub Discussions - WSL](https://github.com/jimmy058910/jmo-security-repo/discussions/categories/wsl)
- **Linux:** [GitHub Discussions - Linux](https://github.com/jimmy058910/jmo-security-repo/discussions/categories/linux)
- **Docker:** [GitHub Discussions - Docker](https://github.com/jimmy058910/jmo-security-repo/discussions/categories/docker)

### Reporting Platform-Specific Bugs

**Include in bug report:**

1. **Platform details:**
   - OS: macOS/Windows/Linux
   - Version: macOS 14.2, Windows 11 22H2, Ubuntu 22.04, etc.
   - Architecture: x86_64, arm64 (M1/M2)

2. **Python details:**

   ```bash
   python3 --version
   pip3 --version
   which python3
   ```

3. **Docker details (if applicable):**

   ```bash
   docker --version
   docker info | grep -i "Operating System"
   ```

4. **Error output:**

   ```bash
   jmo scan --repo . --log-level DEBUG 2>&1 | tee debug.log
   ```

---

## Additional Resources

- **Installation Guide:** [QUICKSTART.md](../QUICKSTART.md)
- **Docker Guide:** [DOCKER_README.md](DOCKER_README.md)
- **User Guide:** [USER_GUIDE.md](USER_GUIDE.md)
- **Wizard Guide:** [examples/wizard-examples.md](examples/wizard-examples.md)
- **Documentation Index:** [index.md](index.md)

---

**Last Updated:** 2025-11-16
**Maintainer:** JMo Security Team
**License:** MIT
