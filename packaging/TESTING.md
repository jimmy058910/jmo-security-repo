# Packaging Testing Guide

Comprehensive testing documentation for Homebrew and Winget packaging.

---

## 🍺 Homebrew Testing

### Prerequisites

- **macOS:** 13 (Ventura) or later, OR 14 (Sonoma) or later
- **Linux:** Ubuntu 22.04+ or Debian 11+
- Homebrew installed: https://brew.sh

### Test Matrix

| Platform | Version | Install | Scan | Plugin | Upgrade | Uninstall | Status |
|----------|---------|---------|------|--------|---------|-----------|--------|
| macOS | 13 (Ventura) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| macOS | 14 (Sonoma) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| Ubuntu | 22.04 LTS | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| Ubuntu | 24.04 LTS | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| Debian | 12 (Bookworm) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |

### Test 1: Fresh Install (macOS/Linux)

```bash
# IMPORTANT: Test on a CLEAN machine or VM
# DO NOT test on a machine with JMo Security already installed

# Step 1: Install formula from local repository
brew install --build-from-source packaging/homebrew/jmo-security.rb

# Expected output:
# ==> Installing jmo-security
# ==> Downloading https://github.com/jimmy058910/jmo-security-repo/archive/refs/tags/v0.9.0.tar.gz
# ...
# 🎉 JMo Security installed successfully!

# Step 2: Verify installation
which jmo
# Expected: /usr/local/bin/jmo (macOS Intel)
#           /opt/homebrew/bin/jmo (macOS Apple Silicon)
#           /home/linuxbrew/.linuxbrew/bin/jmo (Linux)

which jmotools
# Expected: Same directory as jmo

# Step 3: Test CLI commands
jmo --help
# Expected: Help text with scan/report/ci commands

jmotools --help
# Expected: Help text with wizard/fast/balanced/full commands

# Step 4: Test wizard
jmotools wizard --help
# Expected: Wizard help text with --yes, --emit-* flags

# Step 5: Test scan command
mkdir /tmp/test-repo
cd /tmp/test-repo
git init
echo "password = 'secret123'" > test.py
jmo scan --repo . --tools trufflehog --allow-missing-tools
# Expected: Scan completes, writes results to results/

# Step 6: Verify results
ls -la results/individual-repos/test-repo/
# Expected: trufflehog.json exists (may be empty if tool not installed)

# Step 7: Test plugin system
jmo adapters list
# Expected: List of 12 adapter plugins

# Step 8: Cleanup
cd /tmp
rm -rf test-repo

# PASS CRITERIA:
# ✅ All commands execute without errors
# ✅ jmo and jmotools binaries available in PATH
# ✅ Python dependencies installed correctly
# ✅ Plugin system works
# ✅ Scan workflow completes
```

### Test 2: Upgrade from Previous Version

```bash
# Prerequisites: Have jmo-security v0.8.0 installed via Homebrew

# Step 1: Check current version
jmo scan --version
# Expected: 0.8.0 or earlier

# Step 2: Upgrade to v0.9.0
brew upgrade jmo-security

# Step 3: Verify new version
jmo scan --version
# Expected: 0.9.0

# Step 4: Test plugin system (new in v0.9.0)
jmo adapters list
# Expected: List of 12 adapter plugins

# Step 5: Verify backward compatibility
# Run existing v0.8.0 scan command
jmo scan --repo ~/my-project --profile-name balanced
# Expected: Scan completes successfully

# PASS CRITERIA:
# ✅ Upgrade completes without errors
# ✅ Version updated to 0.9.0
# ✅ New features (plugin system) available
# ✅ Existing features still work (backward compatible)
```

### Test 3: Uninstall

```bash
# Step 1: Uninstall
brew uninstall jmo-security

# Step 2: Verify removal
which jmo
# Expected: No output (jmo not found)

which jmotools
# Expected: No output (jmotools not found)

# Step 3: Verify config files preserved (user data)
ls ~/.jmo/
# Expected: Config files still exist (optional, user may want to keep)

# Step 4: Clean uninstall (remove config)
rm -rf ~/.jmo/

# PASS CRITERIA:
# ✅ Binaries removed from PATH
# ✅ Python virtualenv removed
# ✅ No residual files (except user config if desired)
```

### Test 4: Formula Validation

```bash
# Prerequisites: Homebrew installed

# Step 1: Audit formula
brew audit --strict --online packaging/homebrew/jmo-security.rb

# Expected warnings (acceptable):
# - "New formula" (if not yet in homebrew-core)

# Expected errors (must fix):
# - None

# Step 2: Style check
brew style packaging/homebrew/jmo-security.rb

# Expected: No style violations

# Step 3: Test suite
brew test jmo-security

# Expected: All tests pass

# PASS CRITERIA:
# ✅ No audit errors (warnings OK)
# ✅ No style violations
# ✅ Test suite passes
```

---

## 📦 Winget Testing

### Prerequisites

- **Windows 10:** Version 1809 (October 2018 Update) or later
- **Windows 11:** Any version
- Winget installed: Built into Windows 11, or download from Microsoft Store

### Test Matrix

| Platform | Version | Install | Scan | Plugin | Upgrade | Uninstall | Status |
|----------|---------|---------|------|--------|---------|-----------|--------|
| Windows | 11 (23H2) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| Windows | 11 (22H2) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |
| Windows | 10 (22H2) | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 📋 Pending |

### Test 1: Fresh Install (Windows)

```powershell
# IMPORTANT: Test on a CLEAN machine or VM
# DO NOT test on a machine with JMo Security already installed

# Step 1: Install from local manifest
$VERSION = "0.9.0"
winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Expected output:
# Found JMo Security [jmo.jmo-security] Version 0.9.0
# ...
# Successfully installed

# Step 2: Verify installation
Get-Command jmo
# Expected: Path to jmo.exe in $env:LOCALAPPDATA\JMo Security\

Get-Command jmotools
# Expected: Path to jmotools.exe in same directory

# Step 3: Test CLI commands
jmo --help
# Expected: Help text with scan/report/ci commands

jmotools --help
# Expected: Help text with wizard/fast/balanced/full commands

# Step 4: Test wizard
jmotools wizard --help
# Expected: Wizard help text

# Step 5: Test scan command
New-Item -ItemType Directory -Path C:\Temp\test-repo
Set-Location C:\Temp\test-repo
git init
"password = 'secret123'" | Out-File test.py
jmo scan --repo . --tools trufflehog --allow-missing-tools
# Expected: Scan completes, writes results to results\

# Step 6: Verify results
Get-ChildItem results\individual-repos\test-repo\
# Expected: trufflehog.json exists

# Step 7: Test plugin system
jmo adapters list
# Expected: List of 12 adapter plugins

# Step 8: Cleanup
Set-Location C:\Temp
Remove-Item -Recurse -Force test-repo

# PASS CRITERIA:
# ✅ Installer runs without errors
# ✅ jmo and jmotools available in PATH
# ✅ Start Menu shortcuts created
# ✅ Plugin system works
# ✅ Scan workflow completes
```

### Test 2: Upgrade from Previous Version

```powershell
# Prerequisites: Have jmo-security v0.8.0 installed via Winget

# Step 1: Check current version
jmo scan --version
# Expected: 0.8.0 or earlier

# Step 2: Upgrade to v0.9.0
winget upgrade jmo.jmo-security

# Step 3: Verify new version
jmo scan --version
# Expected: 0.9.0

# Step 4: Test plugin system (new in v0.9.0)
jmo adapters list
# Expected: List of 12 adapter plugins

# Step 5: Verify backward compatibility
jmo scan --repo C:\Projects\my-project --profile-name balanced
# Expected: Scan completes successfully

# PASS CRITERIA:
# ✅ Upgrade completes without errors
# ✅ Version updated to 0.9.0
# ✅ New features available
# ✅ Existing features still work
```

### Test 3: Uninstall

```powershell
# Step 1: Uninstall
winget uninstall jmo.jmo-security

# Expected output:
# Successfully uninstalled

# Step 2: Verify removal
Get-Command jmo -ErrorAction SilentlyContinue
# Expected: No output (jmo not found)

Get-Command jmotools -ErrorAction SilentlyContinue
# Expected: No output (jmotools not found)

# Step 3: Verify Start Menu shortcuts removed
Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\JMo Security"
# Expected: False

# Step 4: Verify installation directory removed
Test-Path "$env:LOCALAPPDATA\JMo Security"
# Expected: False

# Step 5: Verify user config preserved
Test-Path "$env:USERPROFILE\.jmo"
# Expected: May still exist (user data)

# PASS CRITERIA:
# ✅ Uninstaller runs without errors
# ✅ Binaries removed from PATH
# ✅ Start Menu shortcuts removed
# ✅ Installation directory removed
# ✅ Registry entries cleaned up
```

### Test 4: Manifest Validation

```powershell
# Prerequisites: winget-create installed
# winget install Microsoft.WingetCreate

# Step 1: Validate manifest
$VERSION = "0.9.0"
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Expected: Validation passed

# Step 2: Test installation from manifest
winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Expected: Installation succeeds

# PASS CRITERIA:
# ✅ Manifest validation passes
# ✅ Installation from manifest succeeds
# ✅ No schema violations
```

---

## 🔄 Cross-Platform Consistency Testing

Test that Homebrew and Winget installations produce consistent behavior.

### Test: Feature Parity

| Feature | Homebrew (macOS) | Homebrew (Linux) | Winget (Windows) | Status |
|---------|------------------|------------------|------------------|--------|
| `jmo --help` | ⬜ | ⬜ | ⬜ | 📋 |
| `jmotools wizard` | ⬜ | ⬜ | ⬜ | 📋 |
| `jmo scan --repo` | ⬜ | ⬜ | ⬜ | 📋 |
| `jmo adapters list` | ⬜ | ⬜ | ⬜ | 📋 |
| Plugin hot-reload | ⬜ | ⬜ | ⬜ | 📋 |
| Multi-target scan | ⬜ | ⬜ | ⬜ | 📋 |
| Profile-based config | ⬜ | ⬜ | ⬜ | 📋 |
| Schedule management | ⬜ | ⬜ | ⬜ | 📋 |

**PASS CRITERIA:**
- ✅ All features work identically across platforms
- ✅ Same CLI commands produce same outputs
- ✅ Same configuration files work across platforms

---

## 📝 Testing Checklist Summary

### Homebrew

- [ ] macOS 13 (Ventura): Install, scan, upgrade, uninstall
- [ ] macOS 14 (Sonoma): Install, scan, upgrade, uninstall
- [ ] Ubuntu 22.04: Install, scan, uninstall
- [ ] Ubuntu 24.04: Install, scan, uninstall
- [ ] Formula audit passes
- [ ] Formula test suite passes
- [ ] Documentation complete in post_install message

### Winget

- [ ] Windows 11 (23H2): Install, scan, upgrade, uninstall
- [ ] Windows 11 (22H2): Install, scan, upgrade, uninstall
- [ ] Windows 10 (22H2): Install, scan, upgrade, uninstall
- [ ] Manifest validation passes
- [ ] Start Menu shortcuts work
- [ ] PATH environment variable updated correctly
- [ ] Uninstaller cleans up completely

### Cross-Platform

- [ ] Feature parity confirmed across all platforms
- [ ] Same scan produces same results
- [ ] Plugin system works on all platforms
- [ ] Configuration files portable

---

## 🐛 Common Issues & Troubleshooting

### Homebrew Issues

**Issue:** `Error: jmo-security: unknown or unsupported macOS version`
- **Solution:** Update formula's `depends_on` to support older macOS versions

**Issue:** `Error: SHA256 mismatch`
- **Solution:** Recalculate SHA256 with `sha256sum` and update formula

**Issue:** `Error: Python not found`
- **Solution:** Ensure `depends_on "python@3.10"` is in formula

### Winget Issues

**Issue:** `Installer hash does not match`
- **Solution:** Recalculate SHA256 and update manifest

**Issue:** `Installation failed: Access denied`
- **Solution:** Run installer as user (not admin), Winget uses user scope

**Issue:** `PATH not updated after install`
- **Solution:** Restart Command Prompt/PowerShell after installation

---

## ✅ Definition of Done

Before submitting to homebrew-core or winget-pkgs:

- [ ] All test matrix cells marked ✅
- [ ] Formula/manifest validation passes
- [ ] Test suite passes on all platforms
- [ ] Documentation reviewed and accurate
- [ ] Cross-platform consistency verified
- [ ] Common issues documented
- [ ] Maintainer review approved

---

**Last Updated:** 2025-10-30
**Version:** v0.9.0
**Maintainer:** Jimmy Moceri (@jimmy058910)
