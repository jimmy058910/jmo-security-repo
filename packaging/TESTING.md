# Packaging Testing Guide

Comprehensive testing documentation for Winget packaging. JMo has no Homebrew formula.

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

# Step 3: Test CLI commands
jmo --help
# Expected: Help text with scan/report/ci commands

jmo wizard --help
# Expected: Help text with wizard/fast/balanced/full commands

# Step 4: Test wizard
jmo wizard --help
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
# ✅ jmo available in PATH
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
jmo scan --repo C:\Projects\my-project
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

## 📝 Testing Checklist Summary

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

### Winget Issues

**Issue:** `Installer hash does not match`

- **Solution:** Recalculate SHA256 and update manifest

**Issue:** `Installation failed: Access denied`

- **Solution:** Run installer as user (not admin), Winget uses user scope

**Issue:** `PATH not updated after install`

- **Solution:** Restart Command Prompt/PowerShell after installation

---

## ✅ Definition of Done

Before submitting to winget-pkgs:

- [ ] All test matrix cells marked ✅
- [ ] Manifest validation passes
- [ ] Test suite passes on all platforms
- [ ] Documentation reviewed and accurate
- [ ] Cross-platform consistency verified
- [ ] Common issues documented
- [ ] Maintainer review approved

---

**Last Updated:** February 2026
**Maintainer:** Jimmy Moceri (@jimmy058910)
