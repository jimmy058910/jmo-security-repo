# Pre-Release Checklist for v0.9.0

**Purpose:** This checklist ensures Windows installer and WinGet manifests are ready before v0.9.0 release.

**Status:** 🚧 IN PROGRESS (2/5 steps complete)

---

## ✅ Phase 1: Preparation (COMPLETE)

### 1.1 Update Windows Installer Builder ✅
- [x] Updated `packaging/windows/build_installer.py` to remove `jmotools.py` references
- [x] Updated PyInstaller spec to only build `jmo.exe` (no more `jmotools.exe`)
- [x] Updated NSIS installer script:
  - Only copies `jmo.exe` (not `jmotools.exe`)
  - Start Menu shortcuts updated (`JMo Security CLI.lnk`, `JMo Security Wizard.lnk`)
  - Help messages reference `jmo wizard` instead of `jmotools wizard`
- [x] Updated hidden imports to include new modules:
  - `scripts.cli.schedule_commands`
  - `scripts.core.cron_installer`
  - `scripts.core.workflow_generators.github_actions`
  - `scripts.core.workflow_generators.gitlab_ci`
  - `croniter`

**Files Modified:**
- `/mnt/c/Projects/jmo-security-repo/packaging/windows/build_installer.py`

### 1.2 Update WinGet Manifests ✅
- [x] Updated `jmo.jmo-security.locale.en-US.yaml`:
  - Breaking changes section now documents CLI consolidation
  - Migration guide: `jmotools wizard → jmo wizard`

**Files Modified:**
- `/mnt/c/Projects/jmo-security-repo/packaging/winget/manifests/j/jmo/jmo-security/0.9.0/jmo.jmo-security.locale.en-US.yaml`

---

## 🚧 Phase 2A: Build Windows Installer (PENDING)

**Platform:** Windows 10+ or Windows 11
**Prerequisites:**
- Python 3.10+ installed
- PyInstaller: `pip install pyinstaller`
- NSIS 3.x: https://nsis.sourceforge.io/Download (add to PATH)

### 2A.1 Build jmo.exe with PyInstaller

```powershell
cd C:\Projects\jmo-security-repo
python packaging/windows/build_installer.py
```

**Expected Output:**
```text
======================================================================
  JMo Security Windows Installer Build Script
  Version: 0.9.0
  Platform: Windows AMD64
======================================================================

🧹 Cleaning previous build artifacts...
   Removed C:\Projects\jmo-security-repo\dist
   Removed C:\Projects\jmo-security-repo\build
✅ Cleanup complete

📝 Creating PyInstaller spec file...
✅ Spec file created: packaging/windows/jmo-security.spec

📝 Creating version info file...
✅ Version info created: packaging/windows/file_version_info.txt

🔨 Building executable with PyInstaller...
   This may take 3-5 minutes...

... (PyInstaller output) ...

✅ Executable built successfully
   jmo.exe: C:\Projects\jmo-security-repo\dist\jmo.exe

📝 Creating NSIS installer script...
✅ NSIS script created: packaging/windows/installer.nsi

🔨 Building Windows installer with NSIS...
   This may take 1-2 minutes...

... (NSIS output) ...

✅ Installer created: C:\Projects\jmo-security-repo\dist\jmo-security-0.9.0-win64.exe
   SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

======================================================================
  ✅ Build Complete!
======================================================================

Installer: C:\Projects\jmo-security-repo\dist\jmo-security-0.9.0-win64.exe
SHA256:    C:\Projects\jmo-security-repo\dist\jmo-security-0.9.0-win64.exe.sha256
```

**Outputs:**
- `dist/jmo-security-0.9.0-win64.exe` (~25-35 MB NSIS installer)
- `dist/jmo-security-0.9.0-win64.exe.sha256` (SHA256 hash for WinGet manifest)

### 2A.2 Verify Installer Smoke Tests

**Test on Windows 11 VM:**

```powershell
# Install
.\dist\jmo-security-0.9.0-win64.exe

# After installation completes...

# Test 1: CLI help
jmo.exe --help
# Expected: Help text shows BEGINNER-FRIENDLY COMMANDS and ADVANCED COMMANDS

# Test 2: Wizard help
jmo.exe wizard --help
# Expected: Wizard help text appears

# Test 3: Scan help
jmo.exe scan --help
# Expected: Scan help text appears

# Test 4: Fast profile help
jmo.exe fast --help
# Expected: Fast profile help text appears

# Test 5: Schedule help
jmo.exe schedule --help
# Expected: Schedule management help text appears

# Uninstall
# Via Control Panel > Programs > Uninstall JMo Security
```

**Success Criteria:**
- [  ] Installer runs without errors
- [  ] `jmo.exe` accessible from PATH
- [  ] All 5 smoke tests pass
- [  ] Start Menu shortcuts work
- [  ] Uninstaller removes all files cleanly

---

## 🚧 Phase 2B: Update WinGet Manifests with SHA256 (PENDING)

### 2B.1 Get SHA256 Hash

```powershell
Get-Content dist\jmo-security-0.9.0-win64.exe.sha256
# Example: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 2B.2 Update Installer Manifest

**File:** `packaging/winget/manifests/j/jmo/jmo-security/0.9.0/jmo.jmo-security.installer.yaml`

Replace:
```yaml
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe
    InstallerSha256: INSERT_SHA256_HERE  # Will be filled by build script
```

With:
```yaml
Installers:
  - Architecture: x64
    InstallerUrl: https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe
    InstallerSha256: <ACTUAL_SHA256_FROM_BUILD>
```

**Note:** If ARM64 build is not available, remove the ARM64 installer entry entirely.

### 2B.3 Validate WinGet Manifests

**Option 1: Using Komac (Recommended)**

```powershell
# Install Komac via WinGet
winget install russellbanks.Komac

# Validate manifests
komac validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0/
```

**Expected Output:**
```text
✅ Manifest validation successful
   - jmo.jmo-security.installer.yaml: VALID
   - jmo.jmo-security.locale.en-US.yaml: VALID
   - jmo.jmo-security.yaml: VALID
```

**Option 2: Using WinGet Client (Windows 11 only)**

```powershell
winget validate --manifest packaging/winget/manifests/j/jmo/jmo-security/0.9.0/
```

**Success Criteria:**
- [  ] SHA256 updated in installer manifest
- [  ] ARM64 entry removed (if not building ARM64)
- [  ] Komac validation passes
- [  ] No schema errors

---

## 🚧 Phase 3: Upload to GitHub Release (PENDING)

### 3.1 Create Release Draft

```bash
gh release create v0.9.0 \
  --draft \
  --title "v0.9.0 - Developer Experience & Orchestration" \
  --notes-file packaging/RELEASE_NOTES_v0.9.0.md
```

### 3.2 Upload Windows Installer

```bash
gh release upload v0.9.0 \
  dist/jmo-security-0.9.0-win64.exe \
  dist/jmo-security-0.9.0-win64.exe.sha256
```

**Verify:**
```bash
gh release view v0.9.0
```

**Success Criteria:**
- [  ] Release draft created
- [  ] Windows installer uploaded
- [  ] SHA256 file uploaded
- [  ] Assets visible in release draft

---

## 🚧 Phase 4: Test Automation Workflows (PENDING)

### 4.1 Test Homebrew Automation (Manual Trigger)

```bash
gh workflow run homebrew-bump-formula.yml -f version=0.9.0
gh run watch
```

**Expected:**
- Workflow completes successfully
- PR created in `Homebrew/homebrew-core`
- PR contains correct formula version and SHA256

**Success Criteria:**
- [  ] Workflow run successful
- [  ] Homebrew PR created
- [  ] Formula version updated to 0.9.0

### 4.2 Test WinGet Automation (Manual Trigger)

```bash
gh workflow run winget-releaser.yml
gh run watch
```

**Expected:**
- Workflow completes successfully
- PR created in `microsoft/winget-pkgs`
- Manifests updated with correct SHA256

**Success Criteria:**
- [  ] Workflow run successful
- [  ] WinGet PR created
- [  ] Manifest SHA256 matches installer

---

## 🚧 Phase 5: Publish Release (PENDING)

### 5.1 Final Pre-Release Checks

- [  ] All tests passing (19/19 Feature #6 tests)
- [  ] Windows installer smoke tests passed
- [  ] WinGet manifests validated
- [  ] Homebrew formula tested locally
- [  ] Automation workflows tested
- [  ] CHANGELOG.md updated
- [  ] README.md installation instructions updated
- [  ] Documentation complete

### 5.2 Publish Release

```bash
# Mark release as published (not draft)
gh release edit v0.9.0 --draft=false
```

**This triggers:**
- `release.yml` workflow
- PyPI publish (OIDC)
- Docker builds (GHCR/ECR/Docker Hub)
- Homebrew automation
- WinGet automation

### 5.3 Monitor Package Manager PRs

**Homebrew:**
```bash
# Check PR status
gh pr view <PR_NUMBER> --repo Homebrew/homebrew-core
```

**WinGet:**
```bash
# Check PR status
gh pr view <PR_NUMBER> --repo microsoft/winget-pkgs
```

**Timeline:**
- Homebrew review: 1-3 days (usually fast for updates)
- WinGet review: 3-7 days (Microsoft maintainers review)

---

## 📊 Success Criteria Summary

### Implementation (2/2 Complete) ✅
- [x] Windows installer builder updated
- [x] WinGet manifests updated

### Windows Build (0/2 Pending) 🚧
- [  ] Windows installer built successfully
- [  ] Smoke tests passed

### Manifests (0/2 Pending) 🚧
- [  ] SHA256 updated in WinGet manifest
- [  ] Manifests validated

### Release (0/3 Pending) 🚧
- [  ] Installer uploaded to GitHub Release
- [  ] Automation workflows tested
- [  ] Release published

**Overall Progress:** 40% (2/5 phases complete)

---

## 🔧 Troubleshooting

### PyInstaller Build Fails

**Error:** `ModuleNotFoundError: No module named 'scripts'`
**Fix:** Run from project root:
```powershell
cd C:\Projects\jmo-security-repo
python packaging/windows/build_installer.py
```

### NSIS Build Fails

**Error:** `makensis: command not found`
**Fix:**
1. Download NSIS from https://nsis.sourceforge.io/Download
2. Install to `C:\Program Files (x86)\NSIS`
3. Add to PATH: `C:\Program Files (x86)\NSIS`
4. Restart PowerShell

### WinGet Validation Fails

**Error:** `Schema validation failed: InstallerSha256 is required`
**Fix:** Ensure SHA256 is filled in `jmo.jmo-security.installer.yaml`:
```yaml
InstallerSha256: <64-char-hex-string>
```

### Automation Workflow Fails

**Error:** `HOMEBREW_BUMP_TOKEN not found`
**Fix:** Verify secrets configured:
```bash
gh secret list
# Should show:
# HOMEBREW_BUMP_TOKEN
# WINGET_RELEASER_TOKEN
```

---

## 📝 Notes

**Why We Can't Build in WSL:**
- PyInstaller requires native Windows Python
- NSIS installer only works on Windows
- Windows .exe cannot be cross-compiled from Linux

**Alternative:** Use GitHub Actions with Windows runner (future enhancement)

**For v0.9.0:** Build manually on Windows 11 VM or local Windows machine

---

## 🎯 Next Steps

After completing this checklist:

1. **Immediately:** Build Windows installer on Windows machine (Phase 2A)
2. **Within 1 hour:** Update WinGet manifests with SHA256 (Phase 2B)
3. **Within 4 hours:** Upload to GitHub Release and test automation (Phase 3-4)
4. **Before EOD:** Publish release and monitor package manager PRs (Phase 5)

**Estimated Total Time:** 2-3 hours (building + testing + uploading)

---

**Last Updated:** 2025-10-31
**Responsible:** @jimmy058910
**Status:** Ready for Windows build
