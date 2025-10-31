# JMo Security Packaging

Distribution packaging for Homebrew (macOS/Linux) and Winget (Windows).

---

## 📂 Directory Structure

```
packaging/
├── README.md                           # This file
├── TESTING.md                          # Comprehensive testing guide
├── homebrew/
│   └── jmo-security.rb                 # Homebrew formula
└── winget/
    ├── manifests/                      # Winget manifests
    │   └── j/jmo/jmo-security/0.9.0/
    │       ├── jmo.jmo-security.installer.yaml
    │       ├── jmo.jmo-security.locale.en-US.yaml
    │       └── jmo.jmo-security.yaml
    └── windows/
        └── build_installer.py          # Windows installer build script
```

---

## 🍺 Homebrew Formula

### Local Testing

Test the formula before submitting to homebrew-core:

```bash
# Install from local formula
brew install --build-from-source packaging/homebrew/jmo-security.rb

# Verify installation
jmo --help
jmotools wizard --help

# Run formula tests
brew test jmo-security

# Audit formula
brew audit --strict --online jmo-security
```

### Submission to homebrew-core

1. **Fork homebrew-core:**
   ```bash
   cd $(brew --repo homebrew/core)
   hub fork
   ```

2. **Create branch:**
   ```bash
   git checkout -b jmo-security
   ```

3. **Copy formula:**
   ```bash
   cp /path/to/jmo-security-repo/packaging/homebrew/jmo-security.rb \
      Formula/j/jmo-security.rb
   ```

4. **Test and submit:**
   ```bash
   brew audit --new-formula jmo-security
   brew test jmo-security
   brew install --build-from-source jmo-security

   git add Formula/j/jmo-security.rb
   git commit -m "jmo-security 0.9.0 (new formula)"
   git push YOUR_FORK jmo-security

   # Open PR to Homebrew/homebrew-core
   hub pull-request
   ```

### Auto-Update Workflow

GitHub Actions workflow automatically updates formula on new releases:
- Workflow: `.github/workflows/update-homebrew-formula.yml`
- Triggers: `release.published`, `workflow_dispatch`
- Updates: Tarball URL, SHA256
- Creates PR to this repository with updated formula

---

## 📦 Winget Package

### Prerequisites

- **Windows 10+** or **Windows Server 2019+**
- **Python 3.10+** (for build script)
- **PyInstaller:** `pip install pyinstaller`
- **NSIS:** https://nsis.sourceforge.io/Download (add to PATH)

### Building Windows Installer

```bash
# From repository root
python packaging/windows/build_installer.py --version 0.9.0

# Output:
# dist/jmo-security-0.9.0-win64.exe
# dist/jmo-security-0.9.0-win64.exe.sha256
```

### Local Testing

```powershell
# Validate manifest
$VERSION = "0.9.0"
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Install from local manifest
winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Verify installation
jmo --help
jmotools wizard --help

# Uninstall
winget uninstall jmo.jmo-security
```

### Submission to microsoft/winget-pkgs

1. **Fork winget-pkgs:**
   ```powershell
   gh repo fork microsoft/winget-pkgs --clone
   ```

2. **Create branch:**
   ```powershell
   cd winget-pkgs
   git checkout -b jmo-security-0.9.0
   ```

3. **Copy manifests:**
   ```powershell
   $VERSION = "0.9.0"
   Copy-Item -Recurse `
       "../jmo-security-repo/packaging/winget/manifests/j/jmo/jmo-security/$VERSION" `
       "manifests/j/jmo/jmo-security/"
   ```

4. **Test and submit:**
   ```powershell
   # Validate
   wingetcreate validate manifests/j/jmo/jmo-security/$VERSION

   # Commit and push
   git add manifests/j/jmo/jmo-security/$VERSION
   git commit -m "Update: jmo.jmo-security version $VERSION"
   git push origin jmo-security-$VERSION

   # Create PR
   gh pr create --title "Update: jmo.jmo-security version $VERSION" `
                --body "Automated update for JMo Security $VERSION"
   ```

### Auto-Update Workflow

GitHub Actions workflow automatically updates manifest on new releases:
- Workflow: `.github/workflows/update-winget-manifest.yml`
- Triggers: `release.published`, `workflow_dispatch`
- Updates: Installer URLs, SHA256 hashes
- Creates PR to this repository with updated manifest

---

## 🔄 Release Process

### Automated (Recommended)

1. **Tag new release:**
   ```bash
   git tag v0.9.0
   git push --tags
   ```

2. **Publish GitHub release:**
   - GitHub Actions automatically triggers release workflow
   - Publishes to PyPI
   - Builds Docker images
   - Updates Homebrew formula (PR created)
   - Updates Winget manifest (PR created)

3. **Review and merge PRs:**
   - Review Homebrew formula PR
   - Review Winget manifest PR
   - Merge both to repository

4. **Submit to package managers:**
   - Submit Homebrew formula to homebrew-core (manual)
   - Submit Winget manifest to microsoft/winget-pkgs (manual)

### Manual

1. **Update version in pyproject.toml**

2. **Build Windows installer:**
   ```bash
   python packaging/windows/build_installer.py
   ```

3. **Upload installer to GitHub Release:**
   - `jmo-security-0.9.0-win64.exe`

4. **Trigger auto-update workflows:**
   - `.github/workflows/update-homebrew-formula.yml`
   - `.github/workflows/update-winget-manifest.yml`

5. **Follow submission process** (see above)

---

## 📊 Package Manager Comparison

| Feature | Homebrew | Winget |
|---------|----------|--------|
| **Platforms** | macOS, Linux | Windows 10+ |
| **Install method** | Source build + virtualenv | Pre-built exe installer |
| **Dependency management** | Automatic (Python deps) | Bundled (PyInstaller) |
| **Auto-update** | `brew upgrade` | `winget upgrade` |
| **User base** | 90M+ installs/month | Built into Windows 11 |
| **Approval time** | 1-2 weeks | 1-2 weeks |
| **Maintenance** | Formula updates | Manifest updates |

---

## 🧪 Testing

See [TESTING.md](TESTING.md) for comprehensive testing guide.

**Quick checklist:**
- [ ] Homebrew: Install, scan, upgrade, uninstall (macOS/Linux)
- [ ] Winget: Install, scan, upgrade, uninstall (Windows)
- [ ] Cross-platform: Feature parity verified
- [ ] Documentation: All install methods documented

---

## 📚 Resources

### Homebrew

- **Formula Cookbook:** https://docs.brew.sh/Formula-Cookbook
- **Python for Formula Authors:** https://docs.brew.sh/Python-for-Formula-Authors
- **How to Open a PR:** https://docs.brew.sh/How-To-Open-a-Homebrew-Pull-Request
- **homebrew-core:** https://github.com/Homebrew/homebrew-core

### Winget

- **Manifest Schema:** https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/v1.6.0/
- **Contribution Guide:** https://github.com/microsoft/winget-pkgs/blob/master/CONTRIBUTING.md
- **winget-create:** https://github.com/microsoft/winget-create
- **winget-pkgs:** https://github.com/microsoft/winget-pkgs

### PyInstaller / NSIS

- **PyInstaller Manual:** https://pyinstaller.org/en/stable/
- **NSIS Documentation:** https://nsis.sourceforge.io/Docs/
- **NSIS Examples:** https://nsis.sourceforge.io/Examples/

---

## 🐛 Troubleshooting

### Homebrew Issues

**Formula audit fails:**
```bash
# Fix style violations
brew style packaging/homebrew/jmo-security.rb

# Re-audit
brew audit --strict --online jmo-security
```

**Installation fails:**
```bash
# Verbose output
brew install --build-from-source --verbose packaging/homebrew/jmo-security.rb

# Check logs
cat ~/Library/Logs/Homebrew/jmo-security/
```

### Winget Issues

**Build fails:**
```powershell
# Check PyInstaller version
pyinstaller --version

# Check NSIS installation
Get-Command makensis

# Verbose build
python packaging/windows/build_installer.py --verbose
```

**Validation fails:**
```powershell
# Schema errors
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0

# Fix manifest and retry
```

---

## 👥 Contributors

- **Jimmy Moceri** (@jimmy058910) — Primary maintainer
- **Claude Code** — Packaging automation

---

## 📄 License

MIT OR Apache-2.0 (dual-licensed)

See [LICENSE](../LICENSE) for details.

---

**Last Updated:** 2025-10-30
**Version:** v0.9.0
