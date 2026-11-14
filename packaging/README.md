# JMo Security Packaging

Distribution packaging for Winget (Windows). JMo has no Homebrew formula: install it with `pip install "jmo-security[yara]"` ([QUICKSTART](../QUICKSTART.md)).

---

## 📂 Directory Structure

```text
packaging/
├── README.md                           # This file
├── TESTING.md                          # Comprehensive testing guide
└── winget/
    ├── manifests/                      # Winget manifests
    │   └── j/jmo/jmo-security/0.9.0/
    │       ├── jmo.jmo-security.installer.yaml
    │       ├── jmo.jmo-security.locale.en-US.yaml
    │       └── jmo.jmo-security.yaml
    └── windows/
        └── build_installer.py          # Windows installer build script
```

packaging/
├── README.md                           # This file
├── TESTING.md                          # Comprehensive testing guide
└── winget/
    ├── manifests/                      # Winget manifests
    │   └── j/jmo/jmo-security/0.9.0/
    │       ├── jmo.jmo-security.installer.yaml
    │       ├── jmo.jmo-security.locale.en-US.yaml
    │       └── jmo.jmo-security.yaml
    └── windows/
        └── build_installer.py          # Windows installer build script

```text

---

## 📦 Winget Package

### Prerequisites

- **Windows 10+** or **Windows Server 2019+**
- **Python 3.12+** (for build script)
- **PyInstaller:** `pip install pyinstaller`
- **NSIS:** <https://nsis.sourceforge.io/Download> (add to PATH)

### Building Windows Installer

```bash
# From repository root
python packaging/windows/build_installer.py --version 0.9.0

# Output:
# dist/jmo-security-0.9.0-win64.exe
# dist/jmo-security-0.9.0-win64.exe.sha256
```

## 📦 Winget Package

### Prerequisites

- **Windows 10+** or **Windows Server 2019+**
- **Python 3.12+** (for build script)
- **PyInstaller:** `pip install pyinstaller`
- **NSIS:** <https://nsis.sourceforge.io/Download> (add to PATH)

### Building Windows Installer

```bash
# From repository root
python packaging/windows/build_installer.py --version 0.9.0

# Output:
# dist/jmo-security-0.9.0-win64.exe
# dist/jmo-security-0.9.0-win64.exe.sha256
```

## From repository root

python packaging/windows/build_installer.py --version 0.9.0

## Output:

## dist/jmo-security-0.9.0-win64.exe

## dist/jmo-security-0.9.0-win64.exe.sha256

```text

### Local Testing

```powershell
# Validate manifest
$VERSION = "0.9.0"
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Install from local manifest
winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/$VERSION

# Verify installation
jmo --help
jmo wizard --help

# Uninstall
winget uninstall jmo.jmo-security
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
jmo wizard --help

# Uninstall
winget uninstall jmo.jmo-security
```

## Validate manifest

$VERSION = "0.9.0"
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/$VERSION

## Install from local manifest

winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/$VERSION

## Verify installation

jmo --help
jmo wizard --help

## Uninstall

winget uninstall jmo.jmo-security

```text

### Submission to microsoft/winget-pkgs

1. **Fork winget-pkgs:**
   ```powershell
   gh repo fork microsoft/winget-pkgs --clone
   ```

1. **Create branch:**

   ```powershell
   cd winget-pkgs
   git checkout -b jmo-security-0.9.0
   ```

2. **Copy manifests:**

   ```powershell
   $VERSION = "0.9.0"
   Copy-Item -Recurse `
       "../jmo-security-repo/packaging/winget/manifests/j/jmo/jmo-security/$VERSION" `
       "manifests/j/jmo/jmo-security/"
   ```

3. **Test and submit:**

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
   - Updates Winget manifest (PR created)

3. **Review and merge PRs:**
   - Review Winget manifest PR
   - Merge both to repository

4. **Submit to package managers:**
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
   - `.github/workflows/update-winget-manifest.yml`

5. **Follow submission process** (see above)

---

## 🧪 Testing

See [TESTING.md](TESTING.md) for comprehensive testing guide.

**Quick checklist:**

- [ ] Winget: Install, scan, upgrade, uninstall (Windows)
- [ ] Cross-platform: Feature parity verified
- [ ] Documentation: All install methods documented

---

## 📚 Resources

### Winget

- **Manifest Schema:** <https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/v1.6.0/>
- **Contribution Guide:** <https://github.com/microsoft/winget-pkgs/blob/master/CONTRIBUTING.md>
- **winget-create:** <https://github.com/microsoft/winget-create>
- **winget-pkgs:** <https://github.com/microsoft/winget-pkgs>

### PyInstaller / NSIS

- **PyInstaller Manual:** <https://pyinstaller.org/en/stable/>
- **NSIS Documentation:** <https://nsis.sourceforge.io/Docs/>
- **NSIS Examples:** <https://nsis.sourceforge.io/Examples/>

---

## 🐛 Troubleshooting

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
   - Updates Winget manifest (PR created)

3. **Review and merge PRs:**
   - Review Winget manifest PR
   - Merge both to repository

4. **Submit to package managers:**
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
   - `.github/workflows/update-winget-manifest.yml`

5. **Follow submission process** (see above)

---

## 🧪 Testing

See [TESTING.md](TESTING.md) for comprehensive testing guide.

**Quick checklist:**

- [ ] Winget: Install, scan, upgrade, uninstall (Windows)
- [ ] Cross-platform: Feature parity verified
- [ ] Documentation: All install methods documented

---

## 📚 Resources

### Winget

- **Manifest Schema:** <https://github.com/microsoft/winget-cli/blob/master/schemas/JSON/manifests/v1.6.0/>
- **Contribution Guide:** <https://github.com/microsoft/winget-pkgs/blob/master/CONTRIBUTING.md>
- **winget-create:** <https://github.com/microsoft/winget-create>
- **winget-pkgs:** <https://github.com/microsoft/winget-pkgs>

### PyInstaller / NSIS

- **PyInstaller Manual:** <https://pyinstaller.org/en/stable/>
- **NSIS Documentation:** <https://nsis.sourceforge.io/Docs/>
- **NSIS Examples:** <https://nsis.sourceforge.io/Examples/>

---

## 🐛 Troubleshooting

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

## Check PyInstaller version

pyinstaller --version

## Check NSIS installation

Get-Command makensis

## Verbose build

python packaging/windows/build_installer.py --verbose

```text

**Validation fails:**

```powershell
# Schema errors
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0

# Fix manifest and retry
```

**Validation fails:**

```powershell
# Schema errors
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0

# Fix manifest and retry
```

## Schema errors

wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0

## Fix manifest and retry

```text

---

## 👥 Contributors

- **Jimmy Moceri** (@jimmy058910) — Primary maintainer
- **Claude Code** — Packaging automation

---

## 📄 License

MIT OR Apache-2.0 (dual-licensed)

See [LICENSE](../LICENSE) for details.

---

**Last Updated:** February 2026
