#!/usr/bin/env python3
"""Build Windows installer for JMo Security.

This script creates a standalone Windows installer using PyInstaller to bundle
Python + dependencies into .exe files, then packages them with NSIS installer.

Requirements:
    - PyInstaller: pip install pyinstaller
    - NSIS: https://nsis.sourceforge.io/Download (add to PATH)
    - Windows 10+ or Windows Server 2019+

Usage:
    python packaging/windows/build_installer.py [--version VERSION]

Output:
    dist/jmo-security-{VERSION}-win64.exe
    dist/jmo-security-{VERSION}-arm64.exe (if built on ARM64)
"""

import argparse
import subprocess
import sys
import shutil
from pathlib import Path
import hashlib
import platform

# Get project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.resolve()
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
PACKAGING_DIR = PROJECT_ROOT / "packaging" / "windows"


def get_version() -> str:
    """Extract version from pyproject.toml."""
    pyproject = PROJECT_ROOT / "pyproject.toml"
    for line in pyproject.read_text().splitlines():
        if line.startswith("version ="):
            return line.split('"')[1]
    return "0.9.0"


def clean_build_artifacts():
    """Remove previous build artifacts."""
    print("🧹 Cleaning previous build artifacts...")
    for path in [DIST_DIR, BUILD_DIR]:
        if path.exists():
            shutil.rmtree(path)
            print(f"   Removed {path}")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    print("✅ Cleanup complete\n")


def create_pyinstaller_spec(version: str) -> Path:
    """Create PyInstaller spec file for jmo.exe.

    Args:
        version: Version string (e.g., "0.9.0")

    Returns:
        Path to generated spec file
    """
    print("📝 Creating PyInstaller spec file...")

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for JMo Security {version}

block_cipher = None

# Collect all scripts/* files for bundling
datas = [
    ('scripts/core', 'scripts/core'),
    ('scripts/cli', 'scripts/cli'),
    ('jmo.yml', '.'),
    ('versions.yaml', '.'),
    ('README.md', '.'),
    ('LICENSE', '.'),
    ('LICENSE-MIT', '.'),
    ('LICENSE-APACHE', '.'),
]

# Hidden imports required by JMo Security
hiddenimports = [
    'scripts.cli.jmo',
    'scripts.cli.jmotools',
    'scripts.core.normalize_and_report',
    'scripts.core.config',
    'scripts.core.suppress',
    'scripts.core.common_finding',
    'scripts.core.plugin_api',
    'scripts.core.plugin_loader',
    'yaml',
    'pyyaml',
    'jsonschema',
]

# Add all adapter plugins
import os
adapters_dir = os.path.join('{PROJECT_ROOT}', 'scripts', 'core', 'adapters')
for fname in os.listdir(adapters_dir):
    if fname.endswith('_adapter.py') and fname != '__init__.py':
        module_name = fname[:-3]  # Remove .py
        hiddenimports.append(f'scripts.core.adapters.{{module_name}}')

# Add all reporter plugins
reporters_dir = os.path.join('{PROJECT_ROOT}', 'scripts', 'core', 'reporters')
for fname in os.listdir(reporters_dir):
    if fname.endswith('_reporter.py') and fname != '__init__.py':
        module_name = fname[:-3]
        hiddenimports.append(f'scripts.core.reporters.{{module_name}}')

# Analysis: Scan entry point and dependencies
a = Analysis(
    ['{PROJECT_ROOT}/scripts/cli/jmo.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        'pytest',
        'hypothesis',
        'black',
        'mypy',
        'ruff',
        'pre_commit',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Create PYZ archive
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Build executable
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='jmo',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='file_version_info.txt',
    icon=None,  # TODO: Add jmo-icon.ico if available
)

# Build jmotools.exe wrapper
b = Analysis(
    ['{PROJECT_ROOT}/scripts/cli/jmotools.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[
        'pytest',
        'hypothesis',
        'black',
        'mypy',
        'ruff',
        'pre_commit',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz2 = PYZ(b.pure, b.zipped_data, cipher=block_cipher)

exe2 = EXE(
    pyz2,
    b.scripts,
    b.binaries,
    b.zipfiles,
    b.datas,
    [],
    name='jmotools',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='file_version_info.txt',
    icon=None,
)
"""

    spec_file = PACKAGING_DIR / "jmo-security.spec"
    spec_file.write_text(spec_content)
    print(f"✅ Spec file created: {spec_file}\n")
    return spec_file


def create_version_info(version: str) -> Path:
    """Create version info file for Windows exe metadata.

    Args:
        version: Version string (e.g., "0.9.0")

    Returns:
        Path to version info file
    """
    print("📝 Creating version info file...")

    # Parse version (e.g., "0.9.0" -> (0, 9, 0, 0))
    parts = version.split(".")
    while len(parts) < 4:
        parts.append("0")
    version_tuple = tuple(int(p) for p in parts[:4])

    version_info_content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={version_tuple},
    prodvers={version_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'JMo Tools'),
            StringStruct(u'FileDescription', u'JMo Security - Unified Security Scanning Suite'),
            StringStruct(u'FileVersion', u'{version}'),
            StringStruct(u'InternalName', u'jmo'),
            StringStruct(u'LegalCopyright', u'Copyright (C) 2024-2026 James Moceri. Licensed under MIT OR Apache-2.0.'),
            StringStruct(u'OriginalFilename', u'jmo.exe'),
            StringStruct(u'ProductName', u'JMo Security'),
            StringStruct(u'ProductVersion', u'{version}')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""

    version_file = PACKAGING_DIR / "file_version_info.txt"
    version_file.write_text(version_info_content)
    print(f"✅ Version info created: {version_file}\n")
    return version_file


def build_executables(spec_file: Path):
    """Build executables using PyInstaller.

    Args:
        spec_file: Path to PyInstaller spec file
    """
    print("🔨 Building executables with PyInstaller...")
    print("   This may take 3-5 minutes...\n")

    try:
        subprocess.run(
            ["pyinstaller", "--clean", "--noconfirm", str(spec_file)],
            check=True,
            cwd=PROJECT_ROOT,
        )
        print("\n✅ Executables built successfully")
        print(f"   jmo.exe: {DIST_DIR / 'jmo.exe'}")
        print(f"   jmotools.exe: {DIST_DIR / 'jmotools.exe'}\n")
    except subprocess.CalledProcessError as e:
        print(f"❌ PyInstaller build failed: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("❌ PyInstaller not found. Install with: pip install pyinstaller", file=sys.stderr)
        sys.exit(1)


def create_nsis_installer(version: str) -> Path:
    """Create NSIS installer script.

    Args:
        version: Version string (e.g., "0.9.0")

    Returns:
        Path to NSIS script
    """
    print("📝 Creating NSIS installer script...")

    # Detect architecture
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "win64"

    nsis_script = f"""
; JMo Security Installer v{version}
; NSIS Installer Script
; https://nsis.sourceforge.io/

!define APP_NAME "JMo Security"
!define APP_VERSION "{version}"
!define APP_PUBLISHER "JMo Tools"
!define APP_URL "https://jmotools.com"
!define APP_SUPPORT_URL "https://github.com/jimmy058910/jmo-security-repo/issues"
!define APP_README "https://docs.jmotools.com"

; Installer name and output file
Name "${{APP_NAME}} ${{APP_VERSION}}"
OutFile "jmo-security-${{APP_VERSION}}-{arch}.exe"
InstallDir "$LOCALAPPDATA\\JMo Security"
InstallDirRegKey HKCU "Software\\JMo Security" "InstallDir"

; Request user permissions
RequestExecutionLevel user

; Modern UI
!include "MUI2.nsh"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${{NSISDIR}}\\Contrib\\Graphics\\Icons\\modern-install.ico"
!define MUI_UNICON "${{NSISDIR}}\\Contrib\\Graphics\\Icons\\modern-uninstall.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page
!define MUI_LICENSEPAGE_TEXT_TOP "JMo Security is dual-licensed under MIT OR Apache-2.0"
!insertmacro MUI_PAGE_LICENSE "..\\..\\LICENSE"

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Installation page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\\jmo.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "--help"
!define MUI_FINISHPAGE_RUN_TEXT "View JMo Security help"
!define MUI_FINISHPAGE_SHOWREADME "${{APP_README}}"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Open online documentation"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; Installer sections
Section "Install" SecInstall
    SetOutPath "$INSTDIR"

    ; Copy executables
    File "..\\..\\dist\\jmo.exe"
    File "..\\..\\dist\\jmotools.exe"

    ; Copy documentation
    File "..\\..\\README.md"
    File "..\\..\\LICENSE"
    File "..\\..\\LICENSE-MIT"
    File "..\\..\\LICENSE-APACHE"

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\\${{APP_NAME}}"
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security.lnk" "$INSTDIR\\jmo.exe" "--help" "$INSTDIR\\jmo.exe" 0
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\JMo Tools Wizard.lnk" "$INSTDIR\\jmotools.exe" "wizard" "$INSTDIR\\jmotools.exe" 0
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\Documentation.lnk" "${{APP_README}}"
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\Uninstall.lnk" "$INSTDIR\\Uninstall.exe"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\\Uninstall.exe"

    ; Write registry keys for Add/Remove Programs
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "DisplayName" "${{APP_NAME}}"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "DisplayVersion" "${{APP_VERSION}}"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "Publisher" "${{APP_PUBLISHER}}"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "URLInfoAbout" "${{APP_URL}}"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "HelpLink" "${{APP_SUPPORT_URL}}"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "UninstallString" "$INSTDIR\\Uninstall.exe"
    WriteRegStr HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "InstallLocation" "$INSTDIR"
    WriteRegDWORD HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "NoModify" 1
    WriteRegDWORD HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}" "NoRepair" 1

    ; Store installation directory
    WriteRegStr HKCU "Software\\JMo Security" "InstallDir" "$INSTDIR"

    ; Add to PATH (user level)
    EnVar::SetHKCU
    EnVar::AddValue "PATH" "$INSTDIR"

    ; Success message with Windows compatibility notice
    MessageBox MB_OK "JMo Security ${{APP_VERSION}} installed successfully!$\\r$\\n$\\r$\\n✅ 7/12 security tools work natively on Windows$\\r$\\n⚠️  5/12 tools require WSL2 or Docker$\\r$\\n$\\r$\\nRecommended Windows Setup:$\\r$\\n  1. Install WSL2 + Docker Desktop (for all 12 tools)$\\r$\\n  2. Run: jmotools wizard --docker$\\r$\\n$\\r$\\nNative Windows (limited to 7 tools):$\\r$\\n  • Run: jmotools wizard$\\r$\\n  • Use --profile fast or --profile balanced$\\r$\\n  • Tools: TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit$\\r$\\n$\\r$\\nDocumentation: ${{APP_README}}"

SectionEnd

; Uninstaller section
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\\jmo.exe"
    Delete "$INSTDIR\\jmotools.exe"
    Delete "$INSTDIR\\README.md"
    Delete "$INSTDIR\\LICENSE"
    Delete "$INSTDIR\\LICENSE-MIT"
    Delete "$INSTDIR\\LICENSE-APACHE"
    Delete "$INSTDIR\\Uninstall.exe"

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\JMo Tools Wizard.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\Documentation.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\Uninstall.lnk"
    RMDir "$SMPROGRAMS\\${{APP_NAME}}"

    ; Remove installation directory
    RMDir "$INSTDIR"

    ; Remove from PATH
    EnVar::SetHKCU
    EnVar::DeleteValue "PATH" "$INSTDIR"

    ; Remove registry keys
    DeleteRegKey HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}"
    DeleteRegKey HKCU "Software\\JMo Security"

    MessageBox MB_OK "JMo Security has been uninstalled."

SectionEnd
"""

    nsis_file = PACKAGING_DIR / "installer.nsi"
    nsis_file.write_text(nsis_script)
    print(f"✅ NSIS script created: {nsis_file}\n")
    return nsis_file


def build_installer(nsis_script: Path, version: str):
    """Build Windows installer using NSIS.

    Args:
        nsis_script: Path to NSIS script
        version: Version string
    """
    print("🔨 Building Windows installer with NSIS...")
    print("   This may take 1-2 minutes...\n")

    try:
        subprocess.run(
            ["makensis", str(nsis_script)],
            check=True,
            cwd=PACKAGING_DIR,
        )

        # Detect architecture
        arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "win64"
        installer_name = f"jmo-security-{version}-{arch}.exe"
        installer_path = PACKAGING_DIR / installer_name

        if installer_path.exists():
            # Move to dist directory
            final_path = DIST_DIR / installer_name
            shutil.move(str(installer_path), str(final_path))
            print(f"\n✅ Installer created: {final_path}")

            # Calculate SHA256 for Winget manifest
            sha256 = hashlib.sha256(final_path.read_bytes()).hexdigest()
            print(f"   SHA256: {sha256}\n")

            # Save SHA256 for later use
            (DIST_DIR / f"{installer_name}.sha256").write_text(sha256)
        else:
            print(f"❌ Installer not found: {installer_path}", file=sys.stderr)
            sys.exit(1)

    except subprocess.CalledProcessError as e:
        print(f"❌ NSIS build failed: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("❌ NSIS not found. Install from https://nsis.sourceforge.io/Download", file=sys.stderr)
        print("   and add to PATH", file=sys.stderr)
        sys.exit(1)


def main():
    """Main build orchestration."""
    parser = argparse.ArgumentParser(description="Build JMo Security Windows installer")
    parser.add_argument(
        "--version",
        help="Version string (default: read from pyproject.toml)",
        default=None,
    )
    args = parser.parse_args()

    version = args.version or get_version()

    print("=" * 70)
    print(f"  JMo Security Windows Installer Build Script")
    print(f"  Version: {version}")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print("=" * 70)
    print()

    # Step 1: Clean previous builds
    clean_build_artifacts()

    # Step 2: Create PyInstaller spec
    spec_file = create_pyinstaller_spec(version)

    # Step 3: Create version info
    create_version_info(version)

    # Step 4: Build executables
    build_executables(spec_file)

    # Step 5: Create NSIS installer script
    nsis_script = create_nsis_installer(version)

    # Step 6: Build installer
    build_installer(nsis_script, version)

    print("=" * 70)
    print("  ✅ Build Complete!")
    print("=" * 70)
    print()
    print(f"Installer: {DIST_DIR / f'jmo-security-{version}-win64.exe'}")
    print(f"SHA256:    {DIST_DIR / f'jmo-security-{version}-win64.exe.sha256'}")
    print()
    print("Next Steps:")
    print("  1. Test installer on clean Windows VM")
    print("  2. Create Winget manifest with SHA256")
    print("  3. Submit to microsoft/winget-pkgs")
    print()


if __name__ == "__main__":
    main()
