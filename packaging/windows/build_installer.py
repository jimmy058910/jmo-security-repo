#!/usr/bin/env python3
"""Build Windows installer for JMo Security.

This script creates a standalone Windows installer using PyInstaller to bundle
Python + dependencies into .exe files, then packages them with NSIS installer.

Requirements:
    - PyInstaller: pip install pyinstaller (auto-detected)
    - NSIS: Automatically installed via Chocolatey if missing (with prompt)
    - Chocolatey: Automatically installed if missing (with prompt)
    - Windows 10+ or Windows Server 2019+

Usage:
    # Interactive mode (prompts for missing dependencies)
    python packaging/windows/build_installer.py

    # Fully automated mode (no prompts, auto-installs everything)
    python packaging/windows/build_installer.py --auto-install

    # Specify version
    python packaging/windows/build_installer.py --version 0.9.0

Output:
    dist/jmo-security-{VERSION}-win64.exe
    dist/jmo-security-{VERSION}-arm64.exe (if built on ARM64)
    dist/jmo-security-{VERSION}-win64.exe.sha256

Features:
    - Automatic dependency detection and installation
    - PyInstaller validation with helpful error messages
    - Chocolatey-based NSIS installation (no manual downloads)
    - UTF-8 encoding support (emoji-safe)
    - SHA256 hash generation for WinGet manifests
"""

import argparse
import subprocess
import sys
import shutil
from pathlib import Path
import hashlib
import platform
import os

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


def find_nsis_path() -> str | None:
    """Find NSIS installation path.

    Returns:
        Path to makensis.exe or None if not found
    """
    # Common installation paths
    common_paths = [
        r"C:\Program Files (x86)\NSIS\makensis.exe",
        r"C:\Program Files\NSIS\makensis.exe",
        r"C:\ProgramData\chocolatey\lib\nsis\tools\makensis.exe",
        r"C:\ProgramData\chocolatey\bin\makensis.exe",
    ]

    for path in common_paths:
        if Path(path).exists():
            return path

    # Check PATH
    try:
        result = subprocess.run(
            ["where", "makensis"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split('\n')[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return None


def check_nsis_installed() -> bool:
    """Check if NSIS is installed and available.

    Returns:
        True if makensis is found, False otherwise
    """
    return find_nsis_path() is not None


def check_chocolatey_installed() -> bool:
    """Check if Chocolatey is installed.

    Returns:
        True if choco is found, False otherwise
    """
    try:
        result = subprocess.run(
            ["choco", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def install_chocolatey():
    """Install Chocolatey package manager.

    Raises:
        RuntimeError: If installation fails or requires elevation
    """
    print("📦 Chocolatey not found. Installing Chocolatey...")
    print("   This requires administrator privileges.\n")

    # Chocolatey installation command
    install_cmd = (
        'powershell -NoProfile -ExecutionPolicy Bypass -Command "'
        '[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; '
        'iex ((New-Object System.Net.WebClient).DownloadString(\'https://community.chocolatey.org/install.ps1\'))'
        '"'
    )

    try:
        result = subprocess.run(
            install_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Chocolatey installation failed:\n{result.stderr}\n\n"
                "Please install Chocolatey manually:\n"
                "1. Open PowerShell as Administrator\n"
                "2. Run: Set-ExecutionPolicy Bypass -Scope Process -Force\n"
                "3. Run: iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\n"
                "4. Restart terminal and try again"
            )

        print("✅ Chocolatey installed successfully\n")

        # Refresh PATH to include choco
        refresh_path()

    except subprocess.TimeoutExpired:
        raise RuntimeError("Chocolatey installation timed out (>5 minutes)")


def install_nsis():
    """Install NSIS using Chocolatey.

    Raises:
        RuntimeError: If installation fails
    """
    print("📦 NSIS not found. Installing NSIS via Chocolatey...")
    print("   This may take 1-2 minutes...\n")

    try:
        result = subprocess.run(
            ["choco", "install", "nsis", "-y"],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"NSIS installation failed:\n{result.stderr}\n\n"
                "Please install NSIS manually:\n"
                "1. Download from https://nsis.sourceforge.io/Download\n"
                "2. Run installer and add to PATH\n"
                "3. Restart terminal and try again"
            )

        print("✅ NSIS installed successfully\n")

        # Refresh PATH to include makensis
        refresh_path()

    except subprocess.TimeoutExpired:
        raise RuntimeError("NSIS installation timed out (>5 minutes)")


def refresh_path():
    """Refresh PATH environment variable to include newly installed programs."""
    import winreg

    try:
        # Read system PATH
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
            system_path = winreg.QueryValueEx(key, "Path")[0]

        # Read user PATH
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            try:
                user_path = winreg.QueryValueEx(key, "Path")[0]
            except FileNotFoundError:
                user_path = ""

        # Combine and update os.environ
        combined_path = f"{system_path};{user_path}"
        os.environ["PATH"] = combined_path

    except Exception as e:
        print(f"⚠️  Could not refresh PATH: {e}")
        print("   You may need to restart your terminal for changes to take effect\n")


def ensure_nsis_available(auto_install: bool = False):
    """Ensure NSIS is installed and available.

    Automatically installs NSIS via Chocolatey if missing.

    Args:
        auto_install: If True, install without prompting

    Raises:
        RuntimeError: If NSIS cannot be installed
    """
    nsis_path = find_nsis_path()
    if nsis_path:
        print(f"✅ NSIS found: {nsis_path}\n")
        return

    print("⚠️  NSIS not found in PATH\n")

    # Check if Chocolatey is installed
    if not check_chocolatey_installed():
        print("⚠️  Chocolatey not found\n")

        if not auto_install:
            response = input("Install Chocolatey package manager? (y/n): ").strip().lower()
            if response != 'y':
                raise RuntimeError(
                    "NSIS installation cancelled. Please install manually:\n"
                    "https://nsis.sourceforge.io/Download"
                )
        else:
            print("   Auto-installing Chocolatey...")

        install_chocolatey()

    # Install NSIS
    if not auto_install:
        response = input("Install NSIS via Chocolatey? (y/n): ").strip().lower()
        if response != 'y':
            raise RuntimeError(
                "NSIS installation cancelled. Please install manually:\n"
                "https://nsis.sourceforge.io/Download"
            )
    else:
        print("   Auto-installing NSIS...")

    install_nsis()

    # Verify installation
    nsis_path = find_nsis_path()
    if not nsis_path:
        print("\n⚠️  NSIS installation completed but not detected.\n")
        print("Possible solutions:")
        print("1. Close this terminal and open a new one (to refresh PATH)")
        print("2. Run the build script again")
        print("3. The script will auto-detect NSIS in common locations\n")
        raise RuntimeError(
            "NSIS installation completed but not detected in PATH.\n"
            "Please restart your terminal and run the script again."
        )
    else:
        print(f"✅ NSIS verified: {nsis_path}\n")


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

    # Convert PROJECT_ROOT to string with forward slashes for cross-platform compatibility
    project_root_str = str(PROJECT_ROOT).replace('\\', '/')

    spec_content = f"""# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for JMo Security {version}

import os
block_cipher = None

# Project root directory
PROJECT_ROOT = r'{PROJECT_ROOT}'

# Collect all scripts/* files for bundling
datas = [
    (os.path.join(PROJECT_ROOT, 'scripts', 'core'), 'scripts/core'),
    (os.path.join(PROJECT_ROOT, 'scripts', 'cli'), 'scripts/cli'),
    (os.path.join(PROJECT_ROOT, 'jmo.yml'), '.'),
    (os.path.join(PROJECT_ROOT, 'versions.yaml'), '.'),
    (os.path.join(PROJECT_ROOT, 'README.md'), '.'),
    (os.path.join(PROJECT_ROOT, 'LICENSE'), '.'),
    (os.path.join(PROJECT_ROOT, 'LICENSE-MIT'), '.'),
    (os.path.join(PROJECT_ROOT, 'LICENSE-APACHE'), '.'),
]

# Hidden imports required by JMo Security
hiddenimports = [
    'scripts.cli.jmo',
    'scripts.cli.schedule_commands',
    'scripts.cli.report_orchestrator',
    'scripts.cli.ci_orchestrator',
    'scripts.cli.scan_orchestrator',
    'scripts.cli.cpu_utils',
    'scripts.core.normalize_and_report',
    'scripts.core.config',
    'scripts.core.suppress',
    'scripts.core.common_finding',
    'scripts.core.plugin_api',
    'scripts.core.plugin_loader',
    'scripts.core.cron_installer',
    'scripts.core.workflow_generators.github_actions',
    'scripts.core.workflow_generators.gitlab_ci',
    'scripts.core.telemetry',
    'scripts.core.exceptions',
    'yaml',
    'pyyaml',
    'jsonschema',
    'croniter',
]

# Add all adapter plugins
adapters_dir = os.path.join(PROJECT_ROOT, 'scripts', 'core', 'adapters')
for fname in os.listdir(adapters_dir):
    if fname.endswith('_adapter.py') and fname != '__init__.py':
        module_name = fname[:-3]  # Remove .py
        hiddenimports.append(f'scripts.core.adapters.{{module_name}}')

# Add all reporter plugins
reporters_dir = os.path.join(PROJECT_ROOT, 'scripts', 'core', 'reporters')
for fname in os.listdir(reporters_dir):
    if fname.endswith('_reporter.py') and fname != '__init__.py':
        module_name = fname[:-3]
        hiddenimports.append(f'scripts.core.reporters.{{module_name}}')

# Analysis: Scan entry point and dependencies
a = Analysis(
    [os.path.join(PROJECT_ROOT, 'scripts', 'cli', 'jmo.py')],
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
"""

    spec_file = PACKAGING_DIR / "jmo-security.spec"
    spec_file.write_text(spec_content, encoding='utf-8')
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
    version_file.write_text(version_info_content, encoding='utf-8')
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
        print("\n✅ Executable built successfully")
        print(f"   jmo.exe: {DIST_DIR / 'jmo.exe'}\n")
    except subprocess.CalledProcessError as e:
        print(f"❌ PyInstaller build failed: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(
            "❌ PyInstaller not found. Install with: pip install pyinstaller",
            file=sys.stderr,
        )
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

    ; Copy executable
    File "..\\..\\dist\\jmo.exe"

    ; Copy documentation
    File "..\\..\\README.md"
    File "..\\..\\LICENSE"
    File "..\\..\\LICENSE-MIT"
    File "..\\..\\LICENSE-APACHE"

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\\${{APP_NAME}}"
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security CLI.lnk" "$INSTDIR\\jmo.exe" "--help" "$INSTDIR\\jmo.exe" 0
    CreateShortcut "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security Wizard.lnk" "$INSTDIR\\jmo.exe" "wizard" "$INSTDIR\\jmo.exe" 0
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

    ; Add to PATH (user level) - Native NSIS approach
    ReadRegStr $0 HKCU "Environment" "Path"
    StrCmp $0 "" 0 +2
        StrCpy $0 "$INSTDIR"
    StrCpy $1 "$0"
    ; Check if already in PATH
    Push "$INSTDIR"
    Push "$1"
    Call StrStr
    Pop $2
    StrCmp $2 "" 0 +2
        WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR;$0"

    ; Broadcast WM_SETTINGCHANGE to notify applications of PATH change
    SendMessage ${{HWND_BROADCAST}} ${{WM_SETTINGCHANGE}} 0 "STR:Environment" /TIMEOUT=5000

    ; Success message with Windows compatibility notice
    MessageBox MB_OK "JMo Security ${{APP_VERSION}} installed successfully!$\\r$\\n$\\r$\\n7/12 security tools work natively on Windows$\\r$\\n5/12 tools require WSL2 or Docker$\\r$\\n$\\r$\\nRecommended Windows Setup:$\\r$\\n  1. Install WSL2 + Docker Desktop (for all 12 tools)$\\r$\\n  2. Run: jmo wizard --docker$\\r$\\n$\\r$\\nNative Windows (limited to 7 tools):$\\r$\\n  - Run: jmo wizard$\\r$\\n  - Use --profile fast or --profile balanced$\\r$\\n  - Tools: TruffleHog, Trivy, Syft, Checkov, Hadolint, Nuclei, Bandit$\\r$\\n$\\r$\\nDocumentation: ${{APP_README}}"

SectionEnd

; Uninstaller section
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\\jmo.exe"
    Delete "$INSTDIR\\README.md"
    Delete "$INSTDIR\\LICENSE"
    Delete "$INSTDIR\\LICENSE-MIT"
    Delete "$INSTDIR\\LICENSE-APACHE"
    Delete "$INSTDIR\\Uninstall.exe"

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security CLI.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\JMo Security Wizard.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\Documentation.lnk"
    Delete "$SMPROGRAMS\\${{APP_NAME}}\\Uninstall.lnk"
    RMDir "$SMPROGRAMS\\${{APP_NAME}}"

    ; Remove installation directory
    RMDir "$INSTDIR"

    ; Remove from PATH (user level) - Native NSIS approach
    ReadRegStr $0 HKCU "Environment" "Path"
    Push "$INSTDIR"
    Push "$0"
    Call un.RemoveFromPath
    Pop $1
    WriteRegExpandStr HKCU "Environment" "Path" "$1"

    ; Broadcast WM_SETTINGCHANGE
    SendMessage ${{HWND_BROADCAST}} ${{WM_SETTINGCHANGE}} 0 "STR:Environment" /TIMEOUT=5000

    ; Remove registry keys
    DeleteRegKey HKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${{APP_NAME}}"
    DeleteRegKey HKCU "Software\\JMo Security"

    MessageBox MB_OK "JMo Security has been uninstalled."

SectionEnd

; Helper function: Check if string contains substring
Function StrStr
    Exch $R1 ; haystack
    Exch
    Exch $R2 ; needle
    Push $R3
    Push $R4
    Push $R5
    StrLen $R3 $R2
    StrCpy $R4 0
    loop:
        StrCpy $R5 $R1 $R3 $R4
        StrCmp $R5 $R2 done
        StrCmp $R5 "" done
        IntOp $R4 $R4 + 1
        Goto loop
    done:
        StrCpy $R1 $R5
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1
FunctionEnd

; Helper function: Remove directory from PATH
Function un.RemoveFromPath
    Exch $0 ; path to remove
    Exch
    Exch $1 ; current PATH
    Push $2
    Push $3
    Push $4
    Push $5
    StrCpy $2 $1 1 -1
    StrCmp $2 ";" +2
        StrCpy $1 "$1;" ; Ensure trailing semicolon
    Push $1
    Push "$0;"
    Call un.StrStr
    Pop $2
    StrCmp $2 "" unRemoveFromPath_done
        StrLen $3 "$0;"
        StrLen $4 $2
        StrCpy $5 $1 -$4
        StrCpy $5 "$5$2" "" $3
        StrCpy $1 $5
    unRemoveFromPath_done:
        StrCpy $0 $1
        StrCpy $2 $0 1 -1
        StrCmp $2 ";" 0 +2
            StrCpy $0 $0 -1 ; Remove trailing semicolon
        Pop $5
        Pop $4
        Pop $3
        Pop $2
        Pop $1
        Exch $0
FunctionEnd

; Helper function for uninstaller: StrStr
Function un.StrStr
    Exch $R1
    Exch
    Exch $R2
    Push $R3
    Push $R4
    Push $R5
    StrLen $R3 $R2
    StrCpy $R4 0
    loop_un:
        StrCpy $R5 $R1 $R3 $R4
        StrCmp $R5 $R2 done_un
        StrCmp $R5 "" done_un
        IntOp $R4 $R4 + 1
        Goto loop_un
    done_un:
        StrCpy $R1 $R5
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1
FunctionEnd
"""

    nsis_file = PACKAGING_DIR / "installer.nsi"
    nsis_file.write_text(nsis_script, encoding='utf-8')
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

    # Find NSIS path
    nsis_path = find_nsis_path()
    if not nsis_path:
        raise RuntimeError(
            "NSIS not found. Please restart your terminal or install manually:\n"
            "https://nsis.sourceforge.io/Download"
        )

    makensis_cmd = nsis_path if Path(nsis_path).exists() else "makensis"

    try:
        subprocess.run(
            [makensis_cmd, str(nsis_script)],
            check=True,
            cwd=PACKAGING_DIR,
        )

        # Detect architecture
        arch = (
            "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "win64"
        )
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
        print(
            "❌ NSIS not found. Install from https://nsis.sourceforge.io/Download",
            file=sys.stderr,
        )
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
    parser.add_argument(
        "--auto-install",
        action="store_true",
        help="Automatically install missing dependencies (Chocolatey, NSIS) without prompting",
    )
    args = parser.parse_args()

    version = args.version or get_version()

    print("=" * 70)
    print("  JMo Security Windows Installer Build Script")
    print(f"  Version: {version}")
    print(f"  Platform: {platform.system()} {platform.machine()}")
    print("=" * 70)
    print()

    # Step 0: Ensure NSIS is available
    try:
        ensure_nsis_available(auto_install=args.auto_install)
    except RuntimeError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

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
