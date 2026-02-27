# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for JMo Security 0.9.0

import os
block_cipher = None

# Project root directory
PROJECT_ROOT = r'C:\Projects\jmo-security-repo'

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
        hiddenimports.append(f'scripts.core.adapters.{module_name}')

# Add all reporter plugins
reporters_dir = os.path.join(PROJECT_ROOT, 'scripts', 'core', 'reporters')
for fname in os.listdir(reporters_dir):
    if fname.endswith('_reporter.py') and fname != '__init__.py':
        module_name = fname[:-3]
        hiddenimports.append(f'scripts.core.reporters.{module_name}')

# Analysis: Scan entry point and dependencies
a = Analysis(
    [os.path.join(PROJECT_ROOT, 'scripts', 'cli', 'jmo.py')],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
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
