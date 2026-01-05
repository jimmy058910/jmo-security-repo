"""Tests for tool_installer URL generation and platform detection.

These tests verify that BINARY_URLS produce correct download URLs
for all supported tools across different platforms and architectures.

The tests focus on URL pattern correctness since incorrect URLs
were the root cause of the "404 saved as binary" bug (v1.0.1).
"""

from __future__ import annotations

import pytest

from scripts.cli.tool_installer import (
    BINARY_URLS,
    INSTALL_SCRIPTS,
    INSTALL_PRIORITIES,
)


class TestBinaryURLPatterns:
    """Test that BINARY_URLS generate correct download URLs."""

    def test_all_urls_use_versioned_paths(self):
        """Verify no URLs use /latest/download/ pattern."""
        for tool, url_template in BINARY_URLS.items():
            assert "/latest/download/" not in url_template, (
                f"{tool} URL uses /latest/download/ which breaks version pinning. "
                f"Use /download/v{{version}}/ instead."
            )

    def test_all_urls_have_version_placeholder(self):
        """Every URL template must include {version} placeholder."""
        for tool, url_template in BINARY_URLS.items():
            assert (
                "{version}" in url_template
            ), f"{tool} URL template missing {{version}} placeholder"

    def test_trivy_url_x86_64(self):
        """Test trivy URL generation for x86_64 Linux."""
        url = BINARY_URLS["trivy"].format(
            version="0.58.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/aquasecurity/trivy/releases/download/v0.58.0/"
            "trivy_0.58.0_Linux-64bit.tar.gz"
        )

    def test_trivy_url_arm64(self):
        """Test trivy URL generation for arm64 Linux."""
        url = BINARY_URLS["trivy"].format(
            version="0.58.0",
            os="Linux",
            os_lower="linux",
            arch="arm64",
            arch_amd="arm64",
            arch_aarch="aarch64",
            trivy_arch="ARM64",
            rust_arch="aarch64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/aquasecurity/trivy/releases/download/v0.58.0/"
            "trivy_0.58.0_Linux-ARM64.tar.gz"
        )

    def test_grype_url_x86_64(self):
        """Test grype URL for x86_64 Linux."""
        url = BINARY_URLS["grype"].format(
            version="0.87.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/anchore/grype/releases/download/v0.87.0/"
            "grype_0.87.0_linux_amd64.tar.gz"
        )

    def test_syft_url_x86_64(self):
        """Test syft URL for x86_64 Linux."""
        url = BINARY_URLS["syft"].format(
            version="1.20.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/anchore/syft/releases/download/v1.20.0/"
            "syft_1.20.0_linux_amd64.tar.gz"
        )

    def test_trufflehog_url_x86_64(self):
        """Test trufflehog URL for x86_64 Linux."""
        url = BINARY_URLS["trufflehog"].format(
            version="3.88.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.0/"
            "trufflehog_3.88.0_linux_amd64.tar.gz"
        )

    def test_nuclei_url_x86_64(self):
        """Test nuclei URL for x86_64 Linux."""
        url = BINARY_URLS["nuclei"].format(
            version="3.3.7",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/"
            "nuclei_3.3.7_linux_amd64.zip"
        )

    def test_gosec_url_x86_64(self):
        """Test gosec URL for x86_64 Linux."""
        url = BINARY_URLS["gosec"].format(
            version="2.21.4",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/securego/gosec/releases/download/v2.21.4/"
            "gosec_2.21.4_linux_amd64.tar.gz"
        )

    def test_bearer_url_x86_64(self):
        """Test bearer URL for x86_64 Linux."""
        url = BINARY_URLS["bearer"].format(
            version="1.51.1",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/Bearer/bearer/releases/download/v1.51.1/"
            "bearer_1.51.1_linux_amd64.tar.gz"
        )

    def test_noseyparker_url_x86_64(self):
        """Test noseyparker URL for x86_64 Linux (Rust target triple)."""
        url = BINARY_URLS["noseyparker"].format(
            version="0.20.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/praetorian-inc/noseyparker/releases/download/v0.20.0/"
            "noseyparker-v0.20.0-x86_64-unknown-linux-gnu.tar.gz"
        )

    def test_shellcheck_url_x86_64(self):
        """Test shellcheck URL for x86_64 Linux (lowercase, dots)."""
        url = BINARY_URLS["shellcheck"].format(
            version="0.10.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/"
            "shellcheck-v0.10.0.linux.x86_64.tar.xz"
        )

    def test_kubescape_url_x86_64(self):
        """Test kubescape URL for x86_64 Linux."""
        url = BINARY_URLS["kubescape"].format(
            version="3.0.47",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        # kubescape uses versioned binary names: kubescape_{version}_{os}_{arch}
        assert url == (
            "https://github.com/kubescape/kubescape/releases/download/v3.0.47/"
            "kubescape_3.0.47_linux_amd64"
        )

    def test_hadolint_url_x86_64(self):
        """Test hadolint URL for x86_64 Linux."""
        url = BINARY_URLS["hadolint"].format(
            version="2.12.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/hadolint/hadolint/releases/download/v2.12.0/"
            "hadolint-Linux-x86_64"
        )

    def test_horusec_url_x86_64(self):
        """Test horusec URL for x86_64 Linux (no version in filename)."""
        url = BINARY_URLS["horusec"].format(
            version="2.8.0",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/ZupIT/horusec/releases/download/v2.8.0/"
            "horusec_linux_amd64"
        )


class TestInstallScripts:
    """Test install script configuration."""

    def test_install_scripts_are_https(self):
        """All install scripts must use HTTPS."""
        for tool, url in INSTALL_SCRIPTS.items():
            assert url.startswith(
                "https://"
            ), f"{tool} install script uses insecure URL: {url}"

    def test_install_scripts_are_raw_github(self):
        """Install scripts should be from raw.githubusercontent.com."""
        for tool, url in INSTALL_SCRIPTS.items():
            assert (
                "raw.githubusercontent.com" in url or "github.io" in url
            ), f"{tool} install script URL may not be reliable: {url}"


class TestInstallPriorities:
    """Test installation method priority configuration."""

    def test_linux_has_all_methods(self):
        """Linux should have all major install methods."""
        linux_methods = INSTALL_PRIORITIES["linux"]
        assert "apt" in linux_methods
        assert "pip" in linux_methods
        assert "binary" in linux_methods
        assert "install_script" in linux_methods

    def test_install_script_before_binary(self):
        """Install script should be tried before binary (more reliable)."""
        linux_methods = INSTALL_PRIORITIES["linux"]
        script_idx = linux_methods.index("install_script")
        binary_idx = linux_methods.index("binary")
        assert (
            script_idx < binary_idx
        ), "install_script should be tried before binary download"

    def test_windows_has_no_install_script(self):
        """Windows doesn't support bash install scripts."""
        windows_methods = INSTALL_PRIORITIES["windows"]
        assert "install_script" not in windows_methods


class TestArchPlaceholders:
    """Test architecture placeholder computation logic.

    These tests document the expected architecture mappings used
    in _install_binary() for different tools.
    """

    @pytest.mark.parametrize(
        "platform_arch,expected_arch_amd,expected_arch_aarch,expected_trivy_arch",
        [
            ("x86_64", "amd64", "x86_64", "64bit"),
            ("arm64", "arm64", "aarch64", "ARM64"),
        ],
    )
    def test_arch_placeholder_mappings(
        self,
        platform_arch: str,
        expected_arch_amd: str,
        expected_arch_aarch: str,
        expected_trivy_arch: str,
    ):
        """Verify architecture placeholder mappings are correct."""
        # Simulate the logic from _install_binary()
        arch = platform_arch

        # Go-style architecture: x86_64 -> amd64
        arch_amd = "amd64" if arch == "x86_64" else "arm64" if arch == "arm64" else arch

        # GNU/Linux style: arm64 -> aarch64
        arch_aarch = (
            "x86_64" if arch == "x86_64" else "aarch64" if arch == "arm64" else arch
        )

        # Trivy's unique format
        trivy_arch = (
            "64bit" if arch == "x86_64" else "ARM64" if arch == "arm64" else arch
        )

        assert arch_amd == expected_arch_amd
        assert arch_aarch == expected_arch_aarch
        assert trivy_arch == expected_trivy_arch

    @pytest.mark.parametrize(
        "os_lower,arch_aarch,expected_rust_arch",
        [
            ("linux", "x86_64", "x86_64-unknown-linux-gnu"),
            ("linux", "aarch64", "aarch64-unknown-linux-gnu"),
            ("darwin", "x86_64", "x86_64-apple-darwin"),
            ("darwin", "aarch64", "aarch64-apple-darwin"),
        ],
    )
    def test_rust_arch_placeholder(
        self, os_lower: str, arch_aarch: str, expected_rust_arch: str
    ):
        """Verify Rust target triple generation."""
        # Simulate the logic from _install_binary()
        if os_lower == "linux":
            rust_arch = f"{arch_aarch}-unknown-linux-gnu"
        elif os_lower == "darwin":
            rust_arch = f"{arch_aarch}-apple-darwin"
        else:
            rust_arch = f"{arch_aarch}-pc-windows-msvc"

        assert rust_arch == expected_rust_arch


class TestSpecialToolHandling:
    """Test special handling for tools that aren't standard binaries.

    Some tools require special detection/installation:
    - yara: Python library (yara-python), not a CLI binary
    - lynis: Git clone to subdirectory, not a single binary
    """

    def test_yara_version_command_uses_python(self):
        """Verify yara version check uses Python import, not CLI."""
        from scripts.cli.tool_manager import VERSION_COMMANDS
        import sys

        yara_cmd = VERSION_COMMANDS.get("yara", [])
        # Should use Python to check import, not 'yara --version'
        assert (
            yara_cmd[0] == sys.executable
        ), "yara version check should use Python interpreter"
        assert "-c" in yara_cmd, "yara version check should use -c flag"
        assert (
            "import yara" in yara_cmd[-1]
        ), "yara version check should import yara module"

    def test_yara_version_pattern_matches_simple_version(self):
        """Verify yara version pattern can parse simple version string."""
        from scripts.cli.tool_manager import VERSION_PATTERNS

        yara_pattern = VERSION_PATTERNS.get("yara")
        assert yara_pattern is not None, "yara should have a version pattern"

        # yara-python outputs just the version number like "4.5.4"
        match = yara_pattern.search("4.5.4")
        assert match is not None, "Pattern should match simple version"
        assert match.group(1) == "4.5.4"

    def test_lynis_installed_via_clone(self):
        """Verify lynis uses clone installation method."""
        from scripts.cli.tool_installer import SPECIAL_INSTALL

        assert "lynis" in SPECIAL_INSTALL, "lynis should be in SPECIAL_INSTALL"
        assert (
            SPECIAL_INSTALL["lynis"] == "clone"
        ), "lynis should use clone installation method"

    def test_lynis_version_command(self):
        """Verify lynis version command is correct."""
        from scripts.cli.tool_manager import VERSION_COMMANDS

        lynis_cmd = VERSION_COMMANDS.get("lynis", [])
        assert lynis_cmd == [
            "lynis",
            "show",
            "version",
        ], "lynis version check should use 'lynis show version'"
