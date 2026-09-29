"""osv-scanner's database fetch, wired into `ToolInstaller._post_install`
(v2.0.0 Phase 4, PR O, Task O2, decision 6).

The same shape as yara's rule-bundle fetch (`_install_yara_rules`), with one
deliberate difference: a yara install with no rules is useless, so a failed
rule-bundle download flips the whole `InstallResult` to a failure. osv-scanner
is not useless without every one of the eleven ecosystems -- it still runs
against whichever ecosystem a target's lockfile needs -- so a fetch failure
here is loud (named ecosystem, reason, on the logger and in the result's
message) but never flips `result.success`.

`scripts.core.osv_database.fetch_all` does the actual network work and is
patched throughout; see `tests/unit/test_osv_database.py` for the fetch itself
against a local HTTP server.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from scripts.cli.installers.models import InstallProgress, InstallResult
from scripts.cli.tool_installer import ToolInstaller, print_install_progress
from scripts.core.osv_database import FetchResult

OK = InstallResult(
    tool_name="osv-scanner", success=True, method="binary", version_installed="2.6.0"
)


def _installer() -> ToolInstaller:
    return ToolInstaller(manager=MagicMock())


def test_a_successful_install_fetches_every_ecosystems_database() -> None:
    installer = _installer()
    fetch_all = MagicMock(return_value=[FetchResult("npm", True, "fetched")])

    with patch("scripts.core.osv_database.fetch_all", fetch_all):
        result = installer._post_install("osv-scanner", OK)

    fetch_all.assert_called_once_with()
    assert result.success is True
    assert result.message == OK.message


def test_a_failed_install_never_fetches() -> None:
    """osv-scanner's binary is not on disk; there is nothing to fill a cache
    for, and no network call should follow a failure that already has one."""
    installer = _installer()
    failed = InstallResult(tool_name="osv-scanner", success=False, message="404")
    fetch_all = MagicMock()

    with patch("scripts.core.osv_database.fetch_all", fetch_all):
        result = installer._post_install("osv-scanner", failed)

    fetch_all.assert_not_called()
    assert result is failed


def test_a_different_tool_never_triggers_the_osv_fetch() -> None:
    installer = _installer()
    other = InstallResult(tool_name="trivy", success=True, method="binary")
    fetch_all = MagicMock()

    with patch("scripts.core.osv_database.fetch_all", fetch_all):
        result = installer._post_install("trivy", other)

    fetch_all.assert_not_called()
    assert result is other


def test_every_ecosystem_succeeding_leaves_the_result_untouched() -> None:
    installer = _installer()
    fetch_all = MagicMock(
        return_value=[
            FetchResult("npm", True, "fetched"),
            FetchResult("PyPI", True, "fetched"),
        ]
    )

    with patch("scripts.core.osv_database.fetch_all", fetch_all):
        result = installer._post_install("osv-scanner", OK)

    assert result == OK


def test_a_failed_ecosystem_is_named_loudly_but_does_not_flip_success(
    caplog,
) -> None:
    installer = _installer()
    fetch_all = MagicMock(
        return_value=[
            FetchResult("npm", True, "fetched"),
            FetchResult("CRAN", False, "download failed: 503 Service Unavailable"),
        ]
    )

    with (
        patch("scripts.core.osv_database.fetch_all", fetch_all),
        caplog.at_level(logging.ERROR, logger="scripts.cli.tool_installer"),
    ):
        result = installer._post_install("osv-scanner", OK)

    assert result.success is True  # the binary installed; that part held
    assert "CRAN" in result.message
    assert "download failed: 503 Service Unavailable" in result.message
    assert "jmo tools update" in result.message
    assert any("CRAN" in r.message for r in caplog.records)
    # Fix round 1, review Important #1: `.message` alone never reaches the
    # CLI's own install summary on a successful result -- `.warning` is what
    # `print_install_progress` actually renders (see the class below).
    assert result.warning is not None
    assert "CRAN" in result.warning
    assert "download failed: 503 Service Unavailable" in result.warning
    assert "jmo tools update" in result.warning


def test_every_ecosystem_failing_still_keeps_the_binary_marked_installed() -> None:
    """The whole point of decoupling the fetch from the install's own
    success: a corporate firewall that blocks Google Cloud Storage should not
    make `jmo tools install` report osv-scanner as not installed."""
    installer = _installer()
    fetch_all = MagicMock(
        return_value=[
            FetchResult(eco, False, "download failed: connection refused")
            for eco in ("npm", "PyPI", "Go")
        ]
    )

    with patch("scripts.core.osv_database.fetch_all", fetch_all):
        result = installer._post_install("osv-scanner", OK)

    assert result.success is True
    assert result.tool_name == "osv-scanner"
    assert result.version_installed == "2.6.0"
    for eco in ("npm", "PyPI", "Go"):
        assert eco in result.message


class TestPrintInstallProgressRendersTheWarning:
    """Fix round 1, review Important #1: a note that reached only
    `result.message` on a `success=True` result was invisible in
    `print_install_progress`'s table -- the CLI's actual install summary, and
    the thing a human watches. These test the RENDERED output (`capsys`),
    not the `InstallResult` object the tests above already cover.
    """

    def test_a_warning_is_rendered_under_the_ok_row(self, capsys) -> None:
        installer = _installer()
        fetch_all = MagicMock(
            return_value=[
                FetchResult("npm", True, "fetched"),
                FetchResult("CRAN", False, "download failed: 503 Service Unavailable"),
            ]
        )

        with patch("scripts.core.osv_database.fetch_all", fetch_all):
            result = installer._post_install("osv-scanner", OK)

        progress = InstallProgress(total=1)
        progress.add_result(result)
        print_install_progress(progress)

        out = capsys.readouterr().out
        assert "[OK] osv-scanner (v2.6.0) - binary" in out
        lines = out.splitlines()
        ok_line = next(i for i, line in enumerate(lines) if "[OK] osv-scanner" in line)
        assert "[WARN]" in lines[ok_line + 1]
        assert "CRAN" in lines[ok_line + 1]
        assert "download failed: 503 Service Unavailable" in lines[ok_line + 1]

    def test_a_clean_install_prints_no_warning_line(self, capsys) -> None:
        installer = _installer()
        fetch_all = MagicMock(return_value=[FetchResult("npm", True, "fetched")])

        with patch("scripts.core.osv_database.fetch_all", fetch_all):
            result = installer._post_install("osv-scanner", OK)

        progress = InstallProgress(total=1)
        progress.add_result(result)
        print_install_progress(progress)

        out = capsys.readouterr().out
        assert "[OK] osv-scanner (v2.6.0) - binary" in out
        assert "[WARN]" not in out

    def test_an_unrelated_tools_successful_row_is_unchanged(self, capsys) -> None:
        """The general `print_install_progress` behaviour for every OTHER
        tool -- whose `InstallResult` never sets `.warning` -- must not
        change: only osv-scanner's caveat gains a line."""
        progress = InstallProgress(total=1)
        progress.add_result(
            InstallResult(
                tool_name="trivy",
                success=True,
                method="binary",
                message="Installed binary to /home/user/.jmo/bin/trivy",
                version_installed="0.50.0",
            )
        )
        print_install_progress(progress)

        out = capsys.readouterr().out
        assert "[OK] trivy (v0.50.0) - binary" in out
        assert "[WARN]" not in out
        # The pre-existing behaviour this task must not disturb: a
        # successful result's `.message` is still never printed.
        assert "Installed binary to" not in out
