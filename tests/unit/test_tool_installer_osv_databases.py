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

from scripts.cli.installers.models import InstallResult
from scripts.cli.tool_installer import ToolInstaller
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
