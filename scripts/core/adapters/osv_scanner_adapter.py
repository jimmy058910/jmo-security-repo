"""osv-scanner (dependency vulnerabilities): a SARIF binding over sarif_common."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import dependency_record
from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

# osv-scanner's SARIF carries no package field (measured, 2.5.1 and 2.6.0):
# the package is in the message, "Package '<name>@<version>' is vulnerable to
# '<id>' (also known as ...)". A scoped npm name holds an `@` of its own, so
# the version is what follows the LAST one.
_MESSAGE = re.compile(r"^Package '(?P<package>.+)' is vulnerable to '")


def _dependency(result: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any] | None:
    """The package from the message template; the aliases from the rule's
    ``deprecatedIds``, which lists every id of the advisory, the rule's own
    included (measured: 179 of 179 rules on NodeGoat)."""
    message = result.get("message")
    text = message.get("text") if isinstance(message, dict) else None
    match = _MESSAGE.match(text) if isinstance(text, str) else None
    if match is None:
        return None
    name, _, version = match.group("package").rpartition("@")
    aliases = rule.get("deprecatedIds")
    return dependency_record(
        name,
        version,
        result.get("ruleId") or rule.get("id"),
        aliases if isinstance(aliases, list) else (),
    )


_SPEC = SarifToolSpec(
    tool="osv-scanner", tags=("sca", "vulnerability", "sarif"), dependency=_dependency
)


@adapter_plugin(
    PluginMetadata(
        name="osv_scanner",
        version="1.0.0",
        description="Adapter for osv-scanner dependency vulnerabilities (SARIF)",
        tool_name="osv-scanner",
        output_format="sarif",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class OsvScannerAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
