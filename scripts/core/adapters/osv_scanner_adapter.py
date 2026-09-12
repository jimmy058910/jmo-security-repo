"""osv-scanner (dependency vulnerabilities) -- SARIF binding.

One SarifToolSpec against sarif_common.parse_sarif; nothing else. Severity
comes from each rule's `security-severity` (a CVSS base score), which is why
the importer reads that before `level`: `level` is `warning` on every result.
"""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

_SPEC = SarifToolSpec(tool="osv-scanner", tags=("sca", "vulnerability", "sarif"))


@adapter_plugin(
    PluginMetadata(
        name="osv_scanner",
        version="1.0.0",
        description="Adapter for osv-scanner dependency vulnerabilities (SARIF)",
        tool_name="osv-scanner",
        schema_version="1.2.0",
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
