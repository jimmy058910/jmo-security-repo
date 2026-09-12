"""zizmor (GitHub Actions auditor) -- SARIF binding.

One SarifToolSpec against sarif_common.parse_sarif; nothing else. Adding a
fourth SARIF tool is another file of this shape.
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

_SPEC = SarifToolSpec(tool="zizmor", tags=("github-actions", "workflow", "sarif"))


@adapter_plugin(
    PluginMetadata(
        name="zizmor",
        version="1.0.0",
        description="Adapter for zizmor GitHub Actions auditor (SARIF)",
        tool_name="zizmor",
        schema_version="1.2.0",
        output_format="sarif",
        exit_codes={0: "clean", 14: "findings"},
    )
)
class ZizmorAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
