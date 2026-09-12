"""gitleaks (secret detection): a SARIF binding over sarif_common."""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

_SPEC = SarifToolSpec(tool="gitleaks", tags=("secrets", "sarif"))


@adapter_plugin(
    PluginMetadata(
        name="gitleaks",
        version="1.0.0",
        description="Adapter for gitleaks secret detection (SARIF)",
        tool_name="gitleaks",
        output_format="sarif",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class GitleaksAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        return parse_sarif(output_path, _SPEC)
