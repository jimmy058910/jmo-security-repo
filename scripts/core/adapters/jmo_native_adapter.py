"""jmo-native (JMo's own Next.js, Supabase and Firebase checks): a SARIF binding
over sarif_common."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.adapters.sarif_common import (
    SarifToolSpec,
    _props,
    _rules,
    parse_sarif,
)
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

_SPEC = SarifToolSpec(tool="jmo-native", tags=("sast", "sarif"))

# A finding's likelihood and impact follow its rule's severity.
_LEVEL = {"CRITICAL": "HIGH", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}


def _rule_cwes(path: Path) -> dict[str, str]:
    """Rule id -> the CWE the runner writes as that rule's `cwe` property.
    SARIF has no CWE field, and `parse_sarif` hands a binding the result, not
    its rule. Walked with `sarif_common`'s own helpers, so a shape it reads
    past (a run that is not an object, a `tool` that is not one) is read past
    here too."""
    data = safe_load_json_file(path, default=None)
    runs = data.get("runs") if isinstance(data, dict) else None
    cwes: dict[str, str] = {}
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict):
            continue
        for rule in _rules(run):
            cwe = _props(rule).get("cwe") if isinstance(rule, dict) else None
            if isinstance(cwe, str) and cwe:
                cwes[str(rule.get("id"))] = cwe
    return cwes


@adapter_plugin(
    PluginMetadata(
        name="jmo_native",
        version="1.0.0",
        description="Adapter for jmo-native, JMo's own check pack (SARIF)",
        tool_name="jmo-native",
        output_format="sarif",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class JmoNativeAdapter(AdapterPlugin):
    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> list[Finding]:
        findings = parse_sarif(output_path, _SPEC)
        cwes = _rule_cwes(output_path) if findings else {}
        for finding in findings:
            # Compliance enrichment reads `risk.cwe` and nowhere else, so the
            # rule's CWE is lifted here, in gitleaks' shape. Confidence is
            # MEDIUM: every check is a pattern over source or config, not a
            # proof. rls-without-policy has no CWE, so no `cwe` key.
            level = _LEVEL.get(finding.severity, "LOW")
            risk: dict[str, Any] = {
                "confidence": "MEDIUM",
                "likelihood": level,
                "impact": level,
            }
            cwe = cwes.get(finding.ruleId)
            if cwe:
                risk["cwe"] = [cwe]
            finding.risk = risk
        return findings
