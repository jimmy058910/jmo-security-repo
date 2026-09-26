"""gitleaks (secret detection): a SARIF binding over sarif_common."""

from __future__ import annotations

from pathlib import Path

from scripts.core.adapters.sarif_common import SarifToolSpec, parse_sarif
from scripts.core.common_finding import fingerprint, secret_digest
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
        findings = parse_sarif(output_path, _SPEC)
        for finding in findings:
            # gitleaks gives no severity, and verifies nothing: HIGH, like an
            # unverified TruffleHog secret, so `--fail-on HIGH` stops on a
            # leaked secret (decided 2026-09-26). SARIF's default is MEDIUM.
            finding.severity = "HIGH"
            snippets = _pop_snippets(finding.raw)
            if snippets:
                finding.secretDigest = secret_digest("\n".join(snippets))
            context = _history_context(finding.raw)
            if context:
                finding.secretContext = context
                # A key rotated in place leaves the old one at the new one's
                # line; the message names the commit only after the path, past
                # the 120 characters an id reads when the path is long.
                finding.id = fingerprint(
                    "gitleaks",
                    finding.ruleId,
                    finding.location.get("path"),
                    finding.location.get("startLine"),
                    finding.message,
                    start_column=finding.location.get("startColumn"),
                    commit=context["commit"],
                )
        return findings


def _pop_snippets(result: dict | None) -> list[str]:
    """Remove every `region.snippet` and return their texts.

    gitleaks writes the matched secret there, unredacted, and `raw` reaches
    findings.json, the dashboard and history. A finding says where a secret
    is, never what it is (trufflehog's adapter drops `Raw` for the same
    reason). The texts are only digested, to pair the tree and history
    records of one secret (v2.0.0 Phase 3, G1).
    """
    texts: list[str] = []
    for location in (result or {}).get("locations") or []:
        physical = (
            location.get("physicalLocation") if isinstance(location, dict) else None
        )
        region = physical.get("region") if isinstance(physical, dict) else None
        if isinstance(region, dict):
            snippet = region.pop("snippet", None)
            text = snippet.get("text") if isinstance(snippet, dict) else None
            if isinstance(text, str) and text:
                texts.append(text)
    return texts


def _history_context(result: dict | None) -> dict[str, str] | None:
    """`secretContext` for a `gitleaks git` result, from its
    `partialFingerprints`; None for a `gitleaks dir` one, where gitleaks
    writes those keys empty (measured, 8.30.1)."""
    prints = (result or {}).get("partialFingerprints")
    if not isinstance(prints, dict) or not prints.get("commitSha"):
        return None
    context = {"commit": str(prints["commitSha"])}
    author, email = prints.get("author"), prints.get("email")
    if author and email:
        context["author"] = f"{author} <{email}>"
    elif author or email:
        context["author"] = str(author or email)
    if prints.get("date"):
        context["date"] = str(prints["date"])
    return context
