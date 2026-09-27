#!/usr/bin/env python3
"""A finding names the version of the tool that found it (#1333).

Every trufflehog and syft finding said `tool.version` "unknown":

- trufflehog's JSON has no version at all (a 3.97.1 record's keys:
  `DecoderName DetectorDescription DetectorName DetectorType ExtraData Raw
  RawV2 Redacted SecretParts SourceID SourceMetadata SourceName SourceType
  StructuredData VerificationFromCache Verified`); it prints it only in its
  stderr log. The adapter read a `Version` key nothing writes. It now takes the
  pinned version from versions.yaml, as the SARIF bindings do.
- syft's adapter hard-coded "unknown", commented "Syft doesn't embed version in
  JSON output". It does: `descriptor.version` (1.51.1, measured).

Through `jmo report`, with the real adapters.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

from scripts.cli import jmo
from scripts.core.tool_registry import ToolRegistry


def _report(results: Path) -> dict[str, set[str]]:
    """`jmo report`; each tool's versions across its findings."""
    with patch.object(sys, "argv", ["jmo", "report", str(results)]):
        args = jmo.parse_args()
    assert jmo.cmd_report(args) == 0
    document = json.loads((results / "summaries" / "findings.json").read_bytes())
    versions: dict[str, set[str]] = {}
    for finding in document["findings"]:
        tool = finding["tool"]
        versions.setdefault(tool["name"], set()).add(tool.get("version"))
    return versions


def test_each_finding_names_its_tools_version(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "results" / "individual-repos" / "proj"
    target.mkdir(parents=True)
    trufflehog = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "config/app.env"}}},
        "DetectorName": "Generic",
        "Verified": False,
        "Raw": "not-a-secret-1333",
    }
    (target / "trufflehog.json").write_bytes((json.dumps(trufflehog) + "\n").encode())
    # Not the pinned version, so the test shows it is read from the output.
    syft = {
        "descriptor": {"name": "syft", "version": "9.8.7"},
        "artifacts": [
            {
                "id": "a1",
                "name": "requests",
                "version": "2.31.0",
                "type": "python",
                "locations": [{"path": "/requirements.txt"}],
            }
        ],
    }
    (target / "syft.json").write_bytes(json.dumps(syft).encode())

    versions = _report(tmp_path / "results")

    pinned = ToolRegistry().get_tool("trufflehog")
    assert pinned is not None and pinned.version
    assert versions == {"trufflehog": {pinned.version}, "syft": {"9.8.7"}}


def test_a_syft_document_without_a_descriptor_takes_the_pinned_version(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "results" / "individual-repos" / "proj"
    target.mkdir(parents=True)
    syft = {
        "artifacts": [
            {
                "id": "a1",
                "name": "requests",
                "version": "2.31.0",
                "locations": [{"path": "/requirements.txt"}],
            }
        ]
    }
    (target / "syft.json").write_bytes(json.dumps(syft).encode())

    versions = _report(tmp_path / "results")

    pinned = ToolRegistry().get_tool("syft")
    assert pinned is not None and pinned.version
    assert versions == {"syft": {pinned.version}}
