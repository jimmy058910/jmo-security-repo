"""A trivy image scan that found a secret keeps no copy of it (#1624).

trivy masks the secret it matched in `Match` and `Code.Lines`, but copies the
image's own build metadata verbatim. Measured on trivy 0.74.0 with throwaway
images carrying a fake token:

- planted by `RUN printf ... > /app/.env`: the token was in `trivy.json` three
  times (`Metadata.ImageConfig.history[].created_by` and each secret's
  `Layer.CreatedBy`), and, through each finding's `raw`, twice in
  `summaries/findings.json`, twice in `findings.yaml`, once in the dashboard
  and in two rows of the history database's findings table;
- set by `ENV`: twice in `trivy.json` (`config.Env` and the history line);
- copied in by `COPY`: nowhere, since trivy masks the file's content.

The fixture below is that output's shape, with placeholder values a secret
scanner would not match.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.adapters.trivy_adapter import TrivyAdapter, redact_image_metadata
from scripts.core.normalize_and_report import gather_results
from scripts.core.secret_output_redaction import redact_secret_outputs

RUN_TOKEN = "planted-trivy-run-token-1624-a1b2"
ENV_TOKEN = "planted-trivy-env-token-1624-c3d4"
TOKENS = (RUN_TOKEN, ENV_TOKEN)
RUN_LINE = f"RUN /bin/sh -c printf 'GITHUB_TOKEN={RUN_TOKEN}\\n' > /app/.env # buildkit"


def _masked(token: str) -> str:
    """As trivy writes a matched secret: one `*` per character."""
    return "GITHUB_TOKEN=" + "*" * len(token)


def _secret(rule: str, line: int, token: str, layer: dict | None) -> dict:
    record = {
        "RuleID": rule,
        "Category": "GitHub",
        "Severity": "CRITICAL",
        "Title": "GitHub Personal Access Token",
        "StartLine": line,
        "EndLine": line,
        "Code": {
            "Lines": [
                {
                    "Number": line,
                    "Content": _masked(token),
                    "IsCause": True,
                    "Highlighted": _masked(token),
                }
            ]
        },
        "Match": _masked(token),
    }
    if layer is not None:
        record["Layer"] = layer
    return record


def _document(*, secrets: bool = True) -> dict:
    results: list[dict] = [
        {
            "Target": "probe:test (alpine 3.20.10)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-0001",
                    "PkgName": "musl",
                    "InstalledVersion": "1.2.5-r1",
                    "Severity": "HIGH",
                    "Title": "musl: a flaw",
                    "Layer": {"Digest": "sha256:aa", "DiffID": "sha256:bb"},
                }
            ],
        }
    ]
    if secrets:
        layer = {"Digest": "sha256:cc", "DiffID": "sha256:dd", "CreatedBy": RUN_LINE}
        results.append(
            {
                "Target": "/app/.env",
                "Class": "secret",
                "Secrets": [_secret("github-pat", 1, RUN_TOKEN, layer)],
            }
        )
        # trivy also reads the image config as a file: a secret found there
        # has no layer.
        results.append(
            {
                "Target": "probe:test",
                "Class": "secret",
                "Secrets": [_secret("github-pat", 18, ENV_TOKEN, None)],
            }
        )
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "probe:test",
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "alpine", "Name": "3.20.10"},
            "ImageID": "sha256:ee",
            "ImageConfig": {
                "history": [
                    {"created_by": "ADD alpine-minirootfs.tar.gz / # buildkit"},
                    {
                        "created_by": f"ENV GITHUB_TOKEN={ENV_TOKEN}",
                        "empty_layer": True,
                    },
                    {"created_by": RUN_LINE},
                ],
                "config": {"Env": ["PATH=/usr/bin", f"GITHUB_TOKEN={ENV_TOKEN}"]},
            },
        },
        "Results": results,
    }


def _output(folder: Path, document: dict) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    out = folder / "trivy.json"
    out.write_bytes(json.dumps(document, indent=2).encode())
    return out


def _leaks(text: str) -> list[str]:
    return [t for t in TOKENS if t in text]


def _findings(out: Path) -> list[dict]:
    return [f.to_dict() for f in TrivyAdapter().parse(out)]


def test_the_fixture_holds_both_tokens_before_a_report(tmp_path: Path) -> None:
    """Without this, a fixture that lost its tokens would pass every test."""
    out = _output(tmp_path, _document())
    assert _leaks(out.read_bytes().decode()) == list(TOKENS)


def test_no_finding_carries_a_token(tmp_path: Path) -> None:
    findings = _findings(_output(tmp_path, _document()))

    assert sorted(f["ruleId"] for f in findings) == [
        "CVE-2026-0001",
        "github-pat",
        "github-pat",
    ]
    assert _leaks(json.dumps(findings)) == []
    layered = next(f for f in findings if f["location"]["path"] == "/app/.env")
    assert layered["raw"]["Layer"] == {"Digest": "sha256:cc", "DiffID": "sha256:dd"}


def test_the_reports_rewrite_keeps_every_id_and_leaves_no_token(
    tmp_path: Path,
) -> None:
    out = _output(tmp_path, _document())
    before = sorted(f["id"] for f in _findings(out))

    assert redact_secret_outputs([out]) == 2  # one CreatedBy, the ImageConfig

    assert sorted(f["id"] for f in _findings(out)) == before
    rewritten = json.loads(out.read_bytes())
    assert _leaks(json.dumps(rewritten)) == []
    assert rewritten["Metadata"]["OS"] == {"Family": "alpine", "Name": "3.20.10"}


def test_a_second_rewrite_changes_nothing(tmp_path: Path) -> None:
    out = _output(tmp_path, _document())
    redact_secret_outputs([out])
    first = out.read_bytes()

    assert redact_secret_outputs([out]) == 0
    assert out.read_bytes() == first


def test_an_output_with_no_secret_result_keeps_its_image_metadata(
    tmp_path: Path,
) -> None:
    """Only what trivy found is taken out. A value trivy did not report as a
    secret stays in the metadata, as it stays in the image."""
    document = _document(secrets=False)
    out = _output(tmp_path, document)
    original = out.read_bytes()

    assert redact_image_metadata(json.loads(original)) == 0
    assert redact_secret_outputs([out]) == 0
    assert out.read_bytes() == original


def test_the_report_leaves_no_token_in_findings_or_the_output(tmp_path: Path) -> None:
    """Through `gather_results`, which reads the image folder and then runs the
    raw-output redaction over it, as `jmo report` does."""
    folder = tmp_path / "individual-images" / "probe_test"
    out = _output(folder, _document())

    findings = gather_results(tmp_path)

    assert len(findings) == 3
    assert _leaks(json.dumps(findings, default=str)) == []
    assert _leaks(out.read_bytes().decode()) == []
