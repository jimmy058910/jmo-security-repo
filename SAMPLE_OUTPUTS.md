# Sample Output Examples

Updated October 2025 using the curated `samples/fixtures/infra-demo` target.

## Aggregated Summary (`summaries/SUMMARY.md`)

Running

```bash
PYTHONPATH=. python3 scripts/cli/jmo.py scan --repo samples/fixtures/infra-demo --results /tmp/jmo-infra-demo-results
PYTHONPATH=. python3 scripts/cli/jmo.py report /tmp/jmo-infra-demo-results
```

generates `SUMMARY.md` under `/tmp/jmo-infra-demo-results/summaries` with the latest numbers:

```markdown
# Security Summary

Total findings: 68

## By Severity
- CRITICAL: 3
- HIGH: 38
- MEDIUM: 9
- LOW: 16
- INFO: 2

## Top Rules
- generic-api-key: 32
- DL3007: 1
- DL3008: 1
- DL3015: 1
- DL3009: 1
```

The aggregate JSON/YAML/SARIF files in the same directory mirror these counts for automated pipelines.

## Individual Tool Outputs (`individual-repos/infra-demo/*.json`)

| Tool        | Findings | Notes |
|-------------|----------|-------|
| trivy       | 26       | 4 Dockerfile + 19 Kubernetes + 3 Terraform misconfigurations; CRITICAL `aws-vpc-no-public-egress-sgr` plus HIGH `AVD-AWS-0107` confirm the Terraform security group is wide open. |
| checkov     | 7        | 7 Terraform findings covering unrestricted ingress/egress; no false positives observed. |
| tfsec       | 3        | 3 Terraform findings, including two CRITICAL rules overlapping with Trivy; demonstrates cross-tool agreement. |
| hadolint    | 4        | DL3007/DL3008/DL3009/DL3015 flag lack of pinned distro, package pinning, and missing non-root user in the Dockerfile. |
| semgrep     | 3        | 3 results (Dockerfile USER, Kubernetes `runAsNonRoot`, `allowPrivilegeEscalation`); all intentional. |
| noseyparker | 0        | 0 matches against the fixture; confirms our sample does not carry additional plaintext secrets. |
| syft        | 0        | 0 SBOM artifacts for this minimal fixture; expected because no build artifacts are present. |
| trufflehog  | 0        | Produced no findings (and therefore an empty JSON file) when run separately with `--tools trufflehog`; see REVIEW.md for guidance on interpreting the output stream. |

## HTML Dashboard (`summaries/dashboard.html`)

The dashboard renders the same 68 finding counts with severity cards and per-tool tables. Use `xdg-open /tmp/jmo-infra-demo-results/summaries/dashboard.html` to view interactively after running the commands above.

## Quick Reference for Report Consumers

- Copy `/tmp/jmo-infra-demo-results/summaries/findings.json` when you need machine-readable output for deduplicated findings.
- Use `findings.sarif` for GitHub code scanning uploads.
- `timings.json` is emitted when `--profile` is passed to `report` and includes worker counts plus per-stage timings.
- `SUPPRESSIONS.md` appears whenever `jmo.suppress.yml` filters findings; not present in the default walkthrough.

Keeping the commands and this table synchronized with the fixtures is part of the REVIEW checklist. Re-run the scan/report pair whenever fixtures change so these samples stay accurate.
