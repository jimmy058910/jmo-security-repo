# Real scanner output for the equivalence table

`tests/unit/test_rule_equivalence_table.py` clusters these outputs the way a
report does, to show which trivy, hadolint and checkov findings merge (#1354).
Each JSON file is a tool's own output on the input beside it, captured
2026-11-04 with trivy 0.74.0, hadolint 2.15.1 and checkov 3.3.29, using the
arguments JMo's descriptors pass:

```bash
trivy fs -q -f json --scanners vuln,misconfig --include-dev-deps --offline-scan . -o Dockerfile.trivy.json
hadolint -f json Dockerfile > Dockerfile.hadolint.json
trivy config -q -f json pod.yaml -o pod.trivy.json
checkov -f pod.yaml -o json > pod.checkov.json
```

The Dockerfile scan ran in a directory holding only `Dockerfile`.
`pod.checkov.json` has two edits: its `passed_checks` list is emptied (67
entries the adapter never reads), and the capture directory in each
`file_abs_path` reads `/work`.

`pod.yaml` fires all eleven Kubernetes pairs the table holds: `hostPID`,
`hostNetwork` and `privileged` fire three that a plain Pod does not.
