# Examples

This folder contains practical examples for running JMo Security in different modes.

## 1) Quick single-repo scan

```bash
python3 scripts/cli/jmo.py scan --repo /path/to/repo --tools trufflehog semgrep --timeout 300 --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

## 2) Multi-repo, full tool matrix

```bash
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

## 3) CI gate (scan + report + threshold)

```bash
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --tools trufflehog semgrep trivy --fail-on HIGH --profile --human-logs
```

## 4) Per-tool overrides via jmo.yml

```yaml
tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint]
per_tool:
  semgrep:
    flags: ["--exclude", "node_modules", "--exclude", ".git"]
  trivy:
    flags: ["--no-progress"]
```

Leave `tools:` out to consider the whole tool matrix; the target's content decides which of them run.

## 5) Timings and threads

```bash
python3 scripts/cli/jmo.py report ./results --profile --threads 6
cat results/summaries/timings.json
```

<!-- Removed ai-search private examples to keep public docs neutral. -->

## 6) Worked example: scanning a single Python package

Step-by-step walkthrough — install tools, scan, report, and open the dashboard.
See [Worked example: scanning a single Python package](../USER_GUIDE.md#worked-example-scanning-a-single-python-package) in the User Guide.
