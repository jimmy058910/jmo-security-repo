# Examples

This folder contains practical examples for running JMo Security in different modes.

## 1) Quick single-repo scan

```bash
python3 scripts/cli/jmo.py scan --repo /path/to/repo --tools gitleaks semgrep --timeout 300 --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

## 2) Multi-repo, curated profile

```bash
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --profile-name balanced --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

## 3) CI gate (scan + report + threshold)

```bash
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --profile-name fast --fail-on HIGH --profile --human-logs
```

## 4) Per-tool overrides via jmo.yml

```yaml
profiles:
  balanced:
    tools: [gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint]
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
      trivy:
        flags: ["--no-progress"]
  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
```

## 5) Timings and threads

```bash
python3 scripts/cli/jmo.py report ./results --profile --threads 6
cat results/summaries/timings.json
```

<!-- Removed ai-search private examples to keep public docs neutral. -->
