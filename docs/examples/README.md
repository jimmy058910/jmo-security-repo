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
    tools: [gitleaks, noseyparker, trufflehog, semgrep, syft, trivy, checkov, tfsec, hadolint, bandit, osv-scanner]
```

## 5) Timings and threads

```bash
python3 scripts/cli/jmo.py report ./results --profile --threads 6
cat results/summaries/timings.json
```

## 6) Discover AI-generated repos (ai-search)

Use the enhanced helper to search GitHub for repos that self-identify as AI-generated or reference LLM tooling.

Basic (TSV to stdout):

```bash
./ai-search/find-ai-generated-repos.sh
```

Write multiple formats to samples/:

```bash
./ai-search/find-ai-generated-repos.sh \
  --limit 100 --months 6 --stars-max 50 \
  --formats tsv,csv,jsonl,md --outdir ai-search
```

Language filters and custom queries:

```bash
./ai-search/find-ai-generated-repos.sh \
  --include-langs python,typescript --exclude-langs html \
  --query-file ai-search/queries.txt --limit 200 --rpm 20
```

Outputs include TSV, CSV, JSONL and an optional Markdown preview under `ai-search/` (when using `--outdir ai-search`).
Environment variables can override flags, for example: `FORMATS=jsonl RPM=15 ./ai-search/find-ai-generated-repos.sh`.
