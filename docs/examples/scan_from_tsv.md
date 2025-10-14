## Scan a list of repositories from a TSV

This guide shows how to clone a set of repositories listed in a TSV file, ensure they are unshallowed, and run the full JMO security scan with all tools, including a Nosey Parker Docker fallback.

Works on Linux/macOS with Git, Python 3.9+, and optional container runtime for Nosey Parker fallback.

### What you'll get

- Local clones under `repos-tsv/owner/repo`
- A `results/targets.tsv.txt` file listing absolute repo paths
- Raw tool outputs under `results/individual-repos/<repo>/`
- Summaries under `results/summaries/` (JSON, Markdown, HTML dashboard, YAML, SARIF depending on `jmo.yml`)

### 1) Install dependencies

Optional but recommended to install dev tools and Python deps:

```bash
make dev-deps
```

Install external scanners as needed (Semgrep, Trivy, Checkov, tfsec, Bandit, Syft, TruffleHog, Gitleaks, Hadolint, Nosey Parker). You can use:

```bash
# See what's installed/missing and how to install
make verify-env
```

Tip: You can still proceed with `--allow-missing-tools` to create stubs for missing tools.

### 2) Clone from TSV and build targets

Use the helper script to clone repos, unshallow them, and produce a targets file:

```bash
python3 scripts/cli/clone_from_tsv.py --tsv ./repos.tsv --dest repos-tsv --targets-out results/targets.tsv.txt --human-logs
```

TSV format note:

- The file must include either a column named `url` (preferred) or `full_name`.
- If `url` is missing, `full_name` should be of the form `owner/repo` and will be converted to `https://github.com/owner/repo.git`.

Minimal examples (tab-separated header and rows):

```text
# Using url
url
https://github.com/example/project-a.git
https://github.com/example/project-b

# Using full_name
full_name
example/project-a
example/project-b
```

This will:

- Clone missing repos into `repos-tsv/owner/repo`
- Update existing clones, fetch tags, and unshallow shallow clones
- Write absolute paths to `results/targets.tsv.txt`

### 3) Run the full scan with all tools

Pick the profile that covers all tools. The repository ships with `deep` including: gitleaks, noseyparker, trufflehog, semgrep, syft, trivy, checkov, tfsec, hadolint, bandit.

Run a CI-like end-to-end flow (scan + report) with human-readable logs:

```bash
python3 scripts/cli/jmo.py ci \
  --targets results/targets.tsv.txt \
  --results-dir results \
  --profile-name deep \
  --threads 4 \
  --timeout 900 \
  --allow-missing-tools \
  --human-logs
```

Notes:

- Nosey Parker uses the local binary if installed; otherwise it will attempt a Docker fallback via `scripts/core/run_noseyparker_docker.sh`. Ensure Docker is available for fallback.
- Increase `--threads` if your machine has more cores.
- If you want the command to fail on HIGH/CRITICAL findings, add `--fail-on HIGH`.

### 4) Review the results

Outputs will be written to:

- Per-repo raw results: `results/individual-repos/<repo>/*.json`
- Aggregated summaries: `results/summaries/`
  - `findings.json` – full, normalized findings list
  - `SUMMARY.md` – human-readable summary
  - `dashboard.html` – interactive HTML dashboard
  - `findings.yaml` – YAML (if PyYAML is installed)
  - `findings.sarif` – SARIF for code scanning integrations

Open the HTML dashboard in a browser to explore:

```bash
xdg-open results/summaries/dashboard.html 2>/dev/null || open results/summaries/dashboard.html
```

### Advanced tips

- Customize per-tool flags via `jmo.yml` under `profiles.deep.per_tool` (e.g., add `--no-progress` to Trivy or excludes to Semgrep).
- To rerun only reporting (faster iteration):

  ```bash
  python3 scripts/cli/jmo.py report --results-dir results --profile --human-logs
  ```

- Suppress known findings using a `jmo.suppress.yml` in the results directory; a `SUPPRESSIONS.md` will be created.

### Troubleshooting

- Tool not found: run `make verify-env` for install hints or add `--allow-missing-tools` to create stubs and continue.
- Nosey Parker fails locally: the CLI will try Docker automatically if available; ensure Docker daemon is running.
- Slow scans: reduce `--threads`, set a lower `--timeout`, or use the `balanced` profile.
