# Scan from TSV Guide

## Scan a list of repositories from a TSV

This guide shows how to scan a set of repositories listed in a TSV file: `jmo scan --tsv`
(or `jmo ci --tsv`) clones each one, then scans the clones with all tools.

Works on Linux, macOS and Windows with Git and Python 3.12+.

### What you'll get

- Local clones under `<dest>/<owner>/<repo>`, kept between runs
- Raw tool outputs under `results/individual-repos/<repo>/`
- Summaries under `results/summaries/` (JSON, Markdown, HTML dashboard, YAML, SARIF depending on `jmo.yml`)

### 1) Install dependencies

Optional but recommended to install dev tools and Python deps:

```bash
make dev-deps
```

Install external scanners as needed (TruffleHog, Semgrep, Syft, Trivy, Checkov, Hadolint, ShellCheck, Gosec, YARA, Grype, ZAP, Nuclei):

```bash
# Check tool status and install missing tools
jmo tools check
jmo tools install
```

Tip: You can still proceed with `--allow-missing-tools` to create stubs for missing tools.

### 2) Write the TSV

The file must include either a column named `url` (preferred) or `full_name`. A
`full_name` of the form `owner/repo` becomes `https://github.com/owner/repo.git`.

Minimal examples (tab-separated header and rows):

```text
# Using url
url
https://github.com/example/project-a.git
git@github.com:example/project-b.git

# Using full_name
full_name
example/project-a
example/project-b
```

A `url` must start with `https://`, `ssh://` or `git@host:`. Anything else, including
`http://`, `file://` and local paths, is refused before git runs, and so is a URL whose
`<owner>/<repo>` would land outside `--dest`.

### 3) Clone and scan

`--dest` is required: it is where the clones go, and there is no safe default. The
current directory would put them inside whatever repository you run from, and the
results directory is what a CI job uploads and what gets deleted between runs.

Run a CI-like end-to-end flow (scan + report) with human-readable logs:

```bash
jmo ci \
  --tsv ./repos.tsv \
  --dest repos-tsv \
  --results-dir results \
  --threads 4 \
  --timeout 900 \
  --allow-missing-tools \
  --human-logs
```

This will:

- Clone each missing repository into `repos-tsv/<owner>/<repo>`
- Bring an existing clone of the same URL up to date: fetch, then fast-forward, so a
  second run scans current code
- Scan every clone and write the reports

Each row that cannot be used is named in the log with its reason, and the rest are
still scanned. If no row could be cloned, the command exits 1. A URL listed twice is
scanned once. Results are written per repository name
(`results/individual-repos/<repo>/`), so of two repositories with the same name
(`alice/app` and `bob/app`) the second is refused by name rather than overwriting the
first one's findings; scan it in a separate run with its own `--results-dir`.

Notes:

- Increase `--threads` if your machine has more cores.
- If you want the command to fail on HIGH/CRITICAL findings, add `--fail-on HIGH`.
- `jmo scan` takes the same `--tsv` and `--dest` when you want the scan phase alone.

### Private repositories

Clones use your own git credentials: a credential helper for `https://`, an ssh key for
`ssh://` and `git@host:`. Nothing asks during a scan: not git, not ssh and not a
credential-manager window. So a row that would need a password, a key's passphrase or
a new host key fails by name instead of holding up the scan. Before a run, load your
key into an agent (`ssh-add`) and trust each ssh host once, for example with
`ssh -T git@github.com`. ssh older than OpenSSH 8.4 (2020) cannot be kept from asking,
and may still prompt on your terminal.

### Docker

The container has no git credentials, so only public repositories clone. Mount the TSV
read-only and the clone destination as a directory the container can write, and create
the host directories first: Docker creates a missing one as root, and the image's user
cannot write to it.

```bash
mkdir -p repos-tsv results
docker run --rm \
  -v "$PWD/repos.tsv:/repos.tsv:ro" \
  -v "$PWD/repos-tsv:/repos-tsv" \
  -v "$PWD/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --tsv /repos.tsv --dest /repos-tsv --results-dir /results
```

`jmo wizard` builds this command for you in its tsv mode.

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

- Customize per-tool flags via the top-level `per_tool` key in `jmo.yml` (e.g., add `--no-progress` to Trivy or excludes to Semgrep).
- To rerun only reporting (faster iteration):

  ```bash
  jmo report --results-dir results --profile --human-logs
  ```

- Suppress known findings using a `jmo.suppress.yml` in the results directory; a `SUPPRESSIONS.md` will be created.

### Troubleshooting

- Tool not found: run `jmo tools check` to see status, then `jmo tools install` to install, or add `--allow-missing-tools` to create stubs and continue.
- Slow scans: reduce `--threads`, set a lower `--timeout`, or narrow the tool list with `--tools` (e.g. `--tools trufflehog semgrep trivy`).
- A row says `exists and is not a clone` or `is a clone of ..., not a clone of this row`:
  something else is at `<dest>/<owner>/<repo>`. jmo will not fetch into a directory it
  did not clone from that URL; move it, or choose another `--dest`.
