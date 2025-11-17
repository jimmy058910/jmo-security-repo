# Dashboard screenshots & capture

This folder documents how to generate the HTML dashboard and capture screenshots or GIFs for the README and changelog.

## What you'll produce

Saved under `docs/screenshots/` by default:

- dashboard.png — static capture of the dashboard
- (optional) repo-comparison.gif — a short animated recording

## Prereqs

- Python 3.8+ (your system has Python 3.8.10)
- A Chromium-based browser for headless capture:
  - Linux: `chromium` or `google-chrome` on PATH
  - macOS: `google-chrome`
- For GIF recording (optional): `peek` (Linux) or QuickTime (macOS)

Tip: Use `make verify-env` to see detected tools and install hints.

## One-command demo (recommended)

Generates demo results from the bundled fixture, renders the dashboard, and captures a PNG:

```bash
make screenshots-demo
```

Outputs:

- Results under `/tmp/jmo-infra-demo-results/summaries/`
- Screenshot saved to `docs/screenshots/dashboard.png`

Notes:

- Works even if some external scanners aren't installed (uses stub outputs where needed).
- Re-run anytime to refresh the screenshot after UI changes.

## Capture from your own results

If you already have a results directory (with `summaries/dashboard.html`):

```bash
make capture-screenshot RESULTS_DIR=/path/to/results
```

Optional variables:

- `OUT=/custom/summaries` — where to write the HTML summary (defaults to `RESULTS_DIR/summaries`)
- `OUTDIR=/custom/screenshots` — where to save PNGs (defaults to `docs/screenshots`)
- `CONFIG=jmo.yml` — custom config if needed

Behind the scenes, the target runs:

1) `python3 scripts/cli/jmo.py report ...` to ensure `dashboard.html` exists

2) `docs/screenshots/capture.sh` to run `chromium --headless --screenshot`

## Manual quick capture (interactive)

1) Render the dashboard from existing results:

```bash
python3 scripts/cli/jmo.py report /path/to/results --profile
xdg-open /path/to/results/summaries/dashboard.html  # mac: open
```

1) Use a screen capture tool while interacting with the dashboard:

- Linux: `peek`, `vokoscreenNG`, or `kazam`
- macOS: QuickTime screen recording

1) Save outputs into `docs/screenshots/` (filenames are suggestions):

- dashboard-overview.png
- severity-breakdown.png
- repo-comparison.gif

## Headless capture (script)

The helper script prefers `chromium`, falling back to `google-chrome`:

```bash
bash docs/screenshots/capture.sh results/summaries/dashboard.html docs/screenshots
```

Equivalent raw command:

```bash
chromium --headless --disable-gpu --screenshot=docs/screenshots/dashboard.png file:///$(pwd)/results/summaries/dashboard.html
```

Note: headless capture is static; animated GIFs require a live screen recorder.

## Troubleshooting

- "No chromium/google-chrome found": install one of them and ensure the binary is on PATH. On Debian/Ubuntu: `sudo apt-get install chromium-browser` (or `chromium`), or install Chrome.
- Blank screenshot: ensure the path is correct and prefixed with `file://` (the helper script handles this). Also verify `dashboard.html` exists.
- Missing results: run the demo once with `make screenshots-demo` or generate your own with `python3 scripts/cli/jmo.py scan ...` followed by `report`.

## Commit hygiene

- Do not commit `/tmp/...` demo artifacts.
- Committing `docs/screenshots/dashboard.png` is fine when updating the README visuals; keep it reasonably fresh with UI changes.
