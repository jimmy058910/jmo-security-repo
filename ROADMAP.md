# JMO Security Suite — Roadmap

Note: Steps 1–13 have been completed and are summarized in `CHANGELOG.md` under “Roadmap Summary (Steps 1–13)”. This roadmap now tracks only active/planned work.

Recently completed infra hardening (October 2025)
- CI: actionlint pinned, concurrency enabled, OS+Python matrix, job-level timeouts
- Coverage: tokenless uploads with Codecov v5
- Release: PyPI Trusted Publisher (OIDC) with `pypa/gh-action-pypi-publish@v1`
- DevEx: pre-commit consolidated, `.yamllint.yaml` added, additional adapter/reporter edge tests

## Step 14 — Interactive Wizard (Beginner Onboarding)

Objective
- Provide an interactive, end-to-end guided flow for beginners to complete a successful first run without knowing flags. The wizard complements `jmotools setup` (tools bootstrap) by handling choices about profile, targets, runtime options, and outputs, then executing the scan and opening results.

Why now
- We now have: profiles (fast/balanced/deep), TSV cloning, a robust `ci` path, and a beginner wrapper (`jmotools`). A wizard stitches these into a single guided experience and outputs a reusable one-liner/Make target/CI workflow to remove future friction.

Scope (User-facing)
- New command: `jmotools wizard` (interactive by default; supports non-interactive flags to pre-answer prompts).
- Runs on Linux/WSL/macOS TTY; degrades gracefully in non-interactive shells.

Feature Breakdown
1) Guided scan configuration
   - Profile selection with context:
     - fast: “2–5 min, secrets + SAST (gitleaks, semgrep).”
     - balanced: “6–15 min, broad coverage (gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint).”
     - full/deep: “10–30+ min, maximum coverage including trufflehog, tfsec, bandit, osv-scanner.”
   - Targets selection:
     - Single repo path
     - Repos directory (immediate subfolders)
     - Existing targets file
     - Clone from TSV (prompt for TSV path, dest, optional max)
   - Optional: “Unshallow repos?” for better secret scanning (applies only when clonable/updateable).

2) Smart defaults & recommendations
   - Detect CPU cores → recommend threads (min 2, max 8; default 4).
   - Recommend timeouts per profile (fast=300, balanced=600, deep=900) with explanation.
   - Offer `--fail-on` (default none; suggest HIGH for CI-like gating with a brief description of exit codes).

3) Tool bootstrap with context
   - Run the same checks as `jmotools setup`, but highlight tools required by the chosen profile.
   - Offer auto-install (Linux/WSL) or print commands; detect Docker for Nosey Parker fallback.
   - Offer to install PyYAML if user wants YAML output.

4) Preflight & preview
   - Show a concise summary: profile, targets, threads, timeout, fail-on, results dir.
   - Generate and display the exact non-interactive command (final `jmo ci` invocation) for copy/paste.
   - Optional: save a preset file (e.g., `.jmotools.preset.json`) for reuse.
   - Optional: generate a Make target or a shell script with the above command.
   - Optional: generate a minimal GitHub Actions workflow that mirrors the configuration.

5) Run & progress
   - Execute the scan/report; use `--human-logs` for readable progress.
   - Print ETA bands from heuristics (repos × profile baseline).
   - Handle cancel (SIGINT) gracefully, mirroring `jmo scan` behavior.

6) Results & follow-up
   - Open `dashboard.html` and `SUMMARY.md` (print paths if headless).
   - Print severity counts and final exit threshold status.
   - Offer to re-run report-only or view suppression guidance.

7) Quality-of-life extras
   - Remember last choices; offer “reuse last config.”
   - Non-interactive/CI mode: if no TTY or `--yes`, use recommended defaults; still print the final command.
   - Provide links to docs sections (config, suppressions, reporters).

CLI/UX Contract (Wizard)
- Command: `jmotools wizard [options]`
  - Interactive by default; prompts unless provided values short-circuit them.
- Non-interactive flags (optional):
  - `--profile {fast,balanced,deep}`
  - `--repo PATH | --repos-dir DIR | --targets FILE | --tsv FILE [--dest DIR] [--max N] [--unshallow]`
  - `--threads N` `--timeout SECONDS` `--fail-on SEVERITY`
  - `--results-dir DIR` `--no-open` `--allow-missing-tools` `--strict`
  - `--save-preset [FILE]` `--emit-make-target [NAME]` `--emit-script [FILE]` `--emit-gha [FILE]`
  - `--yes` (accept recommended defaults for all prompts)

Data & Dependencies
- Reuse:
  - Tool checks: `scripts/core/check_and_install_tools.sh`
  - TSV clone: `scripts/cli/clone_from_tsv.py`
  - Scan/Report: `scripts/cli/jmo.py ci`
- Read config defaults from `jmo.yml` and selected profile (threads, timeout, per_tool flags).
- No new heavy dependencies; prefer stdlib input/printing. If a prompt lib is added later, keep it optional.

Implementation Plan
- Phase 1 (MVP):
  - Add `jmotools wizard` command.
  - Prompts for profile + targets + threads/timeout + fail-on.
  - Run preflight summary; print final command; execute; open outputs; save last choices.
- Phase 2 (Convenience):
  - TSV clone prompts (tsv, dest, max) + unshallow option.
  - Profile-aware tool bootstrap suggestions (and auto-install hooks where supported).
  - Preset save/load; emit Make target or shell script.
- Phase 3 (Polish):
  - Emit GitHub Actions workflow.
  - ETA heuristics & better progress.
  - Rich suppression guidance linking to SUPPRESSIONS.md.

Edge Cases & Handling
- No repos found: warn and offer to pick a different target source or to clone from TSV.
- Missing tools: when `--allow-missing-tools` is selected (default for beginners), write stubs and continue; surface which tools were stubbed.
- Headless environment: skip opening files; always print output paths.
- Non-interactive shells: auto-switch to dry-run or use `--yes` defaults; exit with clear message if insufficient info.
- Permissions/network issues during clone: retry guidance and clear error messages.
- OS constraints: Windows not prioritized; Linux/WSL/macOS focus.

Acceptance Criteria
- Interactive flow completes a successful scan from at least three entry modes: repos-dir, single repo, TSV clone.
- Preflight prints an exact one-liner command that, when run, reproduces the wizarded run.
- Outputs are opened or paths printed; severity counts shown; threshold respected.
- Non-interactive usage supported (pass flags; wizard prompts are skipped).
- Documentation updated with a quick demo and examples.

Testing Strategy
- Unit tests for prompt parsing helpers, defaults selection, and command synthesis.
- Integration tests with a tiny repo fixture covering: fast/balanced/deep flows; TSV path; headless mode (`--no-open`).
- Snapshot tests of synthesized command and preflight summary.
- Smoke tests verifying `--yes` defaults execute without prompts in CI.

Risks & Mitigations
- Prompt UX dependency: keep to stdlib to avoid heavy deps; a nicer prompt lib could be optional.
- Time estimates may be noisy: position them as “rough bands.”
- Tool auto-install can vary by OS: keep optional and provide print-commands fallback.

Docs & Examples
- README: brief “Wizard” blurb with a gif + copy/paste command.
- QUICKSTART: wizard path in Step 3 alongside the CLI and wrapper.
- Examples page: TSV flow, preset save/load, emitting a Make target and GH Action.

Status
- Planned. Wrapper (`jmotools`) and setup flow are in place; wizard will be additive and reuse existing scripts.

---

## CI Linting — Full Pre-commit Coverage (Planned)

Context
- To keep PR feedback tight and CI reliable, the current lint job intentionally runs only structural checks (actionlint, yamllint). Auto-fixing and noisy hooks were skipped to avoid flakiness while we stabilized workflows.

Full Hook Set (from `.pre-commit-config.yaml`)
- pre-commit-hooks: trailing-whitespace, end-of-file-fixer, check-yaml, check-json, check-toml, mixed-line-ending, detect-private-key, check-added-large-files
- yamllint (config: `.yamllint.yaml`)
- actionlint (GitHub workflows)
- markdownlint
- ruff (lint) and ruff-format
- black
- bandit (config: `bandit.yaml`, limited to `scripts/`)
- shellcheck (errors only; excludes: SC2016, SC2028)
- shfmt

Plan to Re-enable in CI (staged)
1. Check-only mode for formatters
  - Switch ruff-format/black/shfmt to check-only in CI (no writes) and gate with clear messages.
  - Keep auto-fix local via pre-commit to reduce CI churn.
1. Markdown lint tuning
  - Add project-specific `.markdownlint.json` with rule relaxations for docs (line length, code blocks).
  - Enable markdownlint in CI after config lands.
1. Python lint policy
  - Pin ruff version; add minimal allowlist of rules to start (E, F) and gradually enable more.
  - Gate on ruff in CI once baseline passes; add rule-by-rule PRs to expand coverage.
1. Shell formatting
  - Configure shfmt style (indent, binary ops) and pin version; run in check-only in CI.
1. Security linting
  - Keep bandit limited to `scripts/` with explicit `-c bandit.yaml`; consider a weekly scheduled job for full repo scan in “info-only” mode.
1. Scheduling and PR signal
  - Add a nightly `lint-full` workflow running all hooks in check-only; PR CI remains fast/structural.
  - Post summary annotations; if stable for >2 weeks, migrate checks into PR CI gating.

Acceptance Criteria
- PR CI remains <5–7 min typical.
- Nightly `lint-full` is green on main for 2 weeks before gating PRs.
- Clear contributor docs on how to run auto-fixes locally with pre-commit.

Developer Guidance
- Local: run `pre-commit install` and `pre-commit run -a` before pushing.
- CI gating will error on check-only violations; fix locally (formatter applies changes) and re-push.

## Step 14 — Interactive Wizard (Beginner Onboarding)

Objective
- Provide an interactive, end-to-end guided flow for beginners to complete a successful first run without knowing flags. The wizard complements `jmotools setup` (tools bootstrap) by handling choices about profile, targets, runtime options, and outputs, then executing the scan and opening results.

Why now
- We now have: profiles (fast/balanced/deep), TSV cloning, a robust `ci` path, and a beginner wrapper (`jmotools`). A wizard stitches these into a single guided experience and outputs a reusable one-liner/Make target/CI workflow to remove future friction.

Scope (User-facing)
- New command: `jmotools wizard` (interactive by default; supports non-interactive flags to pre-answer prompts).
- Runs on Linux/WSL/macOS TTY; degrades gracefully in non-interactive shells.

Feature Breakdown
1) Guided scan configuration
   - Profile selection with context:
     - fast: “2–5 min, secrets + SAST (gitleaks, semgrep).”
     - balanced: “6–15 min, broad coverage (gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint).”
     - full/deep: “10–30+ min, maximum coverage including trufflehog, tfsec, bandit, osv-scanner.”
   - Targets selection:
     - Single repo path
     - Repos directory (immediate subfolders)
     - Existing targets file
     - Clone from TSV (prompt for TSV path, dest, optional max)
   - Optional: “Unshallow repos?” for better secret scanning (applies only when clonable/updateable).

2) Smart defaults & recommendations
   - Detect CPU cores → recommend threads (min 2, max 8; default 4).
   - Recommend timeouts per profile (fast=300, balanced=600, deep=900) with explanation.
   - Offer `--fail-on` (default none; suggest HIGH for CI-like gating with a brief description of exit codes).

3) Tool bootstrap with context
   - Run the same checks as `jmotools setup`, but highlight tools required by the chosen profile.
   - Offer auto-install (Linux/WSL) or print commands; detect Docker for Nosey Parker fallback.
   - Offer to install PyYAML if user wants YAML output.

4) Preflight & preview
   - Show a concise summary: profile, targets, threads, timeout, fail-on, results dir.
   - Generate and display the exact non-interactive command (final `jmo ci` invocation) for copy/paste.
   - Optional: save a preset file (e.g., `.jmotools.preset.json`) for reuse.
   - Optional: generate a Make target or a shell script with the above command.
   - Optional: generate a minimal GitHub Actions workflow that mirrors the configuration.

5) Run & progress
   - Execute the scan/report; use `--human-logs` for readable progress.
   - Print ETA bands from heuristics (repos × profile baseline).
   - Handle cancel (SIGINT) gracefully, mirroring `jmo scan` behavior.

6) Results & follow-up
   - Open `dashboard.html` and `SUMMARY.md` (print paths if headless).
   - Print severity counts and final exit threshold status.
   - Offer to re-run report-only or view suppression guidance.

7) Quality-of-life extras
   - Remember last choices; offer “reuse last config.”
   - Non-interactive/CI mode: if no TTY or `--yes`, use recommended defaults; still print the final command.
   - Provide links to docs sections (config, suppressions, reporters).

CLI/UX Contract (Wizard)
- Command: `jmotools wizard [options]`
  - Interactive by default; prompts unless provided values short-circuit them.
- Non-interactive flags (optional):
  - `--profile {fast,balanced,deep}`
  - `--repo PATH | --repos-dir DIR | --targets FILE | --tsv FILE [--dest DIR] [--max N] [--unshallow]`
  - `--threads N` `--timeout SECONDS` `--fail-on SEVERITY`
  - `--results-dir DIR` `--no-open` `--allow-missing-tools` `--strict`
  - `--save-preset [FILE]` `--emit-make-target [NAME]` `--emit-script [FILE]` `--emit-gha [FILE]`
  - `--yes` (accept recommended defaults for all prompts)

Data & Dependencies
- Reuse:
  - Tool checks: `scripts/core/check_and_install_tools.sh`
  - TSV clone: `scripts/cli/clone_from_tsv.py`
  - Scan/Report: `scripts/cli/jmo.py ci`
- Read config defaults from `jmo.yml` and selected profile (threads, timeout, per_tool flags).
- No new heavy dependencies; prefer stdlib input/printing. If a prompt lib is added later, keep it optional.

Implementation Plan
- Phase 1 (MVP):
  - Add `jmotools wizard` command.
  - Prompts for profile + targets + threads/timeout + fail-on.
  - Run preflight summary; print final command; execute; open outputs; save last choices.
- Phase 2 (Convenience):
  - TSV clone prompts (tsv, dest, max) + unshallow option.
  - Profile-aware tool bootstrap suggestions (and auto-install hooks where supported).
  - Preset save/load; emit Make target or shell script.
- Phase 3 (Polish):
  - Emit GitHub Actions workflow.
  - ETA heuristics & better progress.
  - Rich suppression guidance linking to SUPPRESSIONS.md.

Edge Cases & Handling
- No repos found: warn and offer to pick a different target source or to clone from TSV.
- Missing tools: when `--allow-missing-tools` is selected (default for beginners), write stubs and continue; surface which tools were stubbed.
- Headless environment: skip opening files; always print output paths.
- Non-interactive shells: auto-switch to dry-run or use `--yes` defaults; exit with clear message if insufficient info.
- Permissions/network issues during clone: retry guidance and clear error messages.
- OS constraints: Windows not prioritized; Linux/WSL/macOS focus.

Acceptance Criteria
- Interactive flow completes a successful scan from at least three entry modes: repos-dir, single repo, TSV clone.
- Preflight prints an exact one-liner command that, when run, reproduces the wizarded run.
- Outputs are opened or paths printed; severity counts shown; threshold respected.
- Non-interactive usage supported (pass flags; wizard prompts are skipped).
- Documentation updated with a quick demo and examples.

Testing Strategy
- Unit tests for prompt parsing helpers, defaults selection, and command synthesis.
- Integration tests with a tiny repo fixture covering: fast/balanced/deep flows; TSV path; headless mode (`--no-open`).
- Snapshot tests of synthesized command and preflight summary.
- Smoke tests verifying `--yes` defaults execute without prompts in CI.

Risks & Mitigations
- Prompt UX dependency: keep to stdlib to avoid heavy deps; a nicer prompt lib could be optional.
- Time estimates may be noisy: position them as “rough bands.”
- Tool auto-install can vary by OS: keep optional and provide print-commands fallback.

Docs & Examples
- README: brief “Wizard” blurb with a gif + copy/paste command.
- QUICKSTART: wizard path in Step 3 alongside the CLI and wrapper.
- Examples page: TSV flow, preset save/load, emitting a Make target and GH Action.

Status
- Planned. Wrapper (`jmotools`) and setup flow are in place; wizard will be additive and reuse existing scripts.
