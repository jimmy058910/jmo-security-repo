# Monorepo Examples

Scanning a monorepo — one repository containing multiple applications and shared
packages — with JMo Security. This guide shows the two multi-target entry points
(`--repos-dir` and `--targets`) and how to narrow the tool list with `--tools`.

> Resolves [#83](https://github.com/jimmy058910/jmo-security-repo/issues/83).
> For single-package scans see the [User Guide](../USER_GUIDE.md); for the full
> tool matrix see [TOOLS.md](../TOOLS.md).

## Approach 1 — `--repos-dir` (scan every subfolder)

`--repos-dir` points at a directory whose **immediate subfolders** are each
treated as a separate repo to scan. This is the simplest option when your
monorepo's apps live side by side under one parent.

```bash
# Layout:
#   ~/work/acme-monorepo/
#   ├── app-api/
#   ├── app-web/
#   └── packages/shared/

# Quick pass over every immediate subfolder (app-api, app-web, packages) —
# good for a pre-push check.
jmo scan --repos-dir ~/work/acme-monorepo --tools trufflehog semgrep trivy

# Full pass for a CI gate covering all apps: every applicable tool runs.
jmo scan --repos-dir ~/work/acme-monorepo
```

> Note: `--repos-dir` enumerates only the *immediate* children of the directory.
> Nested packages (e.g. `packages/shared`) are scanned as part of their parent
> subfolder, not as standalone targets. Use `--targets` below for finer control.

## Approach 2 — `--targets` (explicit path list)

`--targets` takes a **file listing repo paths, one per line**. Use this when you
want to scan a specific subset of a monorepo, or reach nested packages directly.

```bash
# Create a targets file (one absolute or relative path per line):
cat > monorepo-targets.txt <<'EOF'
~/work/acme-monorepo/app-api
~/work/acme-monorepo/app-web
~/work/acme-monorepo/packages/shared
EOF

# Full scan of just those three targets — typical before a release.
jmo scan --targets monorepo-targets.txt
```

Lines are plain paths; there is no inline comma-separated form — each target
goes on its own line.

## Reporting across the monorepo

Both approaches write per-target results under `results/`. Generate a single
consolidated report (with cross-tool dedup) once the scan finishes:

```bash
jmo report ./results
```

Open the generated `results/dashboard.html` to browse findings grouped by target.

## Tips

- **Start narrow, widen as needed.** Run a `--tools` subset locally for the
  pre-push loop; reserve the full matrix for CI and release gates — a full pass
  over a large monorepo can take well over an hour.
- **Exclude apps you don't want scanned.** `jmo.yml` takes a top-level
  `exclude:` list of glob patterns matched against target names, e.g.:

  ```yaml
  include: ["*"]
  exclude: ["legacy-app*", "vendored-*"]
  ```

- **Content-triggered tools.** Some tools run only against targets whose contents
  match — `hadolint` on Dockerfiles, `shellcheck` on shell scripts, `gosec` on Go
  sources (see [TOOLS.md](../TOOLS.md#when-each-tool-runs)).
  A polyglot monorepo automatically gets the relevant scanners per subfolder.
