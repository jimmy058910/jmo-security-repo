# Monorepo Examples

Scanning a monorepo — one repository containing multiple applications and shared
packages — with JMo Security. This guide shows the two multi-target entry points
(`--repos-dir` and `--targets`) and how to pair them with scan profiles.

> Resolves [#83](https://github.com/jimmy058910/jmo-security-repo/issues/83).
> For single-package scans see the [User Guide](../USER_GUIDE.md); for the full
> tool/profile matrix see [PROFILES_AND_TOOLS.md](../PROFILES_AND_TOOLS.md).

## Profiles at a glance

| Profile | Tools | Time | Typical monorepo use |
|---------|-------|------|----------------------|
| `fast` | 9 | 5-10 min | Pre-commit / PR validation across changed apps |
| `slim` | 13 | 12-18 min | Cloud / IaC-heavy monorepos (AWS/Azure/GCP/K8s) |
| `balanced` | 17 | 18-25 min | CI/CD gate covering all apps |
| `deep` | 28 | 40-70 min | Pre-release / compliance review of the whole repo |

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

# Fast pass over every immediate subfolder (app-api, app-web, packages) —
# good for a quick pre-push check.
jmo scan --repos-dir ~/work/acme-monorepo --profile fast

# Balanced pass for a CI gate covering all apps.
jmo scan --repos-dir ~/work/acme-monorepo --profile balanced
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

# Deep scan of just those three targets — typical before a release.
jmo scan --targets monorepo-targets.txt --profile deep
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

- **Start `fast`, escalate as needed.** Run `fast` locally for the pre-push loop;
  reserve `deep` for release gates — a 28-tool deep pass over a large monorepo
  can take well over an hour.
- **Exclude apps you don't want scanned.** Each profile in `jmo.yml` takes an
  `exclude:` list of glob patterns matched against target names, e.g.:

  ```yaml
  profiles:
    fast:
      include: ["*"]
      exclude: ["legacy-app*", "vendored-*"]
  ```

- **Content-triggered tools.** Some tools run only against targets whose contents
  match — `prowler` on `*.tf`/CloudFormation, `zap` on HTML/JS, `trivy-rbac` on
  K8s manifests (see [PROFILES_AND_TOOLS.md](../PROFILES_AND_TOOLS.md#content-triggered-tool-execution)).
  A polyglot monorepo automatically gets the relevant scanners per subfolder.
