# Monorepo Examples (JMo Security)

> Status: draft for PR #<your-issue>; branch: feat/monorepo-examples

## Scope

Real-world monorepos with multiple apps and shared packages. Show both CLI styles:

- \--repos-dir\ (root of many repos)
- \--targets\ (explicit repo list)

## Profiles

- **fast** – quick sanity signals
- **balanced** – default, CI-friendly
- **deep** – full sweep for pre-release checks

## Examples

### Using --repos-dir

```bash
jmo-sec wizard verify --repos-dir /path/to/monorepos --profile balanced
jmo-sec wizard verify --targets app-a,app-b,packages/shared --profile fast
