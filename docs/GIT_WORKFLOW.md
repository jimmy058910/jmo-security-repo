# Git Workflow Guide

**Branching Strategy:** Git Flow with `dev` + feature branches

**Current Development:** v1.0.0 (8 major features)

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Branch Structure](#branch-structure)
3. [Daily Workflow](#daily-workflow)
4. [Feature Development](#feature-development)
5. [Release Process](#release-process)
6. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Starting a New Feature

```bash
# Always start from latest dev
git checkout dev
git pull origin dev
git checkout -b feature/your-feature-name dev

# Make changes, commit, push
git add .
git commit -m "feat: your feature description"
git push origin feature/your-feature-name
```

### Merging Feature to Dev

```bash
# When feature is complete and tests pass
make test && make lint

# Merge to dev
git checkout dev
git pull origin dev
git merge feature/your-feature-name
git push origin dev
```

---

## Branch Structure

```
main ← stable releases only (v0.8.0, v0.9.0, v1.0.0)
  └── dev ← active development (v1.0.0 work in progress)
        ├── feature/tools-1.0.0
        ├── feature/ai-remediation
        ├── feature/diff-reports
        └── ... (other features)
```

**Branch Purposes:**

- **`main`** — Stable releases only, tagged with version numbers
- **`dev`** — Active development, integration point for all features
- **`feature/*`** — Individual features, one per major change
- **`hotfix/*`** — Critical bug fixes for released versions

---

## Daily Workflow

### Check Current Status

```bash
# Where am I?
git branch --show-current

# What changed?
git status --short

# Recent commits
git log --oneline -5
```

### Make Changes

```bash
# Edit files
vim scripts/core/adapters/prowler_adapter.py

# Stage changes
git add scripts/core/adapters/prowler_adapter.py
# Or stage all:
git add .

# Commit with conventional commit format
git commit -m "feat(tools): add Prowler CSPM adapter"
```

### Conventional Commit Prefixes

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Push to Backup Work

```bash
# Push feature branch to GitHub
git push origin feature/your-feature-name
```

---

## Feature Development

### Creating a Feature Branch

```bash
# Always branch from dev
git checkout dev
git pull origin dev
git checkout -b feature/your-feature-name dev
```

### Working on Multiple Features

```bash
# Start Feature #1
git checkout -b feature/tools-1.0.0 dev
# ... work ...
git commit -m "feat: add tools"

# Switch to Feature #2 (pause #1)
git checkout dev
git checkout -b feature/ai-remediation dev
# ... work ...
git commit -m "feat: add AI MCP"

# Return to Feature #1
git checkout feature/tools-1.0.0
# ... continue work ...
```

### Merging Feature

```bash
# Ensure tests pass
pytest tests/ -v
make lint
make test

# Update dev
git checkout dev
git pull origin dev

# Merge feature
git merge feature/your-feature-name

# Push merged dev
git push origin dev

# Optional: Delete feature branch
git branch -d feature/your-feature-name
```

---

## Release Process

### Releasing a Version

```bash
# After all features complete on dev
git checkout main
git pull origin main
git merge dev

# Tag release
git tag v1.0.0

# Push to trigger CI/CD
git push origin main --tags

# CI automatically publishes to PyPI + Docker Hub
```

### Hotfix for Released Version

```bash
# Create hotfix from main
git checkout main
git checkout -b hotfix/v0.9.1

# Fix bug
vim scripts/cli/schedule_commands.py
git add . && git commit -m "fix(schedule): handle missing directory"

# Test thoroughly
make test

# Merge to main and tag
git checkout main
git merge hotfix/v0.9.1
git tag v0.9.1
git push origin main --tags

# Merge back to dev
git checkout dev
git merge hotfix/v0.9.1
git push origin dev
```

---

## Troubleshooting

### Merge Conflicts

```bash
# During merge, conflicts appear
git merge feature/your-feature

# Manually resolve conflicts
vim conflicted-file.py  # Fix <<< === >>> markers

# Stage resolved files
git add conflicted-file.py

# Complete merge
git commit -m "merge: resolve conflicts"
```

### Accidentally Committed to Wrong Branch

```bash
# Move last commit to new branch
git checkout -b feature/accidental-work

# Reset original branch
git checkout dev
git reset --hard HEAD~1

# Work is now on feature/accidental-work
```

### Feature Branch Behind Dev

```bash
# Update feature branch with latest dev
git checkout feature/your-feature
git merge dev

# Or rebase (cleaner history, but rewrites commits)
git rebase dev
```

### Stash Changes Temporarily

```bash
# Save work without committing
git stash

# Switch branches
git checkout other-branch

# Return and restore work
git checkout original-branch
git stash pop
```

### Undo Last Commit (Keep Changes)

```bash
git reset --soft HEAD~1
```

### Discard All Local Changes (DANGER)

```bash
git reset --hard HEAD
```

---

## Additional Resources

- **v1.0.0 Roadmap:** [dev-only/VERSION_ROADMAP_1.0.0.md](../dev-only/VERSION_ROADMAP_1.0.0.md) (gitignored)
- **Tools Planning:** [dev-only/TOOLS-1.0.0.md](../dev-only/TOOLS-1.0.0.md) (gitignored)
- **Contributing Guide:** [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Release Process:** [docs/RELEASE.md](RELEASE.md)

---

**Questions?** Open a GitHub issue or ask in discussions.

**Last Updated:** 2025-11-01
