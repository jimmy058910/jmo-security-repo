# Package Manager Automation Setup

This guide walks through the **one-time setup** required to enable fully automated package manager releases for JMo Security.

## Overview

After setup, every version release (`git push --tags v0.9.0`) will automatically:

1. ✅ Publish to PyPI (Trusted Publishers OIDC - already configured)
2. ✅ Build and push Docker images to GHCR/ECR (OIDC - already configured)
3. **✅ Submit PR to homebrew-core** (NEW - requires setup below)
4. **✅ Submit PR to microsoft/winget-pkgs** (NEW - requires setup below)

---

## Prerequisites

Before proceeding, ensure you have:

- [x] **Repository Admin Access** - Needed to add secrets and configure workflows
- [x] **GitHub Account** - For forking Homebrew/Winget repositories
- [x] **PyPI Account** - Already configured via Trusted Publishers

---

## Homebrew Automation Setup

### Step 1: Create Personal Access Token (Classic)

The Homebrew bump action requires a PAT with repository access to fork and create PRs.

1. Go to **GitHub Settings** → **Developer settings** → **Personal access tokens** → [**Tokens (classic)**](https://github.com/settings/tokens)

2. Click **Generate new token (classic)**

3. Configure token:
   - **Note:** `JMo Security Homebrew Bump`
   - **Expiration:** 1 year (you'll need to rotate annually)
   - **Scopes:** Select:
     - ✅ `repo` (Full control of private repositories)
     - ✅ `workflow` (Update GitHub Action workflows)

4. Click **Generate token**

5. **Copy the token** (you won't be able to see it again)

### Step 2: Add Token to Repository Secrets

1. Go to **Repository Settings** → **Secrets and variables** → **Actions**

2. Click **New repository secret**

3. Add secret:
   - **Name:** `HOMEBREW_BUMP_TOKEN`
   - **Secret:** Paste the PAT from Step 1

4. Click **Add secret**

### Step 3: Test Homebrew Automation

Trigger the workflow manually to verify it works:

```bash
# From repository root
gh workflow run homebrew-bump-formula.yml -f version=0.9.0

# Monitor workflow
gh run watch
```

**Expected outcome:**

- Workflow verifies PyPI release exists
- Creates fork of `Homebrew/homebrew-core` (if not already forked)
- Updates `jmo-security.rb` formula with new version and SHA256
- Submits PR to `Homebrew/homebrew-core`

**PR Review Timeline:** 1-2 weeks (Homebrew maintainers review)

---

## WinGet Automation Setup

### Step 1: Fork microsoft/winget-pkgs

The WinGet releaser action requires a fork to submit PRs from.

1. Go to <https://github.com/microsoft/winget-pkgs>

2. Click **Fork** (top right)

3. Ensure fork is under **same account/organization** as this repository

   ```text
   ✅ CORRECT: jimmy058910/jmo-security-repo → jimmy058910/winget-pkgs
   ❌ WRONG:   jimmy058910/jmo-security-repo → other-account/winget-pkgs
   ```

### Step 2: Create Personal Access Token (Classic)

The WinGet releaser action requires a PAT with public repository access.

1. Go to **GitHub Settings** → **Developer settings** → **Personal access tokens** → [**Tokens (classic)**](https://github.com/settings/tokens)

2. Click **Generate new token (classic)**

3. Configure token:
   - **Note:** `JMo Security WinGet Releaser`
   - **Expiration:** 1 year (you'll need to rotate annually)
   - **Scopes:** Select:
     - ✅ `public_repo` (Access public repositories)

4. Click **Generate token**

5. **Copy the token** (you won't be able to see it again)

**NOTE:** Fine-grained PATs are **NOT supported** by the action. You **must** use a classic PAT.

### Step 3: Add Token to Repository Secrets

1. Go to **Repository Settings** → **Secrets and variables** → **Actions**

2. Click **New repository secret**

3. Add secret:
   - **Name:** `WINGET_RELEASER_TOKEN`
   - **Secret:** Paste the PAT from Step 2

4. Click **Add secret**

### Step 4: Create Initial WinGet Manifest (First Release Only)

For the **first release only**, manually create the initial manifest:

```bash
# Install Komac (WinGet manifest creator)
brew install russellbanks/tap/komac  # macOS/Linux
# OR
winget install russellbanks.Komac    # Windows

# Create initial manifest
komac new \
  --id jmo.jmo-security \
  --version 0.9.0 \
  --urls "https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe" \
  --submit

# Follow interactive prompts to fill in metadata
```

**Required metadata:**

- **Package Identifier:** `jmo.jmo-security`
- **Package Name:** `JMo Security`
- **Publisher:** `jmo`
- **Author:** `James Moceri`
- **License:** `MIT OR Apache-2.0`
- **Short Description:** `Unified security scanning suite with 12+ tools and plugin system`
- **Homepage:** `https://jmotools.com`
- **Documentation:** `https://docs.jmotools.com`
- **Repository:** `https://github.com/jimmy058910/jmo-security-repo`

After the initial manifest is merged, all future updates are automated.

### Step 5: Test WinGet Automation

Trigger the workflow manually to verify it works:

```bash
# From repository root
gh workflow run winget-releaser.yml

# Monitor workflow
gh run watch
```

**Expected outcome:**

- Workflow verifies GitHub Release with Windows installer exists
- Uses your fork of `microsoft/winget-pkgs` to submit PR
- Updates manifest with new version and installer SHA256
- Submits PR to `microsoft/winget-pkgs`

**PR Review Timeline:** 1-2 weeks (Microsoft maintainers review)

---

## Token Security Best Practices

### Rotate Tokens Annually

Both PATs expire after 1 year. Set a calendar reminder to rotate:

1. Generate new token with same scopes
2. Update repository secrets with new token
3. Delete old token from GitHub settings

### Audit Token Usage

Regularly review token usage:

```bash
# List all repository secrets (names only, not values)
gh secret list

# Check workflow runs for token issues
gh run list --workflow=homebrew-bump-formula.yml --limit=5
gh run list --workflow=winget-releaser.yml --limit=5
```

### Revoke Tokens Immediately if Compromised

If a token is leaked:

1. Go to **GitHub Settings** → **Developer settings** → **Personal access tokens**
2. Find the compromised token
3. Click **Delete**
4. Generate new token and update secret

---

## Troubleshooting

### Homebrew Workflow Fails: "Resource not accessible by integration"

**Cause:** `HOMEBREW_BUMP_TOKEN` not configured or lacks required scopes

**Fix:**

```bash
# Verify secret exists
gh secret list | grep HOMEBREW_BUMP_TOKEN

# Re-create token with correct scopes (repo + workflow)
# Update secret: Settings → Secrets → Actions → HOMEBREW_BUMP_TOKEN
```

### WinGet Workflow Fails: "Windows installer asset not found"

**Cause:** GitHub Release doesn't have `jmo-security-0.9.0-win64.exe` asset

**Fix:**

```bash
# Verify release has installer
gh release view v0.9.0

# If missing, build and upload installer manually
cd packaging/windows
python build_installer.py
gh release upload v0.9.0 ../../dist/jmo-security-0.9.0-win64.exe
```

### WinGet Workflow Fails: "Fork not found"

**Cause:** `microsoft/winget-pkgs` not forked under correct account

**Fix:**

1. Delete any existing fork under wrong account
2. Fork <https://github.com/microsoft/winget-pkgs> under repository owner account
3. Re-run workflow

### Homebrew PR Rejected: "Formula already up-to-date"

**Cause:** Version already exists in homebrew-core

**Fix:**

This is expected if:

- Version was already submitted manually
- Previous automated PR was merged

No action needed - this is not an error.

### WinGet PR Rejected: "Manifest validation failed"

**Cause:** Installer URL returns 404 or SHA256 mismatch

**Fix:**

```bash
# Verify installer is publicly accessible
curl -fsSL -I "https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe"

# Verify SHA256 matches
curl -fsSL "https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe" | shasum -a 256
```

---

## Monitoring Automation

### Check Workflow Status

```bash
# View recent workflow runs
gh run list --workflow=homebrew-bump-formula.yml --limit=10
gh run list --workflow=winget-releaser.yml --limit=10

# View specific run details
gh run view <run-id>

# Download logs for debugging
gh run download <run-id>
```

### Monitor Package Manager PRs

**Homebrew:**

- PR list: <https://github.com/Homebrew/homebrew-core/pulls?q=is%3Apr+jmo-security>
- Formula: <https://github.com/Homebrew/homebrew-core/blob/master/Formula/j/jmo-security.rb>

**WinGet:**

- PR list: <https://github.com/microsoft/winget-pkgs/pulls?q=is%3Apr+jmo-security>
- Manifest: <https://github.com/microsoft/winget-pkgs/tree/master/manifests/j/jmo/jmo-security>

### Verify Package Installation After Merge

Once PRs are merged, test installation:

```bash
# Homebrew (macOS/Linux)
brew update
brew install jmo-security
jmo --help

# WinGet (Windows)
winget upgrade --all  # Update package list
winget install jmo.jmo-security
jmo --help
```

---

## Manual Fallback Commands

If automation fails, use these manual commands:

### Homebrew Manual Submission

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Submit formula bump
brew bump-formula-pr --tag=v0.9.0 jmo-security
```

### WinGet Manual Submission

```bash
# Using Komac
komac update jmo.jmo-security --version 0.9.0 --submit

# Using WinGetCreate
wingetcreate update jmo.jmo-security \
  -v 0.9.0 \
  -u https://github.com/jimmy058910/jmo-security-repo/releases/download/v0.9.0/jmo-security-0.9.0-win64.exe \
  -t $WINGET_RELEASER_TOKEN
```

---

## Automation Success Metrics

After setup, every release should automatically:

| Step | Status | Timeline |
|------|--------|----------|
| PyPI Publish | ✅ Automated (OIDC) | 2-5 minutes |
| Docker Build | ✅ Automated (OIDC) | 10-15 minutes |
| Homebrew PR Submission | ✅ Automated (PAT) | 5 minutes |
| Homebrew PR Review | ⏳ Manual review | 1-2 weeks |
| WinGet PR Submission | ✅ Automated (PAT) | 5 minutes |
| WinGet PR Review | ⏳ Manual review | 1-2 weeks |

**Success indicators:**

- ✅ Release workflow completes without errors
- ✅ PRs created automatically in homebrew-core and winget-pkgs
- ✅ No manual intervention required after `git push --tags`

---

## Next Steps

After completing setup:

1. **Test automation** with next release (v0.9.0)
2. **Monitor PRs** in homebrew-core and winget-pkgs
3. **Document any issues** for future improvements
4. **Set calendar reminders** for annual token rotation

**Questions or issues?** Open an issue at <https://github.com/jimmy058910/jmo-security-repo/issues>
