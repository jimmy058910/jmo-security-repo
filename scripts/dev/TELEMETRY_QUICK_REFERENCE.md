# Telemetry Quick Reference

**Status:** ✅ FULLY IMPLEMENTED (Opt-Out Model, v0.7.1+)

## For Users

### Default Behavior
- ✅ **Enabled by default** (opt-out model)
- ✅ **Auto-disabled in CI/CD** environments
- ✅ **Banner shown on first 3 scans/wizard runs**
- ✅ **100% anonymous** (random UUID, no PII, no repo names, no secrets)

### How to Opt-Out

**Method 1: Environment Variable (Recommended)**
```bash
export JMO_TELEMETRY_DISABLE=1
```

**Method 2: Edit jmo.yml**
```yaml
telemetry:
  enabled: false
```

**Method 3: Docker**
```bash
docker run -e JMO_TELEMETRY_DISABLE=1 ghcr.io/jimmy058910/jmo-security:latest ...
```

### What's Collected

✅ **Collected:**
- Tool usage (which scanners ran)
- Scan duration (bucketed: `<5min`, `5-15min`, `15-30min`, `>30min`)
- Execution mode (`cli`, `docker`, `wizard`)
- Platform (`Linux`, `macOS`, `Windows`)
- Python version (`3.10`, `3.11`, `3.12`)
- Profile name (`fast`, `balanced`, `deep`)
- Target type counts (repos: 3, images: 1, etc.)

❌ **NOT Collected:**
- Repository names, paths, or URLs
- Finding details, secrets, or vulnerabilities
- File names or directory structures
- IP addresses or network information
- User names, email addresses, or identifiers
- Configuration values, API tokens
- Error messages or stack traces

## For Maintainers

### View Telemetry Data

```bash
# View interactive dashboard
./scripts/dev/view_telemetry.sh

# View raw JSONL
./scripts/dev/view_telemetry.sh --raw

# Export to CSV
./scripts/dev/view_telemetry.sh --export
```

### Configuration

**Environment Variables:**
- `JMO_TELEMETRY_GIST_ID` - GitHub Gist ID (fc897ef9a7f7ed40d001410fa369a1e1)
- `JMO_TELEMETRY_GITHUB_TOKEN` - GitHub token for Gist API access
- `JMO_TELEMETRY_DISABLE` - Set to `1` to force disable

**Local Files:**
- `~/.jmo-security/telemetry-id` - Anonymous UUID (590e5e1b-8c0c-4394-9181-fda22906f3fb)
- `~/.jmo-security/scan-count` - Local scan count for frequency inference

### Implementation Details

**Opt-Out Logic:**
```python
def is_telemetry_enabled(config):
    # 1. Check environment variable override
    if os.environ.get("JMO_TELEMETRY_DISABLE") == "1":
        return False

    # 2. Auto-disable in CI/CD
    if detect_ci_environment():
        return False

    # 3. Check config (default: True = opt-out)
    if "enabled" in config.get("telemetry", {}):
        return config["telemetry"]["enabled"]
    else:
        return True  # Default: enabled (opt-out model)
```

**First-Run Banner:**
- Shows on first CLI scan only (`cmd_scan` in jmo.py)
- Shows on first wizard run only (`run_wizard` in wizard.py)
- Docker shows banner on every run (can't track persistent scan count)
- Users see "This notice shows once only" message

**CI Detection:**
- Checks for: `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILD_ID`, `CIRCLECI`, `TRAVIS`, `TF_BUILD`, `BITBUCKET_PIPELINE_UUID`
- Auto-disables telemetry when any detected

### Event Types

| Event | When Sent | Metadata |
|-------|-----------|----------|
| `scan.started` | User runs `jmo scan` or `jmotools {fast,balanced,full}` | Profile, tools, target counts, mode |
| `scan.completed` | Scan finishes | Duration bucket, success/failure counts, findings bucket |
| `tool.failed` | Tool times out or crashes | Tool name, failure type, exit code |
| `wizard.completed` | Wizard finishes | Profile selected, execution mode, artifact type |
| `report.generated` | User runs `jmo report` or `jmo ci` | Output formats, suppressions, compliance |

### Backend Architecture

**Current (v0.9.0):** GitHub Gist (MVP)
- Gist ID: `fc897ef9a7f7ed40d001410fa369a1e1`
- Format: JSONL (one JSON event per line)
- Access: Private, maintainer-only

**Future (v0.10.0+):** Cloudflare Workers + D1
- Endpoint: TBD
- Database: Cloudflare D1 (SQLite)
- Analytics: Real-time dashboard

### Testing

```bash
# Test opt-out model
python3 -c "
from scripts.core.telemetry import is_telemetry_enabled

# Should be True (opt-out = enabled by default)
print('Default:', is_telemetry_enabled({}))

# Should be False (explicit disable)
print('Disabled:', is_telemetry_enabled({'telemetry': {'enabled': False}}))

# Should be False (env var override)
import os
os.environ['JMO_TELEMETRY_DISABLE'] = '1'
print('Env override:', is_telemetry_enabled({}))
"

# Test banner display
python3 -c "
from scripts.core.telemetry import show_telemetry_banner
show_telemetry_banner(mode='cli')
"

# Test CI detection
CI=true python3 -c "
from scripts.core.telemetry import is_telemetry_enabled
print('CI auto-disable:', is_telemetry_enabled({}))  # Should be False
"
```

### Troubleshooting

**No events showing up:**
1. Check telemetry is enabled: `grep -A1 'telemetry:' jmo.yml`
2. Check environment: `env | grep JMO_TELEMETRY`
3. Check Gist access: `gh gist view fc897ef9a7f7ed40d001410fa369a1e1`
4. Check scan count is < 3: `cat ~/.jmo-security/scan-count`

**Events not sending:**
1. Verify Gist ID and token are set
2. Check network connectivity
3. Check GitHub API status
4. Review background thread logs (silent failures)

### Privacy & Compliance

- ✅ **GDPR compliant** - Anonymous UUIDs not considered personal data
- ✅ **HIPAA compliant** - No protected health information
- ✅ **SOC 2 compliant** - Restricted access, privacy-respecting infrastructure
- ✅ **Open source** - Full code audit available

### Distribution Methods

All methods use the same opt-out implementation:

| Method | Telemetry Banner | Opt-Out Method |
|--------|------------------|----------------|
| **PyPI** (`pip install jmo-security`) | First 3 CLI scans | `JMO_TELEMETRY_DISABLE=1` or `jmo.yml` |
| **Homebrew** (`brew install jmo-security`) | First 3 CLI scans | `JMO_TELEMETRY_DISABLE=1` or `jmo.yml` |
| **WinGet** (`winget install jmo-security`) | First 3 CLI scans | `JMO_TELEMETRY_DISABLE=1` or `jmo.yml` |
| **Docker** (GHCR/Docker Hub/ECR) | Every run (can't persist count) | `-e JMO_TELEMETRY_DISABLE=1` |
| **Manual** (git clone) | First 3 CLI scans | `JMO_TELEMETRY_DISABLE=1` or `jmo.yml` |

## Resources

- **Full Documentation:** [docs/TELEMETRY.md](../../docs/TELEMETRY.md)
- **Privacy Policy:** https://jmotools.com/privacy
- **Dashboard Script:** [scripts/dev/view_telemetry.sh](./view_telemetry.sh)
- **Implementation:** [scripts/core/telemetry.py](../core/telemetry.py)
