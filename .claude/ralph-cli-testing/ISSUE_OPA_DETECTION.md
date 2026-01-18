# Issue: PolicyEngine Doesn't Find JMo-Installed OPA

## Problem

The `PolicyEngine` class uses `shutil.which()` to find OPA, but JMo installs OPA to `~/.jmo/bin/` which isn't in the system PATH. This causes `jmo policy list` and `jmo policy show` to fail with "OPA not installed" even when OPA was installed via `jmo tools install opa`.

## Current Behavior

```python
# scripts/core/policy_engine.py:92-98
def _verify_opa_available(self) -> None:
    # Uses shutil.which() - only checks system PATH
    if shutil.which(self.opa_binary) is None:
        raise OPANotFoundException()
```

**Result:**
```
$ jmo tools install opa --yes
  [OK] opa (v1.12.0) - binary  # Installed to ~/.jmo/bin/opa.exe

$ jmo policy list
OPA not installed. Install via: jmo tools install opa  # FAILS!
```

## Expected Behavior

`jmo policy list` should find OPA installed by `jmo tools install`.

## Root Cause

The codebase has TWO ways to find tools:

1. **`shutil.which()`** - Only checks system PATH (used by PolicyEngine)
2. **`find_tool()`** - Checks PATH + `~/.jmo/bin/` (used by scan adapters)

PolicyEngine should use `find_tool()` for consistency.

## Fix

**File:** `scripts/core/policy_engine.py`

**Change:**
```python
# Before (line 97)
if shutil.which(self.opa_binary) is None:

# After
from scripts.cli.scan_utils import find_tool
opa_path = find_tool(self.opa_binary)
if opa_path is None:
```

Also update line 101-102 to use `opa_path` instead of `self.opa_binary`:
```python
result = subprocess.run(
    [opa_path, "version"],  # Use resolved path
    ...
)
```

## Files to Modify

1. `scripts/core/policy_engine.py:92-102` - Use `find_tool()` instead of `shutil.which()`

## Test Verification

After fix:
```bash
# Should work
python -m scripts.cli.jmo policy list
python -m pytest tests/cli_ralph/test_policy_commands.py -v
```

## Impact

- Policy tests (`test_pl_001_policy_list`, `test_pl_004_policy_show`) will stop being skipped
- Users who install OPA via `jmo tools install` will have working policy commands

## Priority

Medium - Affects policy commands but workaround exists (add `~/.jmo/bin` to system PATH)
