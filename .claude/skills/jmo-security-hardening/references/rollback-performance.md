# Rollback Procedures and Performance Considerations

---

## Rollback Strategy

### Pre-Deployment Checklist

Before deploying security fixes to production:

- [ ] **Create rollback branch**

  ```bash
  git checkout -b rollback/pre-security-fix-MEDIUM-001
  git push origin rollback/pre-security-fix-MEDIUM-001
  ```

- [ ] **Feature flag deployment** (for gradual rollout)

  ```python
  # Add feature flag support
  SECURITY_FIX_ENABLED = os.getenv('SECURITY_FIX_MEDIUM_001', 'true').lower() == 'true'

  if SECURITY_FIX_ENABLED:
      safe_name = _sanitize_path_component(name)
  else:
      safe_name = name  # Legacy behavior
  ```

- [ ] **Backward compatibility tested**
  - Old clients can still interact with API
  - Existing data/paths remain accessible
  - No breaking changes in public APIs

- [ ] **Monitoring alerts configured**
  - ValidationError rate threshold: >1% triggers alert
  - Sanitization frequency: >10/min triggers review
  - Performance degradation: >10% latency triggers alert

### Rollback Procedure

If security fix causes production issues:

```bash
# Option 1: Git revert (recommended for clean rollback)
git revert <commit-sha-of-security-fix>
git push origin main

# Option 2: Feature flag disable (fastest, no deployment)
# Set environment variable: SECURITY_FIX_MEDIUM_001=false
# Restart application

# Option 3: Deploy rollback branch (for complex fixes)
git checkout rollback/pre-security-fix-MEDIUM-001
git push origin main --force  # Use with extreme caution
```

### Gradual Rollout Strategy

For high-risk security fixes, use phased deployment:

```python
# Phase 1: Log-only mode (Week 1)
safe_name = _sanitize_path_component(name)
if safe_name != name:
    logger.warning(f"Would sanitize: {name} -> {safe_name} (MEDIUM-001)")
out_dir = indiv_base / name  # Still use original

# Phase 2: Enforce for new data only (Week 2)
created_at = get_creation_timestamp(name)
if created_at > datetime(2025, 10, 18):  # Cutoff date
    safe_name = _sanitize_path_component(name)
else:
    safe_name = name  # Preserve legacy data

# Phase 3: Full enforcement (Week 3)
safe_name = _sanitize_path_component(name)
```

### Monitoring Post-Deployment

Track these metrics after deploying security fixes:

```python
# Add instrumentation
from collections import Counter
sanitized_paths = Counter()

def _sanitize_path_component(name: str) -> str:
    result = ...  # sanitization logic
    if result != name:
        sanitized_paths[name] += 1
        logger.info(f"Sanitized path: {name} -> {result} (MEDIUM-001)")
    return result
```

**Alert Thresholds:**

- **Warning:** >10 sanitizations per minute (possible attack or misconfiguration)
- **Warning:** >1000 unique sanitized paths in 24h (check for systemic issue)
- **Critical:** ValidationError rate >1% (fix may be too strict)
- **Critical:** Application error rate increased >5% (potential regression)

---

## Performance Considerations

### Expected Overhead by Fix Type

Security fixes add minimal overhead when implemented correctly:

| Fix Type | Per-Operation Overhead | Relative Impact | Acceptable? |
|----------|------------------------|-----------------|-------------|
| Path Sanitization | 5-10us | <0.01% | Yes |
| Input Validation | 10-50us | 0.1% | Yes |
| CSP Header Parse | 100-200us | One-time (page load) | Yes |
| CAPTCHA Verification | 200-500ms | API call | User-facing |
| Regex Validation | 50-500us | Varies by pattern | Depends |

### When to Profile Performance

Profile security fixes in these scenarios:

- **Hot paths:** Functions called >1000x per request
- **Nested loops:** Validation inside loops
- **Large batch operations:** Processing 1000+ items
- **CLI tools:** User perception > milliseconds (no profiling needed)
- **Dashboard generation:** One-time cost (no profiling needed)

### Optimization Strategies

If security fix causes measurable performance impact:

#### 1. Cache Validation Results

```python
from functools import lru_cache

@lru_cache(maxsize=1024)
def _sanitize_path_component_cached(name: str) -> str:
    """Cached version for repeated sanitization of same inputs."""
    return _sanitize_path_component(name)
```

#### 2. Batch Validation

```python
# Bad: Validate each item individually
for item in items:
    validated = validate(item)
    process(validated)

# Good: Batch validate
validated_items = [validate(item) for item in items]
for item in validated_items:
    process(item)
```

#### 3. Fail Fast (Order Checks by Cost)

```python
# Check cheap validations first
if not name:  # Fast: empty check
    return "unknown"
if ".." in name:  # Fast: substring check
    name = name.replace("..", "_")
# Expensive regex last
safe = re.sub(r'[<>:"|?*\x00-\x1f]', '_', name)
```

#### 4. Compile Regex Patterns Once

```python
# Bad: Compile on every call
def sanitize(name):
    return re.sub(r'[<>:"|?*]', '_', name)

# Good: Compile once
DANGEROUS_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')

def sanitize(name):
    return DANGEROUS_CHARS.sub('_', name)
```
