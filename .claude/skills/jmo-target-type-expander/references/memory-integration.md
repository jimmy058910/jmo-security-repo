# Memory Integration

How the target type expander skill integrates with JMo's memory system
for caching learned patterns, tool compatibility, and API structures.

## Memory Namespace

`.jmo/memory/target-types/`

## What Gets Stored

- **API Patterns:** Learned from exploring AWS boto3, npm registry API, GraphQL introspection
- **Schema Structures:** Target-specific data models (S3 buckets, npm package.json, GraphQL types)
- **Performance Metrics:** API response times, rate limits, pagination strategies
- **Tool Compatibility:** Which security tools work best for each target type
- **Authentication Patterns:** Proven auth methods (env vars, IAM roles, tokens)

## Query Before Analysis

```bash
# Check if AWS S3 pattern already learned
cat .jmo/memory/target-types/aws-s3.json | jq '.api_pattern'

# Check if npm registry structure cached
cat .jmo/memory/target-types/npm-registry.json | jq '.schema'

# Check if GraphQL introspection pattern cached
cat .jmo/memory/target-types/graphql.json | jq '.introspection_query'
```

## Storage Format (JSON)

```json
{
  "target_type": "aws-s3",
  "api_pattern": {
    "list_buckets": "s3_client.list_buckets()",
    "list_objects": "s3_client.list_objects_v2(Bucket=bucket)",
    "get_bucket_acl": "s3_client.get_bucket_acl(Bucket=bucket)"
  },
  "schema": {
    "bucket": {
      "Name": "string",
      "CreationDate": "datetime"
    }
  },
  "performance": {
    "avg_list_time_ms": 450,
    "rate_limit": "100 req/sec",
    "pagination": "NextContinuationToken"
  },
  "tools": {
    "recommended": ["prowler", "cloudsplaining"],
    "tested": ["prowler", "cloudsplaining", "cs-suite"],
    "incompatible": ["trivy"]
  },
  "authentication": {
    "method": "IAM role",
    "env_vars": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
    "example": "export AWS_PROFILE=audit-role"
  },
  "metadata": {
    "last_updated": "2025-10-24",
    "usage_count": 5,
    "success_rate": 0.95,
    "avg_time_saved_seconds": 7200
  }
}
```

## Cache Workflow

**Time Savings:** 50% faster repeated use (3-4 hours to 1.5-2 hours)

1. **Query Memory:** Claude checks `.jmo/memory/target-types/<type>.json` before analysis
2. **Cache Hit:** Retrieve API patterns instantly (<1 second)
   - Skip SDK exploration (saves 30-45 min)
   - Skip tool compatibility testing (saves 15-20 min)
   - Skip authentication pattern discovery (saves 10-15 min)
3. **Cache Miss:** Perform full analysis (2-3 hours), then store result
4. **Next Time:** Use cached data (1.5-2 hours, 50% savings)

## Cache Invalidation

- **Manual:** Delete `.jmo/memory/target-types/<type>.json` to force re-analysis
- **Automatic:** Cache expires after 90 days (API patterns may change)
- **Version Change:** Cache invalidated when SDK major version changes (boto3 v1 to v2)

## Cached Target Type Files

```bash
.jmo/memory/target-types/aws-s3.json
.jmo/memory/target-types/npm-registry.json
.jmo/memory/target-types/graphql.json
.jmo/memory/target-types/azure-subscriptions.json
.jmo/memory/target-types/gcp-projects.json
.jmo/memory/target-types/ansible.json
```

## Cache Management

```bash
# Review all cached target types
ls -lh .jmo/memory/target-types/

# Inspect specific cache
cat .jmo/memory/target-types/aws-s3.json | jq '.'

# Invalidate stale cache (force fresh analysis)
rm .jmo/memory/target-types/aws-s3.json

# Check cache age (prune if >90 days)
find .jmo/memory/target-types -name "*.json" -mtime +90
```

## Integration with Skill Workflow

When using this skill to add a new target type (e.g., Azure Storage):

1. **Check Memory First:** Is `.jmo/memory/target-types/azure-storage.json` cached?
2. **If Yes (Cache Hit):**
   - Retrieve Azure Storage API patterns (instant)
   - Skip Azure SDK exploration (saves 30 min)
   - Use cached tool recommendations (saves 15 min)
   - **Total Time:** 1.5-2 hours (50% savings)
3. **If No (Cache Miss):**
   - Explore Azure SDK for Storage APIs (30 min)
   - Test security tools (AzSK, checkov, trivy) (20 min)
   - Determine authentication (Managed Identity vs Service Principal) (15 min)
   - **Store in Memory** for next time
   - **Total Time:** 3-4 hours (full workflow)
