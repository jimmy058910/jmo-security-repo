#!/usr/bin/env python3
"""
Batch update all adapters to include compliance enrichment.

This script updates all adapter files to:
1. Import enrich_finding_with_compliance
2. Call enrichment before appending findings
"""

from pathlib import Path
import re

# List of adapters that need updates (excluding those already updated)
ADAPTERS_TO_UPDATE = [
    "checkov_adapter.py",
    "bandit_adapter.py",
    "zap_adapter.py",
    "syft_adapter.py",
    "noseyparker_adapter.py",
    "hadolint_adapter.py",
    "gitleaks_adapter.py",
    "tfsec_adapter.py",
    "osv_adapter.py",
    "falco_adapter.py",
    "aflplusplus_adapter.py",
]

ADAPTERS_DIR = Path(__file__).parent.parent / "core" / "adapters"


def update_adapter(adapter_path: Path):
    """Update a single adapter file."""
    print(f"Updating {adapter_path.name}...")

    content = adapter_path.read_text()

    # Check if already updated
    if "from scripts.core.compliance_mapper import" in content:
        print("  → Already updated, skipping")
        return

    # Step 1: Add import after common_finding import
    import_pattern = r"(from scripts\.core\.common_finding import[^\n]+)"
    import_replacement = (
        r"\1\nfrom scripts.core.compliance_mapper import enrich_finding_with_compliance"
    )

    if re.search(import_pattern, content):
        content = re.sub(import_pattern, import_replacement, content)
        print("  → Added compliance_mapper import")
    else:
        print("  → Warning: Could not find common_finding import")

    # Step 2: Find all patterns where findings are appended to out list
    # Pattern 1: out.append({...})
    # Pattern 2: out.append(finding) or similar

    # For now, let's add a comment marker where enrichment should happen
    # This requires manual review for each adapter due to different patterns

    # Save updated content
    adapter_path.write_text(content)
    print("  → Import added. Manual review needed for enrichment call placement.")


def main():
    """Update all adapters."""
    for adapter_name in ADAPTERS_TO_UPDATE:
        adapter_path = ADAPTERS_DIR / adapter_name
        if not adapter_path.exists():
            print(f"Warning: {adapter_name} not found")
            continue
        try:
            update_adapter(adapter_path)
        except Exception as e:
            print(f"Error updating {adapter_name}: {e}")

    print("\n✅ Import updates complete")
    print("⚠️  Manual review required for each adapter to add enrichment calls")


if __name__ == "__main__":
    main()
