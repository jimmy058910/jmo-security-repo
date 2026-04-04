# Automated Skill Audit Details

Detailed audit script and verbose review steps for the skill optimizer.

## Automated Skill Audit Script

Use this Python script to automate staleness detection:

```python
#!/usr/bin/env python3
"""
Automated skill audit for JMo Security.
Run manually as needed.

Usage:
    python3 audit_skills.py --report
    python3 audit_skills.py --fix --skill jmo-adapter-generator
"""
import json
import subprocess
from pathlib import Path
from datetime import datetime, timedelta

SKILLS_DIR = Path(".claude/skills")

def find_stale_skills(threshold_days=180):
    """Find skills not updated in threshold_days."""
    stale = []
    threshold = datetime.now() - timedelta(days=threshold_days)

    for skill_file in SKILLS_DIR.glob("*/SKILL.md"):
        mtime = datetime.fromtimestamp(skill_file.stat().st_mtime)
        if mtime < threshold:
            stale.append({
                "skill": skill_file.parent.name,
                "last_modified": mtime.isoformat(),
                "days_old": (datetime.now() - mtime).days
            })

    return sorted(stale, key=lambda x: x["days_old"], reverse=True)

def check_memory_integration(skill_name):
    """Check if skill has memory integration."""
    skill_file = SKILLS_DIR / skill_name / "SKILL.md"
    content = skill_file.read_text()
    return "Memory Integration" in content

def check_version_consistency(skill_name):
    """Check if skill version matches INDEX.md."""
    skill_file = SKILLS_DIR / skill_name / "SKILL.md"
    index_file = SKILLS_DIR / "INDEX.md"

    # Extract version from skill
    skill_content = skill_file.read_text()
    skill_version = None
    for line in skill_content.split("\n"):
        if line.startswith("**Version:**"):
            skill_version = line.split("v")[1].strip()
            break

    # Extract version from INDEX.md
    index_content = index_file.read_text()
    index_version = None
    for line in index_content.split("\n"):
        if skill_name in line and "v" in line:
            parts = line.split("|")
            for part in parts:
                if "v" in part and "." in part:
                    index_version = part.strip().replace("v", "")
                    break

    return skill_version == index_version

def generate_audit_report():
    """Generate comprehensive skill audit report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "skills_total": len(list(SKILLS_DIR.glob("*/SKILL.md"))),
        "stale_skills": [],
        "missing_memory": [],
        "version_mismatches": []
    }

    # Find stale skills
    report["stale_skills"] = find_stale_skills(threshold_days=180)

    # Check memory integration
    for skill_file in SKILLS_DIR.glob("*/SKILL.md"):
        skill_name = skill_file.parent.name
        if not check_memory_integration(skill_name):
            report["missing_memory"].append(skill_name)

    # Check version consistency
    for skill_file in SKILLS_DIR.glob("*/SKILL.md"):
        skill_name = skill_file.parent.name
        if not check_version_consistency(skill_name):
            report["version_mismatches"].append(skill_name)

    return report

def print_audit_report(report):
    """Print human-readable audit report."""
    print("=" * 60)
    print("JMo Security Skill Audit Report")
    print("=" * 60)
    print(f"Generated: {report['timestamp']}")
    print(f"Total Skills: {report['skills_total']}")
    print()

    print(f"Stale Skills ({len(report['stale_skills'])}):")
    for skill in report["stale_skills"]:
        print(f"  - {skill['skill']}: {skill['days_old']} days old")
    print()

    print(f"Missing Memory Integration ({len(report['missing_memory'])}):")
    for skill in report["missing_memory"]:
        print(f"  - {skill}")
    print()

    print(f"Version Mismatches ({len(report['version_mismatches'])}):")
    for skill in report["version_mismatches"]:
        print(f"  - {skill}")
    print()

    # Priority recommendations
    high_priority = len(report["stale_skills"]) + len(report["version_mismatches"])
    medium_priority = len(report["missing_memory"])

    print("Recommendations:")
    if high_priority > 0:
        print(f"  HIGH: Review {high_priority} stale/mismatched skills")
    if medium_priority > 0:
        print(f"  MEDIUM: Add memory to {medium_priority} skills")
    if high_priority == 0 and medium_priority == 0:
        print("  All skills current!")
    print()

if __name__ == "__main__":
    report = generate_audit_report()
    print_audit_report(report)

    # Save report for review
    report_path = Path(f"skill-audit-{datetime.now().strftime('%Y%m%d')}.json")
    report_path.write_text(json.dumps(report, indent=2))
```

**Usage:**

```bash
# Run audit manually (local development only)
python3 audit_skills.py --report

# Output saved to skill-audit-YYYYMMDD.json
```

**Note:** This script is for **local use only**. Skills are gitignored, so CI cannot access `.claude/skills/`.
