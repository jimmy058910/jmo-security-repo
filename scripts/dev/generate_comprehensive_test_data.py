#!/usr/bin/env python3
"""
Generate comprehensive test data for dashboard testing.

Creates realistic findings from all 28 tools with:
- All severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- All 6 compliance frameworks (OWASP, CWE, CIS, NIST, PCI DSS, ATT&CK)
- Multiple finding types (secrets, vulns, misconfigs, code issues)
- Configurable dataset size (default: 5000 findings)

Usage:
    python3 scripts/dev/generate_comprehensive_test_data.py --output results-comprehensive --count 5000
"""

import json
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any
import argparse


# Tool configurations (all 28 tools from JMo Security)
TOOLS = {
    # Secrets scanners
    "trufflehog": {"type": "secrets", "weight": 0.15},
    "noseyparker": {"type": "secrets", "weight": 0.05},
    # SAST scanners
    "semgrep": {"type": "sast", "weight": 0.20},
    "bandit": {"type": "sast", "weight": 0.08},
    "gosec": {"type": "sast", "weight": 0.05},
    "horusec": {"type": "sast", "weight": 0.05},
    # SBOM + Vulnerability scanners
    "syft": {"type": "sbom", "weight": 0.10},
    "trivy": {"type": "vuln", "weight": 0.15},
    "grype": {"type": "vuln", "weight": 0.08},
    "osv-scanner": {"type": "vuln", "weight": 0.05},
    "dependency-check": {"type": "vuln", "weight": 0.04},
    # IaC scanners
    "checkov": {"type": "iac", "weight": 0.10},
    "checkov-cicd": {"type": "iac", "weight": 0.03},
    # Container scanners
    "hadolint": {"type": "container", "weight": 0.05},
    # DAST scanners
    "zap": {"type": "dast", "weight": 0.08},
    "nuclei": {"type": "dast", "weight": 0.06},
    "akto": {"type": "api", "weight": 0.03},
    # Cloud CSPM
    "prowler": {"type": "cloud", "weight": 0.06},
    "kubescape": {"type": "k8s", "weight": 0.05},
    # Other scanners
    "yara": {"type": "malware", "weight": 0.02},
    "bearer": {"type": "privacy", "weight": 0.03},
    "scancode": {"type": "license", "weight": 0.04},
    "cdxgen": {"type": "sbom", "weight": 0.03},
    "mobsf": {"type": "mobile", "weight": 0.02},
    "lynis": {"type": "system", "weight": 0.02},
    "falco": {"type": "runtime", "weight": 0.02},
    "trivy-rbac": {"type": "k8s", "weight": 0.02},
}

# Severity distribution (realistic production distribution)
SEVERITIES = {
    "CRITICAL": 0.05,  # 5%
    "HIGH": 0.15,  # 15%
    "MEDIUM": 0.35,  # 35%
    "LOW": 0.30,  # 30%
    "INFO": 0.15,  # 15%
}

# Compliance framework mappings
COMPLIANCE_MAPPINGS = {
    "owasp": [
        "A01:2021",
        "A02:2021",
        "A03:2021",
        "A04:2021",
        "A05:2021",
        "A06:2021",
        "A07:2021",
        "A08:2021",
        "A09:2021",
        "A10:2021",
    ],
    "cwe": [
        "CWE-79",
        "CWE-89",
        "CWE-78",
        "CWE-22",
        "CWE-352",
        "CWE-434",
        "CWE-611",
        "CWE-798",
        "CWE-502",
        "CWE-287",
        "CWE-190",
        "CWE-787",
        "CWE-416",
        "CWE-125",
        "CWE-20",
    ],
    "cis": ["1.1", "1.2", "2.1", "2.2", "3.1", "4.1", "5.1"],
    "nist": ["ID.AM", "PR.AC", "PR.DS", "DE.CM", "RS.RP"],
    "pci_dss": ["2.2", "6.2", "6.5", "8.2", "10.2"],
    "attack": [
        "T1003",
        "T1059",
        "T1071",
        "T1078",
        "T1105",
        "T1190",
        "T1210",
        "T1547",
        "T1068",
        "T1055",
    ],
}

# Rule templates by tool type
RULE_TEMPLATES = {
    "secrets": [
        ("AWS-KEY-EXPOSED", "Hardcoded AWS access key detected"),
        ("GITHUB-TOKEN", "GitHub personal access token found"),
        ("PRIVATE-KEY", "RSA private key exposed in code"),
        ("API-KEY-HARDCODED", "API key hardcoded in source"),
        ("DATABASE-CREDS", "Database credentials in plaintext"),
    ],
    "sast": [
        ("SQL-INJECTION", "SQL injection vulnerability detected"),
        ("XSS-REFLECTED", "Reflected cross-site scripting vulnerability"),
        ("PATH-TRAVERSAL", "Path traversal vulnerability"),
        ("COMMAND-INJECTION", "OS command injection detected"),
        ("INSECURE-DESERIALIZATION", "Insecure deserialization of user input"),
    ],
    "vuln": [
        ("CVE-2024-12345", "Critical vulnerability in dependency"),
        ("CVE-2024-23456", "Remote code execution in library"),
        ("CVE-2024-34567", "Authentication bypass vulnerability"),
        ("CVE-2023-45678", "SQL injection in database driver"),
        ("CVE-2023-56789", "Cross-site scripting in web framework"),
    ],
    "iac": [
        ("INSECURE-S3-BUCKET", "S3 bucket allows public access"),
        ("MISSING-ENCRYPTION", "Encryption not enabled for resource"),
        ("WEAK-NETWORK-POLICY", "Overly permissive network policy"),
        ("PRIVILEGE-ESCALATION", "IAM role allows privilege escalation"),
        ("INSECURE-PROTOCOL", "Insecure protocol enabled (HTTP)"),
    ],
    "container": [
        ("DOCKERFILE-NO-USER", "Dockerfile missing USER instruction"),
        ("DOCKERFILE-LATEST-TAG", "Using 'latest' tag instead of pinned version"),
        ("DOCKERFILE-SECRETS", "Secrets embedded in Dockerfile"),
        ("EXPOSED-PORT-UNNECESSARY", "Unnecessary port exposed"),
        ("MISSING-HEALTHCHECK", "No HEALTHCHECK instruction"),
    ],
    "dast": [
        ("WEAK-TLS-CONFIG", "Weak TLS configuration detected"),
        ("MISSING-CSP", "Content Security Policy not configured"),
        ("INSECURE-COOKIE", "Cookie missing Secure/HttpOnly flags"),
        ("CORS-MISCONFIGURATION", "Overly permissive CORS policy"),
        ("CLICKJACKING-VULNERABLE", "Missing X-Frame-Options header"),
    ],
}

# File paths for realistic finding locations
FILE_PATHS = [
    "src/auth/login.py",
    "src/api/users.py",
    "src/db/queries.py",
    "src/utils/crypto.py",
    "src/config/settings.py",
    "src/models/user.py",
    "infrastructure/terraform/main.tf",
    "infrastructure/k8s/deployment.yaml",
    "Dockerfile",
    "docker-compose.yml",
    ".github/workflows/ci.yml",
    "frontend/src/components/Login.tsx",
    "frontend/src/api/client.ts",
    "backend/handlers/auth.go",
    "backend/db/migrations/001_init.sql",
]


def weighted_choice(choices: Dict[str, float]) -> str:
    """Select item from dict with weights."""
    items = list(choices.keys())
    weights = list(choices.values())
    return random.choices(items, weights=weights, k=1)[0]


def generate_fingerprint(
    tool: str, rule: str, path: str, line: int, message: str
) -> str:
    """Generate deterministic fingerprint for finding."""
    content = f"{tool}|{rule}|{path}|{line}|{message[:120]}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def generate_compliance(severity: str, tool_type: str) -> Dict[str, Any]:
    """Generate compliance framework mappings based on severity and tool type."""
    compliance: Dict[str, Any] = {}

    # Higher severity = more framework coverage
    coverage_factor = {
        "CRITICAL": 0.9,
        "HIGH": 0.7,
        "MEDIUM": 0.5,
        "LOW": 0.3,
        "INFO": 0.1,
    }[severity]

    # OWASP Top 10
    if random.random() < coverage_factor:
        owasp_list: List[str] = random.sample(
            COMPLIANCE_MAPPINGS["owasp"], k=random.randint(1, 3)
        )
        compliance["owaspTop10_2021"] = owasp_list

    # CWE Top 25
    if random.random() < coverage_factor:
        cwes = random.sample(COMPLIANCE_MAPPINGS["cwe"], k=random.randint(1, 2))
        cwe_dicts: List[Dict[str, Any]] = [
            {"id": cwe, "rank": i + 1, "category": "Weakness"}
            for i, cwe in enumerate(cwes)
        ]
        compliance["cweTop25_2024"] = cwe_dicts

    # CIS Controls
    if (
        tool_type in ["iac", "cloud", "k8s", "container"]
        and random.random() < coverage_factor
    ):
        cis_list = random.sample(COMPLIANCE_MAPPINGS["cis"], k=random.randint(1, 2))
        cis_dicts: List[Dict[str, Any]] = [
            {"control": c, "ig": random.choice([1, 2, 3])} for c in cis_list
        ]
        compliance["cisControlsV8_1"] = cis_dicts

    # NIST CSF
    if random.random() < coverage_factor:
        nist_list = random.sample(COMPLIANCE_MAPPINGS["nist"], k=random.randint(1, 2))
        nist_dicts: List[Dict[str, Any]] = [
            {"function": "PROTECT", "category": c} for c in nist_list
        ]
        compliance["nistCsf2_0"] = nist_dicts

    # PCI DSS
    if tool_type in ["secrets", "vuln", "dast"] and random.random() < coverage_factor:
        pci_list = random.sample(COMPLIANCE_MAPPINGS["pci_dss"], k=random.randint(1, 2))
        pci_dicts: List[Dict[str, Any]] = [
            {"requirement": r, "priority": "P1"} for r in pci_list
        ]
        compliance["pciDss4_0"] = pci_dicts

    # MITRE ATT&CK
    if severity in ["CRITICAL", "HIGH"] and random.random() < coverage_factor:
        attack_list = random.sample(
            COMPLIANCE_MAPPINGS["attack"], k=random.randint(1, 2)
        )
        attack_dicts: List[Dict[str, Any]] = [
            {"tactic": "Initial Access", "technique": t} for t in attack_list
        ]
        compliance["mitreAttack"] = attack_dicts

    return compliance


def generate_finding(
    tool: str, tool_type: str, severity: str, index: int
) -> Dict[str, Any]:
    """Generate a single CommonFinding v1.2.0 finding."""

    # Select rule template based on tool type
    template_type = tool_type if tool_type in RULE_TEMPLATES else "sast"
    rule_id, message_template = random.choice(
        RULE_TEMPLATES.get(template_type, RULE_TEMPLATES["sast"])
    )

    # Generate location
    file_path = random.choice(FILE_PATHS)
    start_line = random.randint(10, 500)

    # Generate fingerprint
    fingerprint = generate_fingerprint(
        tool, rule_id, file_path, start_line, message_template
    )

    # Generate compliance mappings
    compliance = generate_compliance(severity, tool_type)

    # Build CommonFinding
    finding = {
        "schemaVersion": "1.2.0",
        "id": f"finding-{fingerprint}",
        "ruleId": rule_id,
        "severity": severity,
        "tool": {"name": tool, "version": "latest"},
        "location": {
            "path": file_path,
            "startLine": start_line,
            "endLine": start_line + random.randint(0, 5),
        },
        "message": message_template,
        "description": f"Detailed description for {message_template.lower()}",
        "compliance": compliance,
        "priority": {
            "priority": random.randint(50, 100),
            "is_kev": severity == "CRITICAL" and random.random() < 0.2,
        },
    }

    # Add remediation for higher severity
    if severity in ["CRITICAL", "HIGH"]:
        finding["remediation"] = {
            "summary": f"Fix {rule_id.lower().replace('-', ' ')} by updating configuration",
            "references": [f"https://example.com/fix/{rule_id.lower()}"],
        }

    return finding


def generate_tool_output(
    tool: str, tool_type: str, count: int, output_dir: Path
) -> List[Dict[str, Any]]:
    """Generate findings for a tool."""

    findings: List[Dict[str, Any]] = []
    for i in range(count):
        severity = weighted_choice(SEVERITIES)
        finding = generate_finding(tool, tool_type, severity, i)
        findings.append(finding)

    print(f"✅ Generated {count:4d} findings for {tool:20s}")
    return findings


def main():
    parser = argparse.ArgumentParser(description="Generate comprehensive test data")
    parser.add_argument(
        "--output", default="results-comprehensive", help="Output directory"
    )
    parser.add_argument("--count", type=int, default=5000, help="Total finding count")
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed for reproducibility"
    )
    args = parser.parse_args()

    # Set random seed
    random.seed(args.seed)

    output_dir = Path(args.output)
    summaries_dir = output_dir / "summaries"
    summaries_dir.mkdir(parents=True, exist_ok=True)

    print(f"🔨 Generating {args.count} findings across {len(TOOLS)} tools...")
    print(f"📁 Output directory: {output_dir}")
    print()

    # Calculate findings per tool based on weights
    total_weight: float = 0.0
    for config in TOOLS.values():
        if isinstance(config, dict) and "weight" in config:
            weight = config["weight"]
            if isinstance(weight, (int, float)):
                total_weight += float(weight)

    findings_per_tool: Dict[str, int] = {}
    for tool, config in TOOLS.items():
        if isinstance(config, dict) and "weight" in config:
            weight = config["weight"]
            if isinstance(weight, (int, float)):
                weight_val = float(weight)
                findings_per_tool[tool] = max(
                    1, int(args.count * weight_val / total_weight)
                )

    # Generate all findings
    all_findings: List[Dict[str, Any]] = []
    for tool_name, tool_config in TOOLS.items():
        count = findings_per_tool[tool_name]
        tool_type_str = str(tool_config.get("type", "sast"))
        tool_findings = generate_tool_output(
            tool_name, tool_type_str, count, output_dir
        )
        all_findings.extend(tool_findings)

    # Write aggregated findings.json with v1.0.0 metadata wrapper
    total_generated = len(all_findings)
    findings_output = {
        "meta": {
            "output_version": "1.0.0",
            "jmo_version": "1.0.0",
            "schema_version": "1.2.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "scan_id": "test-comprehensive-"
            + hashlib.sha256(str(args.seed).encode()).hexdigest()[:16],
            "profile": "comprehensive-test",
            "tools": list(TOOLS.keys()),
            "target_count": 1,
            "finding_count": total_generated,
            "platform": {"os": "test", "python": "3.11.0"},
        },
        "findings": all_findings,
    }

    output_file = summaries_dir / "findings.json"
    with open(output_file, "w", encoding="utf-8") as output_f:
        json.dump(findings_output, output_f, indent=2)

    print()
    print(f"✅ Generated {total_generated} findings total → {output_file}")
    print(f"📊 Severity distribution:")
    for severity, weight in SEVERITIES.items():
        expected = int(total_generated * weight)
        actual = sum(1 for f in all_findings if f.get("severity") == severity)
        print(
            f"   {severity:10s}: {actual:4d} findings (~{expected:4d} expected, {weight*100:.0f}%)"
        )
    print()
    print(f"🔧 Tool distribution:")
    tool_counts: Dict[str, int] = {}
    for finding in all_findings:
        tool_info = finding.get("tool", {})
        if isinstance(tool_info, dict):
            tool_name = tool_info.get("name", "unknown")
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
    for tool in sorted(tool_counts.keys()):
        print(f"   {tool:20s}: {tool_counts[tool]:4d} findings")
    print()
    print(f"🎯 Next steps:")
    print(f"   1. Copy findings-data.json for external dashboard mode:")
    print(f"      cp {output_file} {summaries_dir}/findings-data.json")
    print(f"   2. Open dashboard.html from results-final or similar")
    print(
        f"   3. Test: All {len(TOOLS)} tools, all severities, all compliance frameworks"
    )


if __name__ == "__main__":
    main()
