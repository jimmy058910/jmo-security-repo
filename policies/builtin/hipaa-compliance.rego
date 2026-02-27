package jmo.policy.hipaa

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "HIPAA Security Rule Compliance",
	"version": "1.0.0",
	"description": "Enforces HIPAA technical safeguards (45 CFR 164.312)",
	"author": "JMo Security",
	"tags": ["hipaa", "healthcare", "compliance", "phi"],
	"frameworks": ["HIPAA Security Rule"],
}

default allow := false

# HIPAA-critical CWEs
hipaa_cwes := [
	"CWE-22", # Path Traversal (PHI exposure)
	"CWE-79", # XSS (PHI exposure)
	"CWE-89", # SQL Injection (PHI access)
	"CWE-200", # Information Exposure
	"CWE-284", # Improper Access Control
	"CWE-306", # Missing Authentication
	"CWE-319", # Cleartext Transmission (PHI)
	"CWE-326", # Inadequate Encryption
	"CWE-327", # Broken Crypto
	"CWE-798", # Hardcoded Credentials
]

# Allow if no HIPAA-critical violations
allow if {
	count(hipaa_violations) == 0
}

# Findings with HIPAA-critical CWEs
hipaa_findings contains finding if {
	finding := input.findings[_]
	finding.risk.cwe
	cwe := sprintf("CWE-%d", [finding.risk.cwe])
	cwe in hipaa_cwes
}

hipaa_violations contains violation if {
	finding := hipaa_findings[_]
	finding.severity in ["CRITICAL", "HIGH"]
	violation := {
		"fingerprint": finding.id,
		"severity": finding.severity,
		"cwe": sprintf("CWE-%d", [finding.risk.cwe]),
		"safeguard": hipaa_safeguard(finding.risk.cwe),
		"rule": finding.ruleId,
		"message": finding.message,
		"remediation": finding.remediation,
	}
}

# Map CWE to HIPAA technical safeguard
hipaa_safeguard(cwe) := safeguard if {
	safeguard_map := {
		22: "164.312(a)(1) - Access Control",
		79: "164.312(a)(1) - Access Control",
		89: "164.312(a)(1) - Access Control",
		200: "164.312(a)(1) - Access Control",
		284: "164.312(a)(1) - Access Control",
		306: "164.312(d) - Person/Entity Authentication",
		319: "164.312(e)(1) - Transmission Security",
		326: "164.312(a)(2)(iv) - Encryption",
		327: "164.312(a)(2)(iv) - Encryption",
		798: "164.312(a)(2)(i) - Unique User ID",
	}
	safeguard := safeguard_map[cwe]
}

violations := hipaa_violations

message := msg if {
	count(violations) > 0
	msg := sprintf("❌ HIPAA violations: %d technical safeguard failures", [count(violations)])
} else := "✅ HIPAA technical safeguards requirements satisfied"
