package jmo.policy.pci

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "PCI DSS 4.0 Compliance",
	"version": "1.0.0",
	"description": "Enforces PCI DSS 4.0 security requirements",
	"author": "JMo Security",
	"tags": ["pci-dss", "compliance", "payment-card"],
	"frameworks": ["PCI DSS 4.0"],
}

default allow := false

# Critical PCI DSS requirements (high priority)
critical_requirements := [
	"2.2.4", # System security parameters
	"3.5.1", # Cryptographic keys protection
	"4.2.1", # Strong cryptography for transmission
	"6.2.4", # Software security vulnerabilities
	"8.3.6", # Password/passphrase strength
]

# Allow if no critical PCI violations
allow if {
	count(critical_violations) == 0
}

# Collect findings mapped to PCI DSS
pci_findings[finding] {
	finding := input.findings[_]
	finding.compliance.pciDss4_0
	count(finding.compliance.pciDss4_0) > 0
}

# Critical violations (block release)
critical_violations[violation] {
	finding := pci_findings[_]
	finding.severity in ["CRITICAL", "HIGH"]
	req := finding.compliance.pciDss4_0[_]
	req.requirement in critical_requirements
	violation := {
		"fingerprint": finding.id,
		"severity": finding.severity,
		"requirement": req.requirement,
		"priority": req.priority,
		"rule": finding.ruleId,
		"message": sprintf("PCI DSS %s: %s", [req.requirement, finding.message]),
	}
}

# Informational violations (warnings only)
warnings[warning] {
	finding := pci_findings[_]
	finding.severity in ["MEDIUM", "LOW"]
	req := finding.compliance.pciDss4_0[_]
	warning := sprintf("⚠️  PCI DSS %s (priority %s): %s", [req.requirement, req.priority, finding.message])
}

violations := critical_violations

message := msg {
	count(critical_violations) > 0
	msg := sprintf("❌ Found %d critical PCI DSS violations", [count(critical_violations)])
} else := "✅ PCI DSS critical requirements satisfied"
