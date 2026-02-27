package jmo.policy.secrets

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "Zero Secrets Policy",
	"version": "1.0.0",
	"description": "Blocks all verified secrets (zero tolerance)",
	"author": "JMo Security",
	"tags": ["secrets", "credentials", "zero-trust"],
	"frameworks": ["NIST CSF", "CIS Controls"],
}

default allow := false

# Secret detection tools
secret_tools := ["trufflehog", "noseyparker", "semgrep-secrets", "trivy"]

# Allow only if zero verified secrets
allow if {
	count(verified_secrets) == 0
}

# Collect verified secrets
verified_secrets contains finding if {
	finding := input.findings[_]
	finding.tool.name in secret_tools
	finding.severity in ["CRITICAL", "HIGH"]
	# TruffleHog verified field
	finding.raw.verified == true
}

violations contains violation if {
	finding := verified_secrets[_]
	violation := {
		"fingerprint": finding.id,
		"severity": "CRITICAL", # Always critical for verified secrets
		"tool": finding.tool.name,
		"path": finding.location.path,
		"line": finding.location.startLine,
		"message": sprintf("🔴 VERIFIED SECRET: %s", [finding.message]),
		"remediation": "Rotate credentials immediately and remove from version control history",
	}
}

message := msg if {
	count(violations) > 0
	msg := sprintf("🚨 CRITICAL: Found %d verified secrets - IMMEDIATE ACTION REQUIRED", [count(violations)])
} else := "✅ No verified secrets detected"
