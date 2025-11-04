package jmo.policy.production

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "Production Hardening Policy",
	"version": "1.0.0",
	"description": "Stricter rules for production deployments",
	"author": "JMo Security",
	"tags": ["production", "hardening", "zero-tolerance"],
	"frameworks": [],
}

default allow := false

# Zero tolerance for production
block_severities := ["CRITICAL", "HIGH"]

# Allow only if zero CRITICAL/HIGH findings
allow if {
	count(blocking_findings) == 0
	count(dockerfile_issues) == 0
	count(secret_findings) == 0
}

# Blocking findings by severity
blocking_findings contains finding if {
	finding := input.findings[_]
	finding.severity in block_severities
}

# Dockerfile-specific issues (critical for containers)
dockerfile_issues contains finding if {
	finding := input.findings[_]
	finding.tool.name == "hadolint"
	finding.severity in ["CRITICAL", "HIGH"]
	contains(lower(finding.location.path), "dockerfile")
}

# Any secrets (verified or not)
secret_findings contains finding if {
	finding := input.findings[_]
	finding.tool.name in ["trufflehog", "noseyparker", "semgrep-secrets"]
	finding.severity in ["CRITICAL", "HIGH"]
}

violations contains violation if {
	finding := blocking_findings[_]
	violation := {
		"fingerprint": finding.id,
		"severity": finding.severity,
		"category": "security",
		"rule": finding.ruleId,
		"message": sprintf("%s: %s", [finding.severity, finding.message]),
	}
}

violations contains violation if {
	finding := dockerfile_issues[_]
	violation := {
		"fingerprint": finding.id,
		"severity": "CRITICAL",
		"category": "dockerfile",
		"rule": finding.ruleId,
		"message": sprintf("Dockerfile issue: %s", [finding.message]),
	}
}

violations contains violation if {
	finding := secret_findings[_]
	violation := {
		"fingerprint": finding.id,
		"severity": "CRITICAL",
		"category": "secrets",
		"rule": finding.ruleId,
		"message": sprintf("Secret detected: %s", [finding.message]),
	}
}

message := msg if {
	count(violations) > 0
	msg := sprintf("🚫 Production gate FAILED: %d blocking issues", [count(violations)])
} else := "✅ Production hardening requirements satisfied"
