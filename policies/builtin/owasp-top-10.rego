package jmo.policy.owasp

import future.keywords.if
import future.keywords.in

# Metadata
metadata := {
	"name": "OWASP Top 10 2021 Enforcer",
	"version": "1.1.0",
	"description": "Blocks findings mapped to OWASP Top 10 categories",
	"author": "JMo Security",
	"tags": ["owasp", "compliance", "web-security"],
	"frameworks": ["OWASP Top 10 2021"],
}

# Default: deny if any OWASP violations found
default allow := false

# Allow if no OWASP Top 10 findings
allow if {
	count(owasp_findings) == 0
}

# Collect findings with OWASP mappings
owasp_findings contains finding if {
	finding := input.findings[_]
	finding.compliance.owaspTop10_2021
	count(finding.compliance.owaspTop10_2021) > 0
}

# Generate detailed violations
violations contains violation if {
	finding := owasp_findings[_]
	categories := finding.compliance.owaspTop10_2021
	violation := {
		"fingerprint": finding.id,
		"severity": finding.severity,
		"category": categories[0], # Primary category
		"rule": finding.ruleId,
		"path": finding.location.path,
		"message": sprintf("OWASP violation (%s): %s", [categories[0], finding.message]),
		# `remediation` is optional in common_finding.v1.json and
		# Finding.to_dict() drops None fields, so a bare `finding.remediation`
		# makes this whole object undefined -- which drops the violation while
		# `allow` (keyed on owasp_findings) still reports false. Measured: two
		# findings, one without the key, produced `violations = 1` and the
		# message "Found 1 OWASP Top 10 violations".
		"remediation": object.get(finding, "remediation", ""),
	}
}

# Summary message
message := msg if {
	count(violations) > 0
	msg := sprintf("❌ Found %d OWASP Top 10 violations", [count(violations)])
} else := "✅ No OWASP Top 10 violations detected"

# Warnings for informational findings
warnings contains warning if {
	finding := owasp_findings[_]
	finding.severity == "INFO"
	warning := sprintf("INFO: %s - %s", [finding.ruleId, finding.message])
}
