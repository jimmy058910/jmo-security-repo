package jmo.policy.production

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "Production Hardening Policy",
	"version": "1.2.0",
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
	reported_by(finding, ["hadolint"])
	finding.severity in ["CRITICAL", "HIGH"]
	contains(lower(finding.location.path), "dockerfile")
}

# Any secrets (verified or not)
secret_findings contains finding if {
	finding := input.findings[_]
	reported_by(finding, ["trufflehog"])
	finding.severity in ["CRITICAL", "HIGH"]
}

# Whether one of `tools` reported `finding`. A consensus finding (cross-tool
# clustering) carries its lead's `tool` and lists every tool that reported it
# in `detected_by`: on a severity tie the lead is the first tool by name, so
# gitleaks or semgrep leads a TruffleHog secret, and checkov a hadolint
# Dockerfile rule, and reading `tool.name` alone moved those findings out of
# their category (#1355). A finding no other tool reported has no
# `detected_by`, so the first definition stays.
reported_by(finding, tools) if finding.tool.name in tools

reported_by(finding, tools) if {
	some reporter in finding.detected_by
	reporter.name in tools
}

# The three populations below overlap -- a verified TruffleHog secret is a
# `secret_findings` member AND a `blocking_findings` member (HIGH). Rego keeps
# set members that differ in any field, so before these `not` guards one finding
# produced two violations under two categories with the same fingerprint, and
# the gate reported "Production gate FAILED: 2 blocking issues" for a single
# finding. Measured 2026-08-20 end to end through `jmo report --policy`.
#
# Ordered most-specific first: secrets, then dockerfile, then plain severity.
violations contains violation if {
	finding := blocking_findings[_]
	not finding in secret_findings
	not finding in dockerfile_issues
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
	not finding in secret_findings
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
