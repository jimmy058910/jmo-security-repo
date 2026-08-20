package jmo.policy.hipaa

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "HIPAA Security Rule Compliance",
	"version": "1.1.0",
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

# `risk.cwe` is an ARRAY of strings in CommonFinding v1.2.0
# (docs/schemas/common_finding.v1.json). Adapters store either the bare id
# ("CWE-798", semgrep-secrets) or the id with its description appended
# ("CWE-78: Improper Neutralization ...", most others), so canonicalise to the
# bare id -- which is what `hipaa_cwes` and `safeguard_map` are keyed on.
#
# This rule previously computed `sprintf("CWE-%d", [finding.risk.cwe])` against
# that array. Go's %d verb applied to a non-integer yields the format-error text
# `CWE-%!d(string=["CWE-78: ..."])`, which matches nothing, so `hipaa_findings`
# was ALWAYS empty and `allow` was unconditionally true: the policy answered
# "HIPAA technical safeguards requirements satisfied" for every possible input.
# Measured 2026-08-20 against a real 263-finding scan carrying 2 CRITICAL and
# 28 HIGH findings, 115 of them with a populated `risk.cwe`.
#
# This is the same `risk.cwe` shape defect #854 fixed on the Python side with
# `compliance_mapper.normalise_cwe_ids`; the Rego side was never updated.
cwe_ids(finding) := ids if {
	ids := {id |
		raw := finding.risk.cwe[_]
		id := canonical_cwe(raw)
	}
}

# Mirrors compliance_mapper.normalise_cwe_ids, which is the Python side's
# answer to the same problem: accept "CWE-79", "CWE-79: description", "cwe_79"
# and the bare integer 79 (bandit stores `issue_cwe.id` as an int). Anything
# else is undefined here, so the comprehension above drops it rather than
# failing the rule.
canonical_cwe(raw) := id if {
	is_number(raw)
	id := sprintf("CWE-%d", [raw])
}

canonical_cwe(raw) := id if {
	not is_number(raw)
	m := regex.find_all_string_submatch_n(`(?i)CWE[-_ ]?([0-9]+)`, raw, 1)
	id := sprintf("CWE-%s", [m[0][1]])
}

# Findings with HIPAA-critical CWEs
hipaa_findings contains finding if {
	finding := input.findings[_]
	cwe_ids(finding)[_] in hipaa_cwes
}

# One violation per (finding, breached safeguard) -- the message below counts
# "technical safeguard failures", so a finding breaching two safeguards is two.
hipaa_violations contains violation if {
	finding := hipaa_findings[_]
	finding.severity in ["CRITICAL", "HIGH"]
	cwe := cwe_ids(finding)[_]
	cwe in hipaa_cwes
	violation := {
		"fingerprint": finding.id,
		"severity": finding.severity,
		"cwe": cwe,
		"safeguard": hipaa_safeguard(cwe),
		"rule": finding.ruleId,
		"message": finding.message,
		# `remediation` is optional in common_finding.v1.json and
		# Finding.to_dict() drops None fields, so a bare `finding.remediation`
		# makes this whole object undefined and drops the violation silently.
		"remediation": object.get(finding, "remediation", ""),
	}
}

# Map CWE to HIPAA technical safeguard
hipaa_safeguard(cwe) := safeguard if {
	safeguard_map := {
		"CWE-22": "164.312(a)(1) - Access Control",
		"CWE-79": "164.312(a)(1) - Access Control",
		"CWE-89": "164.312(a)(1) - Access Control",
		"CWE-200": "164.312(a)(1) - Access Control",
		"CWE-284": "164.312(a)(1) - Access Control",
		"CWE-306": "164.312(d) - Person/Entity Authentication",
		"CWE-319": "164.312(e)(1) - Transmission Security",
		"CWE-326": "164.312(a)(2)(iv) - Encryption",
		"CWE-327": "164.312(a)(2)(iv) - Encryption",
		"CWE-798": "164.312(a)(2)(i) - Unique User ID",
	}
	safeguard := safeguard_map[cwe]
}

violations := hipaa_violations

message := msg if {
	count(violations) > 0
	msg := sprintf("❌ HIPAA violations: %d technical safeguard failures", [count(violations)])
} else := "✅ HIPAA technical safeguards requirements satisfied"
