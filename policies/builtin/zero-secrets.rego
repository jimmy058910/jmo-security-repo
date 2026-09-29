package jmo.policy.secrets

import future.keywords.if
import future.keywords.in

metadata := {
	"name": "Zero Secrets Policy",
	"version": "1.3.0",
	"description": "Blocks all verified secrets (zero tolerance)",
	"author": "JMo Security",
	"tags": ["secrets", "credentials", "zero-trust"],
	"frameworks": ["NIST CSF", "CIS Controls"],
}

default allow := false

# Secret detection tools
secret_tools := ["trufflehog", "trivy"]

# Allow only if zero verified secrets
allow if {
	count(verified_secrets) == 0
}

# The right tool, at a severity worth blocking. Split out so both
# verification signals below share one definition of "candidate".
secret_candidates contains finding if {
	finding := input.findings[_]
	reported_by(finding, secret_tools)
	finding.severity in ["CRITICAL", "HIGH"]
}

# Whether one of `tools` reported `finding`. A consensus finding (cross-tool
# clustering) carries its lead's `tool` and lists every tool that reported it
# in `detected_by`, so its own `tool.name` is one reporter of several: on a
# severity tie gitleaks, which this policy does not list, leads a gitleaks +
# TruffleHog pair, and reading `tool.name` alone passed a verified TruffleHog
# secret whenever gitleaks also found it (#1355). A finding no other tool
# reported has no `detected_by`, so the first definition stays.
reported_by(finding, tools) if finding.tool.name in tools

reported_by(finding, tools) if {
	some reporter in finding.detected_by
	reporter.name in tools
}

# A secret counts as verified on either signal, unioned as a set so a finding
# matching both is still counted once.
#
# `tags` is the NORMALISED signal and the one a policy should read:
# trufflehog_adapter.py writes tags ["secrets", "verified"|"unverified"] into
# CommonFinding v1.2.0. `raw.Verified` is TruffleHog's own spelling, kept
# because `raw` preserves the tool's record verbatim -- and it is checked by
# tests/unit/test_policy_field_contract.py against a finding a real adapter
# actually produced, so it cannot rot into another dead read.
#
# This rule previously read ONLY `finding.raw.verified`, and nothing has ever
# produced that key: TruffleHog emits `Verified` (capital V) and the adapter
# stores its record unaltered (`raw=f`). Measured 2026-08-20 -- a findings file
# holding one verified AWS key, built by running a real TruffleHog record
# through the real adapter, evaluated to `allow = true`, and
# `jmo report --policy zero-secrets` wrote "PASSED / No verified secrets
# detected" into POLICY_REPORT.md. The policy described as "blocks all verified
# secrets" had never blocked one, in any release.
verified_secrets contains finding if {
	finding := secret_candidates[_]
	"verified" in finding.tags
}

verified_secrets contains finding if {
	finding := secret_candidates[_]
	finding.raw.Verified == true
}

# A consensus finding's `raw` is its lead's; each other member keeps its own
# in its `context.duplicates` entry. The `verified` tag reaches the consensus
# either way (tags are merged), so this arm matters only for a TruffleHog
# record carrying `raw.Verified` without the tag -- the same degenerate input
# the arm above is kept for.
verified_secrets contains finding if {
	finding := secret_candidates[_]
	some duplicate in finding.context.duplicates
	duplicate.raw.Verified == true
}

# The secrets this policy passes: every one no tool verified. TruffleHog
# verifies only with `per_tool.trufflehog.verify: true`, off by default since
# v2.0.0, and gitleaks never does. So without that setting every secret passes
# here, and the message said only "No verified secrets detected", with no hint
# why (#1327). Said in the message and as a warning; the verdict is unchanged.
unverified_secrets contains finding if {
	finding := input.findings[_]
	"secrets" in finding.tags
	not finding in verified_secrets
}

warnings contains warning if {
	count(unverified_secrets) > 0
	warning := sprintf(
		"%d secret(s) are not verified, and this policy blocks verified secrets only: TruffleHog verifies with per_tool.trufflehog.verify: true, gitleaks never does",
		[count(unverified_secrets)],
	)
}

violations contains violation if {
	finding := verified_secrets[_]
	violation := {
		"fingerprint": finding.id,
		"severity": "CRITICAL", # Always critical for verified secrets
		"tool": finding.tool.name,
		"path": finding.location.path,
		# `startLine` is optional in common_finding.v1.json. A bare
		# `finding.location.startLine` makes this whole object undefined when
		# it is absent, which drops the violation silently while `allow` still
		# reports false -- a FAIL that under-reports what failed.
		"line": object.get(finding.location, "startLine", 0),
		"message": sprintf("🔴 VERIFIED SECRET: %s", [finding.message]),
		"remediation": "Rotate credentials immediately and remove from version control history",
	}
}

message := msg if {
	count(violations) > 0
	msg := sprintf("🚨 CRITICAL: Found %d verified secrets - IMMEDIATE ACTION REQUIRED", [count(violations)])
} else := msg if {
	count(unverified_secrets) > 0
	msg := sprintf(
		"✅ No verified secrets detected; %d secret(s) are not verified, so not blocked (per_tool.trufflehog.verify: true verifies TruffleHog's)",
		[count(unverified_secrets)],
	)
} else := "✅ No verified secrets detected"
