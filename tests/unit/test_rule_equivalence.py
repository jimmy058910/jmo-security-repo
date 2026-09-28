"""Tests for rule equivalence mapping (rule_equivalence.py).

This module tests the cross-tool rule equivalence mapping that enables
better deduplication of findings from different security tools.

Example:
    Trivy "DS-0001" ("':latest' tag used") and Hadolint "DL3006" report the
    same issue and should be recognized as equivalent.

Author: JMo Security
Version: 1.0.0
"""

from pathlib import Path

import pytest
import yaml

from scripts.core.rule_equivalence import (
    RULE_EQUIVALENCE,
    are_rules_equivalent,
    get_canonical_rule_id,
)

# trivy 0.74.0's own output; how it was recorded is in the docstring of
# tests/adapters/test_trivy_adapter.py.
RECORDED_TRIVY_074 = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "samples"
    / "trivy"
    / "misconfig-0.74.json"
)


def _trivy_074_findings():
    """The recorded output, through the real adapter (47 misconfigurations)."""
    from scripts.core.adapters.trivy_adapter import TrivyAdapter

    findings = TrivyAdapter().parse(RECORDED_TRIVY_074)
    assert len(findings) == 47, len(findings)
    return findings


class TestRuleEquivalenceMapping:
    """Test the RULE_EQUIVALENCE mapping structure."""

    def test_maps_the_documented_cross_tool_equivalence(self):
        """The module docstring's own example, asserted.

        ``test_mapping_structure`` below is a ``for ... in RULE_EQUIVALENCE``
        loop, so an emptied mapping passes it vacuously; the replaced
        ``isinstance``/``len > 0`` pair was the only guard, and it could not
        notice a canonical id losing the very tools it exists to equate.
        """
        latest_tag = RULE_EQUIVALENCE["dockerfile-latest-tag"]
        assert ("trivy", "DS-0001") in latest_tag
        assert ("hadolint", "DL3006") in latest_tag
        # An equivalence naming one tool cannot dedupe anything across tools.
        assert len({tool for tool, _ in latest_tag}) >= 2

    def test_mapping_structure(self):
        """Test that all entries have correct structure."""
        for canonical_id, mappings in RULE_EQUIVALENCE.items():
            # Canonical ID should be lowercase-with-dashes
            assert canonical_id == canonical_id.lower()
            assert "-" in canonical_id or canonical_id.isalpha()

            # Mappings should be list of (tool, rule_id) tuples
            assert isinstance(mappings, list)
            assert len(mappings) >= 2  # Need at least 2 tools for equivalence

            for mapping in mappings:
                assert isinstance(mapping, tuple)
                assert len(mapping) == 2
                tool, rule_id = mapping
                assert isinstance(tool, str)
                assert isinstance(rule_id, str)

    def test_dockerfile_latest_tag_equivalence(self):
        """Test that Dockerfile :latest tag rules are mapped."""
        assert "dockerfile-latest-tag" in RULE_EQUIVALENCE
        mappings = RULE_EQUIVALENCE["dockerfile-latest-tag"]

        # Should have Trivy, Hadolint, and Checkov
        tools = {m[0] for m in mappings}
        assert "trivy" in tools
        assert "hadolint" in tools
        assert "checkov" in tools


class TestGetCanonicalRuleId:
    """Test the get_canonical_rule_id function."""

    def test_hadolint_dl3006(self):
        """Test Hadolint DL3006 maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("hadolint", "DL3006")
        assert canonical == "dockerfile-latest-tag"

    def test_trivy_latest_tag(self):
        """Test Trivy's :latest tag check (DS-0001) maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("trivy", "DS-0001")
        assert canonical == "dockerfile-latest-tag"

    def test_checkov_docker_7(self):
        """Checkov CKV_DOCKER_7 is its latest-tag check.

        CKV_DOCKER_1 stood here until #1221; checkov's own name for it is
        "Ensure port 22 is not exposed".
        """
        assert get_canonical_rule_id("checkov", "CKV_DOCKER_7") == (
            "dockerfile-latest-tag"
        )
        assert get_canonical_rule_id("checkov", "CKV_DOCKER_1") == (
            "dockerfile-port-22-exposed"
        )

    def test_hadolint_dl3057(self):
        """Hadolint's missing-HEALTHCHECK rule is DL3057, not DL3055.

        hadolint 2.14.0's own messages: DL3057 "`HEALTHCHECK` instruction
        missing.", DL3055 "Label `commit` is not a valid git hash."
        """
        assert get_canonical_rule_id("hadolint", "DL3057") == (
            "dockerfile-no-healthcheck"
        )
        assert get_canonical_rule_id("hadolint", "DL3055") is None

    def test_trivy_no_healthcheck(self):
        """Test Trivy's HEALTHCHECK check (DS-0026) maps correctly."""
        canonical = get_canonical_rule_id("trivy", "DS-0026")
        assert canonical == "dockerfile-no-healthcheck"

    def test_case_insensitive_tool(self):
        """Test that tool name matching is case insensitive."""
        canonical1 = get_canonical_rule_id("HADOLINT", "DL3006")
        canonical2 = get_canonical_rule_id("hadolint", "DL3006")
        canonical3 = get_canonical_rule_id("Hadolint", "DL3006")

        assert canonical1 == canonical2 == canonical3 == "dockerfile-latest-tag"

    def test_unknown_tool(self):
        """Test unknown tool returns None."""
        canonical = get_canonical_rule_id("unknown_tool", "SOME_RULE")
        assert canonical is None

    def test_unknown_rule(self):
        """Test unknown rule returns None."""
        canonical = get_canonical_rule_id("hadolint", "UNKNOWN_RULE_12345")
        assert canonical is None

    def test_empty_inputs(self):
        """Test empty inputs return None."""
        assert get_canonical_rule_id("", "DL3006") is None
        assert get_canonical_rule_id("hadolint", "") is None


class TestAreRulesEquivalent:
    """Test the are_rules_equivalent function."""

    def test_trivy_hadolint_latest_tag(self):
        """Test Trivy and Hadolint :latest tag rules are equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "trivy", "DS-0001", "hadolint", "DL3006"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_hadolint_checkov_latest_tag(self):
        """Test Hadolint and Checkov :latest tag rules are equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "checkov", "CKV_DOCKER_7"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_different_issues_not_equivalent(self):
        """Test different issues are not marked as equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint",
            "DL3006",
            "hadolint",
            "DL3057",  # :latest tag  # no healthcheck
        )
        assert is_equiv is False
        assert canonical is None

    def test_same_tool_same_rule(self):
        """Test same tool with same rule is equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "hadolint", "DL3006"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_unknown_rules_not_equivalent(self):
        """Test unknown rules are not marked as equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "unknown_tool", "RULE_A", "another_tool", "RULE_B"
        )
        assert is_equiv is False
        assert canonical is None

    def test_one_known_one_unknown(self):
        """Test one known rule with one unknown rule is not equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "unknown_tool", "SOME_RULE"
        )
        assert is_equiv is False
        assert canonical is None


class TestSecretDetectionEquivalence:
    """Test equivalence for secret detection rules."""

    def test_aws_access_key_equivalence(self):
        """Test AWS access key detection across tools."""
        # Check that at least some AWS-related rules exist
        canonical = get_canonical_rule_id("trufflehog", "AWS")
        # May or may not match depending on exact mapping
        # Just verify no errors occur
        assert canonical is None or canonical == "secret-aws-access-key"

    def test_github_token_equivalence(self):
        """Test GitHub token detection across tools.

        Used to assert on `("gitleaks", "github-pat")`, removed in #846
        because gitleaks had no adapter then. A later edit substituted
        `("trufflehog", "github-pat")` as a stand-in -- but `github-pat` is
        gitleaks' own rule id, not trufflehog's (trufflehog's GitHub-PAT
        detector is named `Github`, see `test_aws_access_key_equivalence`'s
        sibling below), so that entry could never match a real trufflehog
        finding either (#1328). Since #1330 gitleaks has a real adapter, so
        the correct tool is back.
        """
        canonical1 = get_canonical_rule_id("gitleaks", "github-pat")
        canonical2 = get_canonical_rule_id(
            "semgrep", "generic.secrets.security.detected-github-pat"
        )

        assert canonical1 == canonical2 == "secret-github-token"

        # The wrong tuple is gone from the table itself. (Not asserted as
        # `get_canonical_rule_id("trufflehog", "github-pat") is None`: the
        # substring fallback still resolves that query, coincidentally, via
        # trufflehog's own `Github` entry -- "github-pat" starts with
        # "github" at a `-` boundary. That fallback exists for a different
        # case (semgrep's dotted-suffix rule ids) and trufflehog never
        # actually reports a ruleId spelled `github-pat`, so it is not a
        # real-world false match, but it does mean the fallback is not
        # evidence either way here -- the table entry is.)
        assert ("trufflehog", "github-pat") not in (
            RULE_EQUIVALENCE["secret-github-token"]
        )


class TestGitleaksSecretEquivalence:
    """#1328: gitleaks 8.30.1's own ids, added to the secret classes.

    Ids and descriptions read from gitleaks' own default config
    (``config/gitleaks.toml`` at tag v8.30.1), the same discipline the trivy
    keys use (`TestTrivyKeysAreWhatTrivyPrints`).
    """

    def test_private_key_equivalence(self):
        """gitleaks `private-key` = trufflehog `PrivateKey` = semgrep's rule.

        Juice-shop `1618a611`, `terraform/networking.tf:171` (and its
        `infrastructure/` copy): gitleaks and trufflehog each report the same
        committed private key on the one line, under these two ids.
        """
        assert are_rules_equivalent(
            "gitleaks", "private-key", "trufflehog", "PrivateKey"
        ) == (
            True,
            "secret-private-key",
        )
        assert (
            get_canonical_rule_id(
                "semgrep", "generic.secrets.security.detected-private-key"
            )
            == "secret-private-key"
        )

    def test_jwt_equivalence(self):
        """`secret-jwt`: gitleaks `jwt` = trufflehog `JWT`.

        Juice-shop `1618a611`, `test/cypress/e2e/forgedJwt.spec.ts:38` and
        `test/server/currentUser.unit.test.ts:31`: both tools report the same
        embedded JWT on the one line, under these two ids.
        """
        assert are_rules_equivalent("gitleaks", "jwt", "trufflehog", "JWT") == (
            True,
            "secret-jwt",
        )

    def test_aws_access_token_equivalence(self):
        """gitleaks `aws-access-token` = trufflehog `AWS`."""
        assert are_rules_equivalent(
            "gitleaks", "aws-access-token", "trufflehog", "AWS"
        ) == (
            True,
            "secret-aws-access-key",
        )

    def test_generic_api_key_is_deliberately_unmapped(self):
        """gitleaks' broadest secret rule joins no equivalence class.

        Juice-shop `test/api/user.test.ts:280` has gitleaks `jwt`, gitleaks
        `generic-api-key` AND trufflehog `JWT` all on one line. The first and
        third are a genuine cross-tool pair (`test_jwt_equivalence`); the
        second is gitleaks' own broader rule re-firing on the same secret,
        and mapping it into `secret-jwt` would be inert for this triple
        anyway -- `FindingCluster.can_accept` refuses a second finding from a
        tool already in the cluster, so gitleaks' `jwt` and `generic-api-key`
        can never share a cluster regardless of what this table says. It
        stays unmapped because it is not inert *everywhere*: the same rule
        fires 54 times on this one repo alone, on unrelated secrets, and
        location similarity is line-only (no column), so mapping it risks
        merging two distinct secrets that only happen to share a line.
        """
        assert get_canonical_rule_id("gitleaks", "generic-api-key") is None
        for canonical, members in RULE_EQUIVALENCE.items():
            assert ("gitleaks", "generic-api-key") not in members, canonical

    def test_jwt_base64_equivalence(self):
        """gitleaks `jwt-base64` joins `secret-jwt` too -- decided on purpose.

        Unlike `generic-api-key`, this is gitleaks' OWN narrower, structural
        rule for the same secret class (a base64-encoded JWT), not a broad
        catch-all: safe to list explicitly, and listed rather than left to
        the (now gitleaks-disabled) substring fallback that used to reach it
        coincidentally. See `TestGitleaksIdsAreExactMatchOnly` for the
        fallback removal this decision depends on.
        """
        assert get_canonical_rule_id("gitleaks", "jwt-base64") == "secret-jwt"


# gitleaks 8.30.1's full default-config id list (`config/gitleaks.toml` at tag
# v8.30.1), derived with:
#   gh api 'repos/gitleaks/gitleaks/contents/config/gitleaks.toml?ref=v8.30.1' \
#     --jq .content | base64 -d | grep -n '^id = "' | sed -E 's/^[0-9]+:id = "([^"]+)"/\1/' | sort
# Only the id *names* -- gitleaks' regexes and allowlist examples (some of
# which are real-looking key material used as test fixtures upstream) are
# deliberately not reproduced here.
GITLEAKS_8_30_1_DEFAULT_IDS = frozenset(
    {
        "1password-secret-key",
        "1password-service-account-token",
        "adafruit-api-key",
        "adobe-client-id",
        "adobe-client-secret",
        "age-secret-key",
        "airtable-api-key",
        "airtable-personnal-access-token",
        "algolia-api-key",
        "alibaba-access-key-id",
        "alibaba-secret-key",
        "anthropic-admin-api-key",
        "anthropic-api-key",
        "artifactory-api-key",
        "artifactory-reference-token",
        "asana-client-id",
        "asana-client-secret",
        "atlassian-api-token",
        "authress-service-client-access-key",
        "aws-access-token",
        "aws-amazon-bedrock-api-key-long-lived",
        "aws-amazon-bedrock-api-key-short-lived",
        "azure-ad-client-secret",
        "beamer-api-token",
        "bitbucket-client-id",
        "bitbucket-client-secret",
        "bittrex-access-key",
        "bittrex-secret-key",
        "cisco-meraki-api-key",
        "clickhouse-cloud-api-secret-key",
        "clojars-api-token",
        "cloudflare-api-key",
        "cloudflare-global-api-key",
        "cloudflare-origin-ca-key",
        "codecov-access-token",
        "cohere-api-token",
        "coinbase-access-token",
        "confluent-access-token",
        "confluent-secret-key",
        "contentful-delivery-api-token",
        "curl-auth-header",
        "curl-auth-user",
        "databricks-api-token",
        "datadog-access-token",
        "defined-networking-api-token",
        "digitalocean-access-token",
        "digitalocean-pat",
        "digitalocean-refresh-token",
        "discord-api-token",
        "discord-client-id",
        "discord-client-secret",
        "doppler-api-token",
        "droneci-access-token",
        "dropbox-api-token",
        "dropbox-long-lived-api-token",
        "dropbox-short-lived-api-token",
        "duffel-api-token",
        "dynatrace-api-token",
        "easypost-api-token",
        "easypost-test-api-token",
        "etsy-access-token",
        "facebook-access-token",
        "facebook-page-access-token",
        "facebook-secret",
        "fastly-api-token",
        "finicity-api-token",
        "finicity-client-secret",
        "finnhub-access-token",
        "flickr-access-token",
        "flutterwave-encryption-key",
        "flutterwave-public-key",
        "flutterwave-secret-key",
        "flyio-access-token",
        "frameio-api-token",
        "freemius-secret-key",
        "freshbooks-access-token",
        "gcp-api-key",
        "generic-api-key",
        "github-app-token",
        "github-fine-grained-pat",
        "github-oauth",
        "github-pat",
        "github-refresh-token",
        "gitlab-cicd-job-token",
        "gitlab-deploy-token",
        "gitlab-feature-flag-client-token",
        "gitlab-feed-token",
        "gitlab-incoming-mail-token",
        "gitlab-kubernetes-agent-token",
        "gitlab-oauth-app-secret",
        "gitlab-pat",
        "gitlab-pat-routable",
        "gitlab-ptt",
        "gitlab-rrt",
        "gitlab-runner-authentication-token",
        "gitlab-runner-authentication-token-routable",
        "gitlab-scim-token",
        "gitlab-session-cookie",
        "gitter-access-token",
        "gocardless-api-token",
        "grafana-api-key",
        "grafana-cloud-api-token",
        "grafana-service-account-token",
        "harness-api-key",
        "hashicorp-tf-api-token",
        "hashicorp-tf-password",
        "heroku-api-key",
        "heroku-api-key-v2",
        "hubspot-api-key",
        "huggingface-access-token",
        "huggingface-organization-api-token",
        "infracost-api-token",
        "intercom-api-key",
        "intra42-client-secret",
        "jfrog-api-key",
        "jfrog-identity-token",
        "jwt",
        "jwt-base64",
        "kraken-access-token",
        "kubernetes-secret-yaml",
        "kucoin-access-token",
        "kucoin-secret-key",
        "launchdarkly-access-token",
        "linear-api-key",
        "linear-client-secret",
        "linkedin-client-id",
        "linkedin-client-secret",
        "lob-api-key",
        "lob-pub-api-key",
        "looker-client-id",
        "looker-client-secret",
        "mailchimp-api-key",
        "mailgun-private-api-token",
        "mailgun-pub-key",
        "mailgun-signing-key",
        "mapbox-api-token",
        "mattermost-access-token",
        "maxmind-license-key",
        "messagebird-api-token",
        "messagebird-client-id",
        "microsoft-teams-webhook",
        "netlify-access-token",
        "new-relic-browser-api-token",
        "new-relic-insert-key",
        "new-relic-user-api-id",
        "new-relic-user-api-key",
        "notion-api-token",
        "npm-access-token",
        "nuget-config-password",
        "nytimes-access-token",
        "octopus-deploy-api-key",
        "okta-access-token",
        "openai-api-key",
        "openshift-user-token",
        "perplexity-api-key",
        "pkcs12-file",
        "plaid-api-token",
        "plaid-client-id",
        "plaid-secret-key",
        "planetscale-api-token",
        "planetscale-oauth-token",
        "planetscale-password",
        "postman-api-token",
        "prefect-api-token",
        "privateai-api-token",
        "private-key",
        "pulumi-api-token",
        "pypi-upload-token",
        "rapidapi-access-token",
        "readme-api-token",
        "rubygems-api-token",
        "scalingo-api-token",
        "sendbird-access-id",
        "sendbird-access-token",
        "sendgrid-api-token",
        "sendinblue-api-token",
        "sentry-access-token",
        "sentry-org-token",
        "sentry-user-token",
        "settlemint-application-access-token",
        "settlemint-personal-access-token",
        "settlemint-service-access-token",
        "shippo-api-token",
        "shopify-access-token",
        "shopify-custom-access-token",
        "shopify-private-app-access-token",
        "shopify-shared-secret",
        "sidekiq-secret",
        "sidekiq-sensitive-url",
        "slack-app-token",
        "slack-bot-token",
        "slack-config-access-token",
        "slack-config-refresh-token",
        "slack-legacy-bot-token",
        "slack-legacy-token",
        "slack-legacy-workspace-token",
        "slack-user-token",
        "slack-webhook-url",
        "snyk-api-token",
        "sonar-api-token",
        "sourcegraph-access-token",
        "square-access-token",
        "squarespace-access-token",
        "stripe-access-token",
        "sumologic-access-id",
        "sumologic-access-token",
        "telegram-bot-api-token",
        "travisci-access-token",
        "twilio-api-key",
        "twitch-api-token",
        "twitter-access-secret",
        "twitter-access-token",
        "twitter-api-key",
        "twitter-api-secret",
        "twitter-bearer-token",
        "typeform-api-token",
        "vault-batch-token",
        "vault-service-token",
        "yandex-access-token",
        "yandex-api-key",
        "yandex-aws-access-token",
        "zendesk-secret-key",
    }
)

# The only ids, of all 222 above, this table intends to resolve. Everything
# else must resolve to None.
_GITLEAKS_EXPECTED_RESOLUTIONS = {
    "aws-access-token": "secret-aws-access-key",
    "github-pat": "secret-github-token",
    "private-key": "secret-private-key",
    "jwt": "secret-jwt",
    "jwt-base64": "secret-jwt",
}


class TestGitleaksIdsAreExactMatchOnly:
    """Fix-round-1 (#1328): pin the resolved canonical set over EVERY
    gitleaks 8.30.1 default-config id, not just the five this table lists.

    Before this fix-round, `get_canonical_rule_id("gitleaks",
    "yandex-aws-access-token")` returned `secret-aws-access-key` and
    `get_canonical_rule_id("gitleaks", "jwt-base64")` returned `secret-jwt` --
    both via the substring fallback finding a `-`-delimited prefix match
    against a listed gitleaks id, not because either was actually listed.
    The first was a real false equivalence (a Yandex Cloud key is not an AWS
    one); the second happened to be the right answer for the wrong reason,
    and is now listed explicitly (`test_jwt_base64_equivalence` above).
    """

    def test_meta_guard_the_id_list_itself_is_not_empty_or_truncated(self):
        """An extractor that silently found nothing would pass every
        assertion built on it (testing.rules.md's "mirror of a mirror")."""
        assert len(GITLEAKS_8_30_1_DEFAULT_IDS) == 222, len(GITLEAKS_8_30_1_DEFAULT_IDS)
        # A few ids from different parts of the alphabet, spot-checked
        # against the fetched config directly.
        for must_have in (
            "aws-access-token",
            "github-pat",
            "private-key",
            "jwt",
            "jwt-base64",
            "generic-api-key",
            "yandex-aws-access-token",
            "zendesk-secret-key",
        ):
            assert must_have in GITLEAKS_8_30_1_DEFAULT_IDS, must_have

    def test_the_snapshot_is_of_the_gitleaks_versions_yaml_pins(self):
        """The id list is a hand snapshot of one release's config. A gitleaks
        bump can add an id a listed one prefixes, or one that belongs in a
        class, and every test here would still pass against the old list."""
        versions = yaml.safe_load(
            (Path(__file__).resolve().parents[2] / "versions.yaml").read_bytes()
        )
        pinned = str(versions["binary_tools"]["gitleaks"]["version"])
        assert pinned == "8.30.1", (
            f"versions.yaml pins gitleaks {pinned}, but GITLEAKS_8_30_1_DEFAULT_IDS "
            f"is gitleaks 8.30.1's id list. Re-derive it from config/gitleaks.toml "
            f"at tag v{pinned} (the command is above the list), rename it, and "
            f"re-check test_only_the_five_intended_ids_resolve against it."
        )

    def test_only_the_five_intended_ids_resolve(self):
        resolved = {
            gid: canonical
            for gid in GITLEAKS_8_30_1_DEFAULT_IDS
            if (canonical := get_canonical_rule_id("gitleaks", gid)) is not None
        }
        assert resolved == _GITLEAKS_EXPECTED_RESOLUTIONS, (
            f"gitleaks id(s) resolved that should not have, or vice versa: "
            f"extra={set(resolved) - set(_GITLEAKS_EXPECTED_RESOLUTIONS)}, "
            f"missing={set(_GITLEAKS_EXPECTED_RESOLUTIONS) - set(resolved)}"
        )

    def test_yandex_aws_access_token_is_not_an_aws_key(self):
        """The measured false equivalence this fix-round exists for.

        A Yandex Cloud static key formatted to resemble an AWS one (`YC...`)
        is not an AWS credential. Merging a gitleaks
        `yandex-aws-access-token` finding with a trufflehog `AWS` finding on
        one line would be exactly #1242's shape (two different secrets, one
        line) -- see `test_dedup_enhanced.py`'s
        `test_gitleaks_yandex_key_and_trufflehog_aws_on_one_line_stay_two`
        for the cross-tool clustering-level guard.
        """
        assert get_canonical_rule_id("gitleaks", "yandex-aws-access-token") is None

    def test_gitleaks_case_insensitive_exact_match_still_works(self):
        """Exact-match-only must not also disable the case-insensitive path."""
        assert get_canonical_rule_id("gitleaks", "PRIVATE-KEY") == "secret-private-key"
        assert get_canonical_rule_id("gitleaks", "Jwt") == "secret-jwt"

    def test_other_tools_fallback_is_unaffected(self):
        """The gitleaks-only exclusion must not disable the fallback for the
        tools it was built for."""
        assert get_canonical_rule_id("trivy", "AVD-DS-0001") == "dockerfile-latest-tag"
        assert (
            get_canonical_rule_id(
                "semgrep",
                "generic.secrets.security.detected-github-pat.detected-github-pat",
            )
            == "secret-github-token"
        )


class TestKubernetesEquivalence:
    """Test equivalence for Kubernetes rules."""

    def test_privileged_container(self):
        """Test privileged container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV-0017")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_16")

        assert canonical1 == canonical2 == "k8s-privileged-container"
        # CKV_K8S_1 stood here until #1221: a PodSecurityPolicy's host PID.
        assert get_canonical_rule_id("checkov", "CKV_K8S_1") == "k8s-host-pid"
        # KSV-0001 is "Can elevate its own privileges", a different control;
        # the table listed its old id, KSV001, here until #1221.
        assert get_canonical_rule_id("trivy", "KSV-0001") == "k8s-privilege-escalation"

    def test_root_container(self):
        """Test root container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV-0012")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_6")

        assert canonical1 == canonical2 == "k8s-root-container"


class TestTrivyKeysAreWhatTrivyPrints:
    """The trivy keys, checked against trivy 0.74.0's recorded output.

    Until #1221 the adapter made a misconfiguration's ``Title`` its rule id,
    so the table keyed trivy by Titles and by old ids (``DS001``,
    ``KSV001``). 0.74.0 prints ``DS-0001``: measured on the recorded output,
    no old id and only three Titles still matched anything, and eight old ids
    named a different check than their group (``DS031`` sat in the open
    security-group group; it is the Dockerfile secrets check).
    """

    def test_hadolint_dl3006_and_trivys_latest_tag_finding_are_one_issue(self):
        latest = [f for f in _trivy_074_findings() if f.title == "':latest' tag used"]
        # Both FROM lines of the recorded Dockerfile.
        assert [f.location["startLine"] for f in latest] == [1, 5]
        for f in latest:
            assert are_rules_equivalent("hadolint", "DL3006", "trivy", f.ruleId) == (
                True,
                "dockerfile-latest-tag",
            )

    def test_every_trivy_key_is_an_id_trivy_prints(self):
        """Derived from the recorded output, so a Title or old-form key fails."""
        printed = {f.ruleId for f in _trivy_074_findings()}
        keys = {
            rule
            for members in RULE_EQUIVALENCE.values()
            for tool, rule in members
            if tool == "trivy"
        }
        assert len(keys) >= 10, sorted(keys)
        assert keys <= printed, f"no 0.74.0 finding carries {sorted(keys - printed)}"

    def test_what_matched_by_title_still_matches_by_id(self):
        """Measured before the fix: ruleId = Title reached exactly three groups."""
        canonical = {
            f.ruleId: get_canonical_rule_id("trivy", f.ruleId)
            for f in _trivy_074_findings()
        }
        assert canonical["DS-0002"] == "dockerfile-no-user"
        assert canonical["DS-0026"] == "dockerfile-no-healthcheck"
        assert canonical["KSV-0017"] == "k8s-privileged-container"

    def test_no_recorded_id_reaches_a_group_it_is_not_listed_in(self):
        """The substring fallback must not carry one id into another's group."""
        for f in _trivy_074_findings():
            got = get_canonical_rule_id("trivy", f.ruleId)
            if got is not None:
                assert ("trivy", f.ruleId) in RULE_EQUIVALENCE[got], (f.ruleId, got)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_substring_matching(self):
        """A delimited id carrying a mapped id still resolves.

        trivy's ``AVD-DS-0001`` spelling (its ``aliases``) holds ``DS-0001``
        between delimiters, so the boundary fallback reaches the same group.
        """
        canonical = get_canonical_rule_id("trivy", "AVD-DS-0001")
        assert canonical == "dockerfile-latest-tag"

    def test_reverse_map_caching(self):
        """Test that repeated calls use cached reverse map."""
        # Call multiple times - should be fast due to caching
        for _ in range(100):
            get_canonical_rule_id("hadolint", "DL3006")

        # Just verify no errors - caching is internal implementation


class TestSubstringFallbackBoundaries:
    """The substring fallback must not prefix-match structured rule IDs.

    `get_canonical_rule_id` falls back to substring matching so a rule ID that
    carries a suffix still resolves -- semgrep reports a registry rule as
    `<path>.<rule>`, e.g. `...detected-github-pat.detected-github-pat` for the
    rule mapped here as `...detected-github-pat`. Plain containment made that
    fallback fire on the trailing number of every structured ID as well.
    """

    def test_numeric_suffix_does_not_prefix_match(self):
        """CKV_K8S_1 is a substring of CKV_K8S_14 but a different rule.

        CKV_K8S_16 and CKV_K8S_17 are listed in groups of their own since
        #1221, so each must reach its own group, never CKV_K8S_1's.
        """
        host_pid = get_canonical_rule_id("checkov", "CKV_K8S_1")
        assert host_pid == "k8s-host-pid"
        for unrelated in (
            "CKV_K8S_10",
            "CKV_K8S_14",
            "CKV_K8S_15",
            "CKV_K8S_16",
            "CKV_K8S_17",
            "CKV_K8S_18",
        ):
            got = get_canonical_rule_id("checkov", unrelated)
            assert got is None or ("checkov", unrelated) in RULE_EQUIVALENCE[got], (
                f"{unrelated} resolved to {got}, a group it is not listed in"
            )
        # CKV_K8S_17 is listed in k8s-host-pid itself; the other five are not.
        for unrelated in (
            "CKV_K8S_10",
            "CKV_K8S_14",
            "CKV_K8S_15",
            "CKV_K8S_16",
            "CKV_K8S_18",
        ):
            assert get_canonical_rule_id("checkov", unrelated) != host_pid

    def test_shorter_id_is_not_captured_by_a_longer_mapped_one(self):
        """The reverse direction was broken too: CKV_AWS_1 inside CKV_AWS_19."""
        assert get_canonical_rule_id("checkov", "CKV_AWS_1") is None
        assert get_canonical_rule_id("checkov", "CKV_AWS_2") is None

    def test_three_digit_ids_are_not_captured_by_single_digit_ones(self):
        """CKV_AWS_3 (mapped) must not swallow every CKV_AWS_3xx rule."""
        assert (
            get_canonical_rule_id("checkov", "CKV_AWS_3") == "iac-unencrypted-storage"
        )
        for unrelated in (
            "CKV_AWS_30",
            "CKV_AWS_35",
            "CKV_AWS_300",
            "CKV_AWS_353",
            "CKV_AWS_355",
            "CKV_AWS_382",
        ):
            assert get_canonical_rule_id("checkov", unrelated) is None, (
                f"{unrelated} must not resolve to CKV_AWS_3's canonical id"
            )

    def test_unrelated_checkov_rules_are_not_equivalent(self):
        """The measured regression: two different k8s controls scored 1.0 metadata."""
        equivalent, canonical = are_rules_equivalent(
            "checkov", "CKV_K8S_14", "checkov", "CKV_K8S_16"
        )
        assert equivalent is False, (
            f"'Image Tag should be fixed' and 'Container should not be "
            f"privileged' are different controls, got canonical={canonical}"
        )

    def test_separator_delimited_suffix_still_matches(self):
        """The case the fallback exists for must keep working.

        This drives a real cross-tool cluster (semgrep + gitleaks on one
        secret; gitleaks per #1328/#1330, replacing trufflehog here -- see
        `test_github_token_equivalence`'s docstring: `github-pat` is
        gitleaks' rule id, not a real trufflehog one). Tightening the
        fallback must not disable it.
        """
        semgrep_reported = (
            "generic.secrets.security.detected-github-pat.detected-github-pat"
        )
        assert get_canonical_rule_id("semgrep", semgrep_reported) == (
            "secret-github-token"
        )
        equivalent, canonical = are_rules_equivalent(
            "semgrep", semgrep_reported, "gitleaks", "github-pat"
        )
        assert equivalent is True
        assert canonical == "secret-github-token"

    def test_exact_table_entries_are_untouched(self):
        """Every (tool, rule) pair the table declares must still resolve."""
        for canonical, members in RULE_EQUIVALENCE.items():
            for tool, rule in members:
                assert get_canonical_rule_id(tool, rule) is not None, (
                    f"({tool}, {rule}) is in the table but no longer resolves"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
