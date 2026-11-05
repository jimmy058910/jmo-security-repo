"""Which bundled opengrep rules match a secret's value (#1585).

A finding from such a rule quotes the secret wherever it quotes the code: its
message (a rule can interpolate the matched value), its snippet, and the raw
record's `extra.lines`, `metavars` and `dataflow_trace`. Those then reach
`summaries/`, the dashboard and history. Decided 2026-11-05: a reviewed list.

`SECRET_LIKE_RULE_ID` is the net: every rule in `scripts/jmo_rules/` whose id it
matches is listed in `SECRET_VALUE_RULES` once, True when what it matches holds a
credential's value, False when it is about handling one (a weak hash, an empty
password, a key's expiry). `tests/unit/test_secret_value_rules.py` fails on a rule
the net catches and the list does not hold, so a bundle update cannot add one
silently. Any tool's finding with a hard-coded-credential CWE counts as well.
"""

from __future__ import annotations

import re

#: Rule ids that may name a secret. Widened by token|passwd|pwd|key it caught 27
#: more on 2026-11-05, none matching a value (key sizes, JWT verification);
#: `entropy` catches the one rule that looks for secret strings by randomness.
SECRET_LIKE_RULE_ID = re.compile(
    r"hard-?code|secret|password|credential|api-?key|private-key|entropy",
    re.IGNORECASE,
)

#: Hard-coded credentials, password and cryptographic key: a finding of any tool
#: carrying one quotes a secret whether or not its rule is listed.
CREDENTIAL_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321"})

# Rule ids, not credentials: bandit's B105 reads a key naming a password as one.
SECRET_VALUE_RULES: dict[str, bool] = {  # nosec B105
    # What the rule matches holds the value: a literal key, password, token or
    # session secret, a default value, or a value the message interpolates.
    "apex.lang.security.ncino.endpoints.NamedCredentialsConstantMatch.named-credentials-constant-match": True,
    "apex.lang.security.ncino.endpoints.NamedCredentialsStringMatch.named-credentials-string-match": True,
    "dockerfile.security.secret-in-build-arg.secret-in-build-arg": True,
    "generic.gradle.security.build-gradle-password-hardcoded.build-gradle-password-hardcoded": True,
    "go.jwt-go.security.jwt.hardcoded-jwt-key": True,
    "java.java-jwt.security.jwt-hardcode.java-jwt-hardcoded-secret": True,
    "javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret": True,
    "javascript.express.security.express-jwt-hardcoded-secret.express-jwt-hardcoded-secret": True,
    "javascript.jose.security.jwt-hardcode.hardcoded-jwt-secret": True,
    "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret": True,
    "javascript.lang.security.audit.hardcoded-hmac-key.hardcoded-hmac-key": True,
    "javascript.passport-jwt.security.passport-hardcode.hardcoded-passport-secret": True,
    "kotlin.gradle.security.build-gradle-password-hardcoded.build-gradle-password-hardcoded": True,
    "python.boto3.security.hardcoded-token.hardcoded-token": True,
    "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY": True,
    "python.jwt.security.jwt-exposed-credentials.jwt-python-exposed-credentials": True,
    "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret": True,
    "python.lang.security.audit.hardcoded-password-default-argument.hardcoded-password-default-argument": True,
    "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure": True,
    "ruby.jwt.security.jwt-exposed-credentials.ruby-jwt-exposed-credentials": True,
    "ruby.jwt.security.jwt-hardcode.ruby-jwt-hardcoded-secret": True,
    "ruby.lang.security.hardcoded-http-auth-in-controller.hardcoded-http-auth-in-controller": True,
    "ruby.lang.security.hardcoded-secret-rsa-passphrase.hardcoded-secret-rsa-passphrase": True,
    "ruby.rails.security.brakeman.check-rails-secret-yaml.check-rails-secret-yaml": True,
    "ruby.rails.security.brakeman.check-rails-session-secret-handling.check-rails-session-secret-handling": True,
    "ruby.rails.security.brakeman.check-secrets.check-secrets": True,
    "scala.jwt-scala.security.jwt-scala-hardcode.jwt-scala-hardcode": True,
    "scala.scala-jwt.security.jwt-hardcode.scala-jwt-hardcoded-secret": True,
    "terraform.aws.security.aws-lambda-environment-credentials.aws-lambda-environment-credentials": True,
    "terraform.aws.security.aws-provider-static-credentials.aws-provider-static-credentials": True,
    "terraform.lang.security.rds-insecure-password-storage-in-source-code.rds-insecure-password-storage-in-source-code": True,
    "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file": True,
    # Measured by the review of #1585: a default value (bicep), a literal
    # set_password() and basic-auth tuple, a high-entropy string, and a
    # resource whose snippet reaches its `value` line two lines down.
    "0xdea.c.high-entropy-assignment.raptor-high-entropy-assignment": True,
    "generic.bicep.security.secure-parameter-for-secrets.secure-parameter-for-secrets": True,
    "python.django.security.audit.unvalidated-password.unvalidated-password": True,
    "python.requests.security.no-auth-over-http.no-auth-over-http": True,
    "terraform.azure.security.keyvault.keyvault-ensure-secret-expires.keyvault-ensure-secret-expires": True,
    # About handling a secret, not its value: weak hashing, an empty or missing
    # password, a settings reference, a resource's encryption or expiry.
    "go.lang.security.audit.md5-used-as-password.md5-used-as-password": False,
    "java.lang.security.audit.md5-used-as-password.md5-used-as-password": False,
    "javascript.lang.security.audit.md5-used-as-password.md5-used-as-password": False,
    "php.lang.security.ldap-bind-without-password.ldap-bind-without-password": False,
    "php.lang.security.md5-used-as-password.md5-used-as-password": False,
    "python.django.security.hashids-with-django-secret.hashids-with-django-secret": False,
    "python.django.security.passwords.password-empty-string.password-empty-string": False,
    "python.django.security.passwords.use-none-for-password-default.use-none-for-password-default": False,
    "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_DEBUG": False,
    "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_ENV": False,
    "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_TESTING": False,
    "python.flask.security.hashids-with-flask-secret.hashids-with-flask-secret": False,
    "python.lang.security.audit.md5-used-as-password.md5-used-as-password": False,
    "ruby.lang.security.md5-used-as-password.md5-used-as-password": False,
    "terraform.aws.security.aws-secretsmanager-secret-unencrypted.aws-secretsmanager-secret-unencrypted": False,
    "terraform.azure.security.azure-scale-set-password.azure-scale-set-password": False,
    "yaml.openapi.security.api-key-in-query-parameter.api-key-in-query-parameter": False,
}


#: For each listed rule whose message interpolates metavariables (opengrep fills
#: `$NAME` with what it matched), the ones that hold the secret, () for none.
#: The adapter replaces their values in the message; prose like `$FUNC`'s
#: function name stays. A test fails on an interpolating rule not listed here.
MESSAGE_SECRET_METAVARS: dict[str, tuple[str, ...]] = {
    "python.lang.security.audit.hardcoded-password-default-argument."
    "hardcoded-password-default-argument": (),
    "python.lang.security.audit.logging.logger-credential-leak."
    "python-logger-credential-disclosure": ("$FORMAT_STRING",),
    "python.django.security.audit.unvalidated-password.unvalidated-password": (),
    "ruby.rails.security.brakeman.check-rails-secret-yaml.check-rails-secret-yaml": (
        "$VALUE",
    ),
    "ruby.rails.security.brakeman.check-rails-session-secret-handling."
    "check-rails-session-secret-handling": (),
    "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file": (
        "$VALUE",
    ),
}


#: The message of each rule whose message carries the secret, as the bundle
#: writes it, `$NAME` unfilled. The adapter rebuilds such a message from it with
#: the secret's metavariables set to "[redacted]": opengrep renders a value into
#: the message as the source spells it, which `abstract_content` does not (a
#: test holds these equal to the bundle).
MESSAGE_TEMPLATES: dict[str, str] = {
    "python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure": (
        "Detected a python logger call with a potential hardcoded secret $FORMAT_STRING being logged. This may lead to secret credentials being exposed. Make sure that the logger is not logging  sensitive information."
    ),
    "ruby.rails.security.brakeman.check-rails-secret-yaml.check-rails-secret-yaml": (
        "$VALUE Found a string literal assignment to a production Rails session secret in `secrets.yaml`. Do not commit secret values to source control! Any user in possession of this value may falsify arbitrary session data in your application. Read this value from an environment variable, KMS, or file on disk outside of source control."
    ),
    "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file": (
        "Secrets ($VALUE) should not be stored in infrastructure as code files. Use an alternative such as Bitnami Sealed Secrets or KSOPS to encrypt Kubernetes Secrets. "
    ),
}


def _cwe_ids(cwes: object) -> set[str]:
    values = cwes if isinstance(cwes, (list, tuple, set)) else [cwes]
    return {
        m.group(0).upper()
        for c in values
        for m in re.finditer(r"CWE-\d+", str(c), re.IGNORECASE)
    }


def is_secret_value_finding(rule_id: str, cwes: object = ()) -> bool:
    """Whether a finding quotes a credential's value: its rule is listed True, or
    it carries a hard-coded-credential CWE (`CWE-798: ...` spellings included)."""
    return SECRET_VALUE_RULES.get(rule_id, False) or bool(
        _cwe_ids(cwes) & CREDENTIAL_CWES
    )
