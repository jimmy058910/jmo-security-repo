"""An opengrep finding whose rule matches a secret's value never quotes the secret (#1585).

Measured with `jmo ci --tools opengrep` on planted secrets: a finding from such a
rule carried the secret in its snippet, in the raw record's `extra.lines`,
`metavars` and `dataflow_trace`, and, for rules whose message interpolates what
they matched, in its message, which also feeds the finding's id. All of that
reached summaries/, the dashboard, the PCI report and history. The adapter now
redacts such a finding before its id is computed, as trufflehog's drops `Raw`
(redaction, not enrichment); the report redacts `opengrep.json` and opengrep's log
once it has read them, so a later report reads the same findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.core.adapters.opengrep_adapter import OpengrepAdapter
from scripts.core.secret_output_redaction import redact_secret_outputs

JWT_SECRET = "planted-jwt-secret-7f3a9c41"
K8S_SECRET = "cGxhbnRlZDE1ODVrOHNzZWNyZXQ="
CWE_ONLY_SECRET = "planted-cwe-only-secret-5d2e"
NOT_A_SECRET = "hashlib.md5(password_input)"
SECRETS = (JWT_SECRET, K8S_SECRET, CWE_ONLY_SECRET)

JWT_RULE = "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret"
K8S_RULE = "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file"
MD5_RULE = "python.lang.security.audit.md5-used-as-password.md5-used-as-password"
UNLISTED_RULE = "rules.someone.elses.hardcoded-thing"


def _result(rule: str, path: Path, line: int, message: str, **extra) -> dict:
    return {
        "check_id": rule,
        "path": str(path),
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 40, "offset": 40},
        "extra": {
            "message": message,
            "severity": "WARNING",
            "metadata": extra.pop("metadata", {}),
            "engine_kind": "OSS",
            "fingerprint": "b1946ac92492d2347c6235b4d2611184",
            "is_ignored": False,
            "validation_state": "NO_VALIDATOR",
            **extra,
        },
    }


def _output(tmp_path: Path) -> Path:
    """A target folder's opengrep.json and log, over source files that exist,
    so the adapter would read a snippet of each."""
    src = tmp_path / "src"
    src.mkdir()
    js = src / "index.js"
    js.write_bytes(f'const t = jwt.sign({{u: 1}}, "{JWT_SECRET}");\n'.encode())
    secret_yaml = src / "secret.yaml"
    secret_yaml.write_bytes(f"kind: Secret\ndata:\n  password: {K8S_SECRET}\n".encode())
    app = src / "app.py"
    app.write_bytes(f'x = "{CWE_ONLY_SECRET}"\nh = {NOT_A_SECRET}\n'.encode())
    results = [
        _result(
            JWT_RULE,
            js,
            1,
            "A hard-coded credential was detected.",
            lines=js.read_text().rstrip("\n"),
            metavars={"$VALUE": {"abstract_content": f'"{JWT_SECRET}"'}},
            dataflow_trace={"taint_source": ["CliLoc", [{}, f'"{JWT_SECRET}"']]},
            metadata={"cwe": ["CWE-798: Use of Hard-coded Credentials"]},
        ),
        _result(
            K8S_RULE,
            secret_yaml,
            3,
            f"Secrets ({K8S_SECRET}) should not be stored in infrastructure as code files.",
            lines=f"  password: {K8S_SECRET}",
            metavars={
                "$KEY": {"abstract_content": "password"},
                "$VALUE": {"abstract_content": K8S_SECRET},
            },
        ),
        _result(
            UNLISTED_RULE,
            app,
            1,
            f"Hard-coded value {CWE_ONLY_SECRET} found.",
            lines=f'x = "{CWE_ONLY_SECRET}"',
            metavars={"$V": {"abstract_content": f'"{CWE_ONLY_SECRET}"'}},
            metadata={"cwe": "CWE-798"},
        ),
        _result(
            MD5_RULE,
            app,
            2,
            "It looks like MD5 is used as a password hash.",
            lines=f"h = {NOT_A_SECRET}",
            metavars={"$FUNCTION": {"abstract_content": "hashlib.md5"}},
        ),
    ]
    target = tmp_path / "results" / "individual-repos" / "app"
    (target / ".opengrep").mkdir(parents=True)
    out = target / "opengrep.json"
    out.write_bytes(json.dumps({"results": results, "errors": []}).encode())
    log = "\n".join(
        f"semgrep.rule_match - DEBUG - match_key = ('{s} {s}', PosixPath('x'))"
        for s in SECRETS
    )
    (target / ".opengrep" / "semgrep.log").write_bytes(log.encode())
    return out


def _by_rule(findings) -> dict[str, dict]:
    return {f.ruleId: f.to_dict() for f in findings}


def test_a_secret_class_finding_quotes_no_secret(tmp_path: Path) -> None:
    findings = _by_rule(OpengrepAdapter().parse(_output(tmp_path)))

    for rule in (JWT_RULE, K8S_RULE, UNLISTED_RULE):
        written = json.dumps(findings[rule])
        assert not [s for s in SECRETS if s in written], rule
        assert findings[rule].get("context") is None, rule
        assert "lines" not in findings[rule]["raw"]["extra"], rule
        assert "metavars" not in findings[rule]["raw"]["extra"], rule
        assert "fingerprint" not in findings[rule]["raw"]["extra"], rule
    # The message keeps its prose: only the interpolated secret goes.
    assert findings[K8S_RULE]["message"] == (
        "Secrets ([redacted]) should not be stored in infrastructure as code files."
    )
    assert findings[JWT_RULE]["message"] == "A hard-coded credential was detected."
    assert findings[JWT_RULE]["risk"]["cwe"] == [
        "CWE-798: Use of Hard-coded Credentials"
    ]


def test_a_finding_whose_rule_is_not_secret_class_keeps_its_code(
    tmp_path: Path,
) -> None:
    md5 = _by_rule(OpengrepAdapter().parse(_output(tmp_path)))[MD5_RULE]

    assert NOT_A_SECRET in md5["context"]["snippet"]
    assert md5["raw"]["extra"]["lines"] == f"h = {NOT_A_SECRET}"


def test_the_reports_rewrite_keeps_every_id_and_leaves_no_secret(
    tmp_path: Path,
) -> None:
    out = _output(tmp_path)
    before = {f.ruleId: f.id for f in OpengrepAdapter().parse(out)}

    redact_secret_outputs([out])

    after = {f.ruleId: f.id for f in OpengrepAdapter().parse(out)}
    assert after == before
    target = out.parent
    for path in (out, target / ".opengrep" / "semgrep.log"):
        assert not [s for s in SECRETS if s.encode() in path.read_bytes()], path.name
    # The finding that is not secret-class is left as opengrep wrote it.
    md5 = next(
        r for r in json.loads(out.read_bytes())["results"] if r["check_id"] == MD5_RULE
    )
    assert md5["extra"]["lines"] == f"h = {NOT_A_SECRET}"


def test_a_second_rewrite_changes_nothing(tmp_path: Path) -> None:
    out = _output(tmp_path)
    redact_secret_outputs([out])
    first = {p: p.read_bytes() for p in out.parent.rglob("*") if p.is_file()}

    redact_secret_outputs([out])

    assert {p: p.read_bytes() for p in out.parent.rglob("*") if p.is_file()} == first
