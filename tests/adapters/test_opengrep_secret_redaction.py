"""An opengrep finding never quotes a secret a rule matched (#1585).

Measured with `jmo ci --tools opengrep` on planted secrets: a finding from a rule
that matches a secret's value carried it in its snippet, in the raw record's
`extra.lines`, `metavars` and `dataflow_trace`, and, for rules whose message
interpolates what they matched, in its message, which also feeds the finding's id.
All of that reached summaries/, the dashboard, the PCI report and history. The
review of the fix then measured two more paths: opengrep reports several results
for one region, so another rule's result over the same code carried the secret
too, and a nearby finding's snippet quoted it.

The adapter now redacts before ids are computed, as trufflehog's drops `Raw`
(redaction, not enrichment), and every decision past the secret-class results
themselves is made from locations, so a later report, reading the opengrep.json
the report rewrote, makes the same ones and computes the same ids.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from scripts.core.adapters.opengrep_adapter import OpengrepAdapter
from scripts.core.secret_output_redaction import redact_secret_outputs
from scripts.core.secret_value_rules import MESSAGE_TEMPLATES

JWT = "planted-jwt-secret-7f3a9c41"
K8S_A = "cGxhbnRlZGZsb3dvbmVhYWE="
K8S_B = "cGxhbnRlZGZsb3d0d29iYmI="
LOGGED = "planted-logtoken-1585-hh88"
CWE_ONLY = "planted-cwe-o'nly\\secret"
SECRETS = (JWT, K8S_A, K8S_B, LOGGED, CWE_ONLY)
NOT_A_SECRET = "hashlib.md5(password_input)"

JWT_RULE = "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret"
K8S_RULE = "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file"
LOGGER_RULE = (
    "python.lang.security.audit.logging.logger-credential-leak."
    "python-logger-credential-disclosure"
)
MD5_RULE = "python.lang.security.audit.md5-used-as-password.md5-used-as-password"
OVERLAPPING_RULE = (
    "javascript.jsonwebtoken.security.audit.jwt-exposed-data.jwt-exposed-data"
)
NEIGHBOUR_RULE = "javascript.lang.security.audit.some-check.some-check"
UNLISTED_RULE = "rules.someone.elses.hardcoded-thing"


def _result(rule: str, path: Path, line: int, message: str, col: int = 1, **extra):
    return {
        "check_id": rule,
        "path": str(path),
        "start": {"line": line, "col": col, "offset": 0},
        "end": {"line": line, "col": col + 30, "offset": 30},
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
    js_lines = [
        f'const t = jwt.sign({{u: 1}}, "{JWT}");',
        "const a = 1;",
        "const b = jwt.decode(t);",
    ]
    js.write_bytes(("\n".join(js_lines) + "\n").encode())
    k8s = src / "secret.yaml"
    k8s_line = f"data: {{password: {K8S_A}, token: {K8S_B}}}"
    k8s.write_bytes(f"kind: Secret\n{k8s_line}\n".encode())
    py = src / "app.py"
    py_lines = [
        f'x = "{CWE_ONLY}"',
        f'logger.info("token={LOGGED} for %s" % user)',
        *(["pass"] * 7),
        f"h = {NOT_A_SECRET}",
    ]
    py.write_bytes(("\n".join(py_lines) + "\n").encode())
    results = [
        _result(
            JWT_RULE, js, 1, "A hard-coded credential was detected.",
            lines=js_lines[0],
            metavars={"$VALUE": {"abstract_content": f'"{JWT}"'}},
            dataflow_trace={"taint_source": ["CliLoc", [{}, f'"{JWT}"']]},
            metadata={"cwe": ["CWE-798: Use of Hard-coded Credentials"]},
        ),
        # Another rule over the same code, as opengrep reports it.
        _result(
            OVERLAPPING_RULE, js, 1, f'Payload of jwt.sign({{u: 1}}, "{JWT}") is exposed.',
            lines=js_lines[0],
            metavars={"$PAYLOAD": {"abstract_content": "{u 1}"}},
        ),
        # Two lines down: its own match holds no secret, its snippet would.
        _result(
            NEIGHBOUR_RULE, js, 3, "jwt.decode without verify.",
            lines=js_lines[2],
        ),
        # Two secrets on one line: one id each.
        *(
            _result(
                K8S_RULE, k8s, 2, f"Secrets ({value}) should not be stored here.",
                col=col, lines=k8s_line,
                metavars={
                    "$KEY": {"abstract_content": key},
                    "$VALUE": {"abstract_content": value},
                },
            )
            for key, value, col in (("password", K8S_A, 8), ("token", K8S_B, 44))
        ),
        # opengrep renders the source; abstract_content is normalised.
        _result(
            LOGGER_RULE, py, 2,
            f'Detected a python logger call with a potential hardcoded secret '
            f'"token={LOGGED} for %s" % user being logged.',
            lines=py_lines[1],
            metavars={
                "$FORMAT_STRING": {"abstract_content": f'"token={LOGGED} for %s"%user'}
            },
        ),
        _result(
            UNLISTED_RULE, py, 1, f"Hard-coded value {CWE_ONLY} found.",
            lines=py_lines[0],
            metavars={"$V": {"abstract_content": json.dumps(CWE_ONLY)}},
            metadata={"cwe": "CWE-798"},
        ),
        _result(
            MD5_RULE, py, 10, "It looks like MD5 is used as a password hash.",
            lines=py_lines[9],
            metavars={"$FUNCTION": {"abstract_content": "hashlib.md5"}},
        ),
    ]  # fmt: skip
    target = tmp_path / "results" / "individual-repos" / "app"
    (target / ".opengrep").mkdir(parents=True)
    out = target / "opengrep.json"
    out.write_bytes(json.dumps({"results": results, "errors": []}).encode())
    # As opengrep's log holds them (measured): each matched literal whole, the
    # logged format string included, escaped as Python's repr escapes it.
    logged = (JWT, K8S_A, K8S_B, f"token={LOGGED} for %s", CWE_ONLY)
    log = "\n".join(
        f"semgrep.rule_match - DEBUG - match_key = ({s!r}, PosixPath('x'))"
        for s in logged
    )
    (target / ".opengrep" / "semgrep.log").write_bytes(log.encode())
    return out


def _findings(out: Path) -> list[dict]:
    return [f.to_dict() for f in OpengrepAdapter().parse(out)]


def _one(findings: list[dict], rule: str) -> dict:
    (found,) = [f for f in findings if f["ruleId"] == rule]
    return found


def _leaks(text: str) -> list[str]:
    return [s for s in SECRETS if s in text]


def test_no_finding_quotes_a_secret(tmp_path: Path) -> None:
    findings = _findings(_output(tmp_path))

    assert len(findings) == 8
    assert _leaks(json.dumps(findings)) == []


def test_a_secret_class_finding_keeps_no_code(tmp_path: Path) -> None:
    findings = _findings(_output(tmp_path))

    for rule in (JWT_RULE, K8S_RULE, LOGGER_RULE, UNLISTED_RULE):
        for found in (f for f in findings if f["ruleId"] == rule):
            assert found.get("context") is None, rule
            assert set(found["raw"]["extra"]) <= {
                "engine_kind", "is_ignored", "message", "metadata", "severity",
                "validation_state",
            }, rule  # fmt: skip
    assert (
        _one(findings, JWT_RULE)["message"] == "A hard-coded credential was detected."
    )


def test_a_message_that_carried_the_secret_is_the_rules_template(
    tmp_path: Path,
) -> None:
    """The logger's message spells the call as written (`... % user`), which
    the normalised metavariable does not match; the template does."""
    findings = _findings(_output(tmp_path))

    expected = MESSAGE_TEMPLATES[LOGGER_RULE].replace("$FORMAT_STRING", "[redacted]")
    assert _one(findings, LOGGER_RULE)["message"] == expected
    assert {f["message"] for f in findings if f["ruleId"] == K8S_RULE} == {
        MESSAGE_TEMPLATES[K8S_RULE].replace("$VALUE", "[redacted]")
    }


def test_two_secrets_on_one_line_are_two_findings(tmp_path: Path) -> None:
    """Their messages became one; the column keeps their ids apart, which
    dedup keys on (the review measured one dropped)."""
    k8s = [f for f in _findings(_output(tmp_path)) if f["ruleId"] == K8S_RULE]

    assert len({f["id"] for f in k8s}) == 2
    assert sorted(f["location"]["startColumn"] for f in k8s) == [8, 44]


def test_another_rules_result_over_the_secret_keeps_no_code(tmp_path: Path) -> None:
    overlapping = _one(_findings(_output(tmp_path)), OVERLAPPING_RULE)

    assert overlapping.get("context") is None
    assert "lines" not in overlapping["raw"]["extra"]
    assert "metavars" not in overlapping["raw"]["extra"]
    assert (
        overlapping["message"]
        == 'Payload of jwt.sign({u: 1}, "[redacted]") is exposed.'
    )


def test_a_finding_whose_snippet_would_reach_the_secret_has_none(
    tmp_path: Path,
) -> None:
    neighbour = _one(_findings(_output(tmp_path)), NEIGHBOUR_RULE)

    assert neighbour.get("context") is None
    assert neighbour["raw"]["extra"]["lines"] == "const b = jwt.decode(t);"


def test_a_finding_away_from_any_secret_keeps_its_code(tmp_path: Path) -> None:
    md5 = _one(_findings(_output(tmp_path)), MD5_RULE)

    assert NOT_A_SECRET in md5["context"]["snippet"]
    assert md5["raw"]["extra"]["lines"] == f"h = {NOT_A_SECRET}"


def test_the_reports_rewrite_keeps_every_id_and_leaves_no_secret(
    tmp_path: Path,
) -> None:
    out = _output(tmp_path)
    before = sorted(f["id"] for f in _findings(out))

    redact_secret_outputs([out])

    assert sorted(f["id"] for f in _findings(out)) == before
    for path in (out, out.parent / ".opengrep" / "semgrep.log"):
        assert _leaks(path.read_bytes().decode()) == [], path.name
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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directory modes")
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root writes into a read-only directory",
)
def test_a_log_that_cannot_be_rewritten_leaves_the_json_for_the_next_report(
    tmp_path: Path,
) -> None:
    """The log's secrets are found through the JSON: rewriting the JSON first
    and then failing on the log would leave them there for good."""
    out = _output(tmp_path)
    original = out.read_bytes()
    log_dir = out.parent / ".opengrep"
    log_dir.chmod(0o555)
    try:
        redact_secret_outputs([out])
        assert out.read_bytes() == original
    finally:
        log_dir.chmod(0o755)

    redact_secret_outputs([out])

    for path in (out, log_dir / "semgrep.log"):
        assert _leaks(path.read_bytes().decode()) == [], path.name


def test_the_log_redacted_is_the_one_the_row_writes() -> None:
    """Two spellings of one path: the report would scrub a file the row
    never wrote, and say nothing."""
    from scripts.core.secret_output_redaction import OPENGREP_LOG
    from scripts.core.tool_descriptors import OPENGREP_LOG as WRITTEN

    assert Path(WRITTEN) == OPENGREP_LOG
