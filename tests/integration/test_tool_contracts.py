"""
Contract tests: verify tool outputs contain required fields.

These run real tools against minimal targets and check structural contracts.
Faster and more maintainable than full JSON Schema validation.

This catches:
- Major version breaking changes in tool output
- Renamed/removed fields
- Structural changes that would break adapters

Usage:
    # Run all contract tests (requires tools installed)
    pytest tests/integration/test_tool_contracts.py -v -m requires_tools

    # Run specific tool's contract test
    pytest tests/integration/test_tool_contracts.py -v -k "trivy"

Schedule:
    These tests run weekly in scheduled.yml (not on every PR - too slow)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

logger = logging.getLogger(__name__)

# Path to sample fixtures for minimal test targets
PROJECT_ROOT = Path(__file__).parent.parent.parent
SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"


def _gitleaks_findings(out: dict[str, Any]) -> list[dict[str, Any]]:
    """The SARIF results the gitleaks binding can use: each needs its rule,
    its path and line, and the matched text (`region.snippet`), which the
    binding digests to pair a secret's tree and history records and then
    scrubs. A result missing any of them is not counted, so a shape change
    reads as "reported nothing"."""
    usable = []
    for run in out.get("runs") or []:
        for result in run.get("results") or []:
            location = (
                ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            )
            region = location.get("region") or {}
            if (
                result.get("ruleId")
                and (location.get("artifactLocation") or {}).get("uri")
                and region.get("startLine")
                and (region.get("snippet") or {}).get("text")
            ):
                usable.append(result)
    return usable


def _zizmor_findings(out: dict[str, Any]) -> list[dict[str, Any]]:
    """The SARIF results the zizmor binding can use: each needs its rule, its
    path and line, and `properties["zizmor/severity"]`, which is where the
    binding reads a severity from (`level` alone folds Low into warning)."""
    usable = []
    for run in out.get("runs") or []:
        for result in run.get("results") or []:
            location = (
                ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            )
            if (
                result.get("ruleId")
                and (location.get("artifactLocation") or {}).get("uri")
                and (location.get("region") or {}).get("startLine")
                and (result.get("properties") or {}).get("zizmor/severity")
            ):
                usable.append(result)
    return usable


def _osv_scanner_findings(out: dict[str, Any]) -> list[dict[str, Any]]:
    """The SARIF results the osv-scanner binding can use: each needs its rule,
    its lockfile, and a message naming `package@version`, which is the only
    place osv-scanner's SARIF carries either."""
    usable = []
    for run in out.get("runs") or []:
        for result in run.get("results") or []:
            location = (
                ((result.get("locations") or [{}])[0]).get("physicalLocation") or {}
            )
            text = (result.get("message") or {}).get("text") or ""
            if (
                result.get("ruleId")
                and (location.get("artifactLocation") or {}).get("uri")
                and text.startswith("Package '")
                and "@" in text
            ):
                usable.append(result)
    return usable


# Required fields per tool (minimal contract)
# These define the structural requirements adapters depend on
#
# `ok_return_codes` and `may_be_empty` were measured 2026-09-25 by running each
# command on its sample (#1073). The linters exit 1 when they report findings
# (hadolint, checkov 3.3.16); the rest exit 0 with findings. Any other code is a
# broken run, whatever it printed. `may_be_empty` holds the reason a tool
# reports nothing on its sample; every other contract must report something.
TOOL_CONTRACTS: dict[str, dict[str, Any]] = {
    "trivy": {
        "required_keys": ["Results"],
        "result_item_keys": ["Target"],
        # Vulnerabilities/Secrets/Misconfigurations are optional (depends on scan mode)
        "vuln_keys": ["VulnerabilityID", "Severity"],
        "sample_target": "python-vulnerable",
        "command": ["trivy", "fs", "--format", "json", "{target}"],
        "ok_return_codes": (0,),
        # A scanned manifest with no vulnerabilities still has a `Results` entry.
        # Measured on the sample: 1 result, 23 vulnerabilities.
        "findings": lambda out: [
            v for r in out.get("Results") or [] for v in r.get("Vulnerabilities") or []
        ],
        "description": "Vulnerability scanner with Results array structure",
    },
    "semgrep": {
        "required_keys": ["results"],
        "result_item_keys": ["check_id", "path", "extra"],
        "sample_target": "python-vulnerable",
        # The file, not the directory: with no .semgrepignore, semgrep's
        # built-in one skips `tests/`, so the directory scanned 0 files and
        # `result_item_keys` was never checked. The file: 1 scanned, 4 results.
        "command": [
            "semgrep",
            "--config",
            "auto",
            "--json",
            "{target}/vulnerable_app.py",
        ],
        "ok_return_codes": (0,),
        "description": "SAST scanner with results array structure",
    },
    "hadolint": {
        "required_keys": [],  # Hadolint returns array at root
        "result_item_keys": ["code", "message", "file", "level"],
        "sample_target": "dockerfile-issues",
        "command": ["hadolint", "--format", "json", "{target}/Dockerfile"],
        "is_array_root": True,
        "ok_return_codes": (1,),
        "description": "Dockerfile linter with array root structure",
    },
    "checkov": {
        "required_keys": ["results"],
        "result_item_keys": ["passed_checks", "failed_checks"],
        "check_item_keys": ["check_id", "resource", "check_result"],
        "sample_target": "terraform-misconfig",
        "command": ["checkov", "-d", "{target}", "--output", "json"],
        "ok_return_codes": (1,),
        # `results` holds its lists even when they are empty. Measured on the
        # sample: 37 failed, 19 passed.
        "findings": lambda out: (out.get("results") or {}).get("failed_checks") or [],
        "description": "IaC scanner with passed/failed checks structure",
    },
    "trufflehog": {
        "required_keys": [],  # Trufflehog uses NDJSON (one object per line)
        # Schema fluctuates across minor versions (v3.91+ drops keys for
        # unverifiable patterns; v3.94+ emits leaner records). The adapter
        # uses defensive .get() fallbacks for every field, so the only real
        # contract is "output is NDJSON we can json.loads() line-by-line".
        "result_item_keys": [],
        "sample_target": "credential-patterns",
        "command": ["trufflehog", "filesystem", "{target}", "--json"],
        "is_ndjson": True,
        "ok_return_codes": (0,),
        "may_be_empty": (
            "3.97.1 reports 0 verified and 0 unverified on the sample: it filters "
            "AWS's documented example key and the placeholder patterns"
        ),
        "description": "Secrets scanner with NDJSON output",
    },
    "gitleaks": {
        "required_keys": ["runs"],
        "result_item_keys": ["tool", "results"],
        "sample_target": "credential-patterns",
        # SARIF on stdout (`--report-path -`), which is what the harness reads;
        # JMo writes it to a file. A leak is not an error, hence `--exit-code 0`.
        "command": [
            "gitleaks",
            "dir",
            "{target}",
            "--report-format",
            "sarif",
            "--report-path",
            "-",
            "--no-banner",
            "--exit-code",
            "0",
        ],
        "ok_return_codes": (0,),
        # Measured 2026-09-26 with 8.30.1: 3 results on the sample, 2
        # generic-api-key and 1 private-key, each with a snippet.
        "findings": _gitleaks_findings,
        "description": "Secrets scanner with SARIF output",
    },
    "grype": {
        "required_keys": ["matches"],
        "result_item_keys": ["vulnerability", "artifact"],
        "vuln_keys": ["id", "severity"],
        "sample_target": "python-vulnerable",
        "command": ["grype", "dir:{target}", "-o", "json"],
        "ok_return_codes": (0,),
        "description": "Vulnerability scanner with matches array",
    },
    "syft": {
        "required_keys": ["artifacts"],
        "result_item_keys": ["name", "version", "type"],
        "sample_target": "python-vulnerable",
        "command": ["syft", "dir:{target}", "-o", "json"],
        "ok_return_codes": (0,),
        "description": "SBOM generator with artifacts array",
    },
    "shellcheck": {
        "required_keys": [],  # Array at root
        "result_item_keys": ["file", "line", "code", "level", "message"],
        "sample_target": "shell-issues",
        "command": ["shellcheck", "--format=json", "{target}/vulnerable_script.sh"],
        "is_array_root": True,
        # The linter exits 1 when it reports. The sample used to open with
        # `# shellcheck disable=all` so the repository's own hook passed on it,
        # which left this contract with nothing to check; the hook excludes
        # the samples instead.
        "ok_return_codes": (1,),
        "description": "Shell script linter with array root",
    },
    "zizmor": {
        "required_keys": ["runs"],
        "result_item_keys": ["tool", "results"],
        "sample_target": "github-actions",
        # As JMo runs it, but given an absolute path (the harness runs from
        # the repository root): `--offline` so a token in the environment
        # makes no network call. Findings are rc 0 (SARIF output already
        # exits 0 with them at 1.30.1; `--no-exit-codes` keeps it so).
        "command": [
            "zizmor",
            "--format",
            "sarif",
            "--offline",
            "--no-exit-codes",
            "{target}/.github/workflows/ci.yml",
        ],
        "ok_return_codes": (0,),
        # Measured 2026-09-27 with 1.30.1: 5 results on the sample
        # (artipacked, excessive-permissions, dangerous-triggers,
        # template-injection, unpinned-uses), each with a zizmor/severity.
        "findings": _zizmor_findings,
        "description": "GitHub Actions auditor with SARIF output",
    },
    "osv-scanner": {
        "required_keys": ["runs"],
        "result_item_keys": ["tool", "results"],
        "sample_target": "python-vulnerable",
        # As JMo runs it, with the lockfile given by an absolute path and the
        # SARIF on stdout. Offline against tests/fixtures/osv-db, a frozen
        # database of three synthetic advisories, so the contract downloads
        # nothing; `--no-resolve` so `requirements.txt` is not resolved over
        # the network (deps.dev); no call analysis, as in a scan.
        "command": [
            "osv-scanner",
            "scan",
            "source",
            "--format",
            "sarif",
            "--offline-vulnerabilities",
            "--no-resolve",
            "--no-call-analysis=all",
            "-L",
            "{target}/requirements.txt",
        ],
        "env": {
            "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(
                PROJECT_ROOT / "tests" / "fixtures" / "osv-db"
            )
        },
        # 1 is findings. Measured 2026-09-28 with 2.6.0: 1 result on the
        # sample, JMO-TEST-2026-0002 on urllib3@1.25.0.
        "ok_return_codes": (1,),
        "findings": _osv_scanner_findings,
        "description": "Dependency scanner with SARIF output, offline database",
    },
}


def tool_available(tool_name: str) -> bool:
    """Check if a tool is available in PATH."""
    # Get the base command (first word)
    contract = TOOL_CONTRACTS.get(tool_name, {})
    command = contract.get("command", [tool_name])
    base_cmd = command[0] if command else tool_name

    return shutil.which(base_cmd) is not None


def run_tool_on_sample(
    tool_name: str, contract: dict[str, Any]
) -> tuple[dict[str, Any] | list[Any], int]:
    """Run a tool against its sample target and return parsed output.

    Args:
        tool_name: Name of the tool
        contract: Tool contract configuration

    Returns:
        Parsed JSON output from tool (dict or list), and its exit code. The
        code used to be dropped, so a run that failed after printing a
        well-formed shape passed every check (#1073).

    Raises:
        subprocess.TimeoutExpired: If tool times out
        json.JSONDecodeError: If output is not valid JSON
    """
    sample_target = SAMPLES_DIR / contract["sample_target"]
    if not sample_target.exists():
        raise FileNotFoundError(f"Sample target not found: {sample_target}")

    # Build command with target substitution
    command = []
    for part in contract["command"]:
        command.append(part.replace("{target}", str(sample_target)))

    logger.info("Running contract test: %s", " ".join(command))

    # Run the tool
    result = subprocess.run(
        command,
        capture_output=True,
        # UTF-8, not the locale codec: on Windows a cp1252 decode error is
        # swallowed in the reader thread and stdout comes back None.
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,  # 3 minute timeout
        cwd=PROJECT_ROOT,
        # Merged over the inherited environment, as ToolRunner merges a
        # definition's (osv-scanner's database directory).
        env={**os.environ, **contract["env"]} if "env" in contract else None,
    )

    # stdout only: every contract tool writes its report there. Falling back to
    # stderr parsed trufflehog's JSON log lines as findings whenever it found
    # nothing, so an empty run looked like a two-finding one.
    output = result.stdout

    if not output.strip():
        logger.warning(
            "%s produced no output (exit code: %d)", tool_name, result.returncode
        )
        # Return empty structure appropriate for tool
        if contract.get("is_array_root") or contract.get("is_ndjson"):
            return [], result.returncode
        return {}, result.returncode

    # Handle NDJSON format (one JSON object per line)
    if contract.get("is_ndjson"):
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # Skip malformed lines
        return results, result.returncode

    # Standard JSON parsing
    return json.loads(output), result.returncode


def check_run(
    tool_name: str,
    contract: dict[str, Any],
    output: dict[str, Any] | list[Any],
    returncode: int,
) -> list[str]:
    """What a sane run of `tool_name` on its sample must satisfy (#1073).

    Returns violation messages, empty when the run is sane: an exit code the
    contract accepts, the root type it declares, and at least one reported
    item unless the contract says why there may be none. The items are what
    the contract's `findings` extracts, or else its first required key (or the
    root): trivy's `Results` and checkov's `results` are containers that are
    present with nothing found.
    """
    violations = []
    if returncode not in contract["ok_return_codes"]:
        violations.append(
            f"{tool_name}: exit code {returncode}, contract accepts "
            f"{contract['ok_return_codes']}"
        )

    expects_array = bool(contract.get("is_array_root") or contract.get("is_ndjson"))
    if not isinstance(output, list if expects_array else dict):
        violations.append(
            f"{tool_name}: contract declares a "
            f"{'array' if expects_array else 'object'} root, "
            f"got {type(output).__name__}"
        )
        return violations

    if contract.get("may_be_empty"):
        return violations
    if "findings" in contract:
        reported = contract["findings"](output)
    else:
        keys = contract.get("required_keys") or []
        reported = output.get(keys[0]) if isinstance(output, dict) and keys else output
    if not reported:
        violations.append(f"{tool_name}: reported nothing on its sample")
    return violations


def verify_contract(
    tool_name: str, contract: dict[str, Any], output: dict[str, Any] | list[Any]
) -> list[str]:
    """Verify tool output matches expected contract.

    Args:
        tool_name: Name of the tool
        contract: Expected contract structure
        output: Actual tool output

    Returns:
        List of contract violation messages (empty if valid)
    """
    violations = []

    # Handle array root structure
    if contract.get("is_array_root") or contract.get("is_ndjson"):
        if not isinstance(output, list):
            violations.append(f"{tool_name}: Expected array root, got {type(output)}")
            return violations

        # Check items if any exist
        if output and contract.get("result_item_keys"):
            first_item = output[0]
            for key in contract["result_item_keys"]:
                if key not in first_item:
                    violations.append(
                        f"{tool_name}: Result item missing required key '{key}'"
                    )
        return violations

    # Handle dict root structure
    if not isinstance(output, dict):
        violations.append(f"{tool_name}: Expected dict root, got {type(output)}")
        return violations

    # Check top-level required keys
    for key in contract.get("required_keys", []):
        if key not in output:
            violations.append(f"{tool_name}: Missing required top-level key '{key}'")

    # Check nested structure if results exist
    results_key = (
        contract.get("required_keys", [None])[0]
        if contract.get("required_keys")
        else None
    )
    if results_key and results_key in output:
        results = output[results_key]

        if isinstance(results, list) and results:
            first_result = results[0]

            # Check result item keys
            for key in contract.get("result_item_keys", []):
                if key not in first_result:
                    violations.append(f"{tool_name}: Result item missing key '{key}'")

            # Check nested vulnerability keys if applicable
            if contract.get("vuln_keys"):
                vuln_array = first_result.get("Vulnerabilities") or first_result.get(
                    "vulnerability"
                )
                if vuln_array and isinstance(vuln_array, (list, dict)):
                    vuln = vuln_array[0] if isinstance(vuln_array, list) else vuln_array
                    for key in contract["vuln_keys"]:
                        if key not in vuln:
                            violations.append(
                                f"{tool_name}: Vulnerability missing key '{key}'"
                            )

    return violations


# Generate test parameters from contracts
CONTRACT_TOOL_NAMES = list(TOOL_CONTRACTS.keys())


@pytest.mark.requires_tools
class TestToolContracts:
    """Contract tests for security tool outputs."""

    @pytest.mark.parametrize("tool_name", CONTRACT_TOOL_NAMES)
    def test_tool_output_contract(self, tool_name: str):
        """
        Contract test: tool output must contain required fields.

        This catches:
        - Major version breaking changes in tool output
        - Renamed/removed fields that would break adapters

        Args:
            tool_name: Name of tool to test
            tmp_path: Pytest temporary directory
        """
        contract = TOOL_CONTRACTS[tool_name]

        # Skip if tool not installed
        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        # Check sample target exists
        sample_target = SAMPLES_DIR / contract["sample_target"]
        if not sample_target.exists():
            pytest.skip(f"Sample target not found: {sample_target}")

        # Run tool and get output. The exit code is `test_tool_produces_some_output`'s.
        try:
            output, _returncode = run_tool_on_sample(tool_name, contract)
        except subprocess.TimeoutExpired:
            pytest.fail(f"{tool_name} timed out after 180s")
        except FileNotFoundError as e:
            pytest.skip(str(e))
        except json.JSONDecodeError as e:
            pytest.fail(f"{tool_name} produced invalid JSON: {e}")

        # Verify contract
        violations = verify_contract(tool_name, contract, output)

        if violations:
            violation_msg = "\n".join(f"  - {v}" for v in violations)
            pytest.fail(
                f"Contract violations for {tool_name}:\n{violation_msg}\n\n"
                f"Tool description: {contract.get('description', 'N/A')}\n"
                f"This may indicate a breaking change in the tool's output format!"
            )

    @pytest.mark.parametrize("tool_name", CONTRACT_TOOL_NAMES)
    def test_tool_produces_some_output(self, tool_name: str):
        """
        Sanity test: tool should produce some output on sample target.

        This catches:
        - Tool completely broken/misconfigured: an exit code outside the
          contract's measured set, even when a parseable shape was printed
        - Sample target doesn't trigger any findings, unless the contract
          declares why it may not (`may_be_empty`)

        Its assertions live in `check_run`, whose negative controls
        (`TestSanityCheckBites`) run on every PR shard. This test used to reach
        no assertion for any tool but the root type (#1073).
        """
        contract = TOOL_CONTRACTS[tool_name]

        if not tool_available(tool_name):
            pytest.skip(f"{tool_name} not installed")

        sample_target = SAMPLES_DIR / contract["sample_target"]
        if not sample_target.exists():
            pytest.skip(f"Sample target not found: {sample_target}")

        try:
            output, returncode = run_tool_on_sample(tool_name, contract)
        except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
            pytest.fail(f"{tool_name} failed: {e}")
        except FileNotFoundError as e:
            pytest.skip(str(e))

        violations = check_run(tool_name, contract, output, returncode)
        assert not violations, "\n".join(violations)


class TestContractInfrastructure:
    """Tests for contract test infrastructure."""

    def test_all_contracts_have_required_fields(self):
        """Verify all tool contracts have necessary configuration."""
        required_fields = ["command", "sample_target", "ok_return_codes"]

        for tool_name, contract in TOOL_CONTRACTS.items():
            for field in required_fields:
                assert field in contract, (
                    f"Contract for {tool_name} missing required field '{field}'"
                )

    def test_sample_targets_exist(self):
        """Verify all sample targets referenced by contracts exist."""
        missing = []

        for tool_name, contract in TOOL_CONTRACTS.items():
            sample_target = SAMPLES_DIR / contract["sample_target"]
            if not sample_target.exists():
                missing.append(f"{tool_name}: {sample_target}")

        if missing:
            pytest.fail(
                "Missing sample targets:\n" + "\n".join(f"  - {m}" for m in missing)
            )

    @pytest.mark.parametrize("workflow", ["ci.yml", "scheduled.yml"])
    def test_every_contract_tool_is_installed_by_the_ci_job(self, workflow):
        """A contract whose tool CI never installs is skipped there, forever.

        grype and syft had contracts and no install line in either job, so
        neither contract had ever run in CI. Derived from TOOL_CONTRACTS, so a
        new contract fails here until both jobs install its tool.
        """
        import re

        import yaml

        path = PROJECT_ROOT / ".github" / "workflows" / workflow
        jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
        steps = jobs["tool-contract-tests"]["steps"]
        run = next(
            s["run"]
            for s in steps
            if s.get("name") == "Install security tools for contract tests"
        )
        install_lines = [
            ln
            for ln in run.splitlines()
            if not ln.lstrip().startswith("#")
            and re.search(r"pip install|apt-get install|tar -x|-o /usr/local/bin/", ln)
        ]

        missing = [
            tool
            for tool in TOOL_CONTRACTS
            if not any(re.search(rf"\b{tool}\b", ln) for ln in install_lines)
        ]
        assert not missing, f"{workflow}: no install line for {missing}"

    def test_contracts_cover_key_adapters(self):
        """Verify contracts exist for critical adapters."""
        critical_tools = ["trivy", "semgrep", "trufflehog", "checkov"]

        missing = [t for t in critical_tools if t not in TOOL_CONTRACTS]

        if missing:
            pytest.fail(
                f"Missing contracts for critical tools: {missing}\n"
                f"Add contracts to TOOL_CONTRACTS in test_tool_contracts.py"
            )


# A real process standing in for hadolint: a well-formed report, then an exit
# code. Not a mock, so the harness's own subprocess handling is exercised.
_HADOLINT_ITEM = (
    "{'code': 'DL3006', 'message': 'm', 'file': 'Dockerfile', 'level': 'warning'}"
)


def _stub_contract(tool_name: str, exit_code: int, script: str | None = None):
    code = script or f"import json; print(json.dumps([{_HADOLINT_ITEM}]))"
    return {
        **TOOL_CONTRACTS[tool_name],
        "command": [sys.executable, "-c", f"{code}; raise SystemExit({exit_code})"],
    }


class TestSanityCheckBites:
    """Negative controls for `check_run`, on every PR shard (#1073).

    `test_tool_produces_some_output` runs only where the tools are installed,
    so the checks it makes are proven here, against real stub processes.
    """

    def test_a_tool_exiting_outside_its_contract_is_a_violation(self):
        contract = _stub_contract("hadolint", exit_code=2)

        output, returncode = run_tool_on_sample("hadolint", contract)

        assert returncode == 2
        assert output, "the stub printed a well-formed report"
        assert any(
            "exit code 2" in v
            for v in check_run("hadolint", contract, output, returncode)
        )

    def test_the_same_report_with_an_accepted_exit_code_is_clean(self):
        contract = _stub_contract("hadolint", exit_code=1)

        output, returncode = run_tool_on_sample("hadolint", contract)

        assert check_run("hadolint", contract, output, returncode) == []

    def test_an_empty_report_is_a_violation_unless_the_contract_allows_it(self):
        assert check_run("grype", TOOL_CONTRACTS["grype"], {"matches": []}, 0)
        assert TOOL_CONTRACTS["trufflehog"].get("may_be_empty")
        assert check_run("trufflehog", TOOL_CONTRACTS["trufflehog"], [], 0) == []

    @pytest.mark.parametrize(
        ("tool_name", "output", "returncode"),
        [
            # A scanned manifest with no vulnerabilities: `Results` is not empty.
            (
                "trivy",
                {"Results": [{"Target": "requirements.txt", "Class": "lang-pkgs"}]},
                0,
            ),
            # checkov's `results` is a dict whose lists exist even when empty.
            ("checkov", {"results": {"passed_checks": [{}], "failed_checks": []}}, 1),
        ],
    )
    def test_a_report_with_no_findings_in_it_is_a_violation(
        self, tool_name, output, returncode
    ):
        """The container being non-empty is not a finding (#1073)."""
        violations = check_run(tool_name, TOOL_CONTRACTS[tool_name], output, returncode)

        assert violations == [f"{tool_name}: reported nothing on its sample"]

    def test_a_gitleaks_result_without_its_snippet_is_not_a_finding(self):
        """The binding pairs a secret's records by digesting `region.snippet`,
        so SARIF without it reports nothing the binding can use."""
        region: dict[str, Any] = {"startLine": 3, "snippet": {"text": "k"}}
        result = {
            "ruleId": "private-key",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a"},
                        "region": region,
                    }
                }
            ],
        }
        report = {"runs": [{"tool": {}, "results": [result]}]}
        contract = TOOL_CONTRACTS["gitleaks"]

        assert check_run("gitleaks", contract, report, 0) == []
        del region["snippet"]
        assert check_run("gitleaks", contract, report, 0) == [
            "gitleaks: reported nothing on its sample"
        ]

    def test_a_zizmor_result_without_its_severity_is_not_a_finding(self):
        """The binding grades a finding by `properties["zizmor/severity"]`, so
        SARIF without it reports nothing the binding can grade."""
        properties = {"zizmor/severity": "High"}
        result = {
            "ruleId": "zizmor/template-injection",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": ".github/workflows/ci.yml"},
                        "region": {"startLine": 14},
                    }
                }
            ],
            "properties": properties,
        }
        report = {"runs": [{"tool": {}, "results": [result]}]}
        contract = TOOL_CONTRACTS["zizmor"]

        assert check_run("zizmor", contract, report, 0) == []
        del properties["zizmor/severity"]
        assert check_run("zizmor", contract, report, 0) == [
            "zizmor: reported nothing on its sample"
        ]

    def test_an_osv_scanner_result_not_naming_its_package_is_not_a_finding(self):
        """osv-scanner's SARIF carries the package and version only in the
        message, so a result without them reports nothing the binding keys."""
        message = {
            "text": "Package 'urllib3@1.25.0' is vulnerable to 'JMO-TEST-2026-0002'."
        }
        result = {
            "ruleId": "JMO-TEST-2026-0002",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "file:///r/requirements.txt"}
                    }
                }
            ],
            "message": message,
        }
        report = {"runs": [{"tool": {}, "results": [result]}]}
        contract = TOOL_CONTRACTS["osv-scanner"]

        assert check_run("osv-scanner", contract, report, 1) == []
        message["text"] = "A vulnerability."
        assert check_run("osv-scanner", contract, report, 1) == [
            "osv-scanner: reported nothing on its sample"
        ]

    def test_a_dict_contract_with_no_required_keys_is_not_indexed(self):
        """`required_keys: []` on a dict root used to raise IndexError."""
        contract = {"required_keys": [], "ok_return_codes": (0,)}

        assert check_run("hypothetical", contract, {}, 0)

    def test_the_report_is_read_from_stdout_only(self):
        """trufflehog logs JSON lines to stderr; they are not findings.

        With nothing on stdout the harness parsed stderr instead, so a
        trufflehog that found nothing reported two "findings": its own logs.
        """
        script = 'import sys; sys.stderr.write(\'{"level": "info-0"}\\n\')'
        contract = _stub_contract("trufflehog", exit_code=0, script=script)

        output, returncode = run_tool_on_sample("trufflehog", contract)

        assert (output, returncode) == ([], 0)

    def test_the_report_is_decoded_as_utf8(self):
        """`text=True` alone decodes with the locale codec: cp1252 on Windows.

        cp1252 has no byte 0x81, which `Ё` encodes to, so a report naming it
        raised UnicodeDecodeError instead of parsing. The tools write UTF-8.
        """
        script = (
            "import sys; "
            "sys.stdout.buffer.write('[{\"message\": \"\\u0401\"}]'.encode('utf-8'))"
        )
        contract = _stub_contract("hadolint", exit_code=1, script=script)

        output, _returncode = run_tool_on_sample("hadolint", contract)

        assert output == [{"message": "\u0401"}]


# Allow running directly for debugging
if __name__ == "__main__":
    print("Tool Contract Test Configuration")
    print("=" * 50)

    for tool_name, contract in TOOL_CONTRACTS.items():
        available = "✅" if tool_available(tool_name) else "❌"
        sample = SAMPLES_DIR / contract["sample_target"]
        sample_exists = "✅" if sample.exists() else "❌"

        print(f"\n{tool_name}:")
        print(f"  Available: {available}")
        print(f"  Sample exists: {sample_exists} ({sample})")
        print(f"  Required keys: {contract.get('required_keys', [])}")
        print(f"  Description: {contract.get('description', 'N/A')}")
