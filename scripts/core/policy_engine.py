#!/usr/bin/env python3
"""
Policy-as-Code engine using Open Policy Agent (OPA).

Provides:
- Rego policy evaluation
- Custom policy loading
- Built-in policy marketplace
- Policy validation and testing
- Integration with CommonFinding v1.2.0 schema
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

# Import packaging for version comparison
try:
    from packaging.version import Version, parse as _parse_packaging

    def parse_version(version: str) -> Any:
        """Parse version using packaging library."""
        return _parse_packaging(version)

except ImportError:
    # Fallback for environments without packaging
    def parse_version(version: str) -> Any:
        """Simple version parser fallback."""
        return tuple(int(x) for x in version.split("."))


logger = logging.getLogger(__name__)


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    policy_name: str
    passed: bool
    violations: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def violation_count(self) -> int:
        """Return total number of violations."""
        return len(self.violations)

    @property
    def has_violations(self) -> bool:
        """Check if any violations exist."""
        return self.violation_count > 0


@dataclass
class PolicyMetadata:
    """Metadata about a policy."""

    name: str
    version: str
    description: str
    author: str = "JMo Security"
    tags: List[str] = field(default_factory=list)
    severity_levels: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)  # e.g., ["OWASP", "PCI DSS"]


class PolicyEngine:
    """OPA-based policy evaluation engine."""

    def __init__(self, opa_binary: str = "opa"):
        """Initialize policy engine.

        Args:
            opa_binary: Path to OPA binary (default: "opa" in PATH)
        """
        self.opa_binary = opa_binary
        self._verify_opa_available()

    def _verify_opa_available(self) -> None:
        """Verify OPA binary is available and version is compatible."""
        try:
            result = subprocess.run(
                [self.opa_binary, "version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                raise RuntimeError(f"OPA binary not functional: {result.stderr}")

            # Check version >= 0.70.0 (recommendation from implementation plan)
            version_match = re.search(r"Version:\s+(\d+\.\d+\.\d+)", result.stdout)
            if version_match:
                version = version_match.group(1)
                try:
                    if parse_version(version) < parse_version("0.70.0"):
                        logger.warning(
                            f"OPA version {version} detected. "
                            "Recommend upgrading to >= 0.70.0 for full compatibility."
                        )
                except Exception as e:
                    logger.debug(f"Could not parse OPA version: {e}")

            logger.debug(f"OPA version: {result.stdout.strip()}")
        except FileNotFoundError:
            raise RuntimeError(
                f"OPA binary not found: {self.opa_binary}. "
                "Install via: make tools or download from https://www.openpolicyagent.org/docs/latest/#running-opa"
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("OPA binary timed out during verification")

    def evaluate(
        self,
        findings: List[Dict[str, Any]],
        policy_path: Path,
        input_data: Optional[Dict[str, Any]] = None,
    ) -> PolicyResult:
        """Evaluate findings against a Rego policy.

        Args:
            findings: List of CommonFinding dictionaries
            policy_path: Path to .rego policy file
            input_data: Additional input data for policy (optional)

        Returns:
            PolicyResult with evaluation outcome

        Raises:
            FileNotFoundError: If policy file doesn't exist
            RuntimeError: If policy evaluation fails
        """
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy not found: {policy_path}")

        # Prepare input document
        input_doc = {
            "findings": findings,
            "metadata": input_data or {},
        }

        # Write input to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(input_doc, f)
            input_file = Path(f.name)

        try:
            # Extract package name from policy file
            package_name = self._extract_package_name(policy_path)
            if not package_name:
                package_name = "data.jmo.policy"  # Fallback to root namespace

            # Evaluate policy using OPA eval
            result = subprocess.run(
                [
                    self.opa_binary,
                    "eval",
                    "-d",
                    str(policy_path),
                    "-i",
                    str(input_file),
                    "--format",
                    "json",
                    package_name,  # Use policy-specific package
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.error(f"OPA evaluation failed: {result.stderr}")
                raise RuntimeError(f"Policy evaluation error: {result.stderr}")

            # Parse OPA output
            output = json.loads(result.stdout)
            policy_result = self._parse_opa_output(output, policy_path.stem)

            return policy_result

        finally:
            # Cleanup temp file
            input_file.unlink(missing_ok=True)

    def _parse_opa_output(
        self, output: Dict[str, Any], policy_name: str
    ) -> PolicyResult:
        """Parse OPA JSON output into PolicyResult with schema validation.

        Expected OPA output structure:
        {
          "result": [{
            "expressions": [{
              "value": {
                "allow": true/false,
                "violations": [...],
                "warnings": [...],
                "message": "..."
              }
            }]
          }]
        }

        Args:
            output: OPA JSON output
            policy_name: Name of the policy (derived from filename)

        Returns:
            PolicyResult object

        Raises:
            ValueError: If OPA output is malformed or missing required fields
        """
        try:
            result_value = output["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected OPA output format: {output}")
            raise ValueError(f"Invalid OPA output structure: {e}")

        # Validate required fields
        if "allow" not in result_value:
            raise ValueError(
                f"Policy {policy_name} missing required 'allow' field in output. "
                "Ensure policy includes: allow := true/false"
            )

        # Extract policy decision
        passed = result_value.get("allow", False)
        violations = result_value.get("violations", [])
        warnings = result_value.get("warnings", [])
        message = result_value.get("message", "")

        # Validate violations structure if present
        if violations and not isinstance(violations, list):
            raise ValueError(
                f"Policy {policy_name} violations must be a list, got {type(violations)}"
            )

        return PolicyResult(
            policy_name=policy_name,
            passed=passed,
            violations=violations,
            warnings=warnings,
            message=message,
        )

    def validate_policy(self, policy_path: Path) -> tuple[bool, str]:
        """Validate Rego syntax without executing.

        Args:
            policy_path: Path to .rego policy file

        Returns:
            Tuple of (is_valid, error_message)
        """
        result = subprocess.run(
            [self.opa_binary, "check", str(policy_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return (False, result.stderr.strip())

        logger.info(f"✅ Policy validation passed: {policy_path.name}")
        return (True, "")

    def test_policy(self, policy_path: Path, test_data_path: Path) -> PolicyResult:
        """Test policy against sample findings.

        Args:
            policy_path: Path to .rego policy file
            test_data_path: Path to JSON file with sample findings

        Returns:
            PolicyResult from test evaluation

        Raises:
            FileNotFoundError: If test data file doesn't exist
            ValueError: If test data is malformed
        """
        if not test_data_path.exists():
            raise FileNotFoundError(f"Test data not found: {test_data_path}")

        with open(test_data_path) as f:
            test_data = json.load(f)

        if not isinstance(test_data, dict):
            raise ValueError("Test data must be a JSON object")

        findings = test_data.get("findings", [])
        input_data = test_data.get("metadata", {})

        return self.evaluate(findings, policy_path, input_data)

    def _extract_package_name(self, policy_path: Path) -> Optional[str]:
        """Extract package declaration from Rego policy file.

        Args:
            policy_path: Path to .rego policy file

        Returns:
            Package name in data.* format (e.g., "data.jmo.policy.secrets"), or None
        """
        try:
            content = policy_path.read_text()
            import re

            # Look for package declaration (e.g., "package jmo.policy.secrets")
            match = re.search(r"^\s*package\s+([\w.]+)", content, re.MULTILINE)
            if match:
                package = match.group(1)
                # Convert to data.* format (package jmo.policy.secrets → data.jmo.policy.secrets)
                return f"data.{package}"
            return None
        except Exception as e:
            logger.warning(f"Failed to extract package name from {policy_path}: {e}")
            return None

    def get_metadata(self, policy_path: Path) -> Dict[str, Any]:
        """Extract metadata from Rego policy file.

        Reads the policy file and parses the metadata object using OPA eval.

        Args:
            policy_path: Path to .rego policy file

        Returns:
            Metadata dictionary (empty if no metadata found)

        Raises:
            FileNotFoundError: If policy file doesn't exist
        """
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")

        try:
            # Use OPA to evaluate just the metadata
            result = subprocess.run(
                [
                    self.opa_binary,
                    "eval",
                    "-d",
                    str(policy_path),
                    "--format",
                    "json",
                    "data.jmo.policy.metadata",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                output = json.loads(result.stdout)
                # OPA eval returns: {"result": [{"expressions": [{"value": {...}}]}]}
                if output.get("result") and len(output["result"]) > 0:
                    expressions = output["result"][0].get("expressions", [])
                    if expressions and len(expressions) > 0:
                        metadata = expressions[0].get("value")
                        if metadata and isinstance(metadata, dict):
                            return cast(Dict[str, Any], metadata)

            # Fallback: parse file manually for metadata
            content = policy_path.read_text()
            import re

            # Look for metadata object definition
            match = re.search(
                r"metadata\s*:=\s*\{([^}]+)\}", content, re.DOTALL | re.MULTILINE
            )
            if match:
                # Basic parsing - extract key-value pairs
                metadata = {}
                pairs = match.group(1).split(",")
                for pair in pairs:
                    if ":" in pair:
                        key, value = pair.split(":", 1)
                        key = key.strip().strip('"')
                        value = value.strip().strip('",')
                        # Try to parse as JSON array
                        if value.startswith("["):
                            try:
                                metadata[key] = json.loads(value)
                            except json.JSONDecodeError:
                                metadata[key] = value
                        else:
                            metadata[key] = value
                return metadata

            return {}

        except Exception as e:
            logger.warning(f"Failed to extract metadata from {policy_path}: {e}")
            return {}
