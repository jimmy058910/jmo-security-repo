# New Tool Adapter Examples (v1.0.0)

Real-world examples of adding new security tool adapters using the v3.0.0 plugin architecture.

---

## Example 1: Prowler (Cloud CSPM)

**Use Case:** AWS/Azure/GCP security auditing

**Key Features:**
- Multi-cloud support (AWS, Azure, GCP, K8s, M365)
- 400+ compliance checks (CIS, PCI-DSS, NIST, GDPR, HIPAA)
- JSON output with severity levels

**Plugin Adapter:**

```python
@adapter_plugin(PluginMetadata(
    name="prowler",
    version="1.0.0",
    tool_name="prowler",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={"0": "pass", "1": "findings", "3": "error"}
))
class ProwlerAdapter(AdapterPlugin):
    """Prowler cloud security auditing adapter."""

    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse Prowler JSON output."""
        if not output_path.exists():
            return []

        findings = []
        data = json.loads(output_path.read_text())

        for check in data.get("findings", []):
            finding = Finding(
                schemaVersion="1.2.0",
                id=self.get_fingerprint(
                    tool="prowler",
                    ruleId=check["check_id"],
                    path=check.get("resource_id", ""),
                    startLine=0,
                    message=check["status_extended"][:120]
                ),
                ruleId=check["check_id"],
                severity=self._map_severity(check["severity"]),
                tool={"name": "prowler", "version": self.metadata.version},
                location={
                    "path": check.get("resource_id", ""),
                    "startLine": 0
                },
                message=check["status_extended"],
                description=check.get("check_title", ""),
                remediation=check.get("remediation", ""),
                raw=check
            )
            findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> str:
        """Map Prowler severity to CommonFinding."""
        mapping = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "informational": "INFO"
        }
        return mapping.get(severity.lower(), "INFO")
```

**CLI Integration:**

```python
# In jmo.py job_aws_account()
if "prowler" in tools:
    cmd = [
        "prowler",
        "aws",
        "--profile", account_id,
        "--output-formats", "json",
        "--output-directory", str(out_dir),
        "--no-banner",
        "--quiet"
    ]
    rc, _, _, used = _run_cmd(cmd, timeout, retries, ok_rcs=(0, 1, 3))
```

---

## Example 2: MobSF (Mobile SAST)

**Use Case:** iOS/Android mobile app security testing

**Key Features:**
- Static + dynamic analysis
- Android (APK) and iOS (IPA) support
- OWASP Mobile Top 10 coverage

**Plugin Adapter:**

```python
@adapter_plugin(PluginMetadata(
    name="mobsf",
    version="1.0.0",
    tool_name="mobsf",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={"0": "complete"}
))
class MobSFAdapter(AdapterPlugin):
    """MobSF mobile security framework adapter."""

    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse MobSF JSON output."""
        if not output_path.exists():
            return []

        findings = []
        data = json.loads(output_path.read_text())

        # Parse static analysis findings
        for severity_key in ["high", "warning", "info"]:
            for issue in data.get(severity_key, []):
                finding = Finding(
                    schemaVersion="1.2.0",
                    id=self.get_fingerprint(
                        tool="mobsf",
                        ruleId=issue.get("rule_id", "MOBSF-UNKNOWN"),
                        path=issue.get("file", ""),
                        startLine=issue.get("line", 0),
                        message=issue.get("title", "")[:120]
                    ),
                    ruleId=issue.get("rule_id", "MOBSF-UNKNOWN"),
                    severity=self._map_severity(severity_key),
                    tool={"name": "mobsf", "version": self.metadata.version},
                    location={
                        "path": issue.get("file", ""),
                        "startLine": issue.get("line", 0)
                    },
                    message=issue.get("title", ""),
                    description=issue.get("description", ""),
                    raw=issue
                )
                findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> str:
        """Map MobSF severity to CommonFinding."""
        mapping = {
            "high": "HIGH",
            "warning": "MEDIUM",
            "info": "INFO"
        }
        return mapping.get(severity.lower(), "INFO")
```

---

## Example 3: Checkov (CI/CD Expansion)

**Use Case:** Scan GitHub Actions, GitLab CI, CircleCI configs

**Key Features:**
- IaC + CI/CD pipeline scanning
- Detects hardcoded secrets, insecure permissions
- GitHub Actions, GitLab CI, CircleCI support

**Plugin Adapter:**

```python
@adapter_plugin(PluginMetadata(
    name="checkov",
    version="1.0.0",
    tool_name="checkov",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={"0": "pass", "1": "findings"}
))
class CheckovAdapter(AdapterPlugin):
    """Checkov IaC and CI/CD security scanner adapter."""

    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse Checkov JSON output (IaC + CI/CD)."""
        if not output_path.exists():
            return []

        findings = []
        data = json.loads(output_path.read_text())

        for check in data.get("results", {}).get("failed_checks", []):
            # Detect if this is a CI/CD finding
            is_cicd = self._is_cicd_file(check.get("file_path", ""))

            finding = Finding(
                schemaVersion="1.2.0",
                id=self.get_fingerprint(
                    tool="checkov",
                    ruleId=check["check_id"],
                    path=check["file_path"],
                    startLine=check.get("file_line_range", [0])[0],
                    message=check["check_name"][:120]
                ),
                ruleId=check["check_id"],
                severity=self._map_severity(check.get("severity", "MEDIUM")),
                tool={"name": "checkov", "version": self.metadata.version},
                location={
                    "path": check["file_path"],
                    "startLine": check.get("file_line_range", [0])[0]
                },
                message=check["check_name"],
                description=check.get("description", ""),
                # Tag CI/CD findings for filtering
                tags=["cicd-security"] if is_cicd else ["iac"],
                raw=check
            )
            findings.append(finding)

        return findings

    def _is_cicd_file(self, file_path: str) -> bool:
        """Check if file is a CI/CD pipeline config."""
        cicd_indicators = [
            ".github/workflows",
            ".gitlab-ci.yml",
            ".circleci/config.yml",
            "azure-pipelines.yml",
            ".bitbucket-pipelines.yml"
        ]
        return any(indicator in file_path for indicator in cicd_indicators)

    def _map_severity(self, severity: str) -> str:
        """Map Checkov severity to CommonFinding."""
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW"
        }
        return mapping.get(severity.upper(), "MEDIUM")
```

---

## Example 4: ScanCode (License Compliance)

**Use Case:** OSS license detection and compliance

**Plugin Adapter:**

```python
@adapter_plugin(PluginMetadata(
    name="scancode",
    version="1.0.0",
    tool_name="scancode",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={"0": "complete"}
))
class ScanCodeAdapter(AdapterPlugin):
    """ScanCode license compliance scanner adapter."""

    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse ScanCode JSON output."""
        if not output_path.exists():
            return []

        findings = []
        data = json.loads(output_path.read_text())

        for file_scan in data.get("files", []):
            for license_info in file_scan.get("licenses", []):
                # Flag risky licenses (GPL, AGPL)
                is_risky = self._is_risky_license(license_info.get("key", ""))

                finding = Finding(
                    schemaVersion="1.2.0",
                    id=self.get_fingerprint(
                        tool="scancode",
                        ruleId=f"LICENSE-{license_info['key']}",
                        path=file_scan["path"],
                        startLine=license_info.get("start_line", 0),
                        message=f"License: {license_info['name']}"[:120]
                    ),
                    ruleId=f"LICENSE-{license_info['key']}",
                    severity="HIGH" if is_risky else "INFO",
                    tool={"name": "scancode", "version": self.metadata.version},
                    location={
                        "path": file_scan["path"],
                        "startLine": license_info.get("start_line", 0)
                    },
                    message=f"License: {license_info['name']}",
                    description=f"Score: {license_info.get('score', 0)}",
                    tags=(["license-compliance", "risky-license"]
                          if is_risky else ["license-compliance"]),
                    raw=license_info
                )
                findings.append(finding)

        return findings

    def _is_risky_license(self, license_key: str) -> bool:
        """Check if license is risky (GPL, AGPL in commercial project)."""
        risky_licenses = ["gpl", "agpl", "lgpl-3.0"]
        return any(risky in license_key.lower() for risky in risky_licenses)
```

---

## Example 5: Lynis (System Hardening)

**Use Case:** Linux/macOS system hardening audits

**Plugin Adapter:**

```python
@adapter_plugin(PluginMetadata(
    name="lynis",
    version="1.0.0",
    tool_name="lynis",
    schema_version="1.2.0",
    output_format="text",  # Lynis outputs text log, parse to JSON
    exit_codes={"0": "complete"}
))
class LynisAdapter(AdapterPlugin):
    """Lynis system hardening audit adapter."""

    @property
    def metadata(self) -> PluginMetadata:
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse Lynis text log output."""
        if not output_path.exists():
            return []

        findings = []
        content = output_path.read_text()

        # Parse Lynis log format
        # WARNING: [test-id] Description
        # SUGGESTION: [test-id] Recommendation
        for line in content.splitlines():
            if line.startswith("warning["):
                finding = self._parse_warning(line)
                if finding:
                    findings.append(finding)
            elif line.startswith("suggestion["):
                finding = self._parse_suggestion(line)
                if finding:
                    findings.append(finding)

        return findings

    def _parse_warning(self, line: str) -> Optional[Finding]:
        """Parse Lynis warning line."""
        # Format: warning[test-id]:description
        import re
        match = re.match(r"warning\[([^\]]+)\]:(.*)", line)
        if not match:
            return None

        test_id, description = match.groups()
        return Finding(
            schemaVersion="1.2.0",
            id=self.get_fingerprint(
                tool="lynis",
                ruleId=test_id,
                path="localhost",
                startLine=0,
                message=description[:120]
            ),
            ruleId=test_id,
            severity="MEDIUM",
            tool={"name": "lynis", "version": self.metadata.version},
            location={"path": "localhost", "startLine": 0},
            message=description.strip(),
            tags=["system-hardening"],
            raw={"line": line}
        )

    def _parse_suggestion(self, line: str) -> Optional[Finding]:
        """Parse Lynis suggestion line."""
        import re
        match = re.match(r"suggestion\[([^\]]+)\]:(.*)", line)
        if not match:
            return None

        test_id, description = match.groups()
        return Finding(
            schemaVersion="1.2.0",
            id=self.get_fingerprint(
                tool="lynis",
                ruleId=test_id,
                path="localhost",
                startLine=0,
                message=description[:120]
            ),
            ruleId=test_id,
            severity="LOW",
            tool={"name": "lynis", "version": self.metadata.version},
            location={"path": "localhost", "startLine": 0},
            message=description.strip(),
            tags=["system-hardening", "suggestion"],
            raw={"line": line}
        )
```
