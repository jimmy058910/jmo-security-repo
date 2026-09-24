# New Tool Adapter Examples (v1.0.0)

Real-world examples of adding new security tool adapters using the v3.0.0 plugin architecture.

---

## Example 1: Checkov (CI/CD Expansion)

**Use Case:** Scan GitHub Actions, GitLab CI, CircleCI configs

> A sketch of the shape, not a copy of the shipped adapter.
> `scripts/core/adapters/checkov_adapter.py:167-212` keys CI/CD tagging on
> Checkov's own `check_type` rather than on the file path, which is more
> reliable; read it before copying this.

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
    exit_codes={0: "pass", 1: "findings"}
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
                # Module-level fingerprint() from scripts.core.common_finding;
                # self.get_fingerprint() takes an already-built Finding.
                id=fingerprint(
                    "checkov",
                    check["check_id"],
                    check["file_path"],
                    check.get("file_line_range", [0])[0],
                    check["check_name"],
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
