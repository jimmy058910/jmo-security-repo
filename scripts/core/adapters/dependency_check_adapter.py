#!/usr/bin/env python3
"""
OWASP Dependency-Check adapter - Maps Dependency-Check SCA JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Software Composition Analysis (SCA)
- Known vulnerability detection in dependencies
- CPE (Common Platform Enumeration) identification
- CVE/NVD integration with CVSS scoring

Tool Version: 12.1.0+
Output Format: JSON with dependencies array
Exit Codes (from ODC's own App.java - it does NOT return 1 for vulnerabilities,
which is what this docstring claimed until #1133):
    0  success
    1  a file named on the command line was not found
    13 fatal exceptions during the scan
    14 non-fatal exceptions during the scan (report still written)
    15 a vulnerability met the --failOnCVSS threshold

Supported Package Managers:
- Maven, Gradle (Java)
- npm, yarn (JavaScript/Node.js)
- pip, poetry (Python)
- NuGet (.NET)
- Ruby gems, Composer (PHP)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

# Configure logging
logger = logging.getLogger(__name__)


@adapter_plugin(
    PluginMetadata(
        name="dependency_check",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for OWASP Dependency-Check SCA tool",
        tool_name="dependency-check",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={
            0: "success",
            1: "file not found",
            13: "fatal analysis exceptions",
            14: "non-fatal analysis exceptions",
            15: "--failOnCVSS threshold met",
        },
    )
)
class DependencyCheckAdapter(AdapterPlugin):
    """Adapter for OWASP Dependency-Check SCA (plugin architecture).

    v1.0.0 Features:
    - Software Composition Analysis (SCA)
    - CVE detection in dependencies
    - CVSS v2/v3 scoring
    - CPE identification

    Findings are automatically tagged as 'dependency' and 'sca'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to dependency-check.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_dependency_check_internal(output_path)

        # Convert dicts to Finding objects
        findings = []
        for f_dict in findings_dicts:
            finding = Finding(
                schemaVersion=f_dict.get("schemaVersion", "1.2.0"),
                id=f_dict.get("id", ""),
                ruleId=f_dict.get("ruleId", ""),
                severity=f_dict.get("severity", "INFO"),
                tool=f_dict.get("tool", {}),
                location=f_dict.get("location", {}),
                message=f_dict.get("message", ""),
                title=f_dict.get("title"),
                description=f_dict.get("description"),
                remediation=f_dict.get("remediation"),
                references=f_dict.get("references", []),
                tags=f_dict.get("tags", []),
                cvss=f_dict.get("cvss"),
                risk=f_dict.get("risk"),
                compliance=f_dict.get("compliance"),
                context=f_dict.get("context"),
                raw=f_dict.get("raw"),
            )
            findings.append(finding)

        return findings


#: Cap on how many ODC analysis exceptions are named in the log, and on how much
#: of each. Both are needed: measured across the three dogfood reports (15,944
#: exceptions - jmoadaptivegolf alone produced 8499 and jmo-security-repo 7442,
#: not the 3 juice-shop showed), a message is a Java class name plus an absolute
#: path, median 99 characters and p90 99. 240 keeps every message measured
#: except one 366-character outlier whole, and bounds the line either way.
MAX_LOGGED_EXCEPTIONS = 5
MAX_EXCEPTION_MESSAGE_CHARS = 240


def _manifest_path(file_path: str) -> str:
    r"""Strip ODC's virtual dependency chain from a `filePath`.

    ODC reports a transitive dependency as `<real manifest>?<chain>`, e.g.::

        C:\repo\package-lock.json?@vitejs\plugin-react:5.1.0\@babel\core:^7.28.4

    Everything after the first `?` is a position in the lockfile's dependency
    graph, not a path on disk. Passing it through gave 65 findings at locations
    like `package-lock.json?/vite:7.1.12`, which no editor or reviewer can open.
    """
    return file_path.split("?", 1)[0]


def _log_analysis_exceptions(scan_info: Any, path: str | Path) -> None:
    """Warn about ODC's non-fatal analysis exceptions, if the report has any."""
    if not isinstance(scan_info, dict):
        return
    exceptions = scan_info.get("analysisExceptions")
    if not isinstance(exceptions, list) or not exceptions:
        return

    messages = []
    for entry in exceptions[:MAX_LOGGED_EXCEPTIONS]:
        if not isinstance(entry, dict):
            continue
        exc = entry.get("exception")
        if isinstance(exc, dict):
            messages.append(
                str(exc.get("message", "")).strip()[:MAX_EXCEPTION_MESSAGE_CHARS]
            )

    logger.warning(
        "dependency-check reported %d non-fatal analysis exception(s) in %s; "
        "those dependencies were not analysed: %s%s",
        len(exceptions),
        path,
        "; ".join(m for m in messages if m),
        (
            f" (and {len(exceptions) - MAX_LOGGED_EXCEPTIONS} more)"
            if len(exceptions) > MAX_LOGGED_EXCEPTIONS
            else ""
        ),
    )


def _load_dependency_check_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse Dependency-Check JSON output.

    Args:
        path: Path to dependency-check.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    data = safe_load_json_file(path, default=None)

    out: list[dict[str, Any]] = []

    # Dependency-Check JSON structure: {"reportSchema": "1.1", "scanInfo": {...}, "dependencies": [...]}
    if not isinstance(data, dict):
        return []

    # Extract version for tool metadata
    scan_info = data.get("scanInfo", {})
    engine_version = str(scan_info.get("engineVersion", "12.1.0"))

    # ODC exits 14 when it hit non-fatal exceptions, and JMo now accepts that
    # code because the report is complete either way. Accepting it silently
    # would hide real coverage gaps - an `encrypted ZIP entry not supported`
    # means that archive's contents were never analysed - so surface them here,
    # where the JSON is already parsed.
    #
    # The scale is the argument for logging at all. The issue reported 3
    # exceptions, which is juice-shop's number (and those 3 are three different
    # messages, not three of one). Re-parsing all three dogfood reports gives
    # 15,944: jmoadaptivegolf 8499 and jmo-security-repo 7442. Almost all of
    # jmoadaptivegolf's name a vanished path under `.horusec/<uuid>/`, so ODC
    # is another casualty of #1132 (#1133).
    _log_analysis_exceptions(scan_info, path)

    # Process dependencies array
    dependencies = data.get("dependencies", [])
    if not isinstance(dependencies, list):
        return []

    for dep in dependencies:
        if not isinstance(dep, dict):
            continue

        # Extract dependency metadata. Note ODC's `fileName` is NOT a filename
        # for a transitive dependency - it is `<package>:<version>`, e.g.
        # `@babel/core:7.28.4`. The manifest it came from is the part of
        # `filePath` before the `?`.
        file_name = str(dep.get("fileName", ""))
        raw_file_path = str(dep.get("filePath", file_name))
        file_path = _manifest_path(raw_file_path)
        dependency_chain = (
            raw_file_path.split("?", 1)[1] if "?" in raw_file_path else None
        )

        # Extract package information (GAV for Maven, etc.)
        packages = dep.get("packages", [])
        package_id = None
        if isinstance(packages, list) and packages:
            pkg = packages[0]
            if isinstance(pkg, dict):
                package_id = str(pkg.get("id", ""))

        # Process vulnerabilities for this dependency
        vulnerabilities = dep.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            continue

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            # Extract vulnerability metadata
            cve_name = str(vuln.get("name", ""))
            description = str(vuln.get("description", ""))
            severity_raw = str(vuln.get("severity", "MEDIUM"))

            # Extract CVSS scores (prefer v3 over v2)
            cvss_field = None
            cvss_v3 = vuln.get("cvssv3", {})
            cvss_v2 = vuln.get("cvssv2", {})

            if isinstance(cvss_v3, dict) and cvss_v3.get("baseScore") is not None:
                cvss_field = {
                    "version": "3.x",
                    "score": float(cvss_v3.get("baseScore", 0)),
                    "vector": str(cvss_v3.get("vectorString", "")),
                }
                # Use CVSS v3 severity if available
                severity_raw = str(cvss_v3.get("baseSeverity", severity_raw))
            elif isinstance(cvss_v2, dict) and cvss_v2.get("score") is not None:
                cvss_field = {
                    "version": "2.0",
                    "score": float(cvss_v2.get("score", 0)),
                    "vector": str(cvss_v2.get("accessVector", "")),
                }

            # Normalize severity
            severity = normalize_severity(severity_raw)

            # Build message. The package leads, for two reasons.
            #
            # Readability: the location is now the manifest, so without the
            # package the finding no longer says *which* dependency is
            # vulnerable.
            #
            # Correctness: `fingerprint()` hashes only `message[:120]`, and
            # collapsing the path removes the only field that used to
            # distinguish two versions of the same package in one lockfile.
            # Measured on jmoadaptivegolf: collapsing the path with the message
            # unchanged collides 5 of 65 findings (brace-expansion 1.1.12 vs
            # 2.0.2 and friends), and `deduplicate_findings_memory_efficient`
            # would then drop all but the first. With the package in front,
            # 0 of 65 collide. Putting it at the END would not work - the CVE
            # description is far longer than the snippet (#1133).
            detail = (
                description or f"Known vulnerability {cve_name} detected in dependency"
            )
            message = f"{file_name}: {detail}" if file_name else detail

            # Build title
            title = f"{cve_name}: {file_name}"

            # Generate stable fingerprint
            fid = fingerprint("dependency-check", cve_name, file_path, 0, message)

            # Build references
            references = []
            if cve_name and cve_name.startswith("CVE-"):
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_name}")

            # Extract additional references from vulnerability
            vuln_refs = vuln.get("references", [])
            if isinstance(vuln_refs, list):
                for ref in vuln_refs[:3]:  # Limit to first 3 references
                    if isinstance(ref, dict):
                        url = ref.get("url") or ref.get("source")
                        if url:
                            references.append(str(url))

            # Build tags
            tags = ["dependency", "sca", "cve", "supply-chain"]
            if package_id:
                if "pkg:maven" in package_id:
                    tags.append("maven")
                if "pkg:npm" in package_id:
                    tags.append("npm")
                if "pkg:pypi" in package_id or "pkg:python" in package_id:
                    tags.append("python")
                if "pkg:nuget" in package_id:
                    tags.append("nuget")
                if "pkg:gem" in package_id:
                    tags.append("ruby")

            # Build remediation
            remediation = f"Update {file_name} to a version that resolves {cve_name}. Review release notes and security advisories."

            # Build finding dict
            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": cve_name,
                "title": title,
                "message": message,
                "description": description,
                "severity": severity,
                "tool": {
                    "name": "dependency-check",
                    "version": engine_version,
                },
                "location": {
                    "path": file_path,
                    "startLine": 0,  # Dependencies don't have line numbers
                },
                "remediation": remediation,
                "references": references,
                "tags": tags,
                "cvss": cvss_field,
                "context": {
                    "cve": cve_name,
                    "dependency_file": file_name,
                    "package_id": package_id or None,
                    # The virtual chain stripped out of location.path, kept so
                    # "which transitive dependency pulled this in" survives.
                    "dependency_chain": dependency_chain,
                },
                "raw": vuln,
            }

            out.append(finding)

    return out
