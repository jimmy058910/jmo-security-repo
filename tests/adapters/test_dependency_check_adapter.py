import json
from pathlib import Path

from scripts.core.adapters.dependency_check_adapter import DependencyCheckAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_dependency_check_adapter_cve_with_cvss_v3(tmp_path: Path):
    """Test Dependency-Check adapter with CVE and CVSS v3 scoring."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "jackson-databind-2.9.8.jar",
                "filePath": "/app/lib/jackson-databind-2.9.8.jar",
                "packages": [
                    {
                        "id": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"
                    }
                ],
                "vulnerabilities": [
                    {
                        "name": "CVE-2020-36518",
                        "description": "Jackson Databind vulnerable to Denial of Service (DoS) via deeply nested JSON",
                        "severity": "HIGH",
                        "cvssv3": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        },
                        "references": [
                            {
                                "url": "https://github.com/advisories/GHSA-jjjh-jjxp-wpff",
                                "source": "GitHub",
                            }
                        ],
                    }
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CVE-2020-36518"
    assert items[0].severity == "HIGH"
    assert "dependency" in items[0].tags
    assert "sca" in items[0].tags
    assert "cve" in items[0].tags
    assert "maven" in items[0].tags
    assert items[0].cvss is not None
    assert items[0].cvss["version"] == "3.x"
    assert items[0].cvss["score"] == 7.5
    assert items[0].cvss["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert items[0].context["cve"] == "CVE-2020-36518"
    assert items[0].context["dependency_file"] == "jackson-databind-2.9.8.jar"
    assert "pkg:maven" in items[0].context["package_id"]
    assert items[0].location["path"] == "/app/lib/jackson-databind-2.9.8.jar"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2020-36518" in items[0].references


def test_dependency_check_adapter_cve_with_cvss_v2_fallback(tmp_path: Path):
    """Test Dependency-Check adapter with CVE using CVSS v2 fallback."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "11.0.0"},
        "dependencies": [
            {
                "fileName": "commons-fileupload-1.3.1.jar",
                "filePath": "commons-fileupload-1.3.1.jar",
                "vulnerabilities": [
                    {
                        "name": "CVE-2016-1000031",
                        "description": "Apache Commons FileUpload DiskFileItem File Manipulation Remote Code Execution",
                        "severity": "CRITICAL",
                        "cvssv2": {
                            "score": 9.8,
                            "accessVector": "NETWORK",
                            "accessComplexity": "LOW",
                        },
                    }
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CVE-2016-1000031"
    assert items[0].severity == "CRITICAL"
    assert items[0].cvss is not None
    assert items[0].cvss["version"] == "2.0"
    assert items[0].cvss["score"] == 9.8
    assert items[0].cvss["vector"] == "NETWORK"


def test_dependency_check_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test Dependency-Check adapter with multiple vulnerabilities in one dependency."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "log4j-core-2.14.1.jar",
                "filePath": "/app/lib/log4j-core-2.14.1.jar",
                "packages": [
                    {"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}
                ],
                "vulnerabilities": [
                    {
                        "name": "CVE-2021-44228",
                        "description": "Log4j Remote Code Execution (Log4Shell)",
                        "severity": "CRITICAL",
                        "cvssv3": {"baseScore": 10.0, "baseSeverity": "CRITICAL"},
                    },
                    {
                        "name": "CVE-2021-45046",
                        "description": "Log4j incomplete fix for CVE-2021-44228",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 9.0, "baseSeverity": "CRITICAL"},
                    },
                    {
                        "name": "CVE-2021-45105",
                        "description": "Log4j Denial of Service",
                        "severity": "MEDIUM",
                        "cvssv3": {"baseScore": 5.9, "baseSeverity": "MEDIUM"},
                    },
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].ruleId == "CVE-2021-44228"
    assert items[0].severity == "CRITICAL"
    assert items[0].cvss["score"] == 10.0
    assert items[1].ruleId == "CVE-2021-45046"
    assert items[1].severity == "CRITICAL"
    assert items[1].cvss["score"] == 9.0
    assert items[2].ruleId == "CVE-2021-45105"
    assert items[2].severity == "MEDIUM"
    assert items[2].cvss["score"] == 5.9


def test_dependency_check_adapter_multiple_dependencies(tmp_path: Path):
    """Test Dependency-Check adapter with multiple dependencies."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "express-4.17.1.tgz",
                "filePath": "node_modules/express/package.json",
                "packages": [{"id": "pkg:npm/express@4.17.1"}],
                "vulnerabilities": [
                    {
                        "name": "CVE-2022-24999",
                        "description": "Express.js open redirect vulnerability",
                        "severity": "MEDIUM",
                        "cvssv3": {"baseScore": 6.1, "baseSeverity": "MEDIUM"},
                    }
                ],
            },
            {
                "fileName": "axios-0.21.0.tgz",
                "filePath": "node_modules/axios/package.json",
                "packages": [{"id": "pkg:npm/axios@0.21.0"}],
                "vulnerabilities": [
                    {
                        "name": "CVE-2021-3749",
                        "description": "Axios Server-Side Request Forgery (SSRF)",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                    }
                ],
            },
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    # First dependency (express)
    assert items[0].ruleId == "CVE-2022-24999"
    assert items[0].severity == "MEDIUM"
    assert "npm" in items[0].tags
    assert items[0].context["dependency_file"] == "express-4.17.1.tgz"
    # Second dependency (axios)
    assert items[1].ruleId == "CVE-2021-3749"
    assert items[1].severity == "HIGH"
    assert "npm" in items[1].tags
    assert items[1].context["dependency_file"] == "axios-0.21.0.tgz"


def test_dependency_check_adapter_package_manager_detection(tmp_path: Path):
    """Test Dependency-Check adapter package manager tag detection."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "requests-2.25.1.tar.gz",
                "filePath": "requests-2.25.1.tar.gz",
                "packages": [{"id": "pkg:pypi/requests@2.25.1"}],
                "vulnerabilities": [
                    {
                        "name": "CVE-2023-32681",
                        "description": "Requests library proxy authentication leak",
                        "severity": "MEDIUM",
                        "cvssv3": {"baseScore": 6.1, "baseSeverity": "MEDIUM"},
                    }
                ],
            },
            {
                "fileName": "Newtonsoft.Json.12.0.3.nupkg",
                "filePath": "Newtonsoft.Json.12.0.3.nupkg",
                "packages": [{"id": "pkg:nuget/Newtonsoft.Json@12.0.3"}],
                "vulnerabilities": [
                    {
                        "name": "CVE-2024-21907",
                        "description": "Newtonsoft.Json Denial of Service",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                    }
                ],
            },
            {
                "fileName": "rails-5.2.3.gem",
                "filePath": "rails-5.2.3.gem",
                "packages": [{"id": "pkg:gem/rails@5.2.3"}],
                "vulnerabilities": [
                    {
                        "name": "CVE-2020-8164",
                        "description": "Rails remote code execution vulnerability",
                        "severity": "CRITICAL",
                        "cvssv3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                    }
                ],
            },
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    # Python package
    assert "python" in items[0].tags
    assert "pkg:pypi" in items[0].context["package_id"]
    # .NET package
    assert "nuget" in items[1].tags
    assert "pkg:nuget" in items[1].context["package_id"]
    # Ruby gem
    assert "ruby" in items[2].tags
    assert "pkg:gem" in items[2].context["package_id"]


def test_dependency_check_adapter_missing_cvss(tmp_path: Path):
    """Test Dependency-Check adapter handles missing CVSS scores gracefully."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "vulnerable-lib-1.0.0.jar",
                "filePath": "vulnerable-lib-1.0.0.jar",
                "vulnerabilities": [
                    {
                        "name": "CVE-2024-99999",
                        "description": "Hypothetical vulnerability without CVSS score",
                        "severity": "MEDIUM",
                    }
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CVE-2024-99999"
    assert items[0].severity == "MEDIUM"
    # CVSS field should be None when not available
    assert items[0].cvss is None


def test_dependency_check_adapter_additional_references(tmp_path: Path):
    """Test Dependency-Check adapter includes additional vulnerability references."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "spring-core-5.2.0.jar",
                "filePath": "spring-core-5.2.0.jar",
                "vulnerabilities": [
                    {
                        "name": "CVE-2022-22965",
                        "description": "Spring Framework RCE (Spring4Shell)",
                        "severity": "CRITICAL",
                        "cvssv3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                        "references": [
                            {
                                "url": "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement",
                                "source": "Spring Blog",
                            },
                            {
                                "url": "https://github.com/advisories/GHSA-36p3-wjmg-h94x",
                                "source": "GitHub",
                            },
                            {
                                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                "source": "CISA",
                            },
                            {
                                "url": "https://access.redhat.com/security/cve/CVE-2022-22965",
                                "source": "Red Hat",
                            },
                        ],
                    }
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should include NVD link + first 3 additional references
    assert len(items[0].references) == 4
    assert "https://nvd.nist.gov/vuln/detail/CVE-2022-22965" in items[0].references
    assert (
        "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"
        in items[0].references
    )
    assert "https://github.com/advisories/GHSA-36p3-wjmg-h94x" in items[0].references
    assert (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        in items[0].references
    )


def test_dependency_check_adapter_empty_dependencies(tmp_path: Path):
    """Test Dependency-Check adapter with empty dependencies array."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert items == []


def test_dependency_check_adapter_empty_vulnerabilities(tmp_path: Path):
    """Test Dependency-Check adapter with dependencies but no vulnerabilities."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "safe-library-1.0.0.jar",
                "filePath": "safe-library-1.0.0.jar",
                "vulnerabilities": [],
            },
            {
                "fileName": "another-safe-lib-2.0.0.jar",
                "filePath": "another-safe-lib-2.0.0.jar",
                "vulnerabilities": [],
            },
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert items == []


def test_dependency_check_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Dependency-Check findings are enriched with compliance mappings."""
    data = {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": [
            {
                "fileName": "test-lib-1.0.0.jar",
                "filePath": "test-lib-1.0.0.jar",
                "vulnerabilities": [
                    {
                        "name": "CVE-2024-12345",
                        "description": "Test vulnerability for compliance enrichment",
                        "severity": "HIGH",
                        "cvssv3": {"baseScore": 7.5, "baseSeverity": "HIGH"},
                    }
                ],
            }
        ],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)
    adapter = DependencyCheckAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")


# ---------------------------------------------------------------------------
# #1133: ODC's `filePath` for a transitive dependency is
# `<real manifest>?<virtual dependency chain>`, and `fileName` is
# `<package>:<version>` rather than a filename. The fixtures above are all
# Maven jars, which have no `?` at all, so this shape was untested.
# Shapes below are taken verbatim from the 2026-09-02 dogfood run against
# jmoadaptivegolf (65 findings, 4 CRITICAL).
# ---------------------------------------------------------------------------


def _npm_report(dependencies):
    return {
        "reportSchema": "1.1",
        "scanInfo": {"engineVersion": "12.1.0"},
        "dependencies": dependencies,
    }


def _npm_dependency(file_name, file_path, cve, description, severity="HIGH"):
    return {
        "fileName": file_name,
        "filePath": file_path,
        "packages": [{"id": f"pkg:npm/{file_name.split(':')[0]}"}],
        "vulnerabilities": [
            {
                "name": cve,
                "description": description,
                "severity": severity,
            }
        ],
    }


def test_location_is_the_manifest_not_the_virtual_dependency_chain(tmp_path: Path):
    """`package-lock.json?@vitejs\\plugin-react:5.1.0\\...` is not a path.

    Everything after the first `?` is a position in the lockfile's dependency
    graph. Passing it through gave 65 findings at locations no editor or
    reviewer can open.
    """
    data = _npm_report(
        [
            _npm_dependency(
                "@babel/core:7.28.4",
                "C:\\Projects\\app\\package-lock.json?@vitejs\\plugin-react:5.1.0\\@babel\\core:^7.28.4",
                "CVE-2026-11111",
                "A vulnerability in the Babel compiler core.",
            )
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    items = DependencyCheckAdapter().parse(f)

    assert len(items) == 1
    assert items[0].location["path"] == "C:\\Projects\\app\\package-lock.json"
    assert "?" not in items[0].location["path"]


def test_the_stripped_dependency_chain_is_kept_in_context(tmp_path: Path):
    """Collapsing the path must not lose which transitive dep pulled it in."""
    chain = "@vitejs\\plugin-react:5.1.0\\@babel\\core:^7.28.4"
    data = _npm_report(
        [
            _npm_dependency(
                "@babel/core:7.28.4",
                "C:\\Projects\\app\\package-lock.json?" + chain,
                "CVE-2026-11111",
                "A vulnerability in the Babel compiler core.",
            )
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    items = DependencyCheckAdapter().parse(f)

    assert items[0].context["dependency_chain"] == chain


def test_a_direct_dependency_has_no_chain(tmp_path: Path):
    """A `filePath` with no `?` must be left exactly as it is."""
    data = _npm_report(
        [
            _npm_dependency(
                "jackson-databind-2.9.8.jar",
                "/app/lib/jackson-databind-2.9.8.jar",
                "CVE-2020-36518",
                "Denial of service via deeply nested JSON.",
            )
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    items = DependencyCheckAdapter().parse(f)

    assert items[0].location["path"] == "/app/lib/jackson-databind-2.9.8.jar"
    assert items[0].context["dependency_chain"] is None


def test_the_message_names_the_package_first(tmp_path: Path):
    """With the location collapsed to the manifest, the message is the only
    place left that says *which* dependency is vulnerable."""
    data = _npm_report(
        [
            _npm_dependency(
                "ajv:6.12.6",
                "C:\\Projects\\app\\package-lock.json?eslint:9.38.0\\ajv:^6.12.4",
                "CVE-2026-22222",
                "Prototype pollution in the ajv schema validator.",
            )
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    items = DependencyCheckAdapter().parse(f)

    assert items[0].message.startswith("ajv:6.12.6: ")
    assert "Prototype pollution" in items[0].message


def test_two_versions_of_one_package_keep_distinct_ids(tmp_path: Path):
    """The load-bearing guard for collapsing the path.

    `fingerprint()` hashes `(tool, ruleId, path, startLine, message[:120])`.
    Before #1133 the full `filePath` made every finding unique. Collapsing it to
    the manifest removes the only distinguishing field, so two versions of the
    same package sharing one CVE in one lockfile would hash identically and
    `deduplicate_findings_memory_efficient` would drop all but the first.

    Measured on the real jmoadaptivegolf report: collapsing the path with the
    message unchanged collides 5 of 65 findings; with the package leading the
    message, 0 of 65. This is the two-row version of that.

    The description is deliberately longer than MESSAGE_SNIPPET_LENGTH (120) so
    the test also proves the package has to lead: appended at the end it would
    be truncated out of the hash and the collision would return.
    """
    long_description = (
        "A specially crafted input can cause the brace expansion routine to "
        "enter a quadratic code path, allowing a remote attacker to exhaust "
        "CPU and deny service to other users of the application. " * 2
    )
    assert len(long_description) > 120

    manifest = "C:\\Projects\\app\\package-lock.json"
    data = _npm_report(
        [
            _npm_dependency(
                "brace-expansion:1.1.12",
                manifest + "?minimatch:3.1.2\\brace-expansion:^1.1.7",
                "CVE-2026-33671",
                long_description,
            ),
            _npm_dependency(
                "brace-expansion:2.0.2",
                manifest + "?brace-expansion",
                "CVE-2026-33671",
                long_description,
            ),
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    items = DependencyCheckAdapter().parse(f)

    assert len(items) == 2
    assert items[0].location["path"] == items[1].location["path"] == manifest
    assert items[0].ruleId == items[1].ruleId
    assert items[0].id != items[1].id, (
        "two versions of one package in one manifest collapsed to a single "
        "fingerprint; deduplication would silently drop one"
    )


def test_non_fatal_analysis_exceptions_are_logged(tmp_path: Path, caplog):
    """ODC exits 14 with a complete report but unanalysed dependencies.

    JMo now accepts exit 14, so the coverage gap it signals has to be said out
    loud somewhere. Measured on juice-shop: 3 exceptions, all
    `encrypted ZIP entry not supported`.
    """
    import logging

    data = {
        "reportSchema": "1.1",
        "scanInfo": {
            "engineVersion": "12.1.0",
            "analysisExceptions": [
                {
                    "exception": {
                        "message": (
                            "org.owasp.dependencycheck.analyzer.exception."
                            "AnalysisException: java.util.zip.ZipException: "
                            "encrypted ZIP entry not supported"
                        ),
                        "stackTrace": ["..."],
                    }
                }
            ],
        },
        "dependencies": [],
    }
    f = tmp_path / "dependency-check.json"
    write(f, data)

    with caplog.at_level(
        logging.WARNING, logger="scripts.core.adapters.dependency_check_adapter"
    ):
        DependencyCheckAdapter().parse(f)

    assert "1 non-fatal analysis exception" in caplog.text
    assert "encrypted ZIP entry not supported" in caplog.text


def test_a_clean_report_logs_no_exception_warning(tmp_path: Path, caplog):
    """No analysisExceptions key must stay silent, not warn about zero."""
    import logging

    data = _npm_report(
        [
            _npm_dependency(
                "ajv:6.12.6",
                "/app/package-lock.json?ajv",
                "CVE-2026-22222",
                "Prototype pollution.",
            )
        ]
    )
    f = tmp_path / "dependency-check.json"
    write(f, data)

    with caplog.at_level(
        logging.WARNING, logger="scripts.core.adapters.dependency_check_adapter"
    ):
        DependencyCheckAdapter().parse(f)

    assert "analysis exception" not in caplog.text
