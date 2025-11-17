#!/usr/bin/env python3
"""
JMo Security Repository Completeness Analyzer

Performs comprehensive analysis to identify:
1. Documentation-code drift (features in code not documented)
2. Undocumented features and APIs
3. Missing or outdated documentation
4. Inconsistencies between CLAUDE.md, README.md, and actual implementation
5. Test coverage gaps mapped to features
6. Configuration drift between examples and actual usage

This replaces Skill Seekers with a custom solution tailored to JMo Security's needs.
"""

import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Add scripts to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class RepositoryAnalyzer:
    """Analyzes JMo Security repository for completeness and drift."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.findings = {
            "undocumented_features": [],
            "doc_code_drift": [],
            "missing_docs": [],
            "inconsistencies": [],
            "config_drift": [],
            "test_gaps": [],
            "recommendations": [],
        }
        self.stats = {
            "total_python_files": 0,
            "total_functions": 0,
            "total_classes": 0,
            "documented_in_claude_md": 0,
            "documented_in_readme": 0,
            "documented_in_user_guide": 0,
        }

    def analyze(self) -> Dict:
        """Run comprehensive analysis."""
        print("🔍 Starting JMo Security Repository Analysis...")
        print()

        # 1. Extract all Python APIs
        print("📊 Step 1/7: Extracting Python APIs...")
        python_apis = self._extract_python_apis()

        # 2. Parse all documentation
        print("📚 Step 2/7: Parsing documentation...")
        doc_content = self._parse_documentation()

        # 3. Detect undocumented features
        print("🔎 Step 3/7: Detecting undocumented features...")
        self._detect_undocumented_features(python_apis, doc_content)

        # 4. Check CLI command completeness
        print("⌨️  Step 4/7: Analyzing CLI commands...")
        self._analyze_cli_completeness()

        # 5. Verify configuration examples
        print("⚙️  Step 5/7: Verifying configuration examples...")
        self._verify_config_examples()

        # 6. Map test coverage to features
        print("🧪 Step 6/7: Mapping test coverage...")
        self._map_test_coverage(python_apis)

        # 7. Check documentation consistency
        print("📖 Step 7/7: Checking documentation consistency...")
        self._check_doc_consistency()

        # 8. Generate recommendations
        print()
        print("💡 Generating recommendations...")
        self._generate_recommendations()

        return self._generate_report()

    def _extract_python_apis(self) -> Dict[str, Dict]:
        """Extract all public APIs from Python files."""
        apis = defaultdict(lambda: {"functions": [], "classes": [], "cli_commands": []})

        python_files = [
            self.repo_root / "scripts" / "cli" / "jmo.py",
            *list((self.repo_root / "scripts" / "core").rglob("*.py")),
            *list((self.repo_root / "scripts" / "cli").rglob("*.py")),
        ]

        for py_file in python_files:
            if py_file.name.startswith("_") or "__pycache__" in str(py_file):
                continue

            self.stats["total_python_files"] += 1
            try:
                content = py_file.read_text(encoding="utf-8")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        if not node.name.startswith("_"):  # Public functions
                            apis[str(py_file.relative_to(self.repo_root))][
                                "functions"
                            ].append(
                                {
                                    "name": node.name,
                                    "args": [a.arg for a in node.args.args],
                                    "docstring": ast.get_docstring(node),
                                    "line": node.lineno,
                                }
                            )
                            self.stats["total_functions"] += 1

                    elif isinstance(node, ast.ClassDef):
                        if not node.name.startswith("_"):
                            apis[str(py_file.relative_to(self.repo_root))][
                                "classes"
                            ].append(
                                {
                                    "name": node.name,
                                    "docstring": ast.get_docstring(node),
                                    "methods": [
                                        m.name
                                        for m in node.body
                                        if isinstance(m, ast.FunctionDef)
                                        and not m.name.startswith("_")
                                    ],
                                    "line": node.lineno,
                                }
                            )
                            self.stats["total_classes"] += 1

                # Special: Extract CLI commands from jmo.py
                if py_file.name == "jmo.py":
                    cli_commands = self._extract_cli_commands(content)
                    apis[str(py_file.relative_to(self.repo_root))][
                        "cli_commands"
                    ] = cli_commands

            except Exception as e:
                print(f"  ⚠️  Error parsing {py_file}: {e}")

        return dict(apis)

    def _extract_cli_commands(self, jmo_content: str) -> List[Dict]:
        """Extract CLI commands and subcommands from jmo.py."""
        commands = []

        # Look for subparser.add_parser calls
        parser_pattern = re.compile(
            r'subparsers\.add_parser\(["\'](\w+)["\'](?:.*?help=["\']([^"\']+)["\'])?',
            re.DOTALL,
        )

        for match in parser_pattern.finditer(jmo_content):
            commands.append({"name": match.group(1), "help": match.group(2) or ""})

        return commands

    def _parse_documentation(self) -> Dict[str, str]:
        """Parse all documentation files."""
        docs = {}

        doc_files = [
            "README.md",
            "QUICKSTART.md",
            "CLAUDE.md",
            "CONTRIBUTING.md",
            "docs/USER_GUIDE.md",
            "docs/DOCKER_README.md",
            "ROADMAP.md",
        ]

        for doc_file in doc_files:
            doc_path = self.repo_root / doc_file
            if doc_path.exists():
                docs[doc_file] = doc_path.read_text(encoding="utf-8")
            else:
                self.findings["missing_docs"].append(
                    {"file": doc_file, "reason": "File does not exist"}
                )

        return docs

    def _detect_undocumented_features(
        self, apis: Dict, docs: Dict[str, str]
    ) -> None:
        """Detect features in code that aren't documented."""
        all_doc_text = " ".join(docs.values()).lower()

        for file_path, api_data in apis.items():
            # Check functions
            for func in api_data.get("functions", []):
                func_name = func["name"]

                # Skip test functions and internal helpers
                if func_name.startswith("test_") or func_name.startswith("_"):
                    continue

                # Check if mentioned in docs
                if (
                    func_name.lower() not in all_doc_text
                    and not func["docstring"]  # Also undocumented in code
                ):
                    self.findings["undocumented_features"].append(
                        {
                            "type": "function",
                            "name": func_name,
                            "file": file_path,
                            "line": func["line"],
                            "severity": "medium"
                            if "public" in file_path
                            else "low",  # Public APIs more critical
                        }
                    )

            # Check classes
            for cls in api_data.get("classes", []):
                cls_name = cls["name"]

                if (
                    cls_name.lower() not in all_doc_text
                    and not cls["docstring"]
                    and not cls_name.endswith("Adapter")  # Adapters are self-documenting
                ):
                    self.findings["undocumented_features"].append(
                        {
                            "type": "class",
                            "name": cls_name,
                            "file": file_path,
                            "line": cls["line"],
                            "severity": "high"
                            if "core" in file_path
                            else "medium",  # Core classes more critical
                        }
                    )

    def _analyze_cli_completeness(self) -> None:
        """Check if all CLI commands are documented."""
        # Extract documented commands from docs
        docs_path = self.repo_root / "docs" / "USER_GUIDE.md"
        if not docs_path.exists():
            return

        user_guide = docs_path.read_text(encoding="utf-8")

        # Known CLI commands from v1.0.0
        expected_commands = [
            "scan",
            "report",
            "ci",
            "diff",
            "history",
            "trends",
            "wizard",
            "adapters",
            "setup",
            "schedule",  # v0.9.0+
        ]

        for cmd in expected_commands:
            if f"`jmo {cmd}`" not in user_guide and f"jmo {cmd}" not in user_guide:
                self.findings["doc_code_drift"].append(
                    {
                        "type": "cli_command",
                        "name": cmd,
                        "issue": f"Command 'jmo {cmd}' not documented in USER_GUIDE.md",
                        "severity": "high",
                        "file": "docs/USER_GUIDE.md",
                    }
                )

        # Check for v1.0.0 subcommands
        v1_subcommands = {
            "history": [
                "list",
                "show",
                "compare",
                "export",
                "prune",
                "vacuum",
                "verify",
            ],
            "trends": [
                "analyze",
                "show",
                "regressions",
                "score",
                "compare",
                "insights",
                "explain",
                "developers",
            ],
            "diff": [],  # Positional args, not subcommands
        }

        for parent_cmd, subcommands in v1_subcommands.items():
            for subcmd in subcommands:
                pattern = f"`jmo {parent_cmd} {subcmd}`"
                if pattern not in user_guide:
                    self.findings["doc_code_drift"].append(
                        {
                            "type": "cli_subcommand",
                            "name": f"{parent_cmd} {subcmd}",
                            "issue": f"Subcommand 'jmo {parent_cmd} {subcmd}' not documented",
                            "severity": "medium",
                            "file": "docs/USER_GUIDE.md",
                        }
                    )

    def _verify_config_examples(self) -> None:
        """Verify configuration examples match actual schema."""
        # Check jmo.yml examples in docs
        claude_md = self.repo_root / "CLAUDE.md"
        if not claude_md.exists():
            return

        content = claude_md.read_text(encoding="utf-8")

        # Extract YAML code blocks
        yaml_blocks = re.findall(r"```yaml\n(.*?)```", content, re.DOTALL)

        # Known v1.0.0 config options
        expected_config_keys = [
            "default_profile",
            "tools",
            "outputs",
            "fail_on",
            "retries",
            "threads",
            "email",  # v0.9.0
            "schedule",  # v0.9.0
            "profiles",
            "per_tool",
            "deduplication",  # v1.0.0
        ]

        # Check if all keys are documented
        for key in expected_config_keys:
            if key not in content:
                self.findings["config_drift"].append(
                    {
                        "key": key,
                        "issue": f"Config key '{key}' not documented in CLAUDE.md",
                        "severity": "medium",
                    }
                )

    def _map_test_coverage(self, apis: Dict) -> None:
        """Map test files to implementation files."""
        test_files = list((self.repo_root / "tests").rglob("test_*.py"))

        # Build mapping of implementation -> tests
        impl_to_tests = defaultdict(list)

        for test_file in test_files:
            # Derive implementation file from test file
            test_name = test_file.stem  # e.g., test_history_db
            impl_name = test_name.replace("test_", "")  # e.g., history_db

            # Find corresponding implementation
            impl_candidates = [
                self.repo_root / "scripts" / "core" / f"{impl_name}.py",
                self.repo_root / "scripts" / "cli" / f"{impl_name}.py",
                self.repo_root / "scripts" / "core" / "adapters" / f"{impl_name}.py",
                self.repo_root / "scripts" / "core" / "reporters" / f"{impl_name}.py",
            ]

            for candidate in impl_candidates:
                if candidate.exists():
                    impl_to_tests[str(candidate.relative_to(self.repo_root))].append(
                        str(test_file.relative_to(self.repo_root))
                    )
                    break

        # Check for untested implementation files
        for file_path in apis.keys():
            if file_path not in impl_to_tests and "adapters" not in file_path:
                # Adapters have separate test structure
                self.findings["test_gaps"].append(
                    {
                        "file": file_path,
                        "issue": "No corresponding test file found",
                        "severity": "high",
                    }
                )

    def _check_doc_consistency(self) -> None:
        """Check consistency between different documentation files."""
        # Read key docs
        readme = (self.repo_root / "README.md").read_text(encoding="utf-8")
        claude_md = (self.repo_root / "CLAUDE.md").read_text(encoding="utf-8")
        quickstart = (self.repo_root / "QUICKSTART.md").read_text(encoding="utf-8")

        # Check version consistency
        version_pattern = re.compile(r"v(\d+\.\d+\.\d+)")

        readme_versions = set(version_pattern.findall(readme))
        claude_versions = set(version_pattern.findall(claude_md))
        quickstart_versions = set(version_pattern.findall(quickstart))

        # Find version mismatches
        all_versions = readme_versions | claude_versions | quickstart_versions

        for version in all_versions:
            docs_with_version = []
            if version in readme_versions:
                docs_with_version.append("README.md")
            if version in claude_versions:
                docs_with_version.append("CLAUDE.md")
            if version in quickstart_versions:
                docs_with_version.append("QUICKSTART.md")

            if len(docs_with_version) < 3:
                missing = set(["README.md", "CLAUDE.md", "QUICKSTART.md"]) - set(
                    docs_with_version
                )
                self.findings["inconsistencies"].append(
                    {
                        "type": "version_mismatch",
                        "version": version,
                        "present_in": docs_with_version,
                        "missing_from": list(missing),
                        "severity": "low",
                    }
                )

        # Check feature consistency
        v1_features = [
            "SQLite historical storage",
            "Machine-readable diffs",
            "Trend analysis",
            "CSV export",
            "Dual-mode HTML",
        ]

        for feature in v1_features:
            present_in = []
            if feature.lower() in readme.lower():
                present_in.append("README.md")
            if feature.lower() in claude_md.lower():
                present_in.append("CLAUDE.md")
            if feature.lower() in quickstart.lower():
                present_in.append("QUICKSTART.md")

            # v1.0.0 features should be in at least README and CLAUDE.md
            if "README.md" not in present_in or "CLAUDE.md" not in present_in:
                self.findings["inconsistencies"].append(
                    {
                        "type": "feature_coverage",
                        "feature": feature,
                        "present_in": present_in,
                        "severity": "high"
                        if len(present_in) == 0
                        else "medium",  # No coverage is critical
                    }
                )

    def _generate_recommendations(self) -> None:
        """Generate actionable recommendations based on findings."""
        # Prioritize high-severity issues
        high_severity = [
            f
            for f in (
                self.findings["undocumented_features"]
                + self.findings["doc_code_drift"]
                + self.findings["test_gaps"]
            )
            if f.get("severity") == "high"
        ]

        if high_severity:
            self.findings["recommendations"].append(
                {
                    "priority": "CRITICAL",
                    "action": "Address high-severity documentation gaps",
                    "count": len(high_severity),
                    "details": "Focus on core classes, CLI commands, and untested implementation files",
                }
            )

        # Check if v1.0.0 features are fully documented
        v1_keywords = ["history", "diff", "trends", "sqlite", "csv"]
        undocumented_v1 = [
            f
            for f in self.findings["undocumented_features"]
            if any(kw in f.get("name", "").lower() for kw in v1_keywords)
        ]

        if undocumented_v1:
            self.findings["recommendations"].append(
                {
                    "priority": "HIGH",
                    "action": "Document v1.0.0 features comprehensively",
                    "count": len(undocumented_v1),
                    "details": "SQLite history, diff engine, trend analysis need complete documentation",
                }
            )

        # Check config drift
        if self.findings["config_drift"]:
            self.findings["recommendations"].append(
                {
                    "priority": "MEDIUM",
                    "action": "Update configuration documentation",
                    "count": len(self.findings["config_drift"]),
                    "details": "Ensure all jmo.yml options are documented with examples",
                }
            )

        # Overall documentation quality
        total_issues = sum(
            len(v)
            for k, v in self.findings.items()
            if k not in ["recommendations", "test_gaps"]
        )

        if total_issues > 50:
            self.findings["recommendations"].append(
                {
                    "priority": "HIGH",
                    "action": "Conduct comprehensive documentation review",
                    "count": total_issues,
                    "details": "Consider using jmo-documentation-updater skill for systematic cleanup",
                }
            )

        # Test coverage
        if len(self.findings["test_gaps"]) > 10:
            self.findings["recommendations"].append(
                {
                    "priority": "MEDIUM",
                    "action": "Expand test coverage",
                    "count": len(self.findings["test_gaps"]),
                    "details": "Use jmo-test-fabricator skill to add missing test files",
                }
            )

    def _generate_report(self) -> Dict:
        """Generate final report."""
        return {
            "metadata": {
                "analyzer_version": "1.0.0",
                "repo_root": str(self.repo_root),
                "analysis_date": "2025-11-16",
            },
            "statistics": self.stats,
            "findings": self.findings,
            "summary": {
                "total_issues": sum(
                    len(v)
                    for k, v in self.findings.items()
                    if k not in ["recommendations"]
                ),
                "critical_issues": len(
                    [
                        f
                        for f in (
                            self.findings["undocumented_features"]
                            + self.findings["doc_code_drift"]
                            + self.findings["test_gaps"]
                        )
                        if f.get("severity") == "high"
                    ]
                ),
                "recommendations_count": len(self.findings["recommendations"]),
            },
        }


def main():
    """Run repository analysis."""
    repo_root = Path(__file__).parent.parent.parent
    analyzer = RepositoryAnalyzer(repo_root)

    report = analyzer.analyze()

    # Write report
    output_file = repo_root / "dev-only" / "REPO_COMPLETENESS_ANALYSIS.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print()
    print("=" * 80)
    print("📊 ANALYSIS COMPLETE")
    print("=" * 80)
    print()
    print(f"📈 Statistics:")
    print(f"  - Python files analyzed: {report['statistics']['total_python_files']}")
    print(f"  - Total functions: {report['statistics']['total_functions']}")
    print(f"  - Total classes: {report['statistics']['total_classes']}")
    print()
    print(f"🔍 Findings Summary:")
    print(
        f"  - Undocumented features: {len(report['findings']['undocumented_features'])}"
    )
    print(f"  - Doc-code drift issues: {len(report['findings']['doc_code_drift'])}")
    print(f"  - Missing docs: {len(report['findings']['missing_docs'])}")
    print(f"  - Inconsistencies: {len(report['findings']['inconsistencies'])}")
    print(f"  - Config drift: {len(report['findings']['config_drift'])}")
    print(f"  - Test gaps: {len(report['findings']['test_gaps'])}")
    print()
    print(f"💡 Recommendations: {len(report['findings']['recommendations'])}")
    print()

    for rec in report["findings"]["recommendations"]:
        print(f"  [{rec['priority']}] {rec['action']}")
        print(f"       → {rec['details']} ({rec['count']} items)")
        print()

    print(f"📄 Full report written to: {output_file}")
    print()
    print("Next steps:")
    print("  1. Review REPO_COMPLETENESS_ANALYSIS.json")
    print("  2. Address CRITICAL priority items first")
    print("  3. Use jmo-documentation-updater skill for systematic fixes")
    print(
        "  4. Consider integrating this analyzer into CI/CD for continuous monitoring"
    )
    print()


if __name__ == "__main__":
    main()
