#!/usr/bin/env python3
# generate_dashboard.py - Create HTML dashboard with metrics

import json
import html
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List, Set


def parse_json_safe(filepath):
    """Safely parse JSON file with error handling"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        return None


def parse_gitleaks(filepath):
    """Parse gitleaks JSON output"""
    data = parse_json_safe(filepath)
    if not data:
        return []

    findings = []
    if isinstance(data, list):
        for item in data:
            findings.append(
                {
                    "tool": "gitleaks",
                    "type": item.get("RuleID", "unknown"),
                    "severity": "HIGH",
                    "file": item.get("File", "unknown"),
                    "line": item.get("StartLine", 0),
                    "description": item.get("Description", ""),
                }
            )
    return findings


def parse_trufflehog(filepath):
    """Parse trufflehog JSON output supporting arrays, objects, nested lists, and NDJSON"""

    def _extract_file_path(metadata):
        data = metadata.get("Data", {}) if isinstance(metadata, dict) else {}
        filesystem_path = (
            data.get("Filesystem", {}).get("file")
            if isinstance(data.get("Filesystem"), dict)
            else None
        )
        git_path = (
            data.get("Git", {}).get("file")
            if isinstance(data.get("Git"), dict)
            else None
        )
        return filesystem_path or git_path or "unknown"

    def _collect(item):
        if not isinstance(item, dict):
            return None
        source_metadata = item.get("SourceMetadata") or {}
        file_path = _extract_file_path(source_metadata)
        return {
            "tool": "trufflehog",
            "type": item.get("DetectorName", "unknown"),
            "severity": "CRITICAL" if item.get("Verified") else "MEDIUM",
            "file": file_path,
            "verified": item.get("Verified", False),
            "description": f"Found {item.get('DetectorName', 'secret')}",
        }

    findings: List[Dict[str, Any]] = []

    try:
        raw_content = Path(filepath).read_text().strip()
    except FileNotFoundError:
        return findings
    except OSError as exc:
        print(f"Warning: Could not read {filepath}: {exc}")
        return findings

    if not raw_content:
        return findings

    def _flatten(items):
        for entry in items:
            if isinstance(entry, dict):
                yield entry
            elif isinstance(entry, list):
                yield from _flatten(entry)

    parsed_items = []
    try:
        parsed = json.loads(raw_content)
        if isinstance(parsed, list):
            parsed_items.extend(_flatten(parsed))
        elif isinstance(parsed, dict):
            parsed_items.append(parsed)
    except json.JSONDecodeError:
        for line in raw_content.splitlines():
            if not line.strip():
                continue
            try:
                parsed_line = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed_line, list):
                parsed_items.extend(_flatten(parsed_line))
            elif isinstance(parsed_line, dict):
                parsed_items.append(parsed_line)

    for item in parsed_items:
        finding = _collect(item)
        if finding:
            findings.append(finding)

    return findings


def parse_semgrep(filepath):
    """Parse semgrep JSON output"""
    data = parse_json_safe(filepath)
    if not data:
        return []

    findings = []
    results = data.get("results", [])
    for item in results:
        severity = item.get("extra", {}).get("severity", "INFO")
        findings.append(
            {
                "tool": "semgrep",
                "type": item.get("check_id", "unknown"),
                "severity": severity,
                "file": item.get("path", "unknown"),
                "line": item.get("start", {}).get("line", 0),
                "description": item.get("extra", {}).get("message", ""),
            }
        )
    return findings


def parse_noseyparker(filepath):
    """Parse nosey parker JSON output"""
    data = parse_json_safe(filepath)
    if not data:
        return []

    # Nosey Parker may emit either a list of findings or an object with matches/findings.
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            records = data.get("findings", [])
        elif isinstance(data.get("matches"), list):
            records = [data]
        else:
            records = []
    else:
        records = []

    findings = []

    for record in records:
        if not isinstance(record, dict):
            continue

        rule_name = (
            record.get("rule_name")
            or record.get("rule")
            or record.get("rule_text_id")
            or "unknown"
        )
        matches = record.get("matches", [])

        if not isinstance(matches, list) or not matches:
            findings.append(
                {
                    "tool": "noseyparker",
                    "type": rule_name,
                    "severity": "HIGH",
                    "file": "unknown",
                    "line": 0,
                    "description": f"Pattern match: {rule_name}",
                    "verified": False,
                }
            )
            continue

        for match in matches:
            if not isinstance(match, dict):
                continue

            file_path = "unknown"
            provenance = match.get("provenance", [])
            if isinstance(provenance, list):
                for source in provenance:
                    if not isinstance(source, dict):
                        continue
                    if source.get("kind") == "file" and source.get("path"):
                        file_path = str(source.get("path"))
                        break
                    if source.get("kind") == "git_repo":
                        commit = source.get("first_commit", {}) or {}
                        blob_path = commit.get("blob_path")
                        if blob_path:
                            file_path = blob_path
                            break

            line_number = 0
            location = match.get("location", {})
            if isinstance(location, dict):
                source_span = location.get("source_span", {})
                if isinstance(source_span, dict):
                    start = source_span.get("start", {})
                    if isinstance(start, dict):
                        line_number = start.get("line", 0)

            description = match.get("snippet", {}).get("matching")
            if isinstance(description, str):
                description = description.strip()
            if not description:
                description = f"Pattern match: {rule_name}"

            findings.append(
                {
                    "tool": "noseyparker",
                    "type": rule_name,
                    "severity": "HIGH",
                    "file": file_path,
                    "line": line_number,
                    "description": description,
                    "verified": False,
                }
            )

    return findings


def calculate_metrics(results_dir):
    """Calculate all metrics from JSON outputs"""

    repos_dir = Path(results_dir) / "individual-repos"

    all_findings: List[Dict[str, Any]] = []
    repo_stats: List[Dict[str, Any]] = []
    # Initialize tool stats explicitly to avoid type ambiguity and ensure stable keys
    tool_stats: Dict[str, Dict[str, Any]] = {
        "gitleaks": {"count": 0, "repos": set()},
        "trufflehog": {"count": 0, "repos": set()},
        "semgrep": {"count": 0, "repos": set()},
        "noseyparker": {"count": 0, "repos": set()},
    }

    if not repos_dir.exists() or not repos_dir.is_dir():
        print(
            f"Warning: Results directory '{repos_dir}' not found. Returning empty dashboard metrics."
        )
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": 0,
            "unique_secrets": 0,
            "verified_secrets": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "repo_stats": [],
            "tool_stats": {},
            "all_findings": [],
        }
    # Parse all repository results
    for repo_dir in repos_dir.iterdir():
        if not repo_dir.is_dir():
            continue

        repo_name = repo_dir.name
        repo_findings = {
            "gitleaks": 0,
            "trufflehog": 0,
            "semgrep": 0,
            "noseyparker": 0,
            "total": 0,
        }

        # Parse each tool's output
        gitleaks_file = repo_dir / "gitleaks.json"
        if gitleaks_file.exists():
            findings = parse_gitleaks(gitleaks_file)
            for finding in findings:
                finding["repo"] = repo_name
            all_findings.extend(findings)
            repo_findings["gitleaks"] = len(findings)
            if findings:
                gitleaks_stats = tool_stats["gitleaks"]
                gitleaks_stats["count"] = gitleaks_stats["count"] + len(findings)
                gitleaks_repos: Set[str] = gitleaks_stats["repos"]
                gitleaks_repos.add(repo_name)

        trufflehog_file = repo_dir / "trufflehog.json"
        if trufflehog_file.exists():
            findings = parse_trufflehog(trufflehog_file)
            for finding in findings:
                finding["repo"] = repo_name
            all_findings.extend(findings)
            repo_findings["trufflehog"] = len(findings)
            if findings:
                trufflehog_stats = tool_stats["trufflehog"]
                trufflehog_stats["count"] = trufflehog_stats["count"] + len(findings)
                trufflehog_repos: Set[str] = trufflehog_stats["repos"]
                trufflehog_repos.add(repo_name)

        semgrep_file = repo_dir / "semgrep.json"
        if semgrep_file.exists():
            findings = parse_semgrep(semgrep_file)
            for finding in findings:
                finding["repo"] = repo_name
            all_findings.extend(findings)
            repo_findings["semgrep"] = len(findings)
            if findings:
                semgrep_stats = tool_stats["semgrep"]
                semgrep_stats["count"] = semgrep_stats["count"] + len(findings)
                semgrep_repos: Set[str] = semgrep_stats["repos"]
                semgrep_repos.add(repo_name)

        noseyparker_file = repo_dir / "noseyparker.json"
        if noseyparker_file.exists():
            findings = parse_noseyparker(noseyparker_file)
            for finding in findings:
                finding["repo"] = repo_name
            all_findings.extend(findings)
            repo_findings["noseyparker"] = len(findings)
            if findings:
                noseyparker_stats = tool_stats["noseyparker"]
                noseyparker_stats["count"] = noseyparker_stats["count"] + len(findings)
                noseyparker_repos: Set[str] = noseyparker_stats["repos"]
                noseyparker_repos.add(repo_name)

        repo_findings["total"] = sum(
            [
                repo_findings["gitleaks"],
                repo_findings["trufflehog"],
                repo_findings["semgrep"],
                repo_findings["noseyparker"],
            ]
        )

        repo_stats.append({"name": repo_name, **repo_findings})

    # Calculate severity distribution
    severity_counts: Dict[str, int] = defaultdict(int)
    for finding in all_findings:
        severity_counts[finding.get("severity", "UNKNOWN")] += 1

    # Count verified secrets
    verified_secrets = sum(1 for f in all_findings if f.get("verified", False))

    # Calculate unique issues (by type)
    unique_types = set(f.get("type", "unknown") for f in all_findings)

    # Convert repo sets to sorted lists for display and potential JSON compatibility
    normalized_tool_stats: Dict[str, Dict[str, Any]] = {
        tool: {
            "count": stats["count"],
            "repos": sorted(list(stats["repos"])),
        }
        for tool, stats in tool_stats.items()
    }

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_findings": len(all_findings),
        "unique_secrets": len(unique_types),
        "verified_secrets": verified_secrets,
        "critical_count": severity_counts.get("CRITICAL", 0),
        "high_count": severity_counts.get("HIGH", 0),
        "medium_count": severity_counts.get("MEDIUM", 0),
        "low_count": severity_counts.get("LOW", 0) + severity_counts.get("INFO", 0),
        "repo_stats": repo_stats,
        "tool_stats": normalized_tool_stats,
        "all_findings": all_findings,
    }


def generate_dashboard(results_dir, output_path=None):
    """Generate an HTML dashboard with all metrics"""

    # Calculate metrics
    metrics = calculate_metrics(results_dir)

    # Build repository rows HTML
    repo_rows = ""
    if metrics["repo_stats"]:
        for repo in metrics["repo_stats"]:
            repo_rows += f"""
            <tr>
                <td>{repo["name"]}</td>
                <td>{repo["gitleaks"]}</td>
                <td>{repo["trufflehog"]}</td>
                <td>{repo["semgrep"]}</td>
                <td>{repo["noseyparker"]}</td>
                <td><strong>{repo["total"]}</strong></td>
            </tr>
        """
    if not repo_rows:
        repo_rows = """
            <tr>
                <td colspan=\"6\" style=\"text-align: center; color: #999;\">No repositories scanned yet</td>
            </tr>
        """

    # Build tool rows HTML
    tool_rows = ""
    if metrics["tool_stats"]:
        for tool_name, stats in metrics["tool_stats"].items():
            repos_count = len(stats["repos"])
            avg_findings = stats["count"] / repos_count if repos_count > 0 else 0
            tool_rows += f"""
            <tr>
                <td>{tool_name}</td>
                <td>{stats["count"]}</td>
                <td>{repos_count}</td>
                <td>{avg_findings:.1f}</td>
            </tr>
        """
    if not tool_rows:
        tool_rows = """
            <tr>
                <td colspan=\"4\" style=\"text-align: center; color: #999;\">No scan results available</td>
            </tr>
        """

    # Build severity breakdown HTML
    severity_rows = f"""
        <tr>
            <td class="severity-critical">Critical</td>
            <td>{metrics["critical_count"]}</td>
        </tr>
        <tr>
            <td class="severity-high">High</td>
            <td>{metrics["high_count"]}</td>
        </tr>
        <tr>
            <td class="severity-medium">Medium</td>
            <td>{metrics["medium_count"]}</td>
        </tr>
        <tr>
            <td class="severity-low">Low</td>
            <td>{metrics["low_count"]}</td>
        </tr>
    """

    # Critical issue details
    critical_findings = [
        f
        for f in metrics["all_findings"]
        if (f.get("severity") or "").upper() == "CRITICAL"
    ]
    critical_findings = sorted(critical_findings, key=lambda x: x.get("repo", ""))

    critical_rows = ""
    for finding in critical_findings:
        repo = html.escape(str(finding.get("repo", "unknown")))
        tool = html.escape(str(finding.get("tool", "unknown")))
        issue_type = html.escape(str(finding.get("type", "unknown")))
        location = html.escape(str(finding.get("file", "unknown")))
        description = html.escape(str(finding.get("description", "")))
        verified = "Yes" if finding.get("verified") else "No"
        critical_rows += f"""
            <tr>
                <td>{repo}</td>
                <td>{tool}</td>
                <td>{issue_type}</td>
                <td>{location}</td>
                <td>{description}</td>
                <td>{verified}</td>
            </tr>
        """

    if not critical_rows:
        critical_rows = """
            <tr>
                <td colspan=\"6\">No critical findings detected.</td>
            </tr>
        """

    dashboard_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Audit Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
            h1 {{ color: #333; border-bottom: 3px solid #2196F3; padding-bottom: 10px; }}
            h2 {{ color: #555; margin-top: 30px; }}
            .metric-card {{
                display: inline-block;
                padding: 20px;
                margin: 10px;
                border: 1px solid #ddd;
                border-radius: 8px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-width: 150px;
            }}
            .metric-value {{
                font-size: 36px;
                font-weight: bold;
            }}
            .metric-label {{
                font-size: 14px;
                margin-top: 5px;
                opacity: 0.9;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{ background-color: #2196F3; color: white; }}
            tr:hover {{ background-color: #f5f5f5; }}
            .severity-critical {{ color: #d32f2f; font-weight: bold; }}
            .severity-high {{ color: #f57c00; font-weight: bold; }}
            .severity-medium {{ color: #fbc02d; font-weight: bold; }}
            .severity-low {{ color: #388e3c; }}
            .summary {{
                background: #e3f2fd;
                padding: 15px;
                border-radius: 8px;
                margin: 20px 0;
                border-left: 4px solid #2196F3;
            }}
            .section-header {{ margin-top: 40px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Security Audit Dashboard</h1>
            <p><strong>Generated:</strong> {metrics["timestamp"]}</p>

            <div class="summary">
                <h3>Executive Summary</h3>
                <p>Total security issues identified: <strong>{metrics["total_findings"]}</strong></p>
                <p>Verified secrets requiring immediate action: <strong>{metrics["verified_secrets"]}</strong></p>
                <p>Unique issue types detected: <strong>{metrics["unique_secrets"]}</strong></p>
            </div>

            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value">{metrics["total_findings"]}</div>
                    <div class="metric-label">Total Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics["critical_count"]}</div>
                    <div class="metric-label">Critical Issues</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics["high_count"]}</div>
                    <div class="metric-label">High Severity</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics["verified_secrets"]}</div>
                    <div class="metric-label">Verified Secrets</div>
                </div>
            </div>

            <h2 class="section-header">Severity Breakdown</h2>
            <table>
                <tr>
                    <th>Severity Level</th>
                    <th>Count</th>
                </tr>
                {severity_rows}
            </table>

            <h2 class="section-header">Critical Issue Details</h2>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Tool</th>
                    <th>Issue Type</th>
                    <th>Location</th>
                    <th>Description</th>
                    <th>Verified</th>
                </tr>
                {critical_rows}
            </table>

            <h2 class="section-header">Repository Results</h2>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Gitleaks</th>
                    <th>TruffleHog</th>
                    <th>Semgrep</th>
                    <th>Nosey Parker</th>
                    <th>Total Issues</th>
                </tr>
                {repo_rows}
            </table>

            <h2 class="section-header">Tool Performance</h2>
            <table>
                <tr>
                    <th>Tool</th>
                    <th>Total Findings</th>
                    <th>Repos Scanned</th>
                    <th>Avg Findings/Repo</th>
                </tr>
                {tool_rows}
            </table>

            <div class="summary" style="margin-top: 30px;">
                <h3>Recommendations</h3>
                <ul>
                    <li><strong>Immediate:</strong> Review and rotate {metrics["verified_secrets"]} verified secrets</li>
                    <li><strong>High Priority:</strong> Address {metrics["critical_count"] + metrics["high_count"]} critical and high severity issues</li>
                    <li><strong>Medium Priority:</strong> Plan remediation for {metrics["medium_count"]} medium severity issues</li>
                    <li><strong>Process:</strong> Implement pre-commit hooks to prevent future issues</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """

    if output_path:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_file = Path(results_dir) / "dashboard.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(dashboard_html)

    print(f"✅ Dashboard generated: {output_file}")
    print(f"📊 Total findings: {metrics['total_findings']}")
    print(f"⚠️  Critical issues: {metrics['critical_count']}")
    print(f"🔍 Verified secrets: {metrics['verified_secrets']}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 generate_dashboard.py <results_directory> [output_file]")
        sys.exit(1)

    results_dir = sys.argv[1]
    output_arg = sys.argv[2] if len(sys.argv) > 2 else None
    generate_dashboard(results_dir, output_arg)
