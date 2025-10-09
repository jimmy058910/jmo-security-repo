#!/usr/bin/env python3
# generate_dashboard.py - Create HTML dashboard with metrics

import json
import os
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_json_safe(filepath):
    """Safely parse JSON file with error handling"""
    try:
        with open(filepath, 'r') as f:
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
            findings.append({
                'tool': 'gitleaks',
                'type': item.get('RuleID', 'unknown'),
                'severity': 'HIGH',
                'file': item.get('File', 'unknown'),
                'line': item.get('StartLine', 0),
                'description': item.get('Description', '')
            })
    return findings

def parse_trufflehog(filepath):
    """Parse trufflehog JSON output"""
    findings = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        item = json.loads(line.strip())
                        findings.append({
                            'tool': 'trufflehog',
                            'type': item.get('DetectorName', 'unknown'),
                            'severity': 'CRITICAL' if item.get('Verified') else 'MEDIUM',
                            'file': item.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown'),
                            'verified': item.get('Verified', False),
                            'description': f"Found {item.get('DetectorName', 'secret')}"
                        })
                    except json.JSONDecodeError:
                        continue
    except FileNotFoundError:
        pass
    return findings

def parse_semgrep(filepath):
    """Parse semgrep JSON output"""
    data = parse_json_safe(filepath)
    if not data:
        return []
    
    findings = []
    results = data.get('results', [])
    for item in results:
        severity = item.get('extra', {}).get('severity', 'INFO')
        findings.append({
            'tool': 'semgrep',
            'type': item.get('check_id', 'unknown'),
            'severity': severity,
            'file': item.get('path', 'unknown'),
            'line': item.get('start', {}).get('line', 0),
            'description': item.get('extra', {}).get('message', '')
        })
    return findings

def parse_noseyparker(filepath):
    """Parse nosey parker JSON output"""
    data = parse_json_safe(filepath)
    if not data:
        return []
    
    findings = []
    if isinstance(data, dict):
        matches = data.get('matches', [])
        for item in matches:
            findings.append({
                'tool': 'noseyparker',
                'type': item.get('rule', 'unknown'),
                'severity': 'MEDIUM',
                'description': f"Pattern match: {item.get('rule', 'unknown')}"
            })
    return findings

def calculate_metrics(results_dir):
    """Calculate all metrics from JSON outputs"""
    repos_dir = Path(results_dir) / "individual-repos"
    
    all_findings = []
    repo_stats = []
    tool_stats = defaultdict(lambda: {'count': 0, 'repos': set()})
    
    # Parse all repository results
    for repo_dir in repos_dir.iterdir():
        if not repo_dir.is_dir():
            continue
            
        repo_name = repo_dir.name
        repo_findings = {
            'gitleaks': 0,
            'trufflehog': 0,
            'semgrep': 0,
            'noseyparker': 0,
            'total': 0
        }
        
        # Parse each tool's output
        gitleaks_file = repo_dir / "gitleaks.json"
        if gitleaks_file.exists():
            findings = parse_gitleaks(gitleaks_file)
            all_findings.extend(findings)
            repo_findings['gitleaks'] = len(findings)
            if len(findings) > 0:
                tool_stats['gitleaks']['count'] += len(findings)
                tool_stats['gitleaks']['repos'].add(repo_name)
        
        trufflehog_file = repo_dir / "trufflehog.json"
        if trufflehog_file.exists():
            findings = parse_trufflehog(trufflehog_file)
            all_findings.extend(findings)
            repo_findings['trufflehog'] = len(findings)
            if len(findings) > 0:
                tool_stats['trufflehog']['count'] += len(findings)
                tool_stats['trufflehog']['repos'].add(repo_name)
        
        semgrep_file = repo_dir / "semgrep.json"
        if semgrep_file.exists():
            findings = parse_semgrep(semgrep_file)
            all_findings.extend(findings)
            repo_findings['semgrep'] = len(findings)
            if len(findings) > 0:
                tool_stats['semgrep']['count'] += len(findings)
                tool_stats['semgrep']['repos'].add(repo_name)
        
        noseyparker_file = repo_dir / "noseyparker.json"
        if noseyparker_file.exists():
            findings = parse_noseyparker(noseyparker_file)
            all_findings.extend(findings)
            repo_findings['noseyparker'] = len(findings)
            if len(findings) > 0:
                tool_stats['noseyparker']['count'] += len(findings)
                tool_stats['noseyparker']['repos'].add(repo_name)
        
        repo_findings['total'] = sum([
            repo_findings['gitleaks'],
            repo_findings['trufflehog'],
            repo_findings['semgrep'],
            repo_findings['noseyparker']
        ])
        
        repo_stats.append({
            'name': repo_name,
            **repo_findings
        })
    
    # Calculate severity distribution
    severity_counts = defaultdict(int)
    for finding in all_findings:
        severity_counts[finding.get('severity', 'UNKNOWN')] += 1
    
    # Count verified secrets
    verified_secrets = sum(1 for f in all_findings if f.get('verified', False))
    
    # Calculate unique issues (by type)
    unique_types = set(f.get('type', 'unknown') for f in all_findings)
    
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(all_findings),
        'unique_secrets': len(unique_types),
        'verified_secrets': verified_secrets,
        'critical_count': severity_counts.get('CRITICAL', 0),
        'high_count': severity_counts.get('HIGH', 0),
        'medium_count': severity_counts.get('MEDIUM', 0),
        'low_count': severity_counts.get('LOW', 0) + severity_counts.get('INFO', 0),
        'repo_stats': repo_stats,
        'tool_stats': tool_stats,
        'all_findings': all_findings
    }

def generate_dashboard(results_dir):
    """Generate an HTML dashboard with all metrics"""
    
    # Calculate metrics
    metrics = calculate_metrics(results_dir)
    
    # Build repository rows HTML
    repo_rows = ""
    for repo in metrics['repo_stats']:
        repo_rows += f"""
            <tr>
                <td>{repo['name']}</td>
                <td>{repo['gitleaks']}</td>
                <td>{repo['trufflehog']}</td>
                <td>{repo['semgrep']}</td>
                <td>{repo['noseyparker']}</td>
                <td><strong>{repo['total']}</strong></td>
            </tr>
        """
    
    # Build tool rows HTML
    tool_rows = ""
    for tool_name, stats in metrics['tool_stats'].items():
        repos_count = len(stats['repos'])
        avg_findings = stats['count'] / repos_count if repos_count > 0 else 0
        tool_rows += f"""
            <tr>
                <td>{tool_name}</td>
                <td>{stats['count']}</td>
                <td>{repos_count}</td>
                <td>{avg_findings:.1f}</td>
            </tr>
        """
    
    # Build severity breakdown HTML
    severity_rows = f"""
        <tr>
            <td class="severity-critical">Critical</td>
            <td>{metrics['critical_count']}</td>
        </tr>
        <tr>
            <td class="severity-high">High</td>
            <td>{metrics['high_count']}</td>
        </tr>
        <tr>
            <td class="severity-medium">Medium</td>
            <td>{metrics['medium_count']}</td>
        </tr>
        <tr>
            <td class="severity-low">Low</td>
            <td>{metrics['low_count']}</td>
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
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Security Audit Dashboard</h1>
            <p><strong>Generated:</strong> {metrics['timestamp']}</p>
            
            <div class="summary">
                <h3>Executive Summary</h3>
                <p>Total security issues identified: <strong>{metrics['total_findings']}</strong></p>
                <p>Verified secrets requiring immediate action: <strong>{metrics['verified_secrets']}</strong></p>
                <p>Unique issue types detected: <strong>{metrics['unique_secrets']}</strong></p>
            </div>
            
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value">{metrics['total_findings']}</div>
                    <div class="metric-label">Total Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics['critical_count']}</div>
                    <div class="metric-label">Critical Issues</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics['high_count']}</div>
                    <div class="metric-label">High Severity</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{metrics['verified_secrets']}</div>
                    <div class="metric-label">Verified Secrets</div>
                </div>
            </div>
            
            <h2>📊 Severity Breakdown</h2>
            <table>
                <tr>
                    <th>Severity Level</th>
                    <th>Count</th>
                </tr>
                {severity_rows}
            </table>
            
            <h2>📁 Repository Results</h2>
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
            
            <h2>🛠️ Tool Performance</h2>
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
                <h3>📝 Recommendations</h3>
                <ul>
                    <li><strong>Immediate:</strong> Review and rotate {metrics['verified_secrets']} verified secrets</li>
                    <li><strong>High Priority:</strong> Address {metrics['critical_count'] + metrics['high_count']} critical and high severity issues</li>
                    <li><strong>Medium Priority:</strong> Plan remediation for {metrics['medium_count']} medium severity issues</li>
                    <li><strong>Process:</strong> Implement pre-commit hooks to prevent future issues</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    output_file = Path(results_dir) / "dashboard.html"
    with open(output_file, 'w') as f:
        f.write(dashboard_html)
    
    print(f"✅ Dashboard generated: {output_file}")
    print(f"📊 Total findings: {metrics['total_findings']}")
    print(f"⚠️  Critical issues: {metrics['critical_count']}")
    print(f"🔍 Verified secrets: {metrics['verified_secrets']}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_dashboard(sys.argv[1])
    else:
        print("Usage: python3 generate_dashboard.py <results_directory>")
        sys.exit(1)
