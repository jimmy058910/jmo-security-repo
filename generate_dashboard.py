#!/usr/bin/env python3
# generate_dashboard.py - Create HTML dashboard with metrics

import json
import os
import sys
from pathlib import Path
from datetime import datetime

def generate_dashboard(results_dir):
    """Generate an HTML dashboard with all metrics"""
    
    dashboard_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Audit Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .metric-card { 
                display: inline-block; 
                padding: 20px; 
                margin: 10px;
                border: 1px solid #ddd;
                border-radius: 8px;
                background: #f9f9f9;
            }
            .metric-value { 
                font-size: 36px; 
                font-weight: bold; 
                color: #333;
            }
            .metric-label { 
                font-size: 14px; 
                color: #666;
                margin-top: 5px;
            }
            table { 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 20px;
            }
            th, td { 
                padding: 12px; 
                text-align: left; 
                border-bottom: 1px solid #ddd;
            }
            th { background-color: #f2f2f2; }
            .severity-high { color: #d32f2f; }
            .severity-medium { color: #f57c00; }
            .severity-low { color: #388e3c; }
        </style>
    </head>
    <body>
        <h1>Security Audit Dashboard</h1>
        <p>Generated: {timestamp}</p>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value">{total_findings}</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{unique_secrets}</div>
                <div class="metric-label">Unique Secrets</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{detection_rate}%</div>
                <div class="metric-label">Detection Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{fp_rate}%</div>
                <div class="metric-label">False Positive Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{throughput}</div>
                <div class="metric-label">Lines/Second</div>
            </div>
        </div>
        
        <h2>Repository Results</h2>
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
        
        <h2>Tool Comparison</h2>
        <table>
            <tr>
                <th>Tool</th>
                <th>Detection Rate</th>
                <th>False Positive Rate</th>
                <th>Avg Scan Time</th>
                <th>Unique Findings</th>
            </tr>
            {tool_rows}
        </table>
    </body>
    </html>
    """
    
    # Calculate metrics (simplified example)
    metrics = calculate_metrics(results_dir)
    
    with open(f"{results_dir}/dashboard.html", 'w') as f:
        f.write(dashboard_html.format(**metrics))

def calculate_metrics(results_dir):
    """Calculate all metrics from JSON outputs"""
    # This would parse all JSON files and calculate real metrics
    # For now, returning placeholder values
    return {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': '234',
        'unique_secrets': '156',
        'detection_rate': '94',
        'fp_rate': '3.5',
        'throughput': '15,234',
        'repo_rows': '',  # Would be populated from actual data
        'tool_rows': ''   # Would be populated from actual data
    }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        generate_dashboard(sys.argv[1])
    else:
        print("Usage: python3 generate_dashboard.py <results_directory>")
