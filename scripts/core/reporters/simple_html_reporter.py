#!/usr/bin/env python3
"""
Simple HTML reporter for email-compatible security findings reports.

Generates static HTML table with inline CSS (no JavaScript) for maximum
email client compatibility (Gmail, Outlook, Apple Mail, etc.).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = {
    "CRITICAL": "#b71c1c",
    "HIGH": "#e65100",
    "MEDIUM": "#f57f17",
    "LOW": "#558b2f",
    "INFO": "#616161",
}


def _escape_html(text: str) -> str:
    """Escape HTML special characters for safe rendering."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _truncate_text(text: str, max_len: int = 80) -> str:
    """Truncate long text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def write_simple_html(findings: list[dict[str, Any]], out_path: str | Path) -> None:
    """
    Write static HTML table for email-compatible findings report.

    Features:
    - Static HTML table (no JavaScript)
    - Inline CSS for email client compatibility
    - Sortable appearance (visual only, not functional)
    - Severity color-coding
    - Responsive design (works on mobile email clients)
    - Dark mode support via CSS media query

    Args:
        findings: List of CommonFinding dictionaries
        out_path: Output file path
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Sort findings: CRITICAL → HIGH → MEDIUM → LOW → INFO
    sorted_findings = sorted(
        findings, key=lambda f: SEV_ORDER.index(f.get("severity", "INFO"))
    )

    # Generate summary statistics
    sev_counts = {sev: 0 for sev in SEV_ORDER}
    for f in findings:
        sev_counts[f.get("severity", "INFO")] += 1

    # Collect unique tools
    tools = set()
    for f in findings:
        tool_name = f.get("tool", {}).get("name", "unknown")
        if "detected_by" in f:
            # Consensus finding
            for t in f.get("detected_by", []):
                tools.add(t.get("name", "unknown"))
        else:
            tools.add(tool_name)

    # Generate HTML
    html = _generate_html_template(sorted_findings, sev_counts, sorted(tools))
    p.write_text(html, encoding="utf-8")


def _generate_html_template(
    findings: list[dict[str, Any]], sev_counts: dict[str, int], tools: list[str]
) -> str:
    """Generate complete HTML document with inline CSS."""
    total = len(findings)

    # Generate summary badges
    summary_html = ""
    for sev in SEV_ORDER:
        count = sev_counts.get(sev, 0)
        if count > 0:
            color = SEV_COLORS.get(sev, "#616161")
            summary_html += f"""
            <span style="display: inline-block; padding: 6px 12px; margin: 4px;
                         background: {color}; color: white; border-radius: 4px;
                         font-weight: 600; font-size: 14px;">
                {sev}: {count}
            </span>
            """

    # Generate findings table rows
    rows_html = ""
    for f in findings:
        severity = f.get("severity", "INFO")
        sev_color = SEV_COLORS.get(severity, "#616161")
        rule_id = _escape_html(f.get("ruleId", "unknown"))
        location = f.get("location", {})
        path = _escape_html(location.get("path", "unknown"))
        start_line = location.get("startLine", "?")
        message = _escape_html(_truncate_text(f.get("message", "No message"), 100))

        # Tool info (handle consensus findings)
        if "detected_by" in f:
            tool_names = [t.get("name", "unknown") for t in f.get("detected_by", [])]
            tool_display = ", ".join(tool_names[:3])  # Show up to 3 tools
            if len(tool_names) > 3:
                tool_display += f" +{len(tool_names) - 3} more"
        else:
            tool_display = _escape_html(f.get("tool", {}).get("name", "unknown"))

        rows_html += f"""
        <tr style="border-bottom: 1px solid #e0e0e0;">
            <td style="padding: 12px 8px; font-weight: 600; color: {sev_color};
                       white-space: nowrap; vertical-align: top;">
                {severity}
            </td>
            <td style="padding: 12px 8px; font-family: 'Courier New', monospace;
                       font-size: 13px; vertical-align: top;">
                {rule_id}
            </td>
            <td style="padding: 12px 8px; font-family: 'Courier New', monospace;
                       font-size: 12px; color: #555; vertical-align: top;">
                {path}:{start_line}
            </td>
            <td style="padding: 12px 8px; vertical-align: top;">
                {message}
            </td>
            <td style="padding: 12px 8px; font-size: 13px; color: #666;
                       white-space: nowrap; vertical-align: top;">
                {tool_display}
            </td>
        </tr>
        """

    # Tools list
    tools_html = ", ".join(_escape_html(t) for t in tools)

    # Complete HTML document
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="format-detection" content="telephone=no">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Security Findings Report</title>
    <!--[if mso]>
    <style type="text/css">
        table {{ border-collapse: collapse; }}
        .no-mso {{ display: none !important; }}
    </style>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont,
             'Segoe UI', Roboto, Arial, sans-serif; background: #f5f5f5;
             color: #212121; line-height: 1.6;">

    <!-- Main Container -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0"
           style="width: 100%; max-width: 1200px; margin: 0 auto;
                  background: #ffffff; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

        <!-- Header -->
        <tr>
            <td style="padding: 24px 20px; background: #1976d2; color: white;">
                <h1 style="margin: 0; font-size: 28px; font-weight: 600;">
                    🔒 Security Findings Report
                </h1>
                <p style="margin: 8px 0 0 0; font-size: 14px; opacity: 0.9;">
                    Generated by JMo Security Audit Tool Suite
                </p>
            </td>
        </tr>

        <!-- Summary Section -->
        <tr>
            <td style="padding: 20px; background: #fafafa; border-bottom: 2px solid #e0e0e0;">
                <h2 style="margin: 0 0 12px 0; font-size: 20px; font-weight: 600; color: #424242;">
                    📊 Summary
                </h2>
                <p style="margin: 0 0 8px 0; font-size: 16px;">
                    <strong>Total Findings:</strong> {total}
                </p>
                <div style="margin: 12px 0;">
                    {summary_html}
                </div>
                <p style="margin: 12px 0 0 0; font-size: 14px; color: #616161;">
                    <strong>Tools Used:</strong> {tools_html}
                </p>
            </td>
        </tr>

        <!-- Findings Table -->
        <tr>
            <td style="padding: 20px;">
                <h2 style="margin: 0 0 16px 0; font-size: 20px; font-weight: 600; color: #424242;">
                    🔍 Findings
                </h2>

                <!-- Responsive table wrapper -->
                <div style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0"
                           style="width: 100%; min-width: 800px; border-collapse: collapse;
                                  border: 1px solid #e0e0e0; background: #ffffff;">

                        <!-- Table Header -->
                        <thead style="background: #f5f5f5;">
                            <tr style="border-bottom: 2px solid #bdbdbd;">
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600;
                                           font-size: 13px; color: #424242; text-transform: uppercase;
                                           letter-spacing: 0.5px;">
                                    Severity
                                </th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600;
                                           font-size: 13px; color: #424242; text-transform: uppercase;
                                           letter-spacing: 0.5px;">
                                    Rule ID
                                </th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600;
                                           font-size: 13px; color: #424242; text-transform: uppercase;
                                           letter-spacing: 0.5px;">
                                    Location
                                </th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600;
                                           font-size: 13px; color: #424242; text-transform: uppercase;
                                           letter-spacing: 0.5px;">
                                    Message
                                </th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600;
                                           font-size: 13px; color: #424242; text-transform: uppercase;
                                           letter-spacing: 0.5px;">
                                    Tool
                                </th>
                            </tr>
                        </thead>

                        <!-- Table Body -->
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                </div>
            </td>
        </tr>

        <!-- Footer -->
        <tr>
            <td style="padding: 20px; background: #fafafa; border-top: 2px solid #e0e0e0;
                       text-align: center; font-size: 13px; color: #757575;">
                <p style="margin: 0;">
                    Generated by <strong>JMo Security</strong> •
                    <a href="https://jmotools.com" style="color: #1976d2; text-decoration: none;">
                        jmotools.com
                    </a>
                </p>
            </td>
        </tr>
    </table>

    <!-- Dark mode support (email clients that support it) -->
    <style>
        @media (prefers-color-scheme: dark) {{
            body {{
                background: #121212 !important;
                color: #e0e0e0 !important;
            }}
            table[role="presentation"] {{
                background: #1e1e1e !important;
            }}
            th, td {{
                color: #e0e0e0 !important;
            }}
        }}

        /* Responsive styles for mobile */
        @media screen and (max-width: 600px) {{
            .responsive-table {{
                font-size: 12px !important;
            }}
            th, td {{
                padding: 8px 4px !important;
            }}
        }}
    </style>
</body>
</html>
"""
