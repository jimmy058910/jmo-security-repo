#!/usr/bin/env python3
"""
CLI commands for historical scan management (jmo history).

Commands:
- store: Manually store a scan
- list: List all scans
- show: Show detailed scan info
- query: Execute custom SQL queries
- prune: Delete old scans
- export: Export to JSON/CSV/SARIF
- stats: Show database statistics
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from scripts.core.history_db import (
    get_connection,
    get_scan_by_id,
    list_scans,
    get_findings_for_scan,
    get_database_stats,
    prune_old_scans,
    store_scan as db_store_scan,
    compute_diff,
    get_trend_summary,
    DEFAULT_DB_PATH,
)


def parse_time_delta(delta_str: str) -> int:
    """
    Parse time delta string to seconds.

    Args:
        delta_str: Time delta like "7d", "30d", "90d"

    Returns:
        Number of seconds

    Examples:
        "7d" → 604800
        "30d" → 2592000
        "1h" → 3600
    """
    delta_str = delta_str.strip().lower()

    if delta_str.endswith("d"):
        days = int(delta_str[:-1])
        return days * 86400
    elif delta_str.endswith("h"):
        hours = int(delta_str[:-1])
        return hours * 3600
    elif delta_str.endswith("m"):
        minutes = int(delta_str[:-1])
        return minutes * 60
    elif delta_str.endswith("s"):
        seconds = int(delta_str[:-1])
        return seconds
    else:
        # Assume days if no suffix
        return int(delta_str) * 86400


def cmd_history_store(args) -> int:
    """Manually store a scan in history database."""
    results_dir = Path(args.results_dir)
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not results_dir.exists():
        sys.stderr.write(f"Error: Results directory not found: {results_dir}\n")
        return 1

    try:
        # Get tools from args or detect from results
        tools = getattr(args, "tools", None)
        if not tools:
            # Try to detect tools from results directory
            tools_json = results_dir / "summaries" / "findings.json"
            if tools_json.exists():
                with open(tools_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    # Extract unique tools from findings
                    tool_set = set()
                    for finding in data.get("findings", []):
                        tool_info = finding.get("tool", {})
                        if isinstance(tool_info, dict):
                            tool_set.add(tool_info.get("name", "unknown"))
                        else:
                            tool_set.add(str(tool_info))
                    tools = sorted(tool_set)
            else:
                tools = []

        # Get profile from args
        profile = getattr(args, "profile", "balanced")

        # Store scan
        scan_id = db_store_scan(
            results_dir=results_dir,
            profile=profile,
            tools=tools,
            db_path=db_path,
            commit_hash=getattr(args, "commit", None),
            branch=getattr(args, "branch", None),
            tag=getattr(args, "tag", None),
        )

        sys.stdout.write(f"✅ Stored scan: {scan_id}\n")
        sys.stdout.write(f"   Database: {db_path}\n")
        return 0

    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error storing scan: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_list(args) -> int:
    """List all scans."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        sys.stderr.write(
            "Run a scan with --store-history first, or use 'jmo history store'\n"
        )
        return 1

    try:
        conn = get_connection(db_path)

        # Parse filters
        branch = getattr(args, "branch", None)
        profile = getattr(args, "profile", None)
        since = None
        if getattr(args, "since", None):
            since_seconds = parse_time_delta(args.since)
            since = int(time.time()) - since_seconds

        # Get scans
        scans = list_scans(
            conn,
            branch=branch,
            profile=profile,
            since=since,
            limit=getattr(args, "limit", 50),
        )

        conn.close()

        if not scans:
            sys.stdout.write("No scans found.\n")
            return 0

        # Format output
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(scans, indent=2) + "\n")
        else:
            # Table output
            try:
                from tabulate import tabulate

                headers = [
                    "Scan ID",
                    "Timestamp",
                    "Branch",
                    "Profile",
                    "Findings",
                    "Critical",
                    "High",
                    "Duration (s)",
                ]
                table_data = []
                for scan in scans:
                    table_data.append(
                        [
                            scan["id"][:8] + "...",
                            scan["timestamp_iso"][:19].replace("T", " "),
                            scan["branch"] or "N/A",
                            scan["profile"],
                            scan["total_findings"],
                            scan["critical_count"],
                            scan["high_count"],
                            (
                                f"{scan['duration_seconds']:.1f}"
                                if scan["duration_seconds"]
                                else "N/A"
                            ),
                        ]
                    )

                sys.stdout.write(
                    tabulate(table_data, headers=headers, tablefmt="grid") + "\n"
                )

            except ImportError:
                # Fallback to simple format if tabulate not available
                for scan in scans:
                    sys.stdout.write(
                        f"{scan['id'][:8]}... {scan['timestamp_iso'][:19]} {scan['branch'] or 'N/A':15} "
                        f"{scan['profile']:8} {scan['total_findings']:3} findings ({scan['critical_count']} CRITICAL, {scan['high_count']} HIGH)\n"
                    )

        return 0

    except Exception as e:
        sys.stderr.write(f"Error listing scans: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_show(args) -> int:
    """Show detailed scan information."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        conn = get_connection(db_path)

        # Resolve scan ID
        scan_id = getattr(args, "scan_id", None)
        if not scan_id:
            sys.stderr.write("Error: Provide --scan-id\n")
            return 1

        scan = get_scan_by_id(conn, scan_id)
        if not scan:
            sys.stderr.write(f"Error: Scan not found: {scan_id}\n")
            return 1

        # Get findings if requested
        if getattr(args, "findings", False):
            findings = get_findings_for_scan(conn, scan["id"])
        else:
            findings = []

        conn.close()

        # Format output
        if getattr(args, "json", False):
            output = dict(scan)
            if findings:
                output["findings"] = [dict(f) for f in findings]
            sys.stdout.write(json.dumps(output, indent=2) + "\n")
        else:
            # Human-readable output
            sys.stdout.write(f"\nScan: {scan['id']}\n")
            sys.stdout.write("─" * 70 + "\n")
            sys.stdout.write(f"Timestamp:       {scan['timestamp_iso']}\n")
            if scan["branch"]:
                sys.stdout.write(f"Branch:          {scan['branch']}\n")
            if scan["commit_hash"]:
                dirty = " (dirty)" if scan["is_dirty"] else " (clean)"
                sys.stdout.write(f"Commit:          {scan['commit_short']}{dirty}\n")
            if scan["tag"]:
                sys.stdout.write(f"Tag:             {scan['tag']}\n")
            sys.stdout.write(f"Profile:         {scan['profile']}\n")
            tools = json.loads(scan["tools"])
            sys.stdout.write(
                f"Tools:           {len(tools)} ({', '.join(tools[:5])}{', ...' if len(tools) > 5 else ''})\n"
            )
            if scan["duration_seconds"]:
                sys.stdout.write(
                    f"Duration:        {scan['duration_seconds']:.1f} seconds\n"
                )
            sys.stdout.write(f"JMo Version:     {scan['jmo_version']}\n")
            sys.stdout.write("\nFindings Summary:\n")
            sys.stdout.write(f"  CRITICAL:      {scan['critical_count']}\n")
            sys.stdout.write(f"  HIGH:          {scan['high_count']}\n")
            sys.stdout.write(f"  MEDIUM:        {scan['medium_count']}\n")
            sys.stdout.write(f"  LOW:           {scan['low_count']}\n")
            sys.stdout.write(f"  INFO:          {scan['info_count']}\n")
            sys.stdout.write("  " + "─" * 14 + "\n")
            sys.stdout.write(f"  TOTAL:         {scan['total_findings']}\n")
            sys.stdout.write("\n")

            if findings:
                sys.stdout.write(f"\nTop Findings ({len(findings)} total):\n")
                for i, finding in enumerate(findings[:10], 1):
                    sys.stdout.write(
                        f"  {i}. [{finding['severity']}] {finding['rule_id']} "
                        f"in {finding['path']}:{finding['start_line'] or '?'}\n"
                    )
                if len(findings) > 10:
                    sys.stdout.write(f"  ... and {len(findings) - 10} more\n")
                sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error showing scan: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_query(args) -> int:
    """Execute custom SQL query."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        conn = get_connection(db_path)
        cursor = conn.cursor()

        query = args.query
        cursor.execute(query)
        rows = cursor.fetchall()

        # Format output
        if getattr(args, "format", "table") == "json":
            sys.stdout.write(json.dumps([dict(row) for row in rows], indent=2) + "\n")
        elif getattr(args, "format", "table") == "csv":
            import csv

            writer = csv.writer(sys.stdout)
            writer.writerow([desc[0] for desc in cursor.description])
            writer.writerows(rows)
        else:
            # Table format
            try:
                from tabulate import tabulate

                headers = [desc[0] for desc in cursor.description]
                sys.stdout.write(
                    tabulate(rows, headers=headers, tablefmt="grid") + "\n"
                )
            except ImportError:
                # Fallback to simple format
                for row in rows:
                    sys.stdout.write(" | ".join(str(v) for v in row) + "\n")

        conn.close()
        return 0

    except Exception as e:
        sys.stderr.write(f"SQL Error: {e}\n")
        return 1


def cmd_history_prune(args) -> int:
    """Delete old scans."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        conn = get_connection(db_path)
        cursor = conn.cursor()

        if getattr(args, "older_than", None):
            seconds = parse_time_delta(args.older_than)
            cutoff = int(time.time()) - seconds

            cursor.execute("SELECT COUNT(*) FROM scans WHERE timestamp < ?", (cutoff,))
            count = cursor.fetchone()[0]

            if count == 0:
                sys.stdout.write("No scans to prune.\n")
                conn.close()
                return 0

            sys.stdout.write(
                f"Will delete {count} scans older than {args.older_than}\n"
            )

            dry_run = getattr(args, "dry_run", False)
            force = getattr(args, "force", False)

            if not force and not dry_run:
                try:
                    confirm = input("Proceed? (y/N): ")
                    if confirm.lower() != "y":
                        sys.stdout.write("Aborted.\n")
                        conn.close()
                        return 0
                except (KeyboardInterrupt, EOFError):
                    sys.stdout.write("\nAborted.\n")
                    conn.close()
                    return 0

            if not dry_run:
                deleted = prune_old_scans(conn, seconds)
                conn.commit()
                sys.stdout.write(f"✅ Deleted {deleted} scans\n")
            else:
                sys.stdout.write(f"[DRY RUN] Would delete {count} scans\n")

        else:
            sys.stderr.write("Error: Provide --older-than\n")
            conn.close()
            return 1

        conn.close()
        return 0

    except Exception as e:
        sys.stderr.write(f"Error pruning scans: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_export(args) -> int:
    """Export scans to JSON/CSV/SARIF."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        conn = get_connection(db_path)

        # Get scans
        scan_id = getattr(args, "scan_id", None)
        if scan_id:
            scan = get_scan_by_id(conn, scan_id)
            if not scan:
                sys.stderr.write(f"Error: Scan not found: {scan_id}\n")
                return 1
            scans = [scan]
        else:
            # Export all scans
            since = None
            if getattr(args, "since", None):
                since_seconds = parse_time_delta(args.since)
                since = int(time.time()) - since_seconds

            scans = list_scans(conn, since=since, limit=10000)

        # Get findings for each scan
        export_data = []
        for scan in scans:
            findings = get_findings_for_scan(conn, scan["id"])
            scan_dict = dict(scan)
            scan_dict["findings"] = [dict(f) for f in findings]
            export_data.append(scan_dict)

        conn.close()

        # Format output
        format_type = getattr(args, "format", "json")
        if format_type == "json":
            sys.stdout.write(json.dumps(export_data, indent=2) + "\n")
        elif format_type == "csv":
            # Export as CSV (flattened format)
            import csv

            writer = csv.writer(sys.stdout)
            writer.writerow(
                [
                    "scan_id",
                    "timestamp",
                    "branch",
                    "profile",
                    "fingerprint",
                    "severity",
                    "tool",
                    "rule_id",
                    "path",
                    "start_line",
                    "message",
                ]
            )
            for scan in export_data:
                for finding in scan["findings"]:
                    writer.writerow(
                        [
                            scan["id"],
                            scan["timestamp_iso"],
                            scan["branch"],
                            scan["profile"],
                            finding["fingerprint"],
                            finding["severity"],
                            finding["tool"],
                            finding["rule_id"],
                            finding["path"],
                            finding["start_line"],
                            finding["message"][:100],
                        ]
                    )
        else:
            sys.stderr.write(f"Error: Unknown format: {format_type}\n")
            return 1

        return 0

    except Exception as e:
        sys.stderr.write(f"Error exporting scans: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_stats(args) -> int:
    """Show database statistics."""
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        sys.stderr.write(
            "Run a scan with --store-history first, or use 'jmo history store'\n"
        )
        return 1

    try:
        conn = get_connection(db_path)
        stats = get_database_stats(conn)
        conn.close()

        # Format output
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps(stats, indent=2) + "\n")
        else:
            sys.stdout.write(f"\nDatabase: {db_path}\n")
            sys.stdout.write(f"Size:     {stats['db_size_mb']} MB\n")
            sys.stdout.write("─" * 60 + "\n")
            sys.stdout.write(f"Scans:            {stats['total_scans']}\n")
            sys.stdout.write(f"Findings:         {stats['total_findings']:,}\n")
            if stats["min_date"] and stats["max_date"]:
                sys.stdout.write(
                    f"Date Range:       {stats['min_date'][:10]} to {stats['max_date'][:10]}\n"
                )
            sys.stdout.write("\n")

            if stats["scans_by_branch"]:
                sys.stdout.write("Scans by Branch:\n")
                for item in stats["scans_by_branch"][:10]:
                    sys.stdout.write(f"  {item['branch']:20} {item['count']:4} scans\n")
                sys.stdout.write("\n")

            if stats["scans_by_profile"]:
                sys.stdout.write("Scans by Profile:\n")
                for item in stats["scans_by_profile"]:
                    sys.stdout.write(
                        f"  {item['profile']:10} {item['count']:4} scans\n"
                    )
                sys.stdout.write("\n")

            if stats["findings_by_severity"]:
                sys.stdout.write("Findings by Severity:\n")
                total = sum(item["count"] for item in stats["findings_by_severity"])
                for item in stats["findings_by_severity"]:
                    pct = (item["count"] / total * 100) if total > 0 else 0
                    sys.stdout.write(
                        f"  {item['severity']:10} {item['count']:6,}  ({pct:5.1f}%)\n"
                    )
                sys.stdout.write("\n")

            if stats["top_tools"]:
                sys.stdout.write("Top Tools:\n")
                for item in stats["top_tools"][:10]:
                    sys.stdout.write(
                        f"  {item['tool']:20} {item['count']:6,} findings\n"
                    )
                sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error getting stats: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_diff(args) -> int:
    """
    Compare two scans and show differences.

    Usage:
        jmo history diff <scan-id-1> <scan-id-2>
        jmo history diff abc123 def456 --output json
    """
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    scan_id_1 = getattr(args, "scan_id_1", None)
    scan_id_2 = getattr(args, "scan_id_2", None)

    if not scan_id_1 or not scan_id_2:
        sys.stderr.write("Error: Provide two scan IDs to compare\n")
        sys.stderr.write("Usage: jmo history diff <scan-id-1> <scan-id-2>\n")
        return 1

    try:
        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Output formatting
        if getattr(args, "json", False):
            # JSON output
            sys.stdout.write(json.dumps(diff, indent=2) + "\n")
        else:
            # Human-readable summary
            sys.stdout.write(f"\n🔍 Diff: {scan_id_1[:8]}... → {scan_id_2[:8]}...\n\n")
            sys.stdout.write(f"✅ New findings:       {len(diff['new'])}\n")
            sys.stdout.write(f"✅ Resolved findings:  {len(diff['resolved'])}\n")
            sys.stdout.write(f"⚪ Unchanged findings: {len(diff['unchanged'])}\n")

            if diff["new"]:
                sys.stdout.write("\n📋 New Findings (top 10):\n")
                for f in diff["new"][:10]:
                    severity = f["severity"]
                    rule_id = f["rule_id"]
                    path = f["path"]
                    sys.stdout.write(f"  - {severity:8s} {rule_id:30s} {path}\n")
                if len(diff["new"]) > 10:
                    sys.stdout.write(f"  ... and {len(diff['new']) - 10} more\n")

            if diff["resolved"]:
                sys.stdout.write("\n✅ Resolved Findings (top 10):\n")
                for f in diff["resolved"][:10]:
                    severity = f["severity"]
                    rule_id = f["rule_id"]
                    path = f["path"]
                    sys.stdout.write(f"  - {severity:8s} {rule_id:30s} {path}\n")
                if len(diff["resolved"]) > 10:
                    sys.stdout.write(f"  ... and {len(diff['resolved']) - 10} more\n")

            sys.stdout.write("\n")

        return 0

    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"Error computing diff: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history_trends(args) -> int:
    """
    Show security trends over time for a branch.

    Usage:
        jmo history trends --branch main --days 30
        jmo history trends --branch dev --days 90 --output json
    """
    db_path = Path(args.db or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    branch = getattr(args, "branch", "main")
    days = getattr(args, "days", 30)

    try:
        conn = get_connection(db_path)
        trend = get_trend_summary(conn, branch, days)
        conn.close()

        if not trend:
            sys.stdout.write(f"No scans found for branch '{branch}' in last {days} days\n")
            return 1

        # Output formatting
        if getattr(args, "json", False):
            # JSON output
            sys.stdout.write(json.dumps(trend, indent=2) + "\n")
        else:
            # Human-readable summary
            sys.stdout.write(f"\n📊 Security Trends: {branch} (last {days} days)\n")
            sys.stdout.write("=" * 70 + "\n\n")

            # Scan count and date range
            sys.stdout.write(f"Scans analyzed:   {trend['scan_count']}\n")
            sys.stdout.write(
                f"Date range:       {trend['date_range']['start'][:10]} to {trend['date_range']['end'][:10]}\n"
            )
            sys.stdout.write("\n")

            # Improvement metrics
            metrics = trend["improvement_metrics"]
            trend_icon = {
                "improving": "📈 ✅",
                "degrading": "📉 ⚠️",
                "stable": "➡️ 🔵",
                "insufficient_data": "❓",
            }.get(metrics["trend"], "❓")

            sys.stdout.write(f"Trend:            {trend_icon} {metrics['trend'].upper()}\n")
            sys.stdout.write(f"Total change:     {metrics['total_change']:+d} findings\n")
            sys.stdout.write(f"CRITICAL change:  {metrics['critical_change']:+d}\n")
            sys.stdout.write(f"HIGH change:      {metrics['high_change']:+d}\n")
            sys.stdout.write("\n")

            # Top rules
            if trend["top_rules"]:
                sys.stdout.write("Top Rules:\n")
                for i, rule in enumerate(trend["top_rules"][:10], 1):
                    sys.stdout.write(
                        f"  {i:2d}. {rule['rule_id']:30s} {rule['severity']:8s} (x{rule['count']})\n"
                    )
                sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error getting trends: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def cmd_history(args) -> int:
    """Main history command router."""
    subcommand = getattr(args, "history_command", None)

    if subcommand == "store":
        return cmd_history_store(args)
    elif subcommand == "list":
        return cmd_history_list(args)
    elif subcommand == "show":
        return cmd_history_show(args)
    elif subcommand == "query":
        return cmd_history_query(args)
    elif subcommand == "prune":
        return cmd_history_prune(args)
    elif subcommand == "export":
        return cmd_history_export(args)
    elif subcommand == "stats":
        return cmd_history_stats(args)
    elif subcommand == "diff":
        return cmd_history_diff(args)
    elif subcommand == "trends":
        return cmd_history_trends(args)
    else:
        sys.stderr.write("Error: Unknown history subcommand\n")
        sys.stderr.write(
            "Usage: jmo history {store|list|show|query|prune|export|stats|diff|trends}\n"
        )
        return 1
