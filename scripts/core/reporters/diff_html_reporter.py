"""HTML reporter for diff results with React + vanilla fallback."""

import json
import logging
from pathlib import Path

from scripts.core.diff_engine import DiffResult

# Threshold for inline vs external JSON mode
INLINE_THRESHOLD = 1000

logger = logging.getLogger(__name__)


def write_html_diff(diff: DiffResult, out_path: Path) -> None:
    """
    Generate HTML diff dashboard with React (or fallback to vanilla).

    Approved hybrid approach:
    1. Check for React dashboard build (scripts/dashboard/dist/index.html)
    2. If exists: Use React dashboard with diff visualization
    3. If not: Fall back to vanilla JS diff dashboard

    Args:
        diff: DiffResult object from DiffEngine
        out_path: Output file path for HTML
    """
    # Check for React dashboard
    react_template = Path(__file__).parent / "../../dashboard/dist/index.html"

    if react_template.exists():
        # Primary path: React dashboard with diff visualization
        logger.info("Using React dashboard for diff visualization")
        return _write_html_diff_react(diff, out_path)
    else:
        # Fallback path: Vanilla JS diff dashboard
        logger.warning("React dashboard not built. Using vanilla JS fallback.")
        logger.warning("Run 'make dashboard-build' for full React features.")
        return _write_html_diff_vanilla(diff, out_path)


def _write_html_diff_react(diff: DiffResult, out_path: Path) -> None:
    """Use React dashboard with diff-specific data injection."""
    # Read React dashboard template
    template_path = Path(__file__).parent / "../../dashboard/dist/index.html"
    template_html = template_path.read_text(encoding="utf-8")

    # Check if template has the required placeholder
    if "window.__DIFF_DATA__ = null" not in template_html:
        logger.warning(
            "React template missing placeholder. Falling back to vanilla JS."
        )
        return _write_html_diff_vanilla(diff, out_path)

    # Prepare diff data
    diff_data = {
        "meta": {
            "diff_version": "1.0.0",
            "baseline": {
                "source_type": diff.baseline_source.source_type,
                "path": diff.baseline_source.path,
                "timestamp": diff.baseline_source.timestamp,
                "profile": diff.baseline_source.profile,
                "total_findings": diff.baseline_source.total_findings,
            },
            "current": {
                "source_type": diff.current_source.source_type,
                "path": diff.current_source.path,
                "timestamp": diff.current_source.timestamp,
                "profile": diff.current_source.profile,
                "total_findings": diff.current_source.total_findings,
            },
        },
        "statistics": diff.statistics,
        "new_findings": diff.new,
        "resolved_findings": diff.resolved,
        "modified_findings": [
            {
                "fingerprint": m.fingerprint,
                "changes": m.changes,
                "baseline": m.baseline,
                "current": m.current,
                "risk_delta": m.risk_delta,
            }
            for m in diff.modified
        ],
    }

    diff_json = json.dumps(diff_data)

    # Replace placeholder (React dashboard expects window.__DIFF_DATA__)
    injected_html = template_html.replace(
        "window.__DIFF_DATA__ = null", f"window.__DIFF_DATA__ = {diff_json}"
    )

    # Write to output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(injected_html, encoding="utf-8")


def _write_html_diff_vanilla(diff: DiffResult, out_path: Path) -> None:
    """
    Vanilla JS diff dashboard (fallback when React not built).

    Features:
    - Before/after comparison table
    - New/resolved/modified findings sections
    - Severity distribution badges
    - Search and filter
    - Dark mode
    - Self-contained HTML (no CDN dependencies)
    """
    # Calculate totals for mode selection
    total_findings = len(diff.new) + len(diff.resolved) + len(diff.modified)
    use_inline = total_findings <= INLINE_THRESHOLD

    # Prepare diff data
    diff_data = {
        "meta": {
            "diff_version": "1.0.0",
            "baseline": {
                "source_type": diff.baseline_source.source_type,
                "path": diff.baseline_source.path,
                "timestamp": diff.baseline_source.timestamp,
                "profile": diff.baseline_source.profile,
                "total_findings": diff.baseline_source.total_findings,
            },
            "current": {
                "source_type": diff.current_source.source_type,
                "path": diff.current_source.path,
                "timestamp": diff.current_source.timestamp,
                "profile": diff.current_source.profile,
                "total_findings": diff.current_source.total_findings,
            },
        },
        "statistics": diff.statistics,
        "new": diff.new,
        "resolved": diff.resolved,
        "modified": [
            {
                "fingerprint": m.fingerprint,
                "changes": m.changes,
                "baseline": m.baseline,
                "current": m.current,
                "risk_delta": m.risk_delta,
            }
            for m in diff.modified
        ],
    }

    if use_inline:
        # Inline mode: Embed JSON directly
        # Escape dangerous characters that could break the <script> tag
        diff_json = (
            json.dumps(diff_data)
            .replace("</script>", "<\\/script>")
            .replace("<script", "<\\script")
            .replace("<!--", "<\\!--")
            .replace("`", "\\`")
        )
        data_injection = f"window.DIFF_DATA = {diff_json};"
    else:
        # External mode: Load JSON via fetch()
        diff_json_path = out_path.parent / "diff-data.json"
        diff_json_path.write_text(json.dumps(diff_data, indent=2), encoding="utf-8")
        data_injection = 'fetch("diff-data.json").then(r => r.json()).then(d => { window.DIFF_DATA = d; renderDiff(); });'

    # Generate HTML template
    html_template = _generate_vanilla_template(data_injection, use_inline)

    # Write to output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_template, encoding="utf-8")


def _generate_vanilla_template(data_injection: str, use_inline: bool) -> str:
    """Generate self-contained HTML template for vanilla diff dashboard."""
    # Determine initialization code
    init_code = "renderDiff();" if use_inline else ""

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none';" />
<meta http-equiv="X-Frame-Options" content="DENY" />
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
<meta name="referrer" content="no-referrer" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>🔍 Security Diff Report</title>
<style>
/* Base Styles */
body {{
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
  margin: 0;
  padding: 20px;
  font-size: 14px;
  line-height: 1.6;
  background: #ffffff;
  color: #212121;
  transition: background 0.3s, color 0.3s;
}}

h1, h2, h3 {{
  margin: 0 0 12px 0;
  font-weight: 600;
}}

h1 {{ font-size: 28px; }}
h2 {{ font-size: 22px; margin-top: 24px; }}
h3 {{ font-size: 18px; margin-top: 16px; }}

/* Header */
.header {{
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 2px solid #e0e0e0;
}}

.header-info {{
  font-size: 13px;
  color: #757575;
}}

/* Dark Mode Toggle */
.dark-mode-toggle {{
  background: #424242;
  color: #fff;
  border: none;
  padding: 8px 16px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 14px;
  transition: background 0.3s;
}}

.dark-mode-toggle:hover {{
  background: #616161;
}}

/* Badges */
.badge {{
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  background: #e0e0e0;
  margin-right: 8px;
  font-size: 13px;
  font-weight: 500;
}}

.badge-new {{ background: #ffebee; color: #c62828; }}
.badge-resolved {{ background: #e8f5e9; color: #2e7d32; }}
.badge-modified {{ background: #fff3e0; color: #ef6c00; }}
.badge-worsening {{ background: #ffebee; color: #c62828; }}
.badge-improving {{ background: #e8f5e9; color: #2e7d32; }}
.badge-stable {{ background: #e3f2fd; color: #1565c0; }}

.sev-CRITICAL {{ color: #b71c1c; font-weight: bold; }}
.sev-HIGH {{ color: #e65100; font-weight: bold; }}
.sev-MEDIUM {{ color: #f57f17; }}
.sev-LOW {{ color: #558b2f; }}
.sev-INFO {{ color: #616161; }}

/* Summary Grid */
.summary-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}}

.summary-card {{
  background: #f5f5f5;
  padding: 16px;
  border-radius: 8px;
  border-left: 4px solid #9e9e9e;
}}

.summary-card.new {{ border-left-color: #c62828; }}
.summary-card.resolved {{ border-left-color: #2e7d32; }}
.summary-card.modified {{ border-left-color: #ef6c00; }}

.summary-card h3 {{
  margin: 0 0 8px 0;
  font-size: 16px;
}}

.summary-card .count {{
  font-size: 32px;
  font-weight: bold;
  margin: 8px 0;
}}

/* Filters */
.filters {{
  display: flex;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}}

.filters input,
.filters select {{
  padding: 8px 12px;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 14px;
  background: #fff;
}}

/* Findings Section */
.findings-section {{
  margin-top: 32px;
}}

.finding-card {{
  background: #fafafa;
  border: 1px solid #e0e0e0;
  border-radius: 6px;
  padding: 16px;
  margin-bottom: 12px;
  transition: box-shadow 0.2s;
}}

.finding-card:hover {{
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}}

.finding-header {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}}

.finding-title {{
  font-weight: 600;
  font-size: 15px;
  margin: 0 0 4px 0;
}}

.finding-meta {{
  font-size: 13px;
  color: #757575;
}}

.finding-location {{
  font-family: "Courier New", monospace;
  font-size: 12px;
  background: #eeeeee;
  padding: 2px 6px;
  border-radius: 3px;
}}

/* Modified Finding Comparison */
.modification-card {{
  background: #fff8e1;
  border-left: 4px solid #f57f17;
}}

.comparison {{
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-top: 12px;
}}

.comparison-column {{
  background: #fff;
  padding: 12px;
  border-radius: 4px;
}}

.comparison-column h4 {{
  margin: 0 0 8px 0;
  font-size: 14px;
  color: #757575;
}}

.change-badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 12px;
  font-weight: 500;
  margin-right: 6px;
}}

.change-severity {{ background: #ffebee; color: #c62828; }}
.change-priority {{ background: #fff3e0; color: #ef6c00; }}
.change-compliance {{ background: #e8f5e9; color: #2e7d32; }}
.change-cwe {{ background: #e3f2fd; color: #1565c0; }}
.change-message {{ background: #f3e5f5; color: #6a1b9a; }}

/* Dark Mode */
body.dark-mode {{
  background: #121212;
  color: #e0e0e0;
}}

body.dark-mode .header {{
  border-bottom-color: #424242;
}}

body.dark-mode .summary-card {{
  background: #1e1e1e;
  color: #e0e0e0;
}}

body.dark-mode .finding-card {{
  background: #1e1e1e;
  border-color: #424242;
}}

body.dark-mode .finding-location {{
  background: #2e2e2e;
}}

body.dark-mode .comparison-column {{
  background: #2e2e2e;
}}

body.dark-mode .filters input,
body.dark-mode .filters select {{
  background: #2e2e2e;
  border-color: #424242;
  color: #e0e0e0;
}}

/* Loading Spinner */
.loading {{
  text-align: center;
  padding: 40px;
  font-size: 16px;
  color: #757575;
}}

/* Responsive */
@media (max-width: 768px) {{
  .comparison {{
    grid-template-columns: 1fr;
  }}
  .summary-grid {{
    grid-template-columns: 1fr;
  }}
}}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>🔍 Security Diff Report</h1>
      <div class="header-info" id="diff-meta"></div>
    </div>
    <button class="dark-mode-toggle" onclick="toggleDarkMode()">🌙 Dark Mode</button>
  </div>

  <div id="app">
    <div id="summary"></div>
    <div id="filters"></div>
    <div id="new-findings" class="findings-section"></div>
    <div id="resolved-findings" class="findings-section"></div>
    <div id="modified-findings" class="findings-section"></div>
  </div>

  <div id="loading" class="loading">Loading diff data...</div>

  <script>
    {data_injection}

    // Dark mode toggle
    function toggleDarkMode() {{
      document.body.classList.toggle('dark-mode');
      localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
    }}

    // Restore dark mode preference
    if (localStorage.getItem('darkMode') === 'true') {{
      document.body.classList.add('dark-mode');
    }}

    // Render diff dashboard
    function renderDiff() {{
      const data = window.DIFF_DATA;
      if (!data) {{
        document.getElementById('loading').textContent = 'Error: No diff data loaded';
        return;
      }}

      document.getElementById('loading').style.display = 'none';

      // Render metadata
      const baseline = data.meta.baseline;
      const current = data.meta.current;
      document.getElementById('diff-meta').innerHTML = `
        <strong>Baseline:</strong> ${{baseline.path}} (${{baseline.timestamp.split('T')[0]}}, ${{baseline.profile}} profile, ${{baseline.total_findings}} findings)<br>
        <strong>Current:</strong> ${{current.path}} (${{current.timestamp.split('T')[0]}}, ${{current.profile}} profile, ${{current.total_findings}} findings)
      `;

      // Render summary
      renderSummary(data.statistics);

      // Render filters
      renderFilters(data);

      // Render findings sections
      renderNewFindings(data.new);
      renderResolvedFindings(data.resolved);
      renderModifiedFindings(data.modified);
    }}

    function renderSummary(stats) {{
      const trendClass = stats.trend === 'worsening' ? 'badge-worsening' :
                         stats.trend === 'improving' ? 'badge-improving' : 'badge-stable';

      document.getElementById('summary').innerHTML = `
        <div class="summary-grid">
          <div class="summary-card new">
            <h3>🔴 New Findings</h3>
            <div class="count">${{stats.total_new}}</div>
            <div>${{renderSeverityBreakdown(stats.new_by_severity)}}</div>
          </div>
          <div class="summary-card resolved">
            <h3>✅ Resolved Findings</h3>
            <div class="count">${{stats.total_resolved}}</div>
            <div>${{renderSeverityBreakdown(stats.resolved_by_severity)}}</div>
          </div>
          <div class="summary-card modified">
            <h3>🔄 Modified Findings</h3>
            <div class="count">${{stats.total_modified}}</div>
            <div>${{renderModificationBreakdown(stats.modifications_by_type)}}</div>
          </div>
        </div>
        <div style="margin-top: 16px;">
          <span class="badge"><strong>Net Change:</strong> ${{stats.net_change > 0 ? '+' : ''}}${{stats.net_change}}</span>
          <span class="badge ${{trendClass}}"><strong>Trend:</strong> ${{stats.trend}}</span>
        </div>
      `;
    }}

    function renderSeverityBreakdown(sevCounts) {{
      if (!sevCounts || Object.keys(sevCounts).length === 0) return '<span style="color: #9e9e9e;">None</span>';

      const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      return severities
        .filter(s => sevCounts[s] > 0)
        .map(s => `<span class="sev-${{s}}">${{s}}: ${{sevCounts[s]}}</span>`)
        .join(', ');
    }}

    function renderModificationBreakdown(modTypes) {{
      if (!modTypes || Object.keys(modTypes).length === 0) return '<span style="color: #9e9e9e;">None</span>';

      return Object.entries(modTypes)
        .map(([type, count]) => `${{type}}: ${{count}}`)
        .join(', ');
    }}

    function renderFilters(data) {{
      // Simple search filter
      document.getElementById('filters').innerHTML = `
        <div class="filters">
          <input type="text" id="search-input" placeholder="Search findings..." onkeyup="filterFindings()">
          <select id="severity-filter" onchange="filterFindings()">
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFO">INFO</option>
          </select>
        </div>
      `;
    }}

    function filterFindings() {{
      const search = document.getElementById('search-input').value.toLowerCase();
      const severity = document.getElementById('severity-filter').value;

      document.querySelectorAll('.finding-card').forEach(card => {{
        const text = card.textContent.toLowerCase();
        const cardSev = card.dataset.severity || '';

        const matchesSearch = !search || text.includes(search);
        const matchesSeverity = !severity || cardSev === severity;

        card.style.display = matchesSearch && matchesSeverity ? 'block' : 'none';
      }});
    }}

    function renderNewFindings(findings) {{
      if (!findings || findings.length === 0) {{
        document.getElementById('new-findings').innerHTML = '';
        return;
      }}

      const html = findings.map(f => renderFindingCard(f, 'new')).join('');
      document.getElementById('new-findings').innerHTML = `
        <h2>🔴 New Findings (${{findings.length}})</h2>
        ${{html}}
      `;
    }}

    function renderResolvedFindings(findings) {{
      if (!findings || findings.length === 0) {{
        document.getElementById('resolved-findings').innerHTML = '';
        return;
      }}

      const html = findings.map(f => renderFindingCard(f, 'resolved')).join('');
      document.getElementById('resolved-findings').innerHTML = `
        <h2>✅ Resolved Findings (${{findings.length}})</h2>
        ${{html}}
      `;
    }}

    function renderModifiedFindings(modifications) {{
      if (!modifications || modifications.length === 0) {{
        document.getElementById('modified-findings').innerHTML = '';
        return;
      }}

      const html = modifications.map(renderModificationCard).join('');
      document.getElementById('modified-findings').innerHTML = `
        <h2>🔄 Modified Findings (${{modifications.length}})</h2>
        ${{html}}
      `;
    }}

    function renderFindingCard(finding, type) {{
      const severity = finding.severity || 'INFO';
      const location = finding.location || {{}};
      const tool = finding.tool || {{}};

      return `
        <div class="finding-card" data-severity="${{severity}}">
          <div class="finding-header">
            <div>
              <div class="finding-title sev-${{severity}}">${{severity}}</div>
              <div class="finding-meta">
                <span class="finding-location">${{location.path || 'unknown'}}:${{location.startLine || '?'}}</span>
                <span> • ${{tool.name || 'unknown'}}</span>
                <span> • ${{finding.ruleId || 'unknown'}}</span>
              </div>
            </div>
          </div>
          <div>${{finding.message || 'No message'}}</div>
        </div>
      `;
    }}

    function renderModificationCard(mod) {{
      const current = mod.current || {{}};
      const baseline = mod.baseline || {{}};
      const severity = current.severity || baseline.severity || 'INFO';
      const location = current.location || baseline.location || {{}};

      const changeTypes = Object.keys(mod.changes || {{}}).map(type => {{
        const typeClass = `change-${{type.replace('_', '-')}}`;
        return `<span class="change-badge ${{typeClass}}">${{type}}</span>`;
      }}).join('');

      return `
        <div class="finding-card modification-card" data-severity="${{severity}}">
          <div class="finding-header">
            <div>
              <div class="finding-title">
                <span class="sev-${{severity}}">${{current.ruleId || baseline.ruleId || 'unknown'}}</span>
              </div>
              <div class="finding-meta">
                <span class="finding-location">${{location.path || 'unknown'}}:${{location.startLine || '?'}}</span>
                <span> • Risk: ${{mod.risk_delta}}</span>
              </div>
            </div>
          </div>
          <div style="margin-bottom: 12px;">
            <strong>Changes:</strong> ${{changeTypes}}
          </div>
          <div class="comparison">
            <div class="comparison-column">
              <h4>📋 Baseline</h4>
              <div><strong>Severity:</strong> <span class="sev-${{baseline.severity}}">${{baseline.severity}}</span></div>
              <div><strong>Message:</strong> ${{(baseline.message || '').substring(0, 100)}}...</div>
            </div>
            <div class="comparison-column">
              <h4>📋 Current</h4>
              <div><strong>Severity:</strong> <span class="sev-${{current.severity}}">${{current.severity}}</span></div>
              <div><strong>Message:</strong> ${{(current.message || '').substring(0, 100)}}...</div>
            </div>
          </div>
        </div>
      `;
    }}

    // Initialize on load
    {init_code}
  </script>
</body>
</html>
"""
    return template
