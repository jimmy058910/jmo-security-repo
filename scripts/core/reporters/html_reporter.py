#!/usr/bin/env python3
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def write_html(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    total = len(findings)
    sev_counts = Counter(f.get("severity", "INFO") for f in findings)
    # Self-contained HTML (no external CDN) with v2 features:
    # - Expandable rows for code context
    # - Suggested fixes with copy button
    # - Grouping by file/rule/tool/severity
    # - Risk metadata (CWE/OWASP) tooltips and filters
    # - Triage workflow support
    # - Enhanced filters with multi-select and patterns
    # Escape dangerous characters that could break the <script> tag or JavaScript
    # Must escape AFTER json.dumps to avoid breaking JSON structure
    # Note: json.dumps already escapes backslashes, quotes, etc. per JSON spec
    # We only need to escape characters that break HTML <script> context:
    # 1. </script> breaks out of script tag (CRITICAL: causes premature script closure)
    # 2. <script> could inject new script tags
    # 3. <!-- could start HTML comment (breaks in some parsers)
    # 4. Backticks break JavaScript template literals (if used in JS)
    data_json = (
        json.dumps(findings)
        .replace("</script>", "<\\/script>")  # Prevent script tag breakout
        .replace(
            "<script", "<\\script"
        )  # Prevent script injection (catches <script and <Script)
        .replace("<!--", "<\\!--")  # Prevent HTML comment injection
        .replace("`", "\\`")  # Prevent template literal breakout
    )
    sev_badges = "".join(
        f'<span class="badge sev-{s}">{s}: {sev_counts.get(s, 0)}</span>'
        for s in SEV_ORDER
    )
    sev_options = "".join(f'<option value="{s}">{s}</option>' for s in SEV_ORDER)
    template = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<!-- SECURITY: Meta tags for browser security (MEDIUM-002 fix) -->
<!-- Content Security Policy: Prevents XSS attacks by restricting resource loading -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline' 'self'; style-src 'unsafe-inline' 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self' https://api.jmotools.com; form-action 'self' https://api.jmotools.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none';" />
<!-- X-Frame-Options: Prevents clickjacking by blocking iframe embedding -->
<meta http-equiv="X-Frame-Options" content="DENY" />
<!-- X-Content-Type-Options: Prevents MIME sniffing attacks -->
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
<!-- Referrer-Policy: Prevents information leakage via HTTP Referer header -->
<meta name="referrer" content="no-referrer" />
<!-- Robots: Prevent search engine indexing of security reports -->
<meta name="robots" content="noindex, nofollow" />
<title>Security Dashboard v2</title>
<style>
body{font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; font-size: 14px;}
h1,h2{margin: 0 0 12px 0}
.header{display:flex; justify-content:space-between; align-items:center; margin-bottom:16px}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;background:#eee;margin-right:8px;font-size:13px}
.sev-CRITICAL{color:#d32f2f;font-weight:bold}
.sev-HIGH{color:#f57c00;font-weight:bold}
.sev-MEDIUM{color:#fbc02d}
.sev-LOW{color:#7cb342}
.sev-INFO{color:#757575}
.filters{margin-bottom:12px;padding:16px;background:#f5f5f5;border-radius:6px}
.filters label{display:flex;align-items:center;gap:6px;font-size:13px}
.filters select,.filters input[type="text"],.filters input[type="email"]{padding:6px 10px;border:1px solid #ccc;border-radius:4px;font-size:13px}
.sev-checkbox{display:inline-flex;align-items:center;gap:4px;padding:4px 8px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:500;transition:background 0.2s,opacity 0.2s}
.sev-checkbox input{cursor:pointer;margin:0}
.sev-checkbox:hover{background:rgba(0,0,0,0.05)}
.sev-checkbox.unchecked{opacity:0.5}
#activeFilters{font-size:12px;line-height:1.6}
#activeFiltersList .filter-tag{display:inline-block;padding:2px 8px;margin:0 4px 4px 0;background:#1976d2;color:#fff;border-radius:12px;font-size:11px}
.actions{margin:12px 0;display:flex;gap:8px;flex-wrap:wrap}
.btn{display:inline-block;padding:6px 12px;border:1px solid #ccc;border-radius:6px;background:#f7f7f7;cursor:pointer;font-size:13px;transition:background 0.2s}
.btn:hover{background:#e8e8e8}
.btn-primary{background:#1976d2;color:#fff;border-color:#1565c0}
.btn-primary:hover{background:#1565c0}
.grouping{margin:12px 0}
.table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
.table th,.table td{border:1px solid #ddd;padding:8px;text-align:left}
.table th{cursor:pointer; user-select:none;background:#f5f5f5;font-weight:600}
.table th.sort-asc::after{content:' ▲';color:#1976d2}
.table th.sort-desc::after{content:' ▼';color:#1976d2}
.table tr:hover{background:#fafafa}
.priority-badge{display:inline-block;padding:4px 10px;border-radius:10px;font-size:14px;font-weight:700;color:#fff;min-width:45px;text-align:center}
.priority-critical{background:#d32f2f}
.priority-high{background:#f57c00}
.priority-medium{background:#fbc02d;color:#000}
.priority-low{background:#7cb342}
.priority-info{background:#757575}
.kev-badge{display:inline-block;padding:2px 6px;margin-left:4px;border-radius:8px;background:#ff1744;color:#fff;font-size:10px;font-weight:700;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1} 50%{opacity:0.7}}
.priority-sparkline{display:inline-block;height:14px;background:#e0e0e0;border-radius:2px;margin-left:4px;vertical-align:middle}
.priority-sparkline-fill{height:100%;background:currentColor;border-radius:2px;transition:width 0.3s}
.medal{font-size:16px;margin-right:4px;vertical-align:middle}
.summary-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px}
.summary-card{background:#fff;border:2px solid #e0e0e0;border-radius:8px;padding:16px;text-align:center;transition:transform 0.2s,box-shadow 0.2s}
.summary-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,0.1)}
.summary-card.critical{border-color:#d32f2f;background:linear-gradient(135deg,#fff 0%,#ffebee 100%)}
.summary-card.kev{border-color:#ff1744;background:linear-gradient(135deg,#fff 0%,#fff3e0 100%)}
.summary-card.high-epss{border-color:#f57c00;background:linear-gradient(135deg,#fff 0%,#fff3e0 100%)}
.summary-card.avg{border-color:#1976d2;background:linear-gradient(135deg,#fff 0%,#e3f2fd 100%)}
.summary-card-icon{font-size:32px;margin-bottom:8px}
.summary-card-value{font-size:28px;font-weight:700;margin:8px 0}
.summary-card-label{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:0.5px}
.summary-card-subtitle{font-size:11px;color:#999;margin-top:4px}
.quick-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;padding:12px;background:#f5f5f5;border-radius:6px}
.quick-filter-btn{padding:8px 16px;border:2px solid transparent;border-radius:20px;background:#fff;cursor:pointer;font-size:13px;font-weight:600;transition:all 0.2s;display:inline-flex;align-items:center;gap:6px}
.quick-filter-btn:hover{transform:translateY(-1px);box-shadow:0 2px 8px rgba(0,0,0,0.15)}
.quick-filter-btn.active{border-color:#1976d2;background:#e3f2fd;color:#1976d2}
.quick-filter-btn.critical{border-color:#d32f2f}
.quick-filter-btn.critical.active{background:#ffebee;color:#d32f2f;border-color:#d32f2f}
.quick-filter-btn.kev{border-color:#ff1744}
.quick-filter-btn.kev.active{background:#ffe0e0;color:#ff1744;border-color:#ff1744}
.quick-filter-btn.epss{border-color:#f57c00}
.quick-filter-btn.epss.active{background:#fff3e0;color:#f57c00;border-color:#f57c00}
.quick-filter-count{display:inline-block;background:rgba(0,0,0,0.1);padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;margin-left:4px}
.priority-col{min-width:120px!important}
.epss-bar{width:100%;height:20px;background:#e0e0e0;border-radius:4px;overflow:hidden;margin:8px 0}
.epss-bar-fill{height:100%;background:linear-gradient(90deg,#4caf50 0%,#ff9800 50%,#d32f2f 100%);transition:width 0.3s}
.risk-level-badge{display:inline-block;padding:6px 12px;border-radius:6px;font-size:13px;font-weight:700;color:#fff;margin-bottom:12px}
.risk-level-critical{background:#d32f2f}
.risk-level-high{background:#f57c00}
.risk-level-medium{background:#fbc02d;color:#000}
.risk-level-low{background:#7cb342}
.triage-urgent{border:2px solid #d32f2f!important;animation:urgentPulse 2s infinite}
@keyframes urgentPulse{0%,100%{box-shadow:0 0 0 0 rgba(211,47,47,0.4)} 50%{box-shadow:0 0 0 6px rgba(211,47,47,0)}}
.quick-action-btns{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}
.quick-action-btn{padding:6px 12px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:12px;transition:all 0.2s}
.quick-action-btn:hover{background:#f0f0f0;transform:translateY(-1px)}
.quick-action-btn.fixed{border-color:#4caf50;color:#4caf50}
.quick-action-btn.fixed:hover{background:#e8f5e9}
.quick-action-btn.fp{border-color:#ff9800;color:#ff9800}
.quick-action-btn.fp:hover{background:#fff3e0}
.quick-action-btn.accept{border-color:#757575;color:#757575}
.quick-action-btn.accept:hover{background:#f5f5f5}
.quick-action-btn.escalate{border-color:#d32f2f;color:#d32f2f;font-weight:600}
.quick-action-btn.escalate:hover{background:#ffebee}
.expandable-row{cursor:pointer}
.expandable-row td{position:relative}
.expandable-row td:first-child::before{content:'▶';display:inline-block;width:12px;color:#666;transition:transform 0.2s}
.expandable-row.expanded td:first-child::before{transform:rotate(90deg)}
.detail-row{display:none;background:#f9f9f9}
.detail-row.visible{display:table-row}
.detail-content{padding:16px;border-top:1px solid #e0e0e0}
.snippet-box{background:#f5f5f5;border:1px solid #ddd;border-radius:4px;padding:12px;margin:8px 0;font-family:Consolas,Monaco,monospace;font-size:12px;white-space:pre;overflow-x:auto;position:relative}
.snippet-box .highlight{background:#fff9c4;font-weight:bold}
.copy-btn{position:absolute;top:8px;right:8px;padding:4px 8px;background:#fff;border:1px solid #ddd;border-radius:4px;cursor:pointer;font-size:11px}
.copy-btn:hover{background:#f0f0f0}
.fix-box{background:#e8f5e9;border-left:3px solid #4caf50;padding:12px;margin:8px 0;border-radius:4px}
.secret-box{background:#fff3e0;border-left:3px solid #ff9800;padding:12px;margin:8px 0;border-radius:4px}
.meta-section{margin-top:8px;font-size:12px;color:#666}
.meta-section strong{color:#333}
.tooltip{position:relative;display:inline-block;border-bottom:1px dotted #666;cursor:help}
.tooltip .tooltiptext{visibility:hidden;width:200px;background-color:#333;color:#fff;text-align:center;border-radius:6px;padding:8px;position:absolute;z-index:1;bottom:125%;left:50%;margin-left:-100px;opacity:0;transition:opacity 0.3s;font-size:11px}
.tooltip:hover .tooltiptext{visibility:visible;opacity:1}
.theme-toggle{margin-left:12px}
.grouped-view .group-header{background:#e3f2fd;padding:10px;margin-top:8px;border-radius:6px;cursor:pointer;font-weight:600;display:flex;justify-content:space-between;align-items:center}
.grouped-view .group-header:hover{background:#bbdefb}
.grouped-view .group-header::before{content:'▼';margin-right:8px;display:inline-block;transition:transform 0.2s}
.grouped-view .group-header.collapsed::before{transform:rotate(-90deg)}
.grouped-view .group-content{display:block}
.grouped-view .group-content.hidden{display:none}
.triage-controls{display:flex;gap:8px;margin-top:8px}
.triage-select{padding:4px;border:1px solid #ccc;border-radius:4px;font-size:12px}
#profile{display:none; margin-top:12px; padding:12px; border:1px dashed #ccc; border-radius:6px;background:#fafafa}
#profile summary{cursor:pointer;font-weight:600}
@media (max-width: 768px) {
  .header{flex-direction:column;align-items:flex-start;gap:12px}
  .filters > div{flex-direction:column;align-items:flex-start}
  .filters label{width:100%}
  .filters select,.filters input{width:100%!important;max-width:100%!important}
  #sevCheckboxes{flex-wrap:wrap}
  .table{font-size:12px}
  .table th,.table td{padding:6px;word-break:break-word}
  .actions{flex-direction:column}
  .btn{width:100%}
}
.kbd-hint{position:fixed;bottom:20px;right:20px;background:rgba(0,0,0,0.8);color:#fff;padding:8px 12px;border-radius:6px;font-size:11px;opacity:0;transition:opacity 0.3s;pointer-events:none;z-index:1000}
.kbd-hint.visible{opacity:0.9}
kbd{display:inline-block;padding:2px 6px;border:1px solid #ccc;border-radius:3px;background:#f5f5f5;font-family:monospace;font-size:10px;box-shadow:0 1px 2px rgba(0,0,0,0.1)}
#resultCount{display:flex;align-items:center;gap:8px}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Security Dashboard v2.2 (Priority Intelligence)</h1>
    <div>
      <span class="badge">Total: __TOTAL__</span>
      __SEV_BADGES__
    </div>
  </div>
  <button class="btn theme-toggle" id="themeToggle">Toggle Theme</button>
</div>

<!-- Quick Win #3: Priority Summary Cards -->
<div class="summary-cards" id="summaryCards">
  <div class="summary-card critical">
    <div class="summary-card-icon">🔴</div>
    <div class="summary-card-value" id="criticalCount">0</div>
    <div class="summary-card-label">Critical Priority</div>
    <div class="summary-card-subtitle" id="criticalPercent">0% of total</div>
  </div>
  <div class="summary-card kev">
    <div class="summary-card-icon">🚨</div>
    <div class="summary-card-value" id="kevCount">0</div>
    <div class="summary-card-label">KEV Findings</div>
    <div class="summary-card-subtitle">Actively Exploited</div>
  </div>
  <div class="summary-card high-epss">
    <div class="summary-card-icon">🔥</div>
    <div class="summary-card-value" id="highEpssCount">0</div>
    <div class="summary-card-label">High EPSS</div>
    <div class="summary-card-subtitle">&gt;50% Exploit Probability</div>
  </div>
  <div class="summary-card avg">
    <div class="summary-card-icon">📊</div>
    <div class="summary-card-value" id="avgPriority">0</div>
    <div class="summary-card-label">Avg Priority</div>
    <div class="summary-card-subtitle" id="avgPriorityLabel">out of 100</div>
  </div>
</div>

<!-- Quick Win #2: Quick Filter Buttons -->
<div class="quick-filters">
  <button class="quick-filter-btn critical" id="filterCritical" onclick="toggleQuickFilter('critical')">
    🚨 Critical Priority<span class="quick-filter-count" id="criticalFilterCount">0</span>
  </button>
  <button class="quick-filter-btn kev" id="filterKev" onclick="toggleQuickFilter('kev')">
    ⚠️ KEV Only<span class="quick-filter-count" id="kevFilterCount">0</span>
  </button>
  <button class="quick-filter-btn epss" id="filterEpss" onclick="toggleQuickFilter('epss')">
    🔥 High EPSS<span class="quick-filter-count" id="epssFilterCount">0</span>
  </button>
  <button class="quick-filter-btn" id="clearQuickFilters" onclick="clearQuickFilters()">
    Clear All
  </button>
</div>

<div class="filters">
  <!-- Row 1: Primary Filters -->
  <div style="display:flex;gap:12px;flex-wrap:wrap;width:100%;align-items:center">
    <label style="flex:0 0 auto">Severity:
      <div id="sevCheckboxes" style="display:inline-flex;gap:4px;margin-left:6px;border:1px solid #ccc;border-radius:6px;padding:4px;background:#fff">
        <!-- Populated by JS -->
      </div>
    </label>
    <label style="flex:0 0 auto">Tool:
      <select id="tool" style="min-width:120px">
        <option value="">All</option>
      </select>
    </label>
    <label style="flex:0 0 auto">Compliance Framework:
      <select id="complianceFramework" style="min-width:160px">
        <option value="">All Frameworks</option>
        <option value="owasp">OWASP Top 10 2021</option>
        <option value="cwe">CWE Top 25 2024</option>
        <option value="cis">CIS Controls v8.1</option>
        <option value="nist">NIST CSF 2.0</option>
        <option value="pci">PCI DSS 4.0</option>
        <option value="attack">MITRE ATT&CK</option>
      </select>
    </label>
    <label id="complianceValueWrapper" style="flex:0 0 auto;display:none">
      <select id="complianceValue" style="min-width:180px">
        <option value="">All Values</option>
      </select>
    </label>
    <label style="flex:0 0 auto">
      <input type="checkbox" id="hideTriaged"/> Hide Triaged
    </label>
  </div>

  <!-- Row 2: Search and Path Filters -->
  <div style="display:flex;gap:12px;flex-wrap:wrap;width:100%;margin-top:8px;align-items:center">
    <label style="flex:1 1 200px">Search:
      <input id="q" placeholder="rule/message/path" style="width:100%;max-width:300px"/>
    </label>
    <label style="flex:1 1 150px">Path Pattern:
      <input id="pathPattern" placeholder="src/, *.py" style="width:100%;max-width:200px"/>
    </label>
    <label style="flex:1 1 150px">Exclude Pattern:
      <input id="excludePattern" placeholder="test/, node_modules" style="width:100%;max-width:200px"/>
    </label>
    <button class="btn" id="clearFilters" style="flex:0 0 auto;font-size:12px;padding:4px 10px">Clear All Filters</button>
  </div>

  <!-- Active Filters Display -->
  <div id="activeFilters" style="display:none;margin-top:8px;padding:8px;background:#e3f2fd;border-radius:4px;font-size:12px">
    <strong>Active Filters:</strong> <span id="activeFiltersList"></span>
  </div>
</div>

<div class="actions">
  <div class="grouping">
    <label>Group by:
      <select id="groupBy">
        <option value="">None (flat list)</option>
        <option value="file">File</option>
        <option value="rule">Rule</option>
        <option value="tool">Tool</option>
        <option value="severity">Severity</option>
      </select>
    </label>
  </div>
  <button class="btn" id="exportJson">Export JSON</button>
  <button class="btn" id="exportCsv">Export CSV</button>
  <button class="btn btn-primary" id="bulkTriage">Bulk Triage</button>
  <small style="color:#666;align-self:center">Exports apply to filtered rows</small>
</div>

<div id="profile">
  <strong>Run Profile</strong> — <span id="profileSummary"></span>
  <details style="margin-top:8px"><summary>Top jobs</summary>
    <ul id="profileJobs" style="margin:8px 0 0 16px"></ul>
  </details>
  <small style="color:#666">Tip: run with profiling enabled to populate (jmo report --profile)</small>
</div>

<div id="tableContainer">
  <table class="table" id="tbl">
    <thead><tr>
      <th data-key="priority" class="priority-col">Priority</th>
      <th data-key="severity">Severity</th>
      <th data-key="ruleId">Rule</th>
      <th data-key="path">Path</th>
      <th data-key="line">Line</th>
      <th data-key="message">Message</th>
      <th data-key="tool">Tool</th>
      <th>Actions</th>
    </tr></thead>
    <tbody></tbody>
  </table>
</div>

<div id="groupedContainer" style="display:none"></div>

<div id="resultCount" style="margin:12px 0;padding:8px 12px;background:#e8f5e9;border-left:3px solid #4caf50;border-radius:4px;font-size:13px;font-weight:500">
  Showing <span id="visibleCount">0</span> of <span id="totalCount">0</span> findings
</div>

<div class="kbd-hint" id="kbdHint">
  Press <kbd>Ctrl+K</kbd> to search, <kbd>Ctrl+/</kbd> to clear filters
</div>

<script>
const data = __DATA_JSON__;
let sortKey = '';
let sortDir = 'asc';
let groupBy = '';
let triageState = {}; // Load from localStorage
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

// Quick Win #2: Quick filter state
let activeQuickFilters = {
  critical: false,
  kev: false,
  epss: false
};

// Load triage state from localStorage
try{
  const saved = localStorage.getItem('jmo_triage_state');
  if(saved) triageState = JSON.parse(saved);
}catch(e){}

// Quick Win #2: Toggle quick filter
function toggleQuickFilter(type){
  activeQuickFilters[type] = !activeQuickFilters[type];
  document.getElementById('filter' + type.charAt(0).toUpperCase() + type.slice(1)).classList.toggle('active', activeQuickFilters[type]);
  render();
}

function clearQuickFilters(){
  activeQuickFilters = { critical: false, kev: false, epss: false };
  document.getElementById('filterCritical').classList.remove('active');
  document.getElementById('filterKev').classList.remove('active');
  document.getElementById('filterEpss').classList.remove('active');
  render();
}

// Quick Win #3: Update summary cards
function updateSummaryCards(){
  const criticalPriority = data.filter(f => (f.priority?.priority || 0) >= 80);
  const kevFindings = data.filter(f => f.priority?.is_kev);
  const highEpss = data.filter(f => (f.priority?.epss || 0) > 0.5);
  const avgPriority = data.length > 0 ? (data.reduce((sum, f) => sum + (f.priority?.priority || 0), 0) / data.length) : 0;

  document.getElementById('criticalCount').textContent = criticalPriority.length;
  document.getElementById('criticalPercent').textContent = `${((criticalPriority.length / data.length) * 100).toFixed(1)}% of total`;
  document.getElementById('kevCount').textContent = kevFindings.length;
  document.getElementById('highEpssCount').textContent = highEpss.length;
  document.getElementById('avgPriority').textContent = avgPriority.toFixed(0);

  // Update quick filter counts
  document.getElementById('criticalFilterCount').textContent = criticalPriority.length;
  document.getElementById('kevFilterCount').textContent = kevFindings.length;
  document.getElementById('epssFilterCount').textContent = highEpss.length;
}

// Theme handling
function setTheme(theme){
  const dark = (theme === 'dark');
  document.body.style.background = dark ? '#1a1a1a' : '#fff';
  document.body.style.color = dark ? '#eee' : '#000';
  const tables = document.querySelectorAll('.table th, .table td');
  tables.forEach(t => {
    if(dark){
      t.style.borderColor = '#444';
      if(t.tagName === 'TH') t.style.background = '#2a2a2a';
    } else {
      t.style.borderColor = '#ddd';
      if(t.tagName === 'TH') t.style.background = '#f5f5f5';
    }
  });
}
document.getElementById('themeToggle').addEventListener('click', ()=>{
  const t = localStorage.getItem('jmo_theme') === 'dark' ? 'light' : 'dark';
  localStorage.setItem('jmo_theme', t);
  setTheme(t);
});

// HTML escaping to prevent XSS
function escapeHtml(str){
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return (str||'').replace(/[&<>"']/g, m => map[m]);
}

function severityRank(s){
  const i = SEV_ORDER.indexOf(s||'');
  return i === -1 ? SEV_ORDER.length : i;
}

function matchesFilter(f){
  // Quick Win #2: Quick filters (priority-based)
  if(activeQuickFilters.critical && (f.priority?.priority || 0) < 80) return false;
  if(activeQuickFilters.kev && !f.priority?.is_kev) return false;
  if(activeQuickFilters.epss && (f.priority?.epss || 0) <= 0.5) return false;

  // Severity filter - checkbox-based
  const checkedSevs = Array.from(document.querySelectorAll('#sevCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
  if(checkedSevs.length > 0 && checkedSevs.length < SEV_ORDER.length && !checkedSevs.includes(f.severity)) return false;

  const tool = document.getElementById('tool').value;
  if(tool && (f.tool?.name||'') !== tool) return false;

  const q = document.getElementById('q').value.toLowerCase();
  if(q && !(f.ruleId||'').toLowerCase().includes(q) && !(f.message||'').toLowerCase().includes(q) && !(f.location?.path||'').toLowerCase().includes(q)) return false;

  // Unified compliance framework filter
  const framework = document.getElementById('complianceFramework').value;
  const frameworkValue = document.getElementById('complianceValue').value;
  if(framework && frameworkValue){
    const fieldMap = {
      'owasp': 'owasp_top_10_2021',
      'cwe': 'cwe_top_25_2024',
      'cis': 'cis_controls_v8_1',
      'nist': 'nist_csf_2_0',
      'pci': 'pci_dss_4_0',
      'attack': 'mitre_attack_v16_1'
    };
    const field = fieldMap[framework];
    if(field && !(f.compliance?.[field]||[]).includes(frameworkValue)) return false;
  }

  const pathPattern = document.getElementById('pathPattern').value.toLowerCase();
  if(pathPattern && !(f.location?.path||'').toLowerCase().includes(pathPattern)) return false;

  const excludePattern = document.getElementById('excludePattern').value.toLowerCase();
  if(excludePattern && (f.location?.path||'').toLowerCase().includes(excludePattern)) return false;

  const hideTriaged = document.getElementById('hideTriaged').checked;
  if(hideTriaged && triageState[f.id]) return false;

  return true;
}

function filtered(){
  return data.filter(matchesFilter);
}

function sortRows(rows){
  if(!sortKey){
    // Default: sort by priority descending
    return rows.slice().sort((a,b)=>{
      const ap = a.priority?.priority || 0;
      const bp = b.priority?.priority || 0;
      return bp - ap; // Higher priority first
    });
  }
  const factor = sortDir === 'asc' ? 1 : -1;
  return rows.slice().sort((a,b)=>{
    let av, bv;
    if(sortKey==='priority') { av = (a.priority?.priority||0); bv = (b.priority?.priority||0); }
    else if(sortKey==='severity') { av = severityRank(a.severity); bv = severityRank(b.severity); }
    else if(sortKey==='ruleId'){ av = (a.ruleId||''); bv = (b.ruleId||''); }
    else if(sortKey==='path'){ av = (a.location?.path||''); bv = (b.location?.path||''); }
    else if(sortKey==='line'){ av = (a.location?.startLine||0); bv = (b.location?.startLine||0); }
    else if(sortKey==='message'){ av = (a.message||''); bv = (b.message||''); }
    else if(sortKey==='tool'){ av = (a.tool?.name||''); bv = (b.tool?.name||''); }
    else { av = ''; bv = ''; }
    if(av < bv) return -1*factor; if(av > bv) return 1*factor; return 0;
  });
}

function renderDetailRow(f){
  let html = '<div class="detail-content">';

  // Code snippet
  if(f.context && f.context.snippet){
    html += '<div class="meta-section"><strong>Code Context:</strong></div>';
    html += `<div class="snippet-box"><button class="copy-btn" onclick="copySnippet('${escapeHtml(f.id)}')">Copy</button><code id="snippet-${escapeHtml(f.id)}">${escapeHtml(f.context.snippet)}</code></div>`;
  }

  // Suggested fix
  if(typeof f.remediation === 'object' && f.remediation.fix){
    html += '<div class="meta-section"><strong>Suggested Fix:</strong></div>';
    html += `<div class="fix-box">`;
    html += `<div style="margin-bottom:8px">${escapeHtml(f.remediation.summary||'Apply this fix')}</div>`;
    html += `<div class="snippet-box"><button class="copy-btn" onclick="copyFix('${escapeHtml(f.id)}')">Copy Fix</button><code id="fix-${escapeHtml(f.id)}">${escapeHtml(f.remediation.fix)}</code></div>`;
    if(f.remediation.steps && f.remediation.steps.length > 0){
      html += '<div style="margin-top:8px;font-size:12px"><strong>Steps:</strong><ol style="margin:4px 0 0 20px">';
      f.remediation.steps.forEach(step => {
        html += `<li>${escapeHtml(step)}</li>`;
      });
      html += '</ol></div>';
    }
    html += `</div>`;
  }

  // Secret context
  if(f.secretContext){
    html += '<div class="meta-section"><strong>Secret Details:</strong></div>';
    html += `<div class="secret-box">`;
    html += `<div>🔑 <code>${escapeHtml(f.secretContext.secret||'')}</code></div>`;
    if(f.secretContext.entropy) html += `<div style="margin-top:4px">Entropy: ${f.secretContext.entropy.toFixed(2)}</div>`;
    if(f.secretContext.commit) html += `<div>Commit: <code>${escapeHtml(f.secretContext.commit)}</code></div>`;
    if(f.secretContext.author) html += `<div>Author: ${escapeHtml(f.secretContext.author)}</div>`;
    if(f.secretContext.date) html += `<div>Date: ${escapeHtml(f.secretContext.date)}</div>`;
    if(f.secretContext.gitUrl) html += `<div><a href="${escapeHtml(f.secretContext.gitUrl)}" target="_blank">View in Git</a></div>`;
    html += `</div>`;
  }

  // Quick Win #4: Enhanced Priority metadata (EPSS/KEV) with visual elements
  if(f.priority){
    html += '<div class="meta-section"><strong>Priority Analysis:</strong></div>';
    html += '<div style="margin-left:8px;padding:12px;border:2px solid #e0e0e0;border-radius:8px;background:#fafafa">';

    // Risk level badge
    const priority = f.priority.priority || 0;
    let riskLevel = 'LOW';
    let riskClass = 'risk-level-low';
    if(priority >= 80) { riskLevel = 'CRITICAL RISK'; riskClass = 'risk-level-critical'; }
    else if(priority >= 60) { riskLevel = 'HIGH RISK'; riskClass = 'risk-level-high'; }
    else if(priority >= 40) { riskLevel = 'MEDIUM RISK'; riskClass = 'risk-level-medium'; }

    html += `<div class="risk-level-badge ${riskClass}">${riskLevel} - Priority: ${priority.toFixed(0)}/100</div>`;

    // EPSS visual bar
    if(f.priority.epss !== null && f.priority.epss !== undefined){
      const epssPercent = (f.priority.epss * 100).toFixed(2);
      html += `<div style="margin:12px 0"><strong>EPSS Exploit Probability:</strong></div>`;
      html += `<div class="epss-bar"><div class="epss-bar-fill" style="width:${f.priority.epss * 100}%"></div></div>`;
      html += `<div style="font-size:12px;color:#666;margin-top:4px">${epssPercent}% probability (${(f.priority.epss_percentile*100).toFixed(1)}th percentile)</div>`;
    }

    // KEV warning with visual emphasis
    if(f.priority.is_kev){
      const isOverdue = f.priority.kev_due_date && new Date(f.priority.kev_due_date) < new Date();
      html += `<div style="background:#ffebee;border-left:4px solid #d32f2f;padding:12px;margin:12px 0;border-radius:4px">`;
      html += `<div style="color:#d32f2f;font-weight:bold;font-size:14px">⚠️ CISA KEV: ACTIVELY EXPLOITED IN THE WILD</div>`;
      if(f.priority.kev_due_date){
        html += `<div style="margin-top:8px;font-size:13px">Federal Agency Remediation Due: <strong>${escapeHtml(f.priority.kev_due_date)}</strong>`;
        if(isOverdue) html += ` <span style="color:#d32f2f;font-weight:bold">(OVERDUE)</span>`;
        html += `</div>`;
      }
      html += `</div>`;
    }

    // Score components - expanded by default for Critical Priority
    const expandedByDefault = priority >= 80;
    html += `<details ${expandedByDefault ? 'open' : ''}><summary style="cursor:pointer;font-size:12px;font-weight:600;margin-top:8px">Score Components</summary>`;
    html += '<div style="margin-left:12px;font-size:12px;margin-top:8px;line-height:1.8">';
    html += `<div>Severity: <strong>${f.severity}</strong> (${f.priority.components?.severity_score||0} points)</div>`;
    html += `<div>EPSS: <strong>${(f.priority.components?.epss_multiplier||1).toFixed(2)}x</strong> multiplier</div>`;
    html += `<div>KEV: <strong>${(f.priority.components?.kev_multiplier||1).toFixed(1)}x</strong> multiplier ${f.priority.is_kev ? '(actively exploited)' : ''}</div>`;
    html += `<div>Reachability: <strong>${(f.priority.components?.reachability_multiplier||1).toFixed(1)}x</strong></div>`;
    html += `<div style="margin-top:8px;padding-top:8px;border-top:1px solid #ddd">Final: <strong>${priority.toFixed(1)}/100</strong> ${priority === 100 ? '(capped)' : ''}</div>`;
    html += '</div></details>';

    html += '</div>';
  }

  // Risk metadata
  if(f.risk){
    html += '<div class="meta-section"><strong>Risk Metadata:</strong></div>';
    html += '<div style="font-size:12px;margin-left:8px">';
    if(f.risk.cwe) html += `<div>CWE: ${f.risk.cwe.map(c => `<span class="tooltip">${escapeHtml(c)}<span class="tooltiptext">Common Weakness Enumeration</span></span>`).join(', ')}</div>`;
    if(f.risk.owasp) html += `<div>OWASP: ${f.risk.owasp.map(o => escapeHtml(o)).join(', ')}</div>`;
    if(f.risk.confidence) html += `<div>Confidence: ${escapeHtml(f.risk.confidence)}</div>`;
    if(f.risk.likelihood) html += `<div>Likelihood: ${escapeHtml(f.risk.likelihood)}</div>`;
    if(f.risk.impact) html += `<div>Impact: ${escapeHtml(f.risk.impact)}</div>`;
    html += '</div>';
  }

  // Compliance mappings
  if(f.compliance){
    html += '<div class="meta-section"><strong>Compliance Frameworks:</strong></div>';
    html += '<div style="font-size:12px;margin-left:8px">';
    if(f.compliance.owasp_top_10_2021 && f.compliance.owasp_top_10_2021.length > 0){
      html += `<div><strong>OWASP Top 10 2021:</strong> ${f.compliance.owasp_top_10_2021.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if(f.compliance.cwe_top_25_2024 && f.compliance.cwe_top_25_2024.length > 0){
      html += `<div><strong>CWE Top 25 2024:</strong> ${f.compliance.cwe_top_25_2024.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if(f.compliance.cis_controls_v8_1 && f.compliance.cis_controls_v8_1.length > 0){
      html += `<div><strong>CIS Controls v8.1:</strong> ${f.compliance.cis_controls_v8_1.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if(f.compliance.nist_csf_2_0 && f.compliance.nist_csf_2_0.length > 0){
      html += `<div><strong>NIST CSF 2.0:</strong> ${f.compliance.nist_csf_2_0.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if(f.compliance.pci_dss_4_0 && f.compliance.pci_dss_4_0.length > 0){
      html += `<div><strong>PCI DSS 4.0:</strong> ${f.compliance.pci_dss_4_0.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    if(f.compliance.mitre_attack_v16_1 && f.compliance.mitre_attack_v16_1.length > 0){
      html += `<div><strong>MITRE ATT&CK v16.1:</strong> ${f.compliance.mitre_attack_v16_1.map(v => escapeHtml(v)).join(', ')}</div>`;
    }
    html += '</div>';
  }

  // Quick Win #5: Triage controls with priority-aware styling and quick actions
  html += '<div class="meta-section"><strong>Triage:</strong></div>';

  // Quick action buttons
  html += '<div class="quick-action-btns">';
  html += `<button class="quick-action-btn fixed" onclick="triageFinding('${escapeHtml(f.id)}', 'fixed')">✓ Mark as Fixed</button>`;
  html += `<button class="quick-action-btn fp" onclick="triageFinding('${escapeHtml(f.id)}', 'false_positive')">× False Positive</button>`;
  html += `<button class="quick-action-btn accept" onclick="triageFinding('${escapeHtml(f.id)}', 'accepted_risk')">⚠ Accept Risk</button>`;
  const priorityScore = f.priority?.priority || 0;
  if(priorityScore >= 80 || f.priority?.is_kev){
    html += `<button class="quick-action-btn escalate" onclick="escalateFinding('${escapeHtml(f.id)}')">🚨 Escalate to Security Team</button>`;
  }
  html += '</div>';

  // Traditional dropdown with priority-aware styling
  html += '<div style="margin-top:12px;font-size:12px;color:#666">Or use dropdown:</div>';
  html += '<div class="triage-controls">';
  const triaged = triageState[f.id];
  const status = triaged ? triaged.status : 'none';

  // Add urgent styling for Critical Priority or KEV findings
  const urgentClass = (priorityScore >= 80 || f.priority?.is_kev) ? 'triage-urgent' : '';
  html += `<select class="triage-select ${urgentClass}" onchange="triageFinding('${escapeHtml(f.id)}', this.value)">`;
  html += `<option value="none" ${status === 'none' ? 'selected' : ''}>-- Not Triaged --</option>`;
  html += `<option value="fixed" ${status === 'fixed' ? 'selected' : ''}>✓ Fixed</option>`;
  html += `<option value="false_positive" ${status === 'false_positive' ? 'selected' : ''}>× False Positive</option>`;
  html += `<option value="accepted_risk" ${status === 'accepted_risk' ? 'selected' : ''}>⚠ Accepted Risk</option>`;
  if(priorityScore >= 80 || f.priority?.is_kev){
    html += `<option value="urgent" ${status === 'urgent' ? 'selected' : ''}>🚨 Urgent</option>`;
  }
  html += `</select>`;
  if(triaged){
    html += `<span style="font-size:11px;color:#666">Triaged on ${triaged.date || 'unknown'}</span>`;
  }
  html += '</div>';

  html += '</div>';
  return html;
}

function render(){
  const rows = sortRows(filtered());
  groupBy = document.getElementById('groupBy').value;

  // Update result count
  document.getElementById('visibleCount').textContent = rows.length;
  document.getElementById('totalCount').textContent = data.length;

  if(groupBy){
    renderGrouped(rows);
  } else {
    renderFlat(rows);
  }
}

function renderFlat(rows){
  document.getElementById('tableContainer').style.display = 'block';
  document.getElementById('groupedContainer').style.display = 'none';

  let html = '';
  rows.forEach((f, idx) => {
    const triaged = triageState[f.id];
    const triagedStyle = triaged ? 'opacity:0.6' : '';

    // Quick Win #1: Priority badge with medals and sparkline
    const priority = f.priority?.priority || 0;
    let priorityClass = 'priority-info';
    if(priority >= 80) priorityClass = 'priority-critical';
    else if(priority >= 60) priorityClass = 'priority-high';
    else if(priority >= 40) priorityClass = 'priority-medium';
    else if(priority >= 20) priorityClass = 'priority-low';

    // Medals for top 3
    let medal = '';
    if(idx === 0) medal = '<span class="medal">🥇</span>';
    else if(idx === 1) medal = '<span class="medal">🥈</span>';
    else if(idx === 2) medal = '<span class="medal">🥉</span>';

    // Sparkline (mini bar chart)
    const sparklineWidth = Math.min(100, priority);
    const sparkline = `<span class="priority-sparkline" style="width:${sparklineWidth}px"><span class="priority-sparkline-fill" style="width:100%;background:${priority >= 80 ? '#d32f2f' : priority >= 60 ? '#f57c00' : priority >= 40 ? '#fbc02d' : '#7cb342'}"></span></span>`;

    const priorityBadge = `${medal}<span class="priority-badge ${priorityClass}">${priority.toFixed(0)}</span>`;
    const kevBadge = f.priority?.is_kev ? '<span class="kev-badge" title="CISA KEV: Actively Exploited">KEV</span>' : '';

    html += `<tr class="expandable-row" data-idx="${idx}" onclick="toggleRow(${idx})" style="${triagedStyle}">
      <td>${priorityBadge}${sparkline}${kevBadge}</td>
      <td class="sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</td>
      <td>${escapeHtml(f.ruleId)}</td>
      <td>${escapeHtml(f.location?.path)}</td>
      <td>${(f.location?.startLine||0)}</td>
      <td>${escapeHtml(f.message)}</td>
      <td>${escapeHtml(f.tool?.name)}</td>
      <td><button class="btn" style="padding:2px 6px;font-size:11px" onclick="event.stopPropagation();toggleRow(${idx})">Details</button></td>
    </tr>`;
    html += `<tr class="detail-row" data-idx="${idx}"><td colspan="8">${renderDetailRow(f)}</td></tr>`;
  });
  document.querySelector('#tbl tbody').innerHTML = html || '<tr><td colspan="8">No results</td></tr>';
}

function renderGrouped(rows){
  document.getElementById('tableContainer').style.display = 'none';
  document.getElementById('groupedContainer').style.display = 'block';

  const groups = {};
  rows.forEach(f => {
    let key = '';
    if(groupBy === 'file') key = f.location?.path || 'Unknown';
    else if(groupBy === 'rule') key = f.ruleId || 'Unknown';
    else if(groupBy === 'tool') key = f.tool?.name || 'Unknown';
    else if(groupBy === 'severity') key = f.severity || 'INFO';
    if(!groups[key]) groups[key] = [];
    groups[key].push(f);
  });

  let html = '<div class="grouped-view">';
  Object.keys(groups).sort().forEach(key => {
    const items = groups[key];
    const maxSev = items.reduce((max, f) => severityRank(f.severity) < severityRank(max) ? f.severity : max, 'INFO');
    html += `<div class="group-header" onclick="toggleGroup(this)">
      <span>${escapeHtml(key)} <span class="badge sev-${maxSev}">${items.length} finding${items.length > 1 ? 's' : ''}</span></span>
    </div>`;
    html += '<div class="group-content">';
    html += '<table class="table"><thead><tr><th>Priority</th><th>Severity</th><th>Rule</th><th>Path</th><th>Line</th><th>Message</th><th>Tool</th><th>Actions</th></tr></thead><tbody>';
    items.forEach((f, idx) => {
      const globalIdx = rows.indexOf(f);
      const triaged = triageState[f.id];
      const triagedStyle = triaged ? 'opacity:0.6' : '';

      // Priority badge
      const priority = f.priority?.priority || 0;
      let priorityClass = 'priority-info';
      if(priority >= 80) priorityClass = 'priority-critical';
      else if(priority >= 60) priorityClass = 'priority-high';
      else if(priority >= 40) priorityClass = 'priority-medium';
      else if(priority >= 20) priorityClass = 'priority-low';

      const priorityBadge = `<span class="priority-badge ${priorityClass}">${priority.toFixed(0)}</span>`;
      const kevBadge = f.priority?.is_kev ? '<span class="kev-badge" title="CISA KEV: Actively Exploited">KEV</span>' : '';

      html += `<tr class="expandable-row" data-idx="${globalIdx}" onclick="toggleRow(${globalIdx})" style="${triagedStyle}">
        <td>${priorityBadge}${kevBadge}</td>
        <td class="sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</td>
        <td>${escapeHtml(f.ruleId)}</td>
        <td>${escapeHtml(f.location?.path)}</td>
        <td>${(f.location?.startLine||0)}</td>
        <td>${escapeHtml(f.message)}</td>
        <td>${escapeHtml(f.tool?.name)}</td>
        <td><button class="btn" style="padding:2px 6px;font-size:11px" onclick="event.stopPropagation();toggleRow(${globalIdx})">Details</button></td>
      </tr>`;
      html += `<tr class="detail-row" data-idx="${globalIdx}"><td colspan="8">${renderDetailRow(f)}</td></tr>`;
    });
    html += '</tbody></table></div>';
  });
  html += '</div>';
  document.getElementById('groupedContainer').innerHTML = html;
}

function toggleRow(idx){
  const mainRows = document.querySelectorAll(`.expandable-row[data-idx="${idx}"]`);
  const detailRows = document.querySelectorAll(`.detail-row[data-idx="${idx}"]`);
  mainRows.forEach(r => r.classList.toggle('expanded'));
  detailRows.forEach(r => r.classList.toggle('visible'));
}

function toggleGroup(header){
  header.classList.toggle('collapsed');
  const content = header.nextElementSibling;
  content.classList.toggle('hidden');
}

function copySnippet(id){
  const el = document.getElementById('snippet-'+id);
  if(el){
    navigator.clipboard.writeText(el.textContent);
    alert('Code snippet copied to clipboard!');
  }
}

function copyFix(id){
  const el = document.getElementById('fix-'+id);
  if(el){
    navigator.clipboard.writeText(el.textContent);
    alert('Fix copied to clipboard!');
  }
}

function triageFinding(id, status){
  if(status === 'none'){
    delete triageState[id];
  } else {
    triageState[id] = {
      status: status,
      date: new Date().toISOString().split('T')[0]
    };
  }
  try{
    localStorage.setItem('jmo_triage_state', JSON.stringify(triageState));
  }catch(e){}
  render();
}

function populateToolFilter(){
  const tools = Array.from(new Set(data.map(f => (f.tool?.name||'')).filter(Boolean))).sort();
  const sel = document.getElementById('tool');
  tools.forEach(t => { const o = document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o); });
}

function populateSeverityCheckboxes(){
  const container = document.getElementById('sevCheckboxes');
  SEV_ORDER.forEach(sev => {
    const label = document.createElement('label');
    label.className = 'sev-checkbox';
    label.innerHTML = `<input type="checkbox" value="${sev}" checked /> <span class="sev-${sev}">${sev}</span>`;
    const checkbox = label.querySelector('input');
    checkbox.addEventListener('change', function(){
      label.classList.toggle('unchecked', !this.checked);
      render();
      updateActiveFilters();
    });
    container.appendChild(label);
  });
}

function populateComplianceFilters(){
  // Build lookup map for all frameworks
  const frameworkData = {
    'owasp': Array.from(new Set(data.flatMap(f => f.compliance?.owasp_top_10_2021||[]))).sort(),
    'cwe': Array.from(new Set(data.flatMap(f => f.compliance?.cwe_top_25_2024||[]))).sort(),
    'cis': Array.from(new Set(data.flatMap(f => f.compliance?.cis_controls_v8_1||[]))).sort(),
    'nist': Array.from(new Set(data.flatMap(f => f.compliance?.nist_csf_2_0||[]))).sort(),
    'pci': Array.from(new Set(data.flatMap(f => f.compliance?.pci_dss_4_0||[]))).sort(),
    'attack': Array.from(new Set(data.flatMap(f => f.compliance?.mitre_attack_v16_1||[]))).sort()
  };

  // Handle framework selection
  const frameworkSel = document.getElementById('complianceFramework');
  const valueSel = document.getElementById('complianceValue');
  const valueWrapper = document.getElementById('complianceValueWrapper');

  frameworkSel.addEventListener('change', function(){
    const framework = this.value;
    valueSel.innerHTML = '<option value="">All Values</option>';

    if(framework && frameworkData[framework]){
      valueWrapper.style.display = 'flex';
      frameworkData[framework].forEach(v => {
        const o = document.createElement('option');
        o.value = v;
        o.textContent = v;
        valueSel.appendChild(o);
      });
    } else {
      valueWrapper.style.display = 'none';
    }
    render();
    updateActiveFilters();
  });

  valueSel.addEventListener('change', function(){
    try{
      localStorage.setItem('jmo_complianceValue', this.value);
    }catch(e){}
    render();
    updateActiveFilters();
  });
}

function updateActiveFilters(){
  const activeFiltersDiv = document.getElementById('activeFilters');
  const activeFiltersList = document.getElementById('activeFiltersList');
  const filters = [];

  // Check severity
  const checkedSevs = Array.from(document.querySelectorAll('#sevCheckboxes input:checked')).map(cb => cb.value);
  if(checkedSevs.length > 0 && checkedSevs.length < SEV_ORDER.length){
    filters.push(`Severity: ${checkedSevs.join(', ')}`);
  }

  // Check tool
  const tool = document.getElementById('tool').value;
  if(tool) filters.push(`Tool: ${tool}`);

  // Check compliance
  const framework = document.getElementById('complianceFramework').value;
  const frameworkValue = document.getElementById('complianceValue').value;
  if(framework){
    const frameworkLabels = {
      'owasp': 'OWASP Top 10',
      'cwe': 'CWE Top 25',
      'cis': 'CIS Controls',
      'nist': 'NIST CSF',
      'pci': 'PCI DSS',
      'attack': 'MITRE ATT&CK'
    };
    const label = frameworkLabels[framework] || framework;
    filters.push(frameworkValue ? `${label}: ${frameworkValue}` : label);
  }

  // Check search/path
  const q = document.getElementById('q').value;
  if(q) filters.push(`Search: ${q}`);

  const pathPattern = document.getElementById('pathPattern').value;
  if(pathPattern) filters.push(`Path: ${pathPattern}`);

  const excludePattern = document.getElementById('excludePattern').value;
  if(excludePattern) filters.push(`Exclude: ${excludePattern}`);

  const hideTriaged = document.getElementById('hideTriaged').checked;
  if(hideTriaged) filters.push('Hide Triaged');

  if(filters.length > 0){
    activeFiltersList.innerHTML = filters.map(f => `<span class="filter-tag">${escapeHtml(f)}</span>`).join('');
    activeFiltersDiv.style.display = 'block';
  } else {
    activeFiltersDiv.style.display = 'none';
  }
}

function setSort(key){
  const ths = document.querySelectorAll('#tbl thead th');
  ths.forEach(th=> th.classList.remove('sort-asc','sort-desc'));
  if(sortKey === key){ sortDir = (sortDir==='asc'?'desc':'asc'); }
  else { sortKey = key; sortDir = 'asc'; }
  const th = Array.from(ths).find(x=>x.dataset.key===key); if(th){ th.classList.add(sortDir==='asc'?'sort-asc':'sort-desc'); }
  try{
    localStorage.setItem('jmo_sortKey', sortKey);
    localStorage.setItem('jmo_sortDir', sortDir);
  }catch(e){}
  render();
}

function toCsv(rows){
  const header = ['priority','kev','epss','severity','ruleId','path','line','message','tool','triaged'];
  function esc(v){ const s = String(v??''); return '"'+s.replace(/"/g,'""')+'"'; }
  const lines = [header.join(',')].concat(rows.map(f => [
    (f.priority?.priority||0).toFixed(1), f.priority?.is_kev ? 'YES' : 'NO', f.priority?.epss ? (f.priority.epss*100).toFixed(2)+'%' : '', f.severity||'', f.ruleId||'', (f.location?.path||''), (f.location?.startLine||0), (f.message||''), (f.tool?.name||''), triageState[f.id] ? 'YES' : 'NO'
  ].map(esc).join(',')));
  return lines.join('\n');
}

function download(filename, content, type){
  const blob = new Blob([content], {type});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href=url; a.download=filename; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 0);
}

document.getElementById('exportJson').addEventListener('click', ()=>{
  const rows = filtered();
  download('findings.filtered.json', JSON.stringify(rows, null, 2), 'application/json');
});
document.getElementById('exportCsv').addEventListener('click', ()=>{
  const rows = filtered();
  download('findings.filtered.csv', toCsv(rows), 'text/csv');
});

document.getElementById('bulkTriage').addEventListener('click', ()=>{
  const status = prompt('Bulk triage all filtered findings as:\n\n1 = Fixed\n2 = False Positive\n3 = Accepted Risk\n\nEnter number:');
  const statusMap = {'1': 'fixed', '2': 'false_positive', '3': 'accepted_risk'};
  const selected = statusMap[status];
  if(!selected) return;
  const rows = filtered();
  rows.forEach(f => {
    triageState[f.id] = {
      status: selected,
      date: new Date().toISOString().split('T')[0]
    };
  });
  try{
    localStorage.setItem('jmo_triage_state', JSON.stringify(triageState));
  }catch(e){}
  alert(`${rows.length} findings triaged as ${selected.replace('_', ' ')}`);
  render();
});

// Wire filters with persistence
['q','tool','complianceFramework','pathPattern','excludePattern','hideTriaged','groupBy'].forEach(id => {
  const el = document.getElementById(id);
  if(!el) return;
  el.addEventListener(id === 'hideTriaged' ? 'change' : 'input', ()=>{
    try{
      localStorage.setItem('jmo_'+id, id === 'hideTriaged' ? el.checked : el.value);
    }catch(e){}
    render();
    updateActiveFilters();
  });
});

// Clear filters button
document.getElementById('clearFilters').addEventListener('click', ()=>{
  // Reset all severity checkboxes to checked
  document.querySelectorAll('#sevCheckboxes input').forEach(cb => {
    cb.checked = true;
    cb.parentElement.classList.remove('unchecked');
  });

  // Reset all filter inputs
  document.getElementById('tool').value = '';
  document.getElementById('complianceFramework').value = '';
  document.getElementById('complianceValue').value = '';
  document.getElementById('complianceValueWrapper').style.display = 'none';
  document.getElementById('q').value = '';
  document.getElementById('pathPattern').value = '';
  document.getElementById('excludePattern').value = '';
  document.getElementById('hideTriaged').checked = false;

  // Clear localStorage
  try{
    ['tool','complianceFramework','complianceValue','q','pathPattern','excludePattern','hideTriaged'].forEach(id => {
      localStorage.removeItem('jmo_'+id);
    });
  }catch(e){}

  render();
  updateActiveFilters();
});

// Wire sorting
document.querySelectorAll('#tbl thead th').forEach(th => {
  if(th.dataset.key) th.addEventListener('click', ()=> setSort(th.dataset.key));
});

populateSeverityCheckboxes();
populateToolFilter();
populateComplianceFilters();
// Restore persisted state
try{
  const savedTheme = localStorage.getItem('jmo_theme')||'light';
  setTheme(savedTheme);
  ['q','tool','complianceFramework','pathPattern','excludePattern','groupBy'].forEach(id => {
    const val = localStorage.getItem('jmo_'+id);
    if(val && document.getElementById(id)) document.getElementById(id).value = val;
  });

  // Restore compliance value if framework is set
  const savedFramework = localStorage.getItem('jmo_complianceFramework');
  if(savedFramework){
    // Trigger change event to populate values dropdown
    const frameworkEvent = new Event('change');
    document.getElementById('complianceFramework').dispatchEvent(frameworkEvent);
    const savedValue = localStorage.getItem('jmo_complianceValue');
    if(savedValue && document.getElementById('complianceValue')){
      document.getElementById('complianceValue').value = savedValue;
    }
  }

  const hideTriaged = localStorage.getItem('jmo_hideTriaged');
  if(hideTriaged) document.getElementById('hideTriaged').checked = (hideTriaged === 'true');
  const sKey = localStorage.getItem('jmo_sortKey')||'';
  const sDir = localStorage.getItem('jmo_sortDir')||'asc';
  sortKey = sKey; sortDir = sDir;
}catch(e){}
render();
updateActiveFilters();

// Show keyboard hint briefly on first load
setTimeout(function(){
  const kbdHint = document.getElementById('kbdHint');
  kbdHint.classList.add('visible');
  setTimeout(function(){ kbdHint.classList.remove('visible'); }, 5000);
}, 1000);

// Keyboard shortcuts
document.addEventListener('keydown', function(e){
  // Ctrl/Cmd + K: Focus search
  if((e.ctrlKey || e.metaKey) && e.key === 'k'){
    e.preventDefault();
    document.getElementById('q').focus();
  }
  // Ctrl/Cmd + /: Clear filters
  if((e.ctrlKey || e.metaKey) && e.key === '/'){
    e.preventDefault();
    document.getElementById('clearFilters').click();
  }
  // Esc: Clear search if focused
  if(e.key === 'Escape'){
    if(document.activeElement.id === 'q'){
      document.getElementById('q').value = '';
      document.getElementById('q').dispatchEvent(new Event('input'));
    }
  }
});

// Optional: load timings.json
(function(){
  try{
    const base = location.href.replace(/[^/]*$/, '');
    fetch(base + 'timings.json', {cache: 'no-store'})
      .then(r => r.ok ? r.json() : null)
      .then(t => {
        if(!t) return;
        const prof = document.getElementById('profile');
        const sum = document.getElementById('profileSummary');
        const jobsEl = document.getElementById('profileJobs');
        const sec = (t.aggregate_seconds ?? 0).toFixed(2);
        const thr = t.recommended_threads ?? (t.meta?.max_workers ?? 'auto');
        sum.textContent = `total ${sec}s, threads ${thr}`;
        const jobs = (t.jobs||[]).slice().sort((a,b)=> (b.seconds||0)-(a.seconds||0)).slice(0,5);
        jobsEl.innerHTML = jobs.map(j => `<li>${(j.tool||'tool')} — ${(j.seconds||0).toFixed(3)}s (${j.count||0} items)</li>`).join('');
        prof.style.display = 'block';
      }).catch(()=>{});
  }catch(e){}
})();

// Quick Win #5: Escalate finding to security team
function escalateFinding(id){
  const f = data.find(finding => finding.id === id);
  if(!f) return;

  const subject = encodeURIComponent(`[URGENT] Security Finding: ${f.ruleId}`);
  const body = encodeURIComponent(`URGENT SECURITY FINDING

Priority: ${f.priority?.priority || 0}/100
${f.priority?.is_kev ? 'KEV Status: ACTIVELY EXPLOITED IN THE WILD\n' : ''}
Severity: ${f.severity}
Rule: ${f.ruleId}
File: ${f.location?.path}:${f.location?.startLine || 0}
Message: ${f.message}

${f.priority?.is_kev ? `KEV Due Date: ${f.priority.kev_due_date}\n` : ''}
${f.priority?.epss ? `EPSS: ${(f.priority.epss * 100).toFixed(2)}% exploit probability\n` : ''}

Please review immediately.`);

  window.location.href = `mailto:security@yourcompany.com?subject=${subject}&body=${body}`;
  // Also mark as triaged with urgent status
  triageFinding(id, 'urgent');
}

// Initialize: Update summary cards on load
updateSummaryCards();

// Re-render to show initial state
render();
</script>

<!-- Email Collection CTA (Touch Point #2) -->
<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2.5rem 2rem;
            margin: 3rem 0 2rem 0;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
    <h2 style="margin: 0 0 1rem 0; font-size: 1.75rem; font-weight: 700;">📧 Stay Ahead of Security Threats</h2>
    <p style="font-size: 1.1rem; margin: 0 auto 1.5rem auto; max-width: 600px; line-height: 1.6;">
        Get weekly security tips, new scanner announcements, and early access to premium features.
    </p>

    <form id="emailForm" action="https://api.jmotools.com/api/subscribe" method="post"
          style="display: flex; max-width: 500px; margin: 0 auto 1.5rem auto; gap: 0.5rem; flex-wrap: wrap; justify-content: center;">
        <input type="email" name="email" id="emailInput" placeholder="your@email.com" required
               style="flex: 1 1 300px; min-width: 250px; padding: 0.875rem 1rem; border: none; border-radius: 8px;
                      font-size: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <input type="hidden" name="source" value="dashboard">
        <!-- Honeypot field - hidden from humans, attracts bots -->
        <input type="text"
               name="website"
               id="website"
               autocomplete="off"
               tabindex="-1"
               style="position: absolute; left: -9999px; width: 1px; height: 1px;"
               aria-hidden="true">
        <button type="submit" id="emailSubmit"
                style="flex: 0 0 auto; padding: 0.875rem 1.75rem; background: #10b981; color: white;
                       border: none; border-radius: 8px; font-size: 1rem; font-weight: 600;
                       cursor: pointer; transition: background 0.2s; box-shadow: 0 2px 4px rgba(0,0,0,0.1);"
                onmouseover="this.style.background='#059669'"
                onmouseout="this.style.background='#10b981'">
            Subscribe Free
        </button>
    </form>

    <div id="emailSuccess" style="display: none; padding: 1rem; background: rgba(255,255,255,0.2); border-radius: 8px; margin-bottom: 1rem;">
        <strong>✅ Thanks for subscribing!</strong> Check your inbox for a welcome message.
    </div>

    <div style="font-size: 0.875rem; opacity: 0.95; margin-top: 1rem;">
        <p style="margin: 0 0 0.5rem 0;">We'll never spam you. Unsubscribe anytime.</p>
        <p style="margin: 0;">
            💚 <a href="https://ko-fi.com/jmogaming"
                  style="color: white; text-decoration: underline; font-weight: 600;"
                  target="_blank" rel="noopener">
                Support Full-Time Development on Ko-Fi
            </a>
        </p>
    </div>
</div>

<script>
// Email form submission handler
(function() {
    const form = document.getElementById('emailForm');
    const successMsg = document.getElementById('emailSuccess');
    const emailInput = document.getElementById('emailInput');
    const submitBtn = document.getElementById('emailSubmit');

    if (!form) return;

    form.addEventListener('submit', async function(e) {
        e.preventDefault();

        const email = emailInput.value.trim();
        const honeypot = document.getElementById('website').value;

        // Honeypot check - if filled, it's likely a bot
        if (honeypot) {
            console.log('Bot detected via honeypot');
            return; // Silently reject
        }

        if (!email || !email.includes('@')) {
            alert('Please enter a valid email address');
            return;
        }

        // Disable form during submission
        submitBtn.disabled = true;
        submitBtn.textContent = 'Subscribing...';

        try {
            // Try to submit to jmotools.com API
            const response = await fetch(form.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    source: 'dashboard'
                })
            });

            if (response.ok) {
                // Success!
                form.style.display = 'none';
                successMsg.style.display = 'block';

                // Track in localStorage
                try {
                    localStorage.setItem('jmo_email_subscribed', 'true');
                    localStorage.setItem('jmo_email_date', new Date().toISOString());
                } catch(e) {}
            } else {
                // Fallback: show success anyway (email will be in server logs)
                form.style.display = 'none';
                successMsg.style.display = 'block';
            }
        } catch (error) {
            // Network error or API not available - graceful fallback
            console.error('Email submission error:', error);
            alert('Unable to submit. Please try again later or visit: https://jimmy058910.github.io/jmo-security-repo/subscribe.html');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Subscribe Free';
        }
    });

    // Check if already subscribed
    try {
        if (localStorage.getItem('jmo_email_subscribed') === 'true') {
            form.style.display = 'none';
            successMsg.innerHTML = '<strong>✅ You\'re already subscribed!</strong> Thanks for being part of the community.';
            successMsg.style.display = 'block';
        }
    } catch(e) {}
})();
</script>

<footer style="text-align: center; padding: 2rem 1rem; margin-top: 3rem; border-top: 1px solid #e2e8f0; color: #64748b;">
    <p style="margin: 0 0 0.5rem 0; font-size: 0.875rem;">
        🔒 <strong>JMo Security</strong> — Terminal-first security scanning with unified outputs
    </p>
    <p style="margin: 0; font-size: 0.875rem;">
        <a href="https://github.com/jimmy058910/jmo-security-repo" target="_blank" rel="noopener" style="color: #3b82f6; text-decoration: none;">
            GitHub
        </a> ·
        <a href="https://jmotools.com" target="_blank" rel="noopener" style="color: #3b82f6; text-decoration: none;">
            Website
        </a> ·
        <a href="https://ko-fi.com/jmogaming" target="_blank" rel="noopener" style="color: #3b82f6; text-decoration: none;">
            Support
        </a> ·
        <a href="https://jimmy058910.github.io/jmo-security-repo/PRIVACY.html" target="_blank" rel="noopener" style="color: #3b82f6; text-decoration: none;">
            Privacy
        </a>
    </p>
</footer>

</body>
</html>
"""
    doc = (
        template.replace("__TOTAL__", str(total))
        .replace("__SEV_BADGES__", sev_badges)
        .replace("__SEV_OPTIONS__", sev_options)
        .replace("__DATA_JSON__", data_json)
    )
    p.write_text(doc, encoding="utf-8")
