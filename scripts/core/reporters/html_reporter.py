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
        .replace("<script", "<\\script")  # Prevent script injection (catches <script and <Script)
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
.filters{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px;padding:12px;background:#f5f5f5;border-radius:6px}
.filters label{display:flex;align-items:center;gap:6px;font-size:13px}
.filters select,.filters input{padding:4px 8px;border:1px solid #ccc;border-radius:4px;font-size:13px}
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
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>Security Dashboard v2.1 (Compliance-Aware)</h1>
    <div>
      <span class="badge">Total: __TOTAL__</span>
      __SEV_BADGES__
    </div>
  </div>
  <button class="btn theme-toggle" id="themeToggle">Toggle Theme</button>
</div>

<div class="filters">
  <label>Severity:
    <select id="sev" multiple size="1" style="width:120px">
      __SEV_OPTIONS__
    </select>
  </label>
  <label>Tool:
    <select id="tool">
      <option value="">All</option>
    </select>
  </label>
  <label>OWASP Top 10:
    <select id="owaspFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>CWE Top 25:
    <select id="cweFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>CIS Controls:
    <select id="cisFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>NIST CSF:
    <select id="nistFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>PCI DSS:
    <select id="pciFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>MITRE ATT&CK:
    <select id="attackFilter">
      <option value="">All</option>
    </select>
  </label>
  <label>Path Pattern:
    <input id="pathPattern" placeholder="src/, *.py" style="width:120px"/>
  </label>
  <label>Exclude Pattern:
    <input id="excludePattern" placeholder="test/, node_modules" style="width:140px"/>
  </label>
  <label>Search:
    <input id="q" placeholder="rule/message" style="width:150px"/>
  </label>
  <label>
    <input type="checkbox" id="hideTriaged"/> Hide Triaged
  </label>
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

<script>
const data = __DATA_JSON__;
let sortKey = '';
let sortDir = 'asc';
let groupBy = '';
let triageState = {}; // Load from localStorage
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

// Load triage state from localStorage
try{
  const saved = localStorage.getItem('jmo_triage_state');
  if(saved) triageState = JSON.parse(saved);
}catch(e){}

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
  const sevSel = document.getElementById('sev');
  const selectedSevs = Array.from(sevSel.selectedOptions).map(o => o.value);
  if(selectedSevs.length > 0 && !selectedSevs.includes(f.severity)) return false;

  const tool = document.getElementById('tool').value;
  if(tool && (f.tool?.name||'') !== tool) return false;

  const q = document.getElementById('q').value.toLowerCase();
  if(q && !(f.ruleId||'').toLowerCase().includes(q) && !(f.message||'').toLowerCase().includes(q) && !(f.location?.path||'').toLowerCase().includes(q)) return false;

  // Compliance framework filters
  const owaspFilter = document.getElementById('owaspFilter').value;
  if(owaspFilter && !(f.compliance?.owasp_top_10_2021||[]).includes(owaspFilter)) return false;

  const cweFilter = document.getElementById('cweFilter').value;
  if(cweFilter && !(f.compliance?.cwe_top_25_2024||[]).includes(cweFilter)) return false;

  const cisFilter = document.getElementById('cisFilter').value;
  if(cisFilter && !(f.compliance?.cis_controls_v8_1||[]).includes(cisFilter)) return false;

  const nistFilter = document.getElementById('nistFilter').value;
  if(nistFilter && !(f.compliance?.nist_csf_2_0||[]).includes(nistFilter)) return false;

  const pciFilter = document.getElementById('pciFilter').value;
  if(pciFilter && !(f.compliance?.pci_dss_4_0||[]).includes(pciFilter)) return false;

  const attackFilter = document.getElementById('attackFilter').value;
  if(attackFilter && !(f.compliance?.mitre_attack_v16_1||[]).includes(attackFilter)) return false;

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
  if(!sortKey){ return rows; }
  const factor = sortDir === 'asc' ? 1 : -1;
  return rows.slice().sort((a,b)=>{
    let av, bv;
    if(sortKey==='severity') { av = severityRank(a.severity); bv = severityRank(b.severity); }
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

  // Triage controls
  html += '<div class="meta-section"><strong>Triage:</strong></div>';
  html += '<div class="triage-controls">';
  const triaged = triageState[f.id];
  const status = triaged ? triaged.status : 'none';
  html += `<select class="triage-select" onchange="triageFinding('${escapeHtml(f.id)}', this.value)">`;
  html += `<option value="none" ${status === 'none' ? 'selected' : ''}>-- Not Triaged --</option>`;
  html += `<option value="fixed" ${status === 'fixed' ? 'selected' : ''}>Fixed</option>`;
  html += `<option value="false_positive" ${status === 'false_positive' ? 'selected' : ''}>False Positive</option>`;
  html += `<option value="accepted_risk" ${status === 'accepted_risk' ? 'selected' : ''}>Accepted Risk</option>`;
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
    html += `<tr class="expandable-row" data-idx="${idx}" onclick="toggleRow(${idx})" style="${triagedStyle}">
      <td class="sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</td>
      <td>${escapeHtml(f.ruleId)}</td>
      <td>${escapeHtml(f.location?.path)}</td>
      <td>${(f.location?.startLine||0)}</td>
      <td>${escapeHtml(f.message)}</td>
      <td>${escapeHtml(f.tool?.name)}</td>
      <td><button class="btn" style="padding:2px 6px;font-size:11px" onclick="event.stopPropagation();toggleRow(${idx})">Details</button></td>
    </tr>`;
    html += `<tr class="detail-row" data-idx="${idx}"><td colspan="7">${renderDetailRow(f)}</td></tr>`;
  });
  document.querySelector('#tbl tbody').innerHTML = html || '<tr><td colspan="7">No results</td></tr>';
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
    html += '<table class="table"><thead><tr><th>Severity</th><th>Rule</th><th>Path</th><th>Line</th><th>Message</th><th>Tool</th><th>Actions</th></tr></thead><tbody>';
    items.forEach((f, idx) => {
      const globalIdx = rows.indexOf(f);
      const triaged = triageState[f.id];
      const triagedStyle = triaged ? 'opacity:0.6' : '';
      html += `<tr class="expandable-row" data-idx="${globalIdx}" onclick="toggleRow(${globalIdx})" style="${triagedStyle}">
        <td class="sev-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</td>
        <td>${escapeHtml(f.ruleId)}</td>
        <td>${escapeHtml(f.location?.path)}</td>
        <td>${(f.location?.startLine||0)}</td>
        <td>${escapeHtml(f.message)}</td>
        <td>${escapeHtml(f.tool?.name)}</td>
        <td><button class="btn" style="padding:2px 6px;font-size:11px" onclick="event.stopPropagation();toggleRow(${globalIdx})">Details</button></td>
      </tr>`;
      html += `<tr class="detail-row" data-idx="${globalIdx}"><td colspan="7">${renderDetailRow(f)}</td></tr>`;
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

function populateComplianceFilters(){
  // Populate OWASP Top 10
  const owasps = Array.from(new Set(data.flatMap(f => f.compliance?.owasp_top_10_2021||[]))).sort();
  const owaspSel = document.getElementById('owaspFilter');
  owasps.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; owaspSel.appendChild(o); });

  // Populate CWE Top 25
  const cwes = Array.from(new Set(data.flatMap(f => f.compliance?.cwe_top_25_2024||[]))).sort();
  const cweSel = document.getElementById('cweFilter');
  cwes.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; cweSel.appendChild(o); });

  // Populate CIS Controls
  const cis = Array.from(new Set(data.flatMap(f => f.compliance?.cis_controls_v8_1||[]))).sort();
  const cisSel = document.getElementById('cisFilter');
  cis.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; cisSel.appendChild(o); });

  // Populate NIST CSF
  const nist = Array.from(new Set(data.flatMap(f => f.compliance?.nist_csf_2_0||[]))).sort();
  const nistSel = document.getElementById('nistFilter');
  nist.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; nistSel.appendChild(o); });

  // Populate PCI DSS
  const pci = Array.from(new Set(data.flatMap(f => f.compliance?.pci_dss_4_0||[]))).sort();
  const pciSel = document.getElementById('pciFilter');
  pci.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; pciSel.appendChild(o); });

  // Populate MITRE ATT&CK
  const attack = Array.from(new Set(data.flatMap(f => f.compliance?.mitre_attack_v16_1||[]))).sort();
  const attackSel = document.getElementById('attackFilter');
  attack.forEach(v => { const o = document.createElement('option'); o.value=v; o.textContent=v; attackSel.appendChild(o); });
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
  const header = ['severity','ruleId','path','line','message','tool','triaged'];
  function esc(v){ const s = String(v??''); return '"'+s.replace(/"/g,'""')+'"'; }
  const lines = [header.join(',')].concat(rows.map(f => [
    f.severity||'', f.ruleId||'', (f.location?.path||''), (f.location?.startLine||0), (f.message||''), (f.tool?.name||''), triageState[f.id] ? 'YES' : 'NO'
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
['sev','q','tool','owaspFilter','cweFilter','cisFilter','nistFilter','pciFilter','attackFilter','pathPattern','excludePattern','hideTriaged','groupBy'].forEach(id => {
  const el = document.getElementById(id);
  if(!el) return;
  el.addEventListener(id === 'hideTriaged' ? 'change' : 'input', ()=>{
    try{
      localStorage.setItem('jmo_'+id, id === 'hideTriaged' ? el.checked : el.value);
    }catch(e){}
    render();
  });
});

// Wire sorting
document.querySelectorAll('#tbl thead th').forEach(th => {
  if(th.dataset.key) th.addEventListener('click', ()=> setSort(th.dataset.key));
});

populateToolFilter();
populateComplianceFilters();
// Restore persisted state
try{
  const savedTheme = localStorage.getItem('jmo_theme')||'light';
  setTheme(savedTheme);
  ['sev','q','tool','owaspFilter','cweFilter','cisFilter','nistFilter','pciFilter','attackFilter','pathPattern','excludePattern','groupBy'].forEach(id => {
    const val = localStorage.getItem('jmo_'+id);
    if(val) document.getElementById(id).value = val;
  });
  const hideTriaged = localStorage.getItem('jmo_hideTriaged');
  if(hideTriaged) document.getElementById('hideTriaged').checked = (hideTriaged === 'true');
  const sKey = localStorage.getItem('jmo_sortKey')||'';
  const sDir = localStorage.getItem('jmo_sortDir')||'asc';
  sortKey = sKey; sortDir = sDir;
}catch(e){}
render();

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
</script>
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
