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
    # Self-contained HTML (no external CDN) with client-side filtering, sorting, and export
    data_json = json.dumps(findings)
    sev_badges = ''.join(f'<span class="badge sev-{s}">{s}: {sev_counts.get(s, 0)}</span>' for s in SEV_ORDER)
    sev_options = ''.join(f'<option value="{s}">{s}</option>' for s in SEV_ORDER)
    template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Security Summary</title>
<style>
body{font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px;}
h1,h2{margin: 0 0 12px 0}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;background:#eee;margin-right:6px}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{border:1px solid #ddd;padding:6px;text-align:left;font-size:14px}
.table th{cursor:pointer; user-select:none}
.table th.sort-asc::after{content:' \25B2';}
.table th.sort-desc::after{content:' \25BC';}
.filters label{margin-right:12px}
.sev-CRITICAL{color:#b30000;font-weight:bold}
.sev-HIGH{color:#b35900;font-weight:bold}
.sev-MEDIUM{color:#996633}
.sev-LOW{color:#666}
.sev-INFO{color:#777}
.actions{margin-top:12px}
.btn{display:inline-block;margin-right:8px;padding:6px 10px;border:1px solid #ccc;border-radius:6px;background:#f7f7f7;cursor:pointer}
.btn:hover{background:#efefef}
.theme-toggle{margin-left:12px}
</style>
</head>
<body>
<h1>Security Summary <button class="btn theme-toggle" id="themeToggle">Toggle Theme</button></h1>
<div>
  <span class="badge">Total: __TOTAL__</span>
  __SEV_BADGES__
  </div>
<div class="filters" style="margin-top:12px">
  <label>Filter severity:
    <select id="sev">
      <option value="">All</option>
      __SEV_OPTIONS__
    </select>
  </label>
  <label>Filter tool:
    <select id="tool">
      <option value="">All</option>
    </select>
  </label>
  <label>Search: <input id="q" placeholder="rule/message/path"/></label>
</div>
<div class="actions">
  <button class="btn" id="exportJson">Export JSON</button>
  <button class="btn" id="exportCsv">Export CSV</button>
  <small style="margin-left:8px;color:#666">Exports apply to filtered rows</small>
  </div>
<div id="profile" style="display:none; margin-top:8px; padding:8px; border:1px dashed #ccc; border-radius:6px;">
  <strong>Run Profile</strong> — <span id="profileSummary"></span>
  <details style="margin-top:6px"><summary>Top jobs</summary>
    <ul id="profileJobs" style="margin:6px 0 0 16px"></ul>
  </details>
  <small style="color:#666">Tip: run with profiling enabled to populate (jmo report --profile)</small>
  </div>
<table class="table" id="tbl">
  <thead><tr>
    <th data-key="severity">Severity</th>
    <th data-key="ruleId">Rule</th>
    <th data-key="path">Path</th>
    <th data-key="line">Line</th>
    <th data-key="message">Message</th>
    <th data-key="tool">Tool</th>
  </tr></thead>
  <tbody></tbody>
</table>
<script>
const data = __DATA_JSON__;
let sortKey = '';
let sortDir = 'asc';
const SEV_ORDER = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];

// Theme handling
function setTheme(theme){
  const dark = (theme === 'dark');
  document.body.style.background = dark ? '#111' : '#fff';
  document.body.style.color = dark ? '#eee' : '#000';
}
document.getElementById('themeToggle').addEventListener('click', ()=>{
  const t = localStorage.getItem('jmo_theme') === 'dark' ? 'light' : 'dark';
  localStorage.setItem('jmo_theme', t);
  setTheme(t);
});

function severityRank(s){
  const i = SEV_ORDER.indexOf(s||'');
  return i === -1 ? SEV_ORDER.length : i;
}

function filtered(){
  const sev = document.getElementById('sev').value;
  const tool = document.getElementById('tool').value;
  const q = document.getElementById('q').value.toLowerCase();
  return data.filter(f => (
    (!sev || f.severity === sev) &&
    (!tool || (f.tool?.name||'') === tool) &&
    (!q || (f.ruleId||'').toLowerCase().includes(q) || (f.message||'').toLowerCase().includes(q) || (f.location?.path||'').toLowerCase().includes(q))
  ));
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

function render(){
  const rows = sortRows(filtered());
  const html = rows.map(f => `
    <tr>
      <td class="sev-${'${'}f.severity${'}'}">${'${'}f.severity${'}'}</td>
      <td>${'${'}(f.ruleId||'')${'}'}</td>
      <td>${'${'}(f.location?.path||'')${'}'}</td>
      <td>${'${'}(f.location?.startLine||0)${'}'}</td>
      <td>${'${'}(f.message||'').replace(/</g,'&lt;')${'}'}</td>
      <td>${'${'}(f.tool?.name||'')${'}'}</td>
    </tr>`).join('');
  document.querySelector('#tbl tbody').innerHTML = html || '<tr><td colspan="6">No results</td></tr>';
}

function populateToolFilter(){
  const tools = Array.from(new Set(data.map(f => (f.tool?.name||'')).filter(Boolean))).sort();
  const sel = document.getElementById('tool');
  tools.forEach(t => { const o = document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o); });
}

function setSort(key){
  const ths = document.querySelectorAll('#tbl thead th');
  ths.forEach(th=> th.classList.remove('sort-asc','sort-desc'));
  if(sortKey === key){ sortDir = (sortDir==='asc'?'desc':'asc'); }
  else { sortKey = key; sortDir = 'asc'; }
  const th = Array.from(ths).find(x=>x.dataset.key===key); if(th){ th.classList.add(sortDir==='asc'?'sort-asc':'sort-desc'); }
  // persist
  localStorage.setItem('jmo_sortKey', sortKey);
  localStorage.setItem('jmo_sortDir', sortDir);
  render();
}

function toCsv(rows){
  const header = ['severity','ruleId','path','line','message','tool'];
  function esc(v){ const s = String(v??''); return '"'+s.replace(/"/g,'""')+'"'; }
  const lines = [header.join(',')].concat(rows.map(f => [
    f.severity||'', f.ruleId||'', (f.location?.path||''), (f.location?.startLine||0), (f.message||''), (f.tool?.name||'')
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

// Wire filters with persistence and deep-linking
['sev','q','tool'].forEach(id => document.getElementById(id).addEventListener('input', ()=>{
  const sev = document.getElementById('sev').value;
  const tool = document.getElementById('tool').value;
  const q = document.getElementById('q').value;
  try{
    localStorage.setItem('jmo_sev', sev);
    localStorage.setItem('jmo_tool', tool);
    localStorage.setItem('jmo_q', q);
    const params = new URLSearchParams();
    if(sev) params.set('sev', sev);
    if(tool) params.set('tool', tool);
    if(q) params.set('q', q);
    const hash = params.toString();
    location.hash = hash ? '#' + hash : '';
  }catch(e){}
  render();
}));
// Wire sorting
document.querySelectorAll('#tbl thead th').forEach(th => th.addEventListener('click', ()=> setSort(th.dataset.key)));

populateToolFilter();
// Restore persisted state (filters/sort/theme)
try{
  const savedTheme = localStorage.getItem('jmo_theme')||'light';
  setTheme(savedTheme);
  const params = new URLSearchParams((location.hash||'').replace(/^#/, ''));
  const sevParam = params.get('sev') || localStorage.getItem('jmo_sev') || '';
  const toolParam = params.get('tool') || localStorage.getItem('jmo_tool') || '';
  const qParam = params.get('q') || localStorage.getItem('jmo_q') || '';
  const sKey = localStorage.getItem('jmo_sortKey')||'';
  const sDir = localStorage.getItem('jmo_sortDir')||'asc';
  if(sevParam) document.getElementById('sev').value = sevParam;
  if(toolParam) document.getElementById('tool').value = toolParam;
  if(qParam) document.getElementById('q').value = qParam;
  sortKey = sKey; sortDir = sDir;
}catch(e){}
render();

// Optional: load timings.json if present in same folder and render profile panel
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
  }catch(e){/* ignore */}
})();
</script>
</body>
</html>
"""
    doc = (
        template
        .replace("__TOTAL__", str(total))
        .replace("__SEV_BADGES__", sev_badges)
        .replace("__SEV_OPTIONS__", sev_options)
        .replace("__DATA_JSON__", data_json)
    )
    p.write_text(doc, encoding="utf-8")
