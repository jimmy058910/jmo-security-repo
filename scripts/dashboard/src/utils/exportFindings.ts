import { CommonFinding, FindingsMetadata } from '../types/findings'

/**
 * Export findings to multiple formats: JSON, CSV, Prometheus, Grafana, HTML, ATT&CK Navigator
 */

/**
 * Generate JSON string from findings (testable)
 */
export function generateJSON(findings: CommonFinding[]): string {
  return JSON.stringify(findings, null, 2)
}

/**
 * Generate CSV string from findings (testable)
 */
export function generateCSV(findings: CommonFinding[]): string {
  // CSV header
  const headers = ['Rule ID', 'Severity', 'Message', 'File', 'Line', 'Tool']
  const rows = [headers.join(',')]

  // CSV rows
  findings.forEach(finding => {
    const row = [
      escapeCSV(finding.ruleId),
      finding.severity,
      escapeCSV(finding.message),
      escapeCSV(finding.location.path),
      finding.location.startLine?.toString() || 'N/A',
      finding.tool.name,
    ]
    rows.push(row.join(','))
  })

  return rows.join('\n')
}

/**
 * Generate Prometheus metrics format (testable)
 */
export function generatePrometheus(findings: CommonFinding[], metadata?: FindingsMetadata): string {
  // Count by severity
  const severityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  }

  findings.forEach(finding => {
    severityCounts[finding.severity]++
  })

  // Count by tool
  const toolCounts: Record<string, number> = {}
  findings.forEach(finding => {
    const tool = finding.tool.name
    toolCounts[tool] = (toolCounts[tool] || 0) + 1
  })

  // Count KEV findings
  const kevCount = findings.filter(f => f.priority?.is_kev).length

  // Calculate priority score (0-100 scale)
  const priorityScores = findings
    .filter(f => f.priority?.priority)
    .map(f => f.priority!.priority)
  const avgPriority = priorityScores.length > 0
    ? priorityScores.reduce((sum, p) => sum + p, 0) / priorityScores.length
    : 0

  // Build Prometheus metrics
  const metrics: string[] = []

  // Severity metrics
  metrics.push('# HELP jmo_security_findings Total security findings by severity')
  metrics.push('# TYPE jmo_security_findings gauge')
  metrics.push(`jmo_security_findings{severity="critical"} ${severityCounts.CRITICAL}`)
  metrics.push(`jmo_security_findings{severity="high"} ${severityCounts.HIGH}`)
  metrics.push(`jmo_security_findings{severity="medium"} ${severityCounts.MEDIUM}`)
  metrics.push(`jmo_security_findings{severity="low"} ${severityCounts.LOW}`)
  metrics.push(`jmo_security_findings{severity="info"} ${severityCounts.INFO}`)
  metrics.push('')

  // Tool metrics
  metrics.push('# HELP jmo_tool_findings Findings detected per tool')
  metrics.push('# TYPE jmo_tool_findings gauge')
  Object.entries(toolCounts)
    .sort(([, a], [, b]) => b - a)
    .forEach(([tool, count]) => {
      const safeTool = tool.replace(/-/g, '_').replace(/\./g, '_')
      metrics.push(`jmo_tool_findings{tool="${safeTool}"} ${count}`)
    })
  metrics.push('')

  // KEV metrics
  metrics.push('# HELP jmo_kev_findings Known Exploited Vulnerabilities (CISA KEV)')
  metrics.push('# TYPE jmo_kev_findings gauge')
  metrics.push(`jmo_kev_findings ${kevCount}`)
  metrics.push('')

  // Priority score
  metrics.push('# HELP jmo_priority_score Average priority score (0-100)')
  metrics.push('# TYPE jmo_priority_score gauge')
  metrics.push(`jmo_priority_score ${avgPriority.toFixed(2)}`)
  metrics.push('')

  // Total findings
  metrics.push('# HELP jmo_findings_total Total number of findings')
  metrics.push('# TYPE jmo_findings_total counter')
  metrics.push(`jmo_findings_total ${findings.length}`)
  metrics.push('')

  // Metadata (if provided)
  if (metadata) {
    metrics.push('# HELP jmo_scan_info Scan metadata (version, profile, tools)')
    metrics.push('# TYPE jmo_scan_info gauge')
    const tools = metadata.tools.join(',')
    metrics.push(`jmo_scan_info{version="${metadata.jmo_version}",profile="${metadata.profile}",tools="${tools}"} 1`)
  }

  return metrics.join('\n')
}

/**
 * Generate Grafana dashboard JSON (testable)
 *
 * Note: Grafana dashboards reference Prometheus metrics, not inline data.
 * Parameters are intentionally unused but kept for API consistency.
 */
export function generateGrafana(_findings: CommonFinding[], _metadata?: FindingsMetadata): string {
  const dashboard = {
    dashboard: {
      title: 'JMo Security Findings',
      uid: 'jmo-security-dashboard',
      tags: ['security', 'jmo'],
      timezone: 'utc',
      schemaVersion: 38,
      version: 1,
      refresh: '1m',
      panels: [
        {
          id: 1,
          title: 'Total Findings by Severity',
          type: 'stat',
          gridPos: { h: 8, w: 12, x: 0, y: 0 },
          targets: [
            { expr: 'jmo_security_findings', refId: 'A', legendFormat: '{{severity}}' }
          ],
          options: {
            textMode: 'value_and_name',
            colorMode: 'background',
            graphMode: 'area'
          },
          fieldConfig: {
            defaults: {
              thresholds: {
                mode: 'absolute',
                steps: [
                  { value: 0, color: 'green' },
                  { value: 10, color: 'yellow' },
                  { value: 50, color: 'orange' },
                  { value: 100, color: 'red' }
                ]
              }
            }
          }
        },
        {
          id: 2,
          title: 'Severity Distribution',
          type: 'piechart',
          gridPos: { h: 8, w: 12, x: 12, y: 0 },
          targets: [
            { expr: 'jmo_security_findings', refId: 'A', legendFormat: '{{severity}}' }
          ],
          options: {
            legend: { displayMode: 'table', placement: 'right' },
            pieType: 'pie'
          }
        },
        {
          id: 3,
          title: 'KEV Findings (Actively Exploited)',
          type: 'stat',
          gridPos: { h: 4, w: 6, x: 0, y: 8 },
          targets: [
            { expr: 'jmo_kev_findings', refId: 'A' }
          ],
          options: {
            textMode: 'value_and_name',
            colorMode: 'background'
          },
          fieldConfig: {
            defaults: {
              thresholds: {
                mode: 'absolute',
                steps: [
                  { value: 0, color: 'green' },
                  { value: 1, color: 'red' }
                ]
              }
            }
          }
        },
        {
          id: 4,
          title: 'Average Priority Score',
          type: 'gauge',
          gridPos: { h: 4, w: 6, x: 6, y: 8 },
          targets: [
            { expr: 'jmo_priority_score', refId: 'A' }
          ],
          options: {
            showThresholdLabels: false,
            showThresholdMarkers: true
          },
          fieldConfig: {
            defaults: {
              min: 0,
              max: 100,
              thresholds: {
                mode: 'absolute',
                steps: [
                  { value: 0, color: 'green' },
                  { value: 50, color: 'yellow' },
                  { value: 70, color: 'orange' },
                  { value: 85, color: 'red' }
                ]
              }
            }
          }
        },
        {
          id: 5,
          title: 'Findings by Tool',
          type: 'bargauge',
          gridPos: { h: 8, w: 12, x: 12, y: 8 },
          targets: [
            { expr: 'jmo_tool_findings', refId: 'A', legendFormat: '{{tool}}' }
          ],
          options: {
            orientation: 'horizontal',
            displayMode: 'gradient'
          }
        }
      ]
    },
    overwrite: true
  }

  return JSON.stringify(dashboard, null, 2)
}

/**
 * Generate simple HTML report (no JavaScript, email-compatible)
 */
export function generateHTML(findings: CommonFinding[], metadata?: FindingsMetadata): string {
  // Count by severity
  const severityCounts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
    INFO: findings.filter(f => f.severity === 'INFO').length,
  }

  const total = findings.length
  const timestamp = new Date().toISOString()

  // Build HTML
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Findings Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      padding: 2rem;
      max-width: 1200px;
      margin: 0 auto;
      background: #f9fafb;
      color: #1f2937;
      line-height: 1.6;
    }
    @media (prefers-color-scheme: dark) {
      body { background: #1a202c; color: #e2e8f0; }
      table { border-color: #4a5568; }
      th { background: #2d3748; }
    }
    h1 { margin-bottom: 1rem; font-size: 2rem; }
    h2 { margin: 2rem 0 1rem; font-size: 1.5rem; }
    p { margin: 0.5rem 0; }
    details { margin: 1rem 0; }
    summary {
      cursor: pointer;
      padding: 0.75rem;
      background: #e5e7eb;
      border-radius: 0.375rem;
      font-weight: 600;
      user-select: none;
    }
    summary:hover { background: #d1d5db; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 1rem 0;
      background: white;
    }
    @media (prefers-color-scheme: dark) {
      table { background: #2d3748; }
    }
    th, td {
      border: 1px solid #d1d5db;
      padding: 0.75rem;
      text-align: left;
    }
    th { background: #f3f4f6; font-weight: 600; position: sticky; top: 0; }
    .severity-critical { color: #dc2626; font-weight: bold; }
    .severity-high { color: #ea580c; font-weight: 600; }
    .severity-medium { color: #f59e0b; }
    .severity-low { color: #3b82f6; }
    .severity-info { color: #6b7280; }
    .summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 1.5rem 0; }
    .stat-card {
      background: white;
      padding: 1rem;
      border-radius: 0.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    @media (prefers-color-scheme: dark) {
      .stat-card { background: #2d3748; }
    }
    .stat-label { font-size: 0.875rem; color: #6b7280; }
    .stat-value { font-size: 1.875rem; font-weight: bold; margin-top: 0.25rem; }
    @media print {
      .no-print { display: none; }
      table { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <h1>🛡️ Security Findings Report</h1>
  <p class="no-print">Generated on: ${new Date(timestamp).toLocaleString()}</p>
  ${metadata ? `<p class="no-print">Profile: ${metadata.profile} | Tools: ${metadata.tools.join(', ')}</p>` : ''}

  <div class="summary-stats">
    <div class="stat-card">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value">${total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical</div>
      <div class="stat-value severity-critical">${severityCounts.CRITICAL}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High</div>
      <div class="stat-value severity-high">${severityCounts.HIGH}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium</div>
      <div class="stat-value severity-medium">${severityCounts.MEDIUM}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Low</div>
      <div class="stat-value severity-low">${severityCounts.LOW}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Info</div>
      <div class="stat-value severity-info">${severityCounts.INFO}</div>
    </div>
  </div>

  ${generateSeveritySection('CRITICAL', findings.filter(f => f.severity === 'CRITICAL'))}
  ${generateSeveritySection('HIGH', findings.filter(f => f.severity === 'HIGH'))}
  ${generateSeveritySection('MEDIUM', findings.filter(f => f.severity === 'MEDIUM'))}
  ${generateSeveritySection('LOW', findings.filter(f => f.severity === 'LOW'))}
  ${generateSeveritySection('INFO', findings.filter(f => f.severity === 'INFO'))}

  <p style="margin-top: 3rem; text-align: center; color: #6b7280; font-size: 0.875rem;">
    Generated by JMo Security${metadata ? ` v${metadata.jmo_version}` : ''}
  </p>
</body>
</html>`

  return html
}

/**
 * Helper function to generate severity section in HTML
 */
function generateSeveritySection(severity: string, findings: CommonFinding[]): string {
  if (findings.length === 0) return ''

  const displayLimit = 100 // Limit to 100 findings per severity for email size
  const displayFindings = findings.slice(0, displayLimit)
  const hasMore = findings.length > displayLimit

  const rows = displayFindings.map(f => {
    const ruleId = escapeHTML(f.ruleId)
    const tool = escapeHTML(f.tool.name)
    const message = escapeHTML(f.message.slice(0, 200)) // Truncate long messages
    const path = escapeHTML(f.location.path)
    const line = f.location.startLine || 'N/A'

    return `          <tr class="severity-${severity.toLowerCase()}">
            <td>${ruleId}</td>
            <td>${tool}</td>
            <td>${message}</td>
            <td>${path}</td>
            <td>${line}</td>
          </tr>`
  }).join('\n')

  return `
  <details open>
    <summary><h2 class="severity-${severity.toLowerCase()}">${severity} Findings (${findings.length})</h2></summary>
    <table>
      <thead>
        <tr>
          <th>Rule ID</th>
          <th>Tool</th>
          <th>Message</th>
          <th>File</th>
          <th>Line</th>
        </tr>
      </thead>
      <tbody>
${rows}${hasMore ? `
        <tr>
          <td colspan="5" style="text-align: center; font-style: italic; color: #6b7280;">
            ... and ${findings.length - displayLimit} more ${severity} findings (see full report)
          </td>
        </tr>` : ''}
      </tbody>
    </table>
  </details>`
}

/**
 * Generate MITRE ATT&CK Navigator JSON (testable)
 */
export function generateAttackNavigator(findings: CommonFinding[], metadata?: FindingsMetadata): string {
  // Filter findings with ATT&CK mappings
  const attackFindings = findings.filter(f => f.compliance?.mitreAttack && f.compliance.mitreAttack.length > 0)

  if (attackFindings.length === 0) {
    throw new Error('No findings with MITRE ATT&CK mappings detected')
  }

  // Group by technique
  const techniqueMap = new Map<string, CommonFinding[]>()

  attackFindings.forEach(finding => {
    finding.compliance!.mitreAttack!.forEach(mapping => {
      const techId = mapping.technique
      if (!techniqueMap.has(techId)) {
        techniqueMap.set(techId, [])
      }
      techniqueMap.get(techId)!.push(finding)
    })
  })

  // Build techniques array with scoring
  const techniques = Array.from(techniqueMap.entries()).map(([techniqueID, finds]) => {
    // Score calculation
    const count = finds.length
    const severityWeight = finds.reduce((sum, f) => {
      switch (f.severity) {
        case 'CRITICAL': return sum + 5
        case 'HIGH': return sum + 3
        case 'MEDIUM': return sum + 1
        default: return sum
      }
    }, 0)

    const score = Math.min(100, count + severityWeight)

    // Color based on score
    const color =
      score >= 80 ? '#ff0000' :  // Red (critical)
      score >= 50 ? '#ff6666' :  // Light red (high)
      score >= 20 ? '#ffcc00' :  // Yellow (medium)
      '#99ccff'                   // Blue (low)

    return {
      techniqueID,
      score,
      color,
      comment: `${count} finding${count > 1 ? 's' : ''} detected`,
      enabled: true
    }
  })

  // Build Navigator JSON
  const navigatorLayer = {
    name: 'JMo Security Findings',
    versions: {
      attack: '14',
      navigator: '4.9.4',
      layer: '4.5'
    },
    domain: 'enterprise-attack',
    description: `ATT&CK coverage from ${findings.length} security findings${metadata ? ` (scan ${metadata.scan_id || 'N/A'})` : ''}`,
    techniques
  }

  return JSON.stringify(navigatorLayer, null, 2)
}

/**
 * Export findings as JSON file (triggers download)
 */
export function exportToJSON(findings: CommonFinding[], filename = 'findings.json') {
  const json = generateJSON(findings)
  downloadFile(json, filename, 'application/json')
}

/**
 * Export findings as CSV file (triggers download)
 */
export function exportToCSV(findings: CommonFinding[], filename = 'findings.csv') {
  const csv = generateCSV(findings)
  downloadFile(csv, filename, 'text/csv')
}

/**
 * Export findings as Prometheus metrics file (triggers download)
 */
export function exportToPrometheus(findings: CommonFinding[], metadata?: FindingsMetadata, filename = 'findings.prom') {
  const prom = generatePrometheus(findings, metadata)
  downloadFile(prom, filename, 'text/plain')
}

/**
 * Export findings as Grafana dashboard JSON (triggers download)
 */
export function exportToGrafana(findings: CommonFinding[], metadata?: FindingsMetadata, filename = 'grafana-dashboard.json') {
  const grafana = generateGrafana(findings, metadata)
  downloadFile(grafana, filename, 'application/json')
}

/**
 * Export findings as simple HTML report (triggers download)
 */
export function exportToHTML(findings: CommonFinding[], metadata?: FindingsMetadata, filename = 'findings-simple.html') {
  const html = generateHTML(findings, metadata)
  downloadFile(html, filename, 'text/html')
}

/**
 * Export findings as MITRE ATT&CK Navigator JSON (triggers download)
 */
export function exportToAttackNavigator(findings: CommonFinding[], metadata?: FindingsMetadata, filename = 'attack-navigator.json') {
  try {
    const navigator = generateAttackNavigator(findings, metadata)
    downloadFile(navigator, filename, 'application/json')
  } catch (error) {
    if (error instanceof Error) {
      alert(error.message)
    } else {
      alert('Failed to generate ATT&CK Navigator export')
    }
  }
}

/**
 * Escape CSV field (handle quotes, commas, newlines)
 */
function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
}

/**
 * Escape HTML special characters
 */
function escapeHTML(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

/**
 * Trigger browser download
 */
function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)

  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.style.display = 'none'

  document.body.appendChild(link)
  link.click()

  // Cleanup
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}
