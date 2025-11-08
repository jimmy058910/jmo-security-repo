import { CommonFinding } from '../types/findings'

/**
 * Export findings to JSON or CSV format
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
 * Escape CSV field (handle quotes, commas, newlines)
 */
function escapeCSV(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`
  }
  return value
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
