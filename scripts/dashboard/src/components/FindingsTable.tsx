import { useState, useMemo, Fragment } from 'react'
import { CommonFinding } from '../types/findings'

interface FindingsTableProps {
  findings: CommonFinding[]
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<string>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())

  // Sorting logic
  const sortedFindings = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      let av, bv

      if (sortKey === 'severity') {
        av = SEVERITY_ORDER.indexOf(a.severity)
        bv = SEVERITY_ORDER.indexOf(b.severity)
      } else if (sortKey === 'priority') {
        av = a.priority?.priority || 0
        bv = b.priority?.priority || 0
      } else if (sortKey === 'ruleId') {
        av = a.ruleId
        bv = b.ruleId
      } else if (sortKey === 'path') {
        av = a.location.path
        bv = b.location.path
      } else {
        av = ''
        bv = ''
      }

      const factor = sortDir === 'asc' ? 1 : -1
      if (av < bv) return -1 * factor
      if (av > bv) return 1 * factor
      return 0
    })
    return sorted
  }, [findings, sortKey, sortDir])

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const toggleRow = (id: string) => {
    const newExpanded = new Set(expandedRows)
    if (newExpanded.has(id)) {
      newExpanded.delete(id)
    } else {
      newExpanded.add(id)
    }
    setExpandedRows(newExpanded)
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: 'text-critical font-bold',
      HIGH: 'text-high font-bold',
      MEDIUM: 'text-medium',
      LOW: 'text-low',
      INFO: 'text-info'
    }
    return colors[severity] || 'text-gray-600'
  }

  if (sortedFindings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        No findings to display
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            <th
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              onClick={() => toggleSort('priority')}
            >
              Priority {sortKey === 'priority' && (sortDir === 'asc' ? '▲' : '▼')}
            </th>
            <th
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              onClick={() => toggleSort('severity')}
            >
              Severity {sortKey === 'severity' && (sortDir === 'asc' ? '▲' : '▼')}
            </th>
            <th
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              onClick={() => toggleSort('ruleId')}
            >
              Rule {sortKey === 'ruleId' && (sortDir === 'asc' ? '▲' : '▼')}
            </th>
            <th
              className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              onClick={() => toggleSort('path')}
            >
              Path {sortKey === 'path' && (sortDir === 'asc' ? '▲' : '▼')}
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Message
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
              Tool
            </th>
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {sortedFindings.map((finding) => (
            <Fragment key={finding.id}>
              <tr
                className="hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                onClick={() => toggleRow(finding.id)}
              >
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary text-white">
                    {finding.priority?.priority.toFixed(0) || '0'}
                  </span>
                  {finding.priority?.is_kev && (
                    <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-bold bg-red-600 text-white">
                      KEV
                    </span>
                  )}
                </td>
                <td className={`px-6 py-4 whitespace-nowrap ${getSeverityColor(finding.severity)}`}>
                  {finding.severity}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                  {finding.ruleId}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {finding.location.path}:{finding.location.startLine || '?'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 max-w-md truncate">
                  {finding.message}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  {finding.tool.name}
                </td>
              </tr>

              {/* Expandable detail row */}
              {expandedRows.has(finding.id) && (
                <tr>
                  <td colSpan={6} className="px-6 py-4 bg-gray-50 dark:bg-gray-700">
                    <div className="space-y-2">
                      <p className="text-sm text-gray-700 dark:text-gray-300">{finding.description || finding.message}</p>

                      {finding.context?.snippet && (
                        <div className="bg-gray-900 text-gray-100 p-4 rounded font-mono text-xs overflow-x-auto">
                          {finding.context.snippet}
                        </div>
                      )}

                      {finding.remediation && (
                        <div className="bg-green-50 border-l-4 border-green-500 p-4">
                          <p className="text-sm font-medium text-green-800">Remediation:</p>
                          <p className="text-sm text-green-700 mt-1">
                            {typeof finding.remediation === 'string'
                              ? finding.remediation
                              : finding.remediation.summary}
                          </p>
                        </div>
                      )}

                      {finding.references && finding.references.length > 0 && (
                        <div className="mt-2">
                          <p className="text-xs font-medium text-gray-700">References:</p>
                          <ul className="list-disc list-inside text-xs text-gray-600">
                            {finding.references.slice(0, 3).map((ref, idx) => (
                              <li key={idx}>{ref}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
