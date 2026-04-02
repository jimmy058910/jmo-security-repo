import { useState, useMemo } from 'react'
import { CommonFinding, DiffResult } from '../types/findings'
import { GitCompare, ChevronDown, ChevronRight } from 'lucide-react'

interface DiffViewProps {
  diff: DiffResult
}

type CategoryFilter = 'all' | 'new' | 'fixed' | 'modified'

/**
 * Diff comparison view with color-coded changes
 *
 * Color scheme:
 * - Green: Fixed findings (security improvement)
 * - Red: New findings (regressions)
 * - Yellow: Modified findings (severity/message changes)
 * - Gray: Unchanged findings
 */
export default function DiffView({ diff }: DiffViewProps) {
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all')
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(['new', 'fixed', 'modified'])
  )

  const toggleSection = (section: string) => {
    setExpandedSections(prev => {
      const next = new Set(prev)
      if (next.has(section)) {
        next.delete(section)
      } else {
        next.add(section)
      }
      return next
    })
  }

  // Compute summary statistics
  const summary = useMemo(
    () => ({
      new: diff.new_findings.length,
      fixed: diff.fixed_findings.length,
      modified: diff.modified_findings.length,
      unchanged: diff.unchanged_findings.length,
      total_change: diff.current_count - diff.baseline_count,
    }),
    [diff]
  )

  const renderFindingRow = (
    finding: CommonFinding,
    category: 'new' | 'fixed' | 'modified' | 'unchanged',
    changes?: {
      severity?: { old: string; new: string }
      message?: { old: string; new: string }
    }
  ) => {
    const categoryStyles = {
      new: 'bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500',
      fixed: 'bg-green-50 dark:bg-green-900/20 border-l-4 border-green-500',
      modified: 'bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-yellow-500',
      unchanged: 'bg-gray-50 dark:bg-gray-800 border-l-4 border-gray-300 dark:border-gray-600',
    }

    const severityColors = {
      CRITICAL: 'text-red-700 dark:text-red-400 font-bold',
      HIGH: 'text-orange-600 dark:text-orange-400 font-semibold',
      MEDIUM: 'text-yellow-600 dark:text-yellow-400',
      LOW: 'text-blue-600 dark:text-blue-400',
      INFO: 'text-gray-600 dark:text-gray-400',
    }

    return (
      <div
        key={finding.id}
        className={`p-4 mb-2 rounded ${categoryStyles[category]}`}
      >
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className={`text-sm font-medium ${severityColors[finding.severity]}`}>
                {finding.severity}
              </span>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {finding.ruleId}
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-500">
                {finding.tool.name}
              </span>
            </div>

            {/* Show changes for modified findings */}
            {changes && (
              <div className="mb-2 space-y-1">
                {changes.severity && (
                  <div className="text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Severity: </span>
                    <span className={severityColors[changes.severity.old as keyof typeof severityColors]}>
                      {changes.severity.old}
                    </span>
                    <span className="mx-2">→</span>
                    <span className={severityColors[changes.severity.new as keyof typeof severityColors]}>
                      {changes.severity.new}
                    </span>
                  </div>
                )}
                {changes.message && (
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    Message changed
                  </div>
                )}
              </div>
            )}

            <p className="text-sm text-gray-700 dark:text-gray-300 mb-1">
              {finding.message}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-500">
              {finding.location.path}
              {finding.location.startLine && `:${finding.location.startLine}`}
            </p>
          </div>
        </div>
      </div>
    )
  }

  const renderSection = (
    title: string,
    count: number,
    findings: CommonFinding[] | Array<{ finding: CommonFinding; changes: any }>,
    category: 'new' | 'fixed' | 'modified' | 'unchanged',
    icon: React.ReactNode
  ) => {
    const isExpanded = expandedSections.has(category)
    const isFiltered = categoryFilter !== 'all' && categoryFilter !== category

    if (isFiltered) return null

    return (
      <div className="mb-6">
        <button
          onClick={() => toggleSection(category)}
          className="flex items-center gap-2 w-full text-left mb-3 hover:bg-gray-100 dark:hover:bg-gray-700 p-2 rounded transition-colors"
        >
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          )}
          <span className="flex items-center gap-2">
            {icon}
            <span className="font-semibold text-gray-900 dark:text-white">
              {title}
            </span>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              ({count})
            </span>
          </span>
        </button>

        {isExpanded && (
          <div className="space-y-2">
            {findings.length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400 italic pl-9">
                No {category} findings
              </p>
            ) : (
              findings.map(item =>
                'finding' in item
                  ? renderFindingRow(item.finding, category, item.changes)
                  : renderFindingRow(item as CommonFinding, category)
              )
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Diff Summary Header */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        <div className="flex items-center gap-3 mb-4">
          <GitCompare className="w-6 h-6 text-primary" />
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
            Scan Comparison
          </h2>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Baseline</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {diff.baseline_count}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Current</p>
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {diff.current_count}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Net Change</p>
            <p
              className={`text-2xl font-bold ${
                summary.total_change > 0
                  ? 'text-red-600 dark:text-red-400'
                  : summary.total_change < 0
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-gray-600 dark:text-gray-400'
              }`}
            >
              {summary.total_change > 0 ? '+' : ''}
              {summary.total_change}
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Modified</p>
            <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
              {summary.modified}
            </p>
          </div>
        </div>

        {/* Category Filter */}
        <div className="flex gap-2">
          <button
            onClick={() => setCategoryFilter('all')}
            className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
              categoryFilter === 'all'
                ? 'bg-primary text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setCategoryFilter('new')}
            className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
              categoryFilter === 'new'
                ? 'bg-red-600 text-white'
                : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-900/50'
            }`}
          >
            New ({summary.new})
          </button>
          <button
            onClick={() => setCategoryFilter('fixed')}
            className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
              categoryFilter === 'fixed'
                ? 'bg-green-600 text-white'
                : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 hover:bg-green-200 dark:hover:bg-green-900/50'
            }`}
          >
            Fixed ({summary.fixed})
          </button>
          <button
            onClick={() => setCategoryFilter('modified')}
            className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
              categoryFilter === 'modified'
                ? 'bg-yellow-600 text-white'
                : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 hover:bg-yellow-200 dark:hover:bg-yellow-900/50'
            }`}
          >
            Modified ({summary.modified})
          </button>
        </div>
      </div>

      {/* Diff Sections */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
        {renderSection(
          'New Findings (Regressions)',
          summary.new,
          diff.new_findings,
          'new',
          <span className="text-red-600 dark:text-red-400">▲</span>
        )}

        {renderSection(
          'Fixed Findings (Improvements)',
          summary.fixed,
          diff.fixed_findings,
          'fixed',
          <span className="text-green-600 dark:text-green-400">✓</span>
        )}

        {renderSection(
          'Modified Findings',
          summary.modified,
          diff.modified_findings,
          'modified',
          <span className="text-yellow-600 dark:text-yellow-400">⚠</span>
        )}

        {categoryFilter === 'all' && (
          <p className="text-sm text-gray-500 dark:text-gray-400 italic mt-4">
            {summary.unchanged} unchanged findings (hidden by default)
          </p>
        )}
      </div>
    </div>
  )
}
