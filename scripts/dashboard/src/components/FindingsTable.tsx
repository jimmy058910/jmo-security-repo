import { useState, useMemo, Fragment, useRef, useEffect } from 'react'
import * as Tooltip from '@radix-ui/react-tooltip'
import { CommonFinding } from '../types/findings'

interface FindingsTableProps {
  findings: CommonFinding[]
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export default function FindingsTable({ findings }: FindingsTableProps) {
  const [sortKey, setSortKey] = useState<string>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set())
  const [currentPage, setCurrentPage] = useState<number>(1)
  const [pageSize, setPageSize] = useState<number>(25)
  const [showScrollbar, setShowScrollbar] = useState<boolean>(false)

  // Refs for syncing horizontal scroll between table and fixed scrollbar
  const tableContainerRef = useRef<HTMLDivElement>(null)
  const stickyScrollbarRef = useRef<HTMLDivElement>(null)
  const scrollbarContentRef = useRef<HTMLDivElement>(null)

  // Sync scroll positions and update scrollbar width
  useEffect(() => {
    const tableContainer = tableContainerRef.current
    const stickyScrollbar = stickyScrollbarRef.current
    const scrollbarContent = scrollbarContentRef.current
    if (!tableContainer || !stickyScrollbar || !scrollbarContent) return

    // Update scrollbar content width to match table scroll width and check if scrollbar is needed
    const updateScrollbarWidth = () => {
      const scrollWidth = tableContainer.scrollWidth
      const clientWidth = tableContainer.clientWidth
      scrollbarContent.style.width = `${scrollWidth}px`

      // Only show scrollbar if table is wider than container (needs horizontal scrolling)
      setShowScrollbar(scrollWidth > clientWidth)
    }
    updateScrollbarWidth()

    // Use flags to prevent infinite loop
    let isTableScrolling = false
    let isScrollbarScrolling = false

    const handleTableScroll = () => {
      if (isScrollbarScrolling) {
        isScrollbarScrolling = false
        return
      }
      isTableScrolling = true
      stickyScrollbar.scrollLeft = tableContainer.scrollLeft
    }

    const handleStickyScroll = () => {
      if (isTableScrolling) {
        isTableScrolling = false
        return
      }
      isScrollbarScrolling = true
      tableContainer.scrollLeft = stickyScrollbar.scrollLeft
    }

    // Add event listeners
    tableContainer.addEventListener('scroll', handleTableScroll)
    stickyScrollbar.addEventListener('scroll', handleStickyScroll)

    // Also update scrollbar width on window resize
    window.addEventListener('resize', updateScrollbarWidth)

    return () => {
      tableContainer.removeEventListener('scroll', handleTableScroll)
      stickyScrollbar.removeEventListener('scroll', handleStickyScroll)
      window.removeEventListener('resize', updateScrollbarWidth)
    }
  }, [])

  // Pagination Controls Component (rendered both top and bottom)
  const PaginationControls = () => {
    const totalPages = Math.ceil(sortedFindings.length / pageSize)

    return (
      <div className="flex items-center justify-between px-4 py-3 bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-4">
          <div className="text-sm text-gray-700 dark:text-gray-300">
            Showing <span className="font-medium">{(currentPage - 1) * pageSize + 1}</span> to{' '}
            <span className="font-medium">{Math.min(currentPage * pageSize, sortedFindings.length)}</span> of{' '}
            <span className="font-medium">{sortedFindings.length}</span> findings
          </div>
          <div className="flex items-center gap-2">
            <label htmlFor="pageSize" className="text-sm text-gray-700 dark:text-gray-300">
              Per page:
            </label>
            <select
              id="pageSize"
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value))
                setCurrentPage(1) // Reset to first page when changing page size
              }}
              className="rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm py-1 px-2"
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
              <option value="200">200</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setCurrentPage(1)}
            disabled={currentPage === 1}
            className="px-3 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            First
          </button>
          <button
            onClick={() => setCurrentPage(currentPage - 1)}
            disabled={currentPage === 1}
            className="px-3 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <span className="text-sm text-gray-700 dark:text-gray-300">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(currentPage + 1)}
            disabled={currentPage === totalPages}
            className="px-3 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next
          </button>
          <button
            onClick={() => setCurrentPage(totalPages)}
            disabled={currentPage === totalPages}
            className="px-3 py-1 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Last
          </button>
        </div>
      </div>
    )
  }

  // Sorting logic with KEV-first prioritization
  const sortedFindings = useMemo(() => {
    const sorted = [...findings].sort((a, b) => {
      // KEV-FIRST SORTING: Always prioritize KEV findings regardless of other sort criteria
      const aIsKEV = a.priority?.is_kev || false
      const bIsKEV = b.priority?.is_kev || false

      if (aIsKEV && !bIsKEV) return -1  // a is KEV, b is not → a comes first
      if (!aIsKEV && bIsKEV) return 1   // b is KEV, a is not → b comes first

      // Both KEV or both not KEV → apply normal sorting
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

  // Pagination logic
  const paginatedFindings = useMemo(() => {
    const startIndex = (currentPage - 1) * pageSize
    const endIndex = startIndex + pageSize
    return sortedFindings.slice(startIndex, endIndex)
  }, [sortedFindings, currentPage, pageSize])

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      // Default to DESC for priority (higher numbers = more urgent)
      // Default to ASC for other columns
      setSortDir(key === 'priority' ? 'desc' : 'asc')
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
    <Tooltip.Provider delayDuration={300}>
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        {/* TOP PAGINATION CONTROLS */}
        {sortedFindings.length > 0 && <PaginationControls />}

        {/* TABLE - Horizontal scrollable with minimum width (native scrollbar hidden, using custom sticky scrollbar below) */}
        <div ref={tableContainerRef} className="overflow-x-auto hide-scrollbar">
          <table className="w-full divide-y divide-gray-200 dark:divide-gray-700" style={{ minWidth: '1200px' }}>
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
          {paginatedFindings.map((finding) => (
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
                  <Tooltip.Root>
                    <Tooltip.Trigger asChild>
                      <span className="cursor-help truncate max-w-xs block">
                        {finding.ruleId}
                      </span>
                    </Tooltip.Trigger>
                    <Tooltip.Portal>
                      <Tooltip.Content
                        className="bg-gray-900 dark:bg-gray-700 text-white px-3 py-2 rounded text-sm max-w-md shadow-lg z-50"
                        sideOffset={5}
                        side="top"
                      >
                        {finding.description || finding.ruleId}
                        <Tooltip.Arrow className="fill-gray-900 dark:fill-gray-700" />
                      </Tooltip.Content>
                    </Tooltip.Portal>
                  </Tooltip.Root>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                  <Tooltip.Root>
                    <Tooltip.Trigger asChild>
                      <span className="cursor-help truncate max-w-xs block">
                        {finding.location.path}:{finding.location.startLine || '?'}
                      </span>
                    </Tooltip.Trigger>
                    <Tooltip.Portal>
                      <Tooltip.Content
                        className="bg-gray-900 dark:bg-gray-700 text-white px-3 py-2 rounded text-sm max-w-md shadow-lg z-50"
                        sideOffset={5}
                        side="top"
                      >
                        {finding.location.path}:{finding.location.startLine || '?'}
                        <Tooltip.Arrow className="fill-gray-900 dark:fill-gray-700" />
                      </Tooltip.Content>
                    </Tooltip.Portal>
                  </Tooltip.Root>
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-gray-100 min-w-96 max-w-2xl">
                  <Tooltip.Root>
                    <Tooltip.Trigger asChild>
                      <div className="break-words line-clamp-2 cursor-help">
                        {finding.message}
                      </div>
                    </Tooltip.Trigger>
                    <Tooltip.Portal>
                      <Tooltip.Content
                        className="bg-gray-900 dark:bg-gray-700 text-white px-3 py-2 rounded text-sm max-w-md shadow-lg z-50"
                        sideOffset={5}
                        side="top"
                      >
                        {finding.message}
                        <Tooltip.Arrow className="fill-gray-900 dark:fill-gray-700" />
                      </Tooltip.Content>
                    </Tooltip.Portal>
                  </Tooltip.Root>
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

      {/* STICKY HORIZONTAL SCROLLBAR - Above pagination (only shown when table needs horizontal scrolling) */}
      {showScrollbar && (
        <div
          ref={stickyScrollbarRef}
          className="sticky bottom-16 overflow-x-auto bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 z-20 shadow-lg"
          style={{ height: '20px' }}
        >
          <div ref={scrollbarContentRef} style={{ width: '1200px', height: '1px' }}></div>
        </div>
      )}

      {/* BOTTOM PAGINATION CONTROLS - STICKY */}
      {sortedFindings.length > 0 && (
        <div className="sticky bottom-0 border-t border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 z-10 shadow-lg">
          <PaginationControls />
        </div>
      )}
      </div>
    </Tooltip.Provider>
  )
}
