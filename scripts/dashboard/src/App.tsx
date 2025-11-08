import { useState, useMemo, useRef, useCallback, lazy, Suspense } from 'react'
import FindingsTable from './components/FindingsTable'
import FilterPanel from './components/FilterPanel'
import DarkModeToggle from './components/DarkModeToggle'
import KeyboardShortcutsHelp from './components/KeyboardShortcutsHelp'
import ExportButton from './components/ExportButton'
import HistoryPanel from './components/HistoryPanel'
import DiffView from './components/DiffView'
import { useFindings } from './hooks/useFindings'
import { useDarkMode } from './hooks/useDarkMode'
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts'
import { useScanHistory } from './hooks/useScanHistory'
import { useDiffMode } from './hooks/useDiffMode'
import { GitCompare, Table, TrendingUp, Shield } from 'lucide-react'
import { CommonFinding } from './types/findings'

// Lazy load Recharts-dependent components (Phase 5.1)
const TrendsPanel = lazy(() => import('./components/TrendsPanel'))
const ComplianceRadar = lazy(() => import('./components/ComplianceRadar'))

export default function App() {
  const [isDark, toggleDark] = useDarkMode()
  const searchInputRef = useRef<HTMLInputElement>(null)

  // History navigation
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)
  const [baselineScanId, setBaselineScanId] = useState<string | null>(null)
  const { scans } = useScanHistory()
  const { findings, loading, error } = useFindings(selectedScanId)

  // Load baseline findings for diff mode
  const { findings: baselineFindings } = useFindings(baselineScanId)

  // Diff mode
  const { isDiffMode, diff, enableDiffMode, disableDiffMode } = useDiffMode(
    findings,
    baselineFindings,
    selectedScanId || 'current',
    baselineScanId || undefined
  )

  // View mode (findings, trends, compliance)
  type ViewMode = 'findings' | 'trends' | 'compliance'
  const [viewMode, setViewMode] = useState<ViewMode>('findings')

  // Load all findings for trends (Map of scan_id -> findings)
  const allFindingsMap = useMemo(() => {
    const map = new Map<string, CommonFinding[]>()
    // Add current findings
    if (findings.length > 0) {
      map.set(selectedScanId || 'current', findings)
    }
    return map
  }, [findings, selectedScanId])

  const [severities, setSeverities] = useState<Set<string>>(
    new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
  )
  const [selectedTool, setSelectedTool] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState<string>('')

  // Memoized callbacks (Phase 5.3)
  const handleSearchFocus = useCallback(() => {
    searchInputRef.current?.focus()
  }, [])

  const handleClearFilters = useCallback(() => {
    setSeverities(new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']))
    setSelectedTool('')
    setSearchQuery('')
  }, [])

  const toggleSeverity = useCallback((sev: string) => {
    setSeverities(prev => {
      const newSeverities = new Set(prev)
      if (newSeverities.has(sev)) {
        newSeverities.delete(sev)
      } else {
        newSeverities.add(sev)
      }
      return newSeverities
    })
  }, [])

  // Keyboard shortcuts
  useKeyboardShortcuts({
    onSearchFocus: handleSearchFocus,
    onClearFilters: handleClearFilters,
  })

  // Get unique tools
  const tools = useMemo(() => {
    const toolSet = new Set(findings.map(f => f.tool.name))
    return Array.from(toolSet).sort()
  }, [findings])

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings.filter(f => {
      // Severity filter
      if (!severities.has(f.severity)) return false

      // Tool filter
      if (selectedTool && f.tool.name !== selectedTool) return false

      // Search filter
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        const matches =
          f.ruleId.toLowerCase().includes(q) ||
          f.message.toLowerCase().includes(q) ||
          f.location.path.toLowerCase().includes(q)
        if (!matches) return false
      }

      return true
    })
  }, [findings, severities, selectedTool, searchQuery])

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading findings...</p>
        </div>
      </div>
    )
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow-lg p-8 max-w-md">
          <h2 className="text-2xl font-bold text-red-600 mb-4">⚠️ Loading Failed</h2>
          <p className="text-gray-700 mb-4">{error}</p>
          <p className="text-gray-500 text-sm">
            Make sure findings.json is in the same directory as this HTML file.
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 transition-colors">
      <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            🛡️ JMo Security Dashboard
          </h1>
          <div className="flex items-center gap-3">
            {/* Diff Mode Toggle (only in findings view) */}
            {viewMode === 'findings' && scans.length > 0 && !isDiffMode && (
              <button
                onClick={() => {
                  if (!baselineScanId) {
                    // Auto-select most recent scan as baseline
                    setBaselineScanId(scans[0].scan_id)
                  }
                  enableDiffMode()
                }}
                className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                aria-label="Enable diff mode"
              >
                <GitCompare className="w-4 h-4 mr-2" />
                Compare Scans
              </button>
            )}

            {isDiffMode && (
              <button
                onClick={disableDiffMode}
                className="inline-flex items-center px-4 py-2 border border-primary rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
                aria-label="Exit diff mode"
              >
                Exit Diff Mode
              </button>
            )}

            <ExportButton findings={filteredFindings} />
            <DarkModeToggle isDark={isDark} onToggle={toggleDark} />
          </div>
        </div>

        {/* View Mode Tabs */}
        <div className="mb-6 border-b border-gray-200 dark:border-gray-700">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => {
                setViewMode('findings')
                if (isDiffMode) disableDiffMode()
              }}
              className={`${
                viewMode === 'findings'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors`}
            >
              <Table className="w-4 h-4" />
              Findings
            </button>

            {scans.length > 0 && (
              <button
                onClick={() => {
                  setViewMode('trends')
                  if (isDiffMode) disableDiffMode()
                }}
                className={`${
                  viewMode === 'trends'
                    ? 'border-primary text-primary'
                    : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors`}
              >
                <TrendingUp className="w-4 h-4" />
                Trends
              </button>
            )}

            <button
              onClick={() => {
                setViewMode('compliance')
                if (isDiffMode) disableDiffMode()
              }}
              className={`${
                viewMode === 'compliance'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              } whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm flex items-center gap-2 transition-colors`}
            >
              <Shield className="w-4 h-4" />
              Compliance
            </button>
          </nav>
        </div>

        {/* Findings View: Sidebar + Table/Diff */}
        {viewMode === 'findings' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            {/* Sidebar: Filters */}
            <div className="lg:col-span-1 space-y-4">
              {/* History Panel */}
              {scans.length > 0 && (
                <HistoryPanel
                  scans={scans}
                  selectedScanId={selectedScanId}
                  onScanSelect={setSelectedScanId}
                  baselineScanId={baselineScanId}
                  onBaselineScanSelect={setBaselineScanId}
                  isDiffMode={isDiffMode}
                />
              )}

              {/* Filter Panel */}
              <FilterPanel
                ref={searchInputRef}
                severities={severities}
                onSeverityChange={toggleSeverity}
                selectedTool={selectedTool}
                onToolChange={setSelectedTool}
                tools={tools}
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
              />

              {/* Count Badge */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 transition-colors">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Showing <span className="font-bold">{filteredFindings.length}</span> of{' '}
                  <span className="font-bold">{findings.length}</span> findings
                </p>
              </div>
            </div>

            {/* Main: Findings Table or Diff View */}
            <div className="lg:col-span-3">
              {isDiffMode && diff ? (
                <DiffView diff={diff} />
              ) : (
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow transition-colors">
                  <FindingsTable findings={filteredFindings} />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Trends View */}
        {viewMode === 'trends' && (
          <Suspense
            fallback={
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
                <div className="flex items-center justify-center h-96">
                  <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
                    <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                      Loading trend analysis...
                    </p>
                  </div>
                </div>
              </div>
            }
          >
            <TrendsPanel scans={scans} allFindings={allFindingsMap} />
          </Suspense>
        )}

        {/* Compliance View */}
        {viewMode === 'compliance' && (
          <Suspense
            fallback={
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6 transition-colors">
                <div className="flex items-center justify-center h-96">
                  <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
                    <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                      Loading compliance radar...
                    </p>
                  </div>
                </div>
              </div>
            }
          >
            <ComplianceRadar findings={findings} />
          </Suspense>
        )}
      </div>

      {/* Keyboard shortcuts help button */}
      <KeyboardShortcutsHelp />
    </div>
  )
}
