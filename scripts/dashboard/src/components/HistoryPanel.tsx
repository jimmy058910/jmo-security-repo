import { History, GitCommit } from 'lucide-react'
import { ScanMetadata } from '../types/findings'

interface HistoryPanelProps {
  scans: ScanMetadata[]
  selectedScanId: string | null
  onScanSelect: (scanId: string | null) => void
  baselineScanId?: string | null
  onBaselineScanSelect?: (scanId: string | null) => void
  isDiffMode?: boolean
}

/**
 * History panel with scan selector dropdown
 *
 * Displays:
 * - Dropdown to select past scans
 * - Current scan metadata (timestamp, profile, git context)
 * - Severity summary for selected scan
 */
export default function HistoryPanel({
  scans,
  selectedScanId,
  onScanSelect,
  baselineScanId,
  onBaselineScanSelect,
  isDiffMode
}: HistoryPanelProps) {
  const selectedScan = scans.find(s => s.scan_id === selectedScanId)
  const currentScan = selectedScanId === null

  // Format timestamp
  const formatTimestamp = (timestamp: string) => {
    try {
      const date = new Date(timestamp)
      return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    } catch {
      return timestamp
    }
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 space-y-3 transition-colors">
      <div className="flex items-center gap-2">
        <History className="w-5 h-5 text-primary" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white">
          Scan History
        </h3>
      </div>

      {/* Scan selector */}
      <div>
        <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
          {isDiffMode ? 'Current Scan' : 'Select Scan'}
        </label>
        <select
          value={selectedScanId || ''}
          onChange={(e) => onScanSelect(e.target.value || null)}
          className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary focus:ring-primary text-sm dark:bg-gray-700 dark:text-white"
        >
          <option value="">Current Scan</option>
          {scans.map((scan) => (
            <option key={scan.scan_id} value={scan.scan_id}>
              {formatTimestamp(scan.timestamp)} - {scan.profile}
              {scan.git_context?.branch && ` (${scan.git_context.branch})`}
            </option>
          ))}
        </select>
      </div>

      {/* Baseline selector (diff mode only) */}
      {isDiffMode && onBaselineScanSelect && (
        <div>
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Baseline Scan
          </label>
          <select
            value={baselineScanId || ''}
            onChange={(e) => onBaselineScanSelect(e.target.value || null)}
            className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary focus:ring-primary text-sm dark:bg-gray-700 dark:text-white"
          >
            <option value="">Select baseline...</option>
            {scans.map((scan) => (
              <option key={scan.scan_id} value={scan.scan_id}>
                {formatTimestamp(scan.timestamp)} - {scan.profile}
                {scan.git_context?.branch && ` (${scan.git_context.branch})`}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Scan metadata */}
      {(currentScan || selectedScan) && (
        <div className="space-y-2 text-xs text-gray-600 dark:text-gray-400">
          {selectedScan && (
            <>
              <div className="flex justify-between">
                <span className="font-medium">Profile:</span>
                <span>{selectedScan.profile}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-medium">Tools:</span>
                <span>{selectedScan.tools.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-medium">Targets:</span>
                <span>{selectedScan.target_count}</span>
              </div>

              {/* Git context */}
              {selectedScan.git_context && (
                <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                  <div className="flex items-center gap-1 mb-1">
                    <GitCommit className="w-3 h-3" />
                    <span className="font-medium">Git Context</span>
                  </div>
                  {selectedScan.git_context.branch && (
                    <div className="pl-4">Branch: {selectedScan.git_context.branch}</div>
                  )}
                  {selectedScan.git_context.commit && (
                    <div className="pl-4">Commit: {selectedScan.git_context.commit.slice(0, 7)}</div>
                  )}
                  {selectedScan.git_context.tag && (
                    <div className="pl-4">Tag: {selectedScan.git_context.tag}</div>
                  )}
                </div>
              )}

              {/* Severity summary */}
              <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                <div className="font-medium mb-1">Summary</div>
                <div className="space-y-0.5 pl-4">
                  <div className="flex justify-between">
                    <span className="text-critical font-bold">Critical:</span>
                    <span>{selectedScan.summary.critical}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-high font-bold">High:</span>
                    <span>{selectedScan.summary.high}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-medium">Medium:</span>
                    <span>{selectedScan.summary.medium}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-low">Low:</span>
                    <span>{selectedScan.summary.low}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-info">Info:</span>
                    <span>{selectedScan.summary.info}</span>
                  </div>
                </div>
              </div>
            </>
          )}

          {currentScan && (
            <div className="text-gray-500 dark:text-gray-400 italic">
              Viewing current scan (not saved to history)
            </div>
          )}
        </div>
      )}

      {scans.length === 0 && (
        <div className="text-xs text-gray-500 dark:text-gray-400 italic">
          No scan history available
        </div>
      )}
    </div>
  )
}
