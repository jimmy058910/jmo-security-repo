import { useState } from 'react'
import { Download } from 'lucide-react'
import { CommonFinding } from '../types/findings'
import {
  exportToJSON,
  exportToCSV,
  exportToPrometheus,
  exportToGrafana,
  exportToHTML,
  exportToAttackNavigator,
} from '../utils/exportFindings'

interface ExportButtonProps {
  findings: CommonFinding[]
}

/**
 * Export button with dropdown menu for JSON/CSV export
 */
export default function ExportButton({ findings }: ExportButtonProps) {
  const [isOpen, setIsOpen] = useState(false)

  const handleExportJSON = () => {
    exportToJSON(findings)
    setIsOpen(false)
  }

  const handleExportCSV = () => {
    exportToCSV(findings)
    setIsOpen(false)
  }

  const handleExportPrometheus = () => {
    exportToPrometheus(findings)
    setIsOpen(false)
  }

  const handleExportGrafana = () => {
    exportToGrafana(findings)
    setIsOpen(false)
  }

  const handleExportHTML = () => {
    exportToHTML(findings)
    setIsOpen(false)
  }

  const handleExportAttackNavigator = () => {
    try {
      exportToAttackNavigator(findings)
      setIsOpen(false)
    } catch (error) {
      alert(
        'No MITRE ATT&CK mappings found in findings. Cannot generate ATT&CK Navigator layer.'
      )
    }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary"
        aria-label="Export findings"
      >
        <Download className="w-4 h-4 mr-2" />
        Export
      </button>

      {isOpen && (
        <>
          {/* Backdrop to close on click outside */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />

          {/* Dropdown menu */}
          <div className="absolute right-0 mt-2 w-56 rounded-md shadow-lg bg-white dark:bg-gray-800 ring-1 ring-black ring-opacity-5 z-20">
            <div className="py-1" role="menu" aria-orientation="vertical">
              <button
                onClick={handleExportJSON}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as JSON
              </button>
              <button
                onClick={handleExportCSV}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as CSV
              </button>
              <button
                onClick={handleExportPrometheus}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as Prometheus
              </button>
              <button
                onClick={handleExportGrafana}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as Grafana Dashboard
              </button>
              <button
                onClick={handleExportHTML}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as Simple HTML
              </button>
              <button
                onClick={handleExportAttackNavigator}
                className="block w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700"
                role="menuitem"
              >
                Export as ATT&amp;CK Navigator
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
