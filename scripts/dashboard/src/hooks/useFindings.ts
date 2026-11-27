import { useState, useEffect } from 'react'
import { CommonFinding } from '../types/findings'

/**
 * Hook to load findings from current scan or historical scan
 *
 * @param scanId - Optional scan ID to load historical findings
 * @returns {findings, loading, error}
 */
export function useFindings(scanId: string | null = null) {
  const [findings, setFindings] = useState<CommonFinding[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const loadFindings = async () => {
      try {
        // If scanId provided, load historical findings
        if (scanId) {
          const response = await fetch(`scans/${scanId}/findings.json`)
          if (!response.ok) {
            throw new Error(`Failed to load scan ${scanId}: HTTP ${response.status}`)
          }

          const json = await response.json()
          if (json.meta && json.findings) {
            setFindings(json.findings)
          } else if (Array.isArray(json)) {
            setFindings(json)
          } else {
            throw new Error('Invalid historical findings format')
          }

          setLoading(false)
          return
        }

        // Current scan, inline mode: write_html marks the page when it embeds
        // the findings. Trust the mark, not the array: a scan with no findings
        // embeds [], the same value external mode leaves in place (#1710).
        const embedded = (window as any).__FINDINGS__

        if ((window as any).__FINDINGS_INLINE__ === true && Array.isArray(embedded)) {
          setFindings(embedded)
          setLoading(false)
          return
        }

        // External mode: fetch dashboard-data.json (separate from metadata-wrapped findings.json)
        const response = await fetch('dashboard-data.json')
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }

        const json = await response.json()

        // Handle v1.0.0 metadata wrapper
        if (json.meta && json.findings) {
          // Wrapped format: { meta: {...}, findings: [...] }
          setFindings(json.findings)
        } else if (Array.isArray(json)) {
          // Legacy format: [finding1, finding2, ...]
          setFindings(json)
        } else {
          throw new Error('Invalid findings.json format')
        }

        setLoading(false)
      } catch (err) {
        console.error('Failed to load findings:', err)
        setError(err instanceof Error ? err.message : 'Unknown error')
        setLoading(false)
      }
    }

    loadFindings()
  }, [scanId]) // Re-run when scanId changes

  return { findings, loading, error }
}
