import { useState, useEffect } from 'react'
import { ScanMetadata } from '../types/findings'

/**
 * Hook to load scan history from embedded data or external JSON
 *
 * Data sources (in priority order):
 * 1. window.__SCAN_HISTORY__ (embedded by Python)
 * 2. scans.json in same directory
 *
 * @returns {scans, loading, error}
 */

interface UseScanHistoryReturn {
  scans: ScanMetadata[]
  loading: boolean
  error: string | null
}

export function useScanHistory(): UseScanHistoryReturn {
  const [scans, setScans] = useState<ScanMetadata[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const loadScans = async () => {
      try {
        // Check if data is embedded (Python injected)
        const embedded = (window as any).__SCAN_HISTORY__

        if (embedded && Array.isArray(embedded) && embedded.length > 0) {
          // Embedded mode: data already loaded
          setScans(embedded)
          setLoading(false)
          return
        }

        // External mode: try to fetch scans.json
        try {
          const response = await fetch('scans.json')
          if (!response.ok) {
            // Not an error - just means no history available
            setScans([])
            setLoading(false)
            return
          }

          const json = await response.json()

          // Handle wrapper format
          if (json.scans && Array.isArray(json.scans)) {
            setScans(json.scans)
          } else if (Array.isArray(json)) {
            setScans(json)
          } else {
            setScans([])
          }

          setLoading(false)
        } catch (fetchError) {
          // No scans.json available - not an error, just no history
          setScans([])
          setLoading(false)
        }
      } catch (err) {
        console.error('Failed to load scan history:', err)
        setError(err instanceof Error ? err.message : 'Unknown error')
        setLoading(false)
      }
    }

    loadScans()
  }, [])

  return { scans, loading, error }
}
