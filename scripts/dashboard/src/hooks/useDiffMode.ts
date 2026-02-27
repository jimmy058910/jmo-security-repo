import { useState, useMemo } from 'react'
import { CommonFinding, DiffResult } from '../types/findings'
import { computeDiff } from '../utils/diffFindings'

/**
 * Hook to manage diff comparison mode
 *
 * Compares baseline scan against current scan
 * Returns diff result and control functions
 */
export function useDiffMode(
  currentFindings: CommonFinding[],
  baselineFindings: CommonFinding[] | null,
  currentScanId?: string,
  baselineScanId?: string
): {
  isDiffMode: boolean
  diff: DiffResult | null
  enableDiffMode: () => void
  disableDiffMode: () => void
} {
  const [isDiffMode, setIsDiffMode] = useState(false)

  const diff = useMemo(() => {
    if (!isDiffMode || !baselineFindings) {
      return null
    }

    return computeDiff(
      baselineFindings,
      currentFindings,
      baselineScanId,
      currentScanId
    )
  }, [isDiffMode, baselineFindings, currentFindings, baselineScanId, currentScanId])

  const enableDiffMode = () => {
    if (baselineFindings && baselineFindings.length > 0) {
      setIsDiffMode(true)
    }
  }

  const disableDiffMode = () => {
    setIsDiffMode(false)
  }

  return {
    isDiffMode,
    diff,
    enableDiffMode,
    disableDiffMode,
  }
}
