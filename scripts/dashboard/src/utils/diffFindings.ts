import { CommonFinding, DiffResult } from '../types/findings'

/**
 * Compare two sets of findings to compute diff
 *
 * Algorithm: O(n) set-based diff using fingerprint IDs
 * - New findings: In current but not in baseline
 * - Fixed findings: In baseline but not in current
 * - Modified findings: Same ID but different severity/message
 * - Unchanged findings: Same ID and content
 */
export function computeDiff(
  baselineFindings: CommonFinding[],
  currentFindings: CommonFinding[],
  baselineScanId?: string,
  currentScanId?: string
): DiffResult {
  // Build maps by fingerprint ID for O(1) lookup
  const baselineMap = new Map<string, CommonFinding>()
  baselineFindings.forEach(f => baselineMap.set(f.id, f))

  const currentMap = new Map<string, CommonFinding>()
  currentFindings.forEach(f => currentMap.set(f.id, f))

  const newFindings: CommonFinding[] = []
  const modifiedFindings: Array<{
    finding: CommonFinding
    changes: {
      severity?: { old: string; new: string }
      message?: { old: string; new: string }
    }
  }> = []
  const unchangedFindings: CommonFinding[] = []

  // Iterate through current findings
  currentFindings.forEach(current => {
    const baseline = baselineMap.get(current.id)

    if (!baseline) {
      // New finding
      newFindings.push(current)
    } else {
      // Check for modifications
      const changes: {
        severity?: { old: string; new: string }
        message?: { old: string; new: string }
      } = {}

      if (baseline.severity !== current.severity) {
        changes.severity = { old: baseline.severity, new: current.severity }
      }

      if (baseline.message !== current.message) {
        changes.message = { old: baseline.message, new: current.message }
      }

      if (Object.keys(changes).length > 0) {
        // Modified finding
        modifiedFindings.push({ finding: current, changes })
      } else {
        // Unchanged finding
        unchangedFindings.push(current)
      }
    }
  })

  // Fixed findings: in baseline but not in current
  const fixedFindings: CommonFinding[] = []
  baselineFindings.forEach(baseline => {
    if (!currentMap.has(baseline.id)) {
      fixedFindings.push(baseline)
    }
  })

  return {
    baseline_scan_id: baselineScanId,
    current_scan_id: currentScanId,
    baseline_count: baselineFindings.length,
    current_count: currentFindings.length,
    new_findings: newFindings,
    fixed_findings: fixedFindings,
    modified_findings: modifiedFindings,
    unchanged_findings: unchangedFindings,
  }
}

/**
 * Filter diff by category
 */
export function filterDiffByCategory(
  diff: DiffResult,
  categories: ('new' | 'fixed' | 'modified' | 'unchanged')[]
): CommonFinding[] {
  const results: CommonFinding[] = []

  if (categories.includes('new')) {
    results.push(...diff.new_findings)
  }

  if (categories.includes('fixed')) {
    results.push(...diff.fixed_findings)
  }

  if (categories.includes('modified')) {
    results.push(...diff.modified_findings.map(m => m.finding))
  }

  if (categories.includes('unchanged')) {
    results.push(...diff.unchanged_findings)
  }

  return results
}
