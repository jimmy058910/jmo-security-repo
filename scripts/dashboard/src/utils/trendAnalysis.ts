import { ScanMetadata, CommonFinding, TrendDataPoint, TopRule, TrendAnalysis } from '../types/findings'

/**
 * Compute trend analysis from scan history
 *
 * Analyzes:
 * - Findings over time (by severity)
 * - Top 10 most frequent rules
 * - Trend direction (improving/degrading/stable)
 */
export function computeTrendAnalysis(
  scans: ScanMetadata[],
  allFindings: Map<string, CommonFinding[]>
): TrendAnalysis {
  // Sort scans by timestamp (oldest first)
  const sortedScans = [...scans].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )

  // Build data points for line chart
  const dataPoints: TrendDataPoint[] = sortedScans.map(scan => ({
    timestamp: scan.timestamp,
    date: formatDate(scan.timestamp),
    scan_id: scan.scan_id,
    total: scan.finding_count,
    critical: scan.summary.critical,
    high: scan.summary.high,
    medium: scan.summary.medium,
    low: scan.summary.low,
    info: scan.summary.info,
  }))

  // Aggregate top rules across all scans
  const ruleFrequency = new Map<string, { count: number; severity: string; tool: string }>()

  allFindings.forEach(findings => {
    findings.forEach(finding => {
      const key = finding.ruleId
      const existing = ruleFrequency.get(key)

      if (existing) {
        existing.count++
        // Upgrade severity if higher
        if (compareSeverity(finding.severity, existing.severity) > 0) {
          existing.severity = finding.severity
        }
      } else {
        ruleFrequency.set(key, {
          count: 1,
          severity: finding.severity,
          tool: finding.tool.name,
        })
      }
    })
  })

  // Top 10 rules
  const topRules: TopRule[] = Array.from(ruleFrequency.entries())
    .map(([rule_id, data]) => ({
      rule_id,
      count: data.count,
      severity: data.severity,
      tool: data.tool,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  // Trend direction
  const trendDirection = computeTrendDirection(dataPoints)

  // Total change (latest - oldest)
  const totalChange =
    dataPoints.length > 1
      ? dataPoints[dataPoints.length - 1].total - dataPoints[0].total
      : 0

  const criticalChange =
    dataPoints.length > 1
      ? dataPoints[dataPoints.length - 1].critical - dataPoints[0].critical
      : 0

  return {
    data_points: dataPoints,
    top_rules: topRules,
    trend_direction: trendDirection,
    total_change: totalChange,
    critical_change: criticalChange,
  }
}

/**
 * Compute trend direction (simple linear regression)
 */
function computeTrendDirection(
  dataPoints: TrendDataPoint[]
): 'improving' | 'degrading' | 'stable' {
  if (dataPoints.length < 2) return 'stable'

  // Simple slope calculation: (last - first) / n
  const first = dataPoints[0].total
  const last = dataPoints[dataPoints.length - 1].total
  const change = last - first

  // Threshold: 10% change
  const threshold = Math.abs(first * 0.1)

  if (change < -threshold) return 'improving' // Fewer findings
  if (change > threshold) return 'degrading' // More findings
  return 'stable'
}

/**
 * Compare severities (returns positive if a > b)
 */
function compareSeverity(a: string, b: string): number {
  const order: Record<string, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
  }
  return (order[a] || 0) - (order[b] || 0)
}

/**
 * Format timestamp for display
 */
function formatDate(timestamp: string): string {
  try {
    const date = new Date(timestamp)
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return timestamp
  }
}
