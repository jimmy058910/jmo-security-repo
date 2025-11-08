// CommonFinding schema v1.2.0 (from scripts/core/common_finding.py)

export interface CommonFinding {
  // Required fields
  schemaVersion: string
  id: string // Fingerprint ID
  ruleId: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  tool: {
    name: string
    version: string
  }
  location: {
    path: string
    startLine?: number
    endLine?: number
  }
  message: string

  // Optional fields
  title?: string
  description?: string
  remediation?: string | {
    summary?: string
    fix?: string
    steps?: string[]
  }
  references?: string[]
  tags?: string[]
  cvss?: number
  context?: {
    snippet?: string
    lines?: string[]
  }

  // v1.2.0: Compliance field (6 frameworks)
  compliance?: {
    owaspTop10_2021?: string[]
    cweTop25_2024?: Array<{ rank: number; id: string; category: string }>
    cisControlsV8_1?: Array<{ control: string; ig: string }>
    nistCsf2_0?: Array<{ function: string; category: string; subcategory: string }>
    pciDss4_0?: Array<{ requirement: string; priority: string }>
    mitreAttack?: Array<{ tactic: string; technique: string; subtechnique?: string }>
  }

  // Risk field
  risk?: {
    cwe?: string
    confidence?: number
    likelihood?: string
    impact?: string
  }

  // EPSS field (v0.9.0+)
  epss?: number
  epss_percentile?: number

  // KEV field (v0.9.0+)
  kev?: boolean
  kev_due_date?: string

  // Priority field (v0.9.0+)
  priority?: {
    priority: number // 0-100 score
    is_kev: boolean
    epss: number | null
    epss_percentile: number | null
    kev_due_date: string | null
    components?: {
      severity_score: number
      epss_multiplier: number
      kev_multiplier: number
      reachability_multiplier: number
    }
  }

  // Cross-tool consensus (v1.0.0+)
  detected_by?: Array<{ name: string; version: string }>

  // Raw tool output
  raw?: any
}

// v1.0.0: Metadata wrapper
export interface FindingsMetadata {
  output_version: string
  jmo_version: string
  schema_version: string
  timestamp: string
  scan_id?: string
  profile: string
  tools: string[]
  target_count: number
  finding_count: number
  platform: {
    os: string
    python: string
  }
}

export interface FindingsWrapper {
  meta: FindingsMetadata
  findings: CommonFinding[]
}

// SQLite History Types (v1.0.0)
export interface ScanMetadata {
  scan_id: string
  timestamp: string
  profile: string
  tools: string[]
  target_count: number
  finding_count: number
  git_context?: {
    commit?: string
    branch?: string
    tag?: string
  }
  summary: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
}

export interface ScanHistoryWrapper {
  scans: ScanMetadata[]
}

// Diff Comparison Types (v1.0.0)
export type DiffCategory = 'new' | 'fixed' | 'modified' | 'unchanged'

export interface DiffFinding {
  finding: CommonFinding
  category: DiffCategory
  changes?: {
    severity?: { old: string; new: string }
    message?: { old: string; new: string }
  }
}

export interface DiffResult {
  baseline_scan_id?: string
  current_scan_id?: string
  baseline_count: number
  current_count: number
  new_findings: CommonFinding[]
  fixed_findings: CommonFinding[]
  modified_findings: Array<{
    finding: CommonFinding
    changes: {
      severity?: { old: string; new: string }
      message?: { old: string; new: string }
    }
  }>
  unchanged_findings: CommonFinding[]
}

// Trend Analysis Types (v1.0.0)
export interface TrendDataPoint {
  timestamp: string
  date: string // Formatted date for display
  scan_id: string
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface TopRule {
  rule_id: string
  count: number
  severity: string
  tool: string
}

export interface TrendAnalysis {
  data_points: TrendDataPoint[]
  top_rules: TopRule[]
  trend_direction: 'improving' | 'degrading' | 'stable'
  total_change: number
  critical_change: number
}
