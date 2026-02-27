import { computeTrendAnalysis } from '../../src/utils/trendAnalysis'
import { ScanMetadata, CommonFinding } from '../../src/types/findings'

// Helper to create test findings
const createFinding = (overrides: Partial<CommonFinding>): CommonFinding => ({
  schemaVersion: '1.2.0',
  id: `fingerprint-${Math.random()}`,
  ruleId: 'TEST-001',
  severity: 'HIGH',
  message: 'Test finding',
  tool: { name: 'test-tool', version: '1.0.0' },
  location: {
    path: 'test.ts',
    startLine: 1,
    endLine: 1,
    startColumn: 1,
    endColumn: 10,
  },
  ...overrides,
})

// Helper to create scan metadata
const createScan = (overrides: Partial<ScanMetadata>): ScanMetadata => ({
  scan_id: `scan-${Math.random()}`,
  timestamp: new Date().toISOString(),
  finding_count: 10,
  summary: {
    critical: 1,
    high: 2,
    medium: 3,
    low: 3,
    info: 1,
  },
  git: {},
  config: {
    profile: 'balanced',
    tools: ['trivy'],
  },
  ...overrides,
})

describe('trendAnalysis', () => {
  describe('computeTrendAnalysis', () => {
    it('should compute data points from scans', () => {
      const scans: ScanMetadata[] = [
        createScan({
          scan_id: 'scan-1',
          timestamp: '2025-01-01T00:00:00Z',
          finding_count: 10,
          summary: { critical: 1, high: 2, medium: 3, low: 3, info: 1 },
        }),
        createScan({
          scan_id: 'scan-2',
          timestamp: '2025-01-02T00:00:00Z',
          finding_count: 8,
          summary: { critical: 0, high: 1, medium: 3, low: 3, info: 1 },
        }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.data_points).toHaveLength(2)
      expect(analysis.data_points[0]).toMatchObject({
        scan_id: 'scan-1',
        total: 10,
        critical: 1,
        high: 2,
        medium: 3,
        low: 3,
        info: 1,
      })
      expect(analysis.data_points[1]).toMatchObject({
        scan_id: 'scan-2',
        total: 8,
        critical: 0,
        high: 1,
      })
    })

    it('should sort scans by timestamp (oldest first)', () => {
      const scans: ScanMetadata[] = [
        createScan({ scan_id: 'scan-2', timestamp: '2025-01-02T00:00:00Z' }),
        createScan({ scan_id: 'scan-1', timestamp: '2025-01-01T00:00:00Z' }),
        createScan({ scan_id: 'scan-3', timestamp: '2025-01-03T00:00:00Z' }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.data_points[0].scan_id).toBe('scan-1')
      expect(analysis.data_points[1].scan_id).toBe('scan-2')
      expect(analysis.data_points[2].scan_id).toBe('scan-3')
    })

    it('should compute top 10 rules from all findings', () => {
      const scans: ScanMetadata[] = [createScan({ scan_id: 'scan-1' })]

      const allFindings = new Map<string, CommonFinding[]>([
        [
          'scan-1',
          [
            createFinding({ ruleId: 'RULE-001', severity: 'HIGH', tool: { name: 'tool-1', version: '1.0' } }),
            createFinding({ ruleId: 'RULE-001', severity: 'CRITICAL', tool: { name: 'tool-1', version: '1.0' } }), // Upgrade severity
            createFinding({ ruleId: 'RULE-002', severity: 'MEDIUM', tool: { name: 'tool-2', version: '1.0' } }),
          ],
        ],
      ])

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.top_rules).toHaveLength(2)
      expect(analysis.top_rules[0]).toMatchObject({
        rule_id: 'RULE-001',
        count: 2,
        severity: 'CRITICAL', // Highest severity wins
        tool: 'tool-1',
      })
      expect(analysis.top_rules[1]).toMatchObject({
        rule_id: 'RULE-002',
        count: 1,
        severity: 'MEDIUM',
      })
    })

    it('should limit top rules to 10', () => {
      const scans: ScanMetadata[] = [createScan({ scan_id: 'scan-1' })]

      // Create 15 unique rules
      const findings = Array.from({ length: 15 }, (_, i) =>
        createFinding({ ruleId: `RULE-${i.toString().padStart(3, '0')}` })
      )

      const allFindings = new Map<string, CommonFinding[]>([['scan-1', findings]])

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.top_rules).toHaveLength(10)
    })

    it('should detect improving trend', () => {
      const scans: ScanMetadata[] = [
        createScan({ timestamp: '2025-01-01T00:00:00Z', finding_count: 100 }),
        createScan({ timestamp: '2025-01-02T00:00:00Z', finding_count: 80 }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.trend_direction).toBe('improving')
      expect(analysis.total_change).toBe(-20)
    })

    it('should detect degrading trend', () => {
      const scans: ScanMetadata[] = [
        createScan({ timestamp: '2025-01-01T00:00:00Z', finding_count: 50 }),
        createScan({ timestamp: '2025-01-02T00:00:00Z', finding_count: 80 }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.trend_direction).toBe('degrading')
      expect(analysis.total_change).toBe(30)
    })

    it('should detect stable trend', () => {
      const scans: ScanMetadata[] = [
        createScan({ timestamp: '2025-01-01T00:00:00Z', finding_count: 100 }),
        createScan({ timestamp: '2025-01-02T00:00:00Z', finding_count: 105 }), // 5% change - within threshold
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.trend_direction).toBe('stable')
    })

    it('should compute critical change', () => {
      const scans: ScanMetadata[] = [
        createScan({
          timestamp: '2025-01-01T00:00:00Z',
          summary: { critical: 5, high: 10, medium: 20, low: 10, info: 5 },
        }),
        createScan({
          timestamp: '2025-01-02T00:00:00Z',
          summary: { critical: 2, high: 8, medium: 15, low: 8, info: 3 },
        }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.critical_change).toBe(-3)
    })

    it('should format dates correctly', () => {
      const scans: ScanMetadata[] = [
        createScan({ timestamp: '2025-01-15T12:34:56Z' }),
        createScan({ timestamp: '2025-02-20T08:00:00Z' }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.data_points[0].date).toMatch(/Jan\s+\d+/)
      expect(analysis.data_points[1].date).toMatch(/Feb\s+\d+/)
    })

    it('should handle single scan', () => {
      const scans: ScanMetadata[] = [
        createScan({ scan_id: 'scan-1', finding_count: 50 }),
      ]

      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.data_points).toHaveLength(1)
      expect(analysis.total_change).toBe(0)
      expect(analysis.critical_change).toBe(0)
      expect(analysis.trend_direction).toBe('stable')
    })

    it('should handle empty scans', () => {
      const scans: ScanMetadata[] = []
      const allFindings = new Map<string, CommonFinding[]>()

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.data_points).toHaveLength(0)
      expect(analysis.top_rules).toHaveLength(0)
      expect(analysis.total_change).toBe(0)
      expect(analysis.critical_change).toBe(0)
      expect(analysis.trend_direction).toBe('stable')
    })

    it('should aggregate rules across multiple scans', () => {
      const scans: ScanMetadata[] = [
        createScan({ scan_id: 'scan-1' }),
        createScan({ scan_id: 'scan-2' }),
      ]

      const allFindings = new Map<string, CommonFinding[]>([
        ['scan-1', [createFinding({ ruleId: 'RULE-001', tool: { name: 'tool-1', version: '1.0' } })]],
        ['scan-2', [createFinding({ ruleId: 'RULE-001', tool: { name: 'tool-1', version: '1.0' } })]],
      ])

      const analysis = computeTrendAnalysis(scans, allFindings)

      expect(analysis.top_rules[0]).toMatchObject({
        rule_id: 'RULE-001',
        count: 2, // Aggregated across both scans
      })
    })

    it('should perform efficiently with large datasets', () => {
      // Create 100 scans
      const scans: ScanMetadata[] = Array.from({ length: 100 }, (_, i) =>
        createScan({
          scan_id: `scan-${i}`,
          timestamp: new Date(2025, 0, i + 1).toISOString(),
          finding_count: 50 + i,
        })
      )

      // Create 50 findings per scan
      const allFindings = new Map<string, CommonFinding[]>()
      scans.forEach(scan => {
        allFindings.set(
          scan.scan_id,
          Array.from({ length: 50 }, (_, i) =>
            createFinding({ ruleId: `RULE-${i % 20}` }) // 20 unique rules
          )
        )
      })

      const start = performance.now()
      const analysis = computeTrendAnalysis(scans, allFindings)
      const duration = performance.now() - start

      expect(analysis.data_points).toHaveLength(100)
      expect(analysis.top_rules).toHaveLength(10)
      expect(duration).toBeLessThan(500) // Should be fast even with 5000 findings
    })
  })
})
