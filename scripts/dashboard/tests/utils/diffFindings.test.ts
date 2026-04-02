import { computeDiff, filterDiffByCategory } from '../../src/utils/diffFindings'
import { CommonFinding } from '../../src/types/findings'

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

describe('diffFindings', () => {
  describe('computeDiff', () => {
    it('should identify new findings', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
      ]
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
        createFinding({ id: 'finding-2', ruleId: 'RULE-002' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.new_findings).toHaveLength(1)
      expect(diff.new_findings[0].id).toBe('finding-2')
      expect(diff.baseline_count).toBe(1)
      expect(diff.current_count).toBe(2)
    })

    it('should identify fixed findings', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
        createFinding({ id: 'finding-2', ruleId: 'RULE-002' }),
      ]
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.fixed_findings).toHaveLength(1)
      expect(diff.fixed_findings[0].id).toBe('finding-2')
    })

    it('should identify modified findings (severity change)', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'HIGH', message: 'Test' }),
      ]
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'CRITICAL', message: 'Test' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.modified_findings).toHaveLength(1)
      expect(diff.modified_findings[0].finding.id).toBe('finding-1')
      expect(diff.modified_findings[0].changes.severity).toEqual({
        old: 'HIGH',
        new: 'CRITICAL',
      })
    })

    it('should identify modified findings (message change)', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'HIGH', message: 'Old message' }),
      ]
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'HIGH', message: 'New message' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.modified_findings).toHaveLength(1)
      expect(diff.modified_findings[0].changes.message).toEqual({
        old: 'Old message',
        new: 'New message',
      })
    })

    it('should identify unchanged findings', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'HIGH', message: 'Test' }),
      ]
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', severity: 'HIGH', message: 'Test' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.unchanged_findings).toHaveLength(1)
      expect(diff.unchanged_findings[0].id).toBe('finding-1')
      expect(diff.new_findings).toHaveLength(0)
      expect(diff.fixed_findings).toHaveLength(0)
      expect(diff.modified_findings).toHaveLength(0)
    })

    it('should handle empty baseline', () => {
      const baseline: CommonFinding[] = []
      const current: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
      ]

      const diff = computeDiff(baseline, current)

      expect(diff.new_findings).toHaveLength(1)
      expect(diff.fixed_findings).toHaveLength(0)
      expect(diff.baseline_count).toBe(0)
      expect(diff.current_count).toBe(1)
    })

    it('should handle empty current scan', () => {
      const baseline: CommonFinding[] = [
        createFinding({ id: 'finding-1', ruleId: 'RULE-001' }),
      ]
      const current: CommonFinding[] = []

      const diff = computeDiff(baseline, current)

      expect(diff.fixed_findings).toHaveLength(1)
      expect(diff.new_findings).toHaveLength(0)
      expect(diff.baseline_count).toBe(1)
      expect(diff.current_count).toBe(0)
    })

    it('should include scan IDs when provided', () => {
      const baseline: CommonFinding[] = []
      const current: CommonFinding[] = []

      const diff = computeDiff(baseline, current, 'scan-baseline', 'scan-current')

      expect(diff.baseline_scan_id).toBe('scan-baseline')
      expect(diff.current_scan_id).toBe('scan-current')
    })

    it('should handle large diffs efficiently', () => {
      // Create 1000 baseline findings
      const baseline: CommonFinding[] = Array.from({ length: 1000 }, (_, i) =>
        createFinding({ id: `finding-${i}`, ruleId: `RULE-${i}` })
      )

      // Create 1000 current findings (500 new, 500 same)
      const current: CommonFinding[] = [
        ...baseline.slice(0, 500),
        ...Array.from({ length: 500 }, (_, i) =>
          createFinding({ id: `finding-new-${i}`, ruleId: `RULE-NEW-${i}` })
        ),
      ]

      const start = performance.now()
      const diff = computeDiff(baseline, current)
      const duration = performance.now() - start

      expect(diff.new_findings).toHaveLength(500)
      expect(diff.fixed_findings).toHaveLength(500)
      expect(diff.unchanged_findings).toHaveLength(500)
      expect(duration).toBeLessThan(100) // Should be O(n) - very fast
    })
  })

  describe('filterDiffByCategory', () => {
    const mockDiff = {
      baseline_count: 3,
      current_count: 4,
      new_findings: [createFinding({ id: 'new-1' })],
      fixed_findings: [createFinding({ id: 'fixed-1' })],
      modified_findings: [
        {
          finding: createFinding({ id: 'modified-1' }),
          changes: { severity: { old: 'HIGH', new: 'CRITICAL' } },
        },
      ],
      unchanged_findings: [createFinding({ id: 'unchanged-1' })],
    }

    it('should filter by new category', () => {
      const results = filterDiffByCategory(mockDiff, ['new'])

      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('new-1')
    })

    it('should filter by fixed category', () => {
      const results = filterDiffByCategory(mockDiff, ['fixed'])

      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('fixed-1')
    })

    it('should filter by modified category', () => {
      const results = filterDiffByCategory(mockDiff, ['modified'])

      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('modified-1')
    })

    it('should filter by unchanged category', () => {
      const results = filterDiffByCategory(mockDiff, ['unchanged'])

      expect(results).toHaveLength(1)
      expect(results[0].id).toBe('unchanged-1')
    })

    it('should filter by multiple categories', () => {
      const results = filterDiffByCategory(mockDiff, ['new', 'fixed'])

      expect(results).toHaveLength(2)
      expect(results.some(f => f.id === 'new-1')).toBe(true)
      expect(results.some(f => f.id === 'fixed-1')).toBe(true)
    })

    it('should return empty array when no categories match', () => {
      const results = filterDiffByCategory(mockDiff, [])

      expect(results).toHaveLength(0)
    })
  })
})
