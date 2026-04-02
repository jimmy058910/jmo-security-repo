import { generateJSON, generateCSV } from '../../src/utils/exportFindings'
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

describe('exportFindings', () => {
  describe('generateJSON', () => {
    it('should generate findings as formatted JSON', () => {
      const findings: CommonFinding[] = [
        createFinding({ ruleId: 'RULE-001', severity: 'HIGH' }),
        createFinding({ ruleId: 'RULE-002', severity: 'MEDIUM' }),
      ]

      const json = generateJSON(findings)

      expect(json).toContain('"ruleId": "RULE-001"')
      expect(json).toContain('"severity": "HIGH"')
      expect(json).toContain('"ruleId": "RULE-002"')
      // Should be pretty-printed with 2-space indentation
      expect(json).toContain('  ')
    })

    it('should handle empty findings array', () => {
      const json = generateJSON([])

      expect(json).toBe('[]')
    })

    it('should preserve all finding properties', () => {
      const finding = createFinding({
        ruleId: 'RULE-001',
        severity: 'CRITICAL',
        message: 'Security vulnerability',
        title: 'SQL Injection',
        description: 'Potential SQL injection vulnerability',
      })

      const json = generateJSON([finding])
      const parsed = JSON.parse(json)

      expect(parsed[0]).toMatchObject({
        ruleId: 'RULE-001',
        severity: 'CRITICAL',
        message: 'Security vulnerability',
        title: 'SQL Injection',
        description: 'Potential SQL injection vulnerability',
      })
    })

    it('should escape special characters correctly', () => {
      const finding = createFinding({
        message: 'Test with "quotes" and newline\nand tab\t',
      })

      const json = generateJSON([finding])
      const parsed = JSON.parse(json)

      expect(parsed[0].message).toBe('Test with "quotes" and newline\nand tab\t')
    })
  })

  describe('generateCSV', () => {
    it('should generate findings as CSV with headers', () => {
      const findings: CommonFinding[] = [
        createFinding({
          ruleId: 'RULE-001',
          severity: 'HIGH',
          location: { path: 'test.ts', startLine: 10 },
        }),
      ]

      const csv = generateCSV(findings)

      expect(csv).toContain('Rule ID,Severity,Message,File,Line,Tool')
      expect(csv).toContain('RULE-001,HIGH,Test finding,test.ts,10,test-tool')
    })

    it('should escape commas in CSV values', () => {
      const finding = createFinding({
        message: 'Test, with, commas',
        location: { path: 'path/to/file.ts', startLine: 5 },
      })

      const csv = generateCSV([finding])

      expect(csv).toContain('"Test, with, commas"')
    })

    it('should escape quotes in CSV values', () => {
      const finding = createFinding({
        message: 'Test with "quotes"',
      })

      const csv = generateCSV([finding])

      expect(csv).toContain('"Test with ""quotes"""')
    })

    it('should handle newlines in CSV values', () => {
      const finding = createFinding({
        message: 'Line 1\nLine 2',
      })

      const csv = generateCSV([finding])

      // Newlines should be escaped in CSV
      expect(csv).toContain('"Line 1\nLine 2"')
    })

    it('should handle missing line numbers', () => {
      const finding = createFinding({
        location: { path: 'test.ts', startLine: undefined },
      })

      const csv = generateCSV([finding])

      expect(csv).toContain(',test.ts,N/A,')
    })

    it('should handle empty findings array', () => {
      const csv = generateCSV([])

      expect(csv).toBe('Rule ID,Severity,Message,File,Line,Tool')
    })

    it('should generate multiple findings correctly', () => {
      const findings: CommonFinding[] = [
        createFinding({
          ruleId: 'RULE-001',
          severity: 'CRITICAL',
          message: 'Critical issue',
          location: { path: 'file1.ts', startLine: 10 },
          tool: { name: 'tool1', version: '1.0' },
        }),
        createFinding({
          ruleId: 'RULE-002',
          severity: 'LOW',
          message: 'Minor issue',
          location: { path: 'file2.ts', startLine: 20 },
          tool: { name: 'tool2', version: '2.0' },
        }),
      ]

      const csv = generateCSV(findings)

      const lines = csv.split('\n')
      expect(lines).toHaveLength(3) // Header + 2 rows + trailing newline
      expect(lines[1]).toContain('RULE-001,CRITICAL,Critical issue,file1.ts,10,tool1')
      expect(lines[2]).toContain('RULE-002,LOW,Minor issue,file2.ts,20,tool2')
    })

    it('should maintain correct order of findings', () => {
      const findings: CommonFinding[] = Array.from({ length: 10 }, (_, i) =>
        createFinding({ ruleId: `RULE-${i}` })
      )

      const csv = generateCSV(findings)
      const lines = csv.split('\n').slice(1) // Skip header

      lines.forEach((line, i) => {
        if (line.trim()) {
          expect(line).toContain(`RULE-${i}`)
        }
      })
    })

    it('should handle long messages', () => {
      const longMessage = 'A'.repeat(1000)
      const finding = createFinding({ message: longMessage })

      const csv = generateCSV([finding])

      expect(csv).toContain(longMessage)
    })

    it('should escape all special CSV characters', () => {
      const finding = createFinding({
        ruleId: 'RULE-001',
        message: 'Test, with "quotes" and\nnewlines',
      })

      const csv = generateCSV([finding])

      // The message should be properly escaped with quotes
      expect(csv).toContain('"Test, with ""quotes"" and')
      expect(csv).toContain('newlines"')
      // Should contain the escaped quotes (doubled)
      expect(csv).toContain('""quotes""')
    })
  })
})
