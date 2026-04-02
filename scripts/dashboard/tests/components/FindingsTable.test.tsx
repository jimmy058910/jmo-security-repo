import { render, screen, fireEvent, within } from '@testing-library/react'
import FindingsTable from '../../src/components/FindingsTable'
import { CommonFinding } from '../../src/types/findings'

// Helper to create test findings
const createFinding = (overrides: Partial<CommonFinding>): CommonFinding => ({
  schemaVersion: '1.2.0',
  id: `fingerprint-${Math.random()}`,
  ruleId: 'TEST-001',
  severity: 'HIGH',
  message: 'Test finding message',
  tool: { name: 'test-tool', version: '1.0.0' },
  location: {
    path: 'src/test.ts',
    startLine: 10,
    endLine: 10,
    startColumn: 1,
    endColumn: 20,
  },
  ...overrides,
})

describe('FindingsTable', () => {
  describe('Rendering', () => {
    it('should render empty state when no findings', () => {
      render(<FindingsTable findings={[]} />)

      expect(screen.getByText('No findings to display')).toBeInTheDocument()
    })

    it('should render table headers', () => {
      const findings = [createFinding({})]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText(/Priority/)).toBeInTheDocument()
      expect(screen.getByText(/Severity/)).toBeInTheDocument()
      expect(screen.getByText(/Rule/)).toBeInTheDocument()
      expect(screen.getByText(/Path/)).toBeInTheDocument()
      expect(screen.getByText(/Message/)).toBeInTheDocument()
      expect(screen.getByText(/Tool/)).toBeInTheDocument()
    })

    it('should render finding rows', () => {
      const findings = [
        createFinding({
          ruleId: 'RULE-001',
          severity: 'CRITICAL',
          message: 'Critical security issue',
          location: { path: 'src/app.ts', startLine: 42 },
          tool: { name: 'trivy', version: '1.0' },
        }),
        createFinding({
          ruleId: 'RULE-002',
          severity: 'LOW',
          message: 'Minor code smell',
          location: { path: 'src/util.ts', startLine: 15 },
          tool: { name: 'semgrep', version: '2.0' },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('RULE-001')).toBeInTheDocument()
      expect(screen.getByText('RULE-002')).toBeInTheDocument()
      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      expect(screen.getByText('LOW')).toBeInTheDocument()
      expect(screen.getByText('Critical security issue')).toBeInTheDocument()
      expect(screen.getByText('Minor code smell')).toBeInTheDocument()
      expect(screen.getByText('trivy')).toBeInTheDocument()
      expect(screen.getByText('semgrep')).toBeInTheDocument()
    })

    it('should render priority scores', () => {
      const findings = [
        createFinding({
          priority: { priority: 95, is_kev: false, epss_score: 0.8 },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('95')).toBeInTheDocument()
    })

    it('should render KEV badge for known exploited vulnerabilities', () => {
      const findings = [
        createFinding({
          priority: { priority: 100, is_kev: true, epss_score: 0.95 },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('KEV')).toBeInTheDocument()
    })

    it('should render location with line number', () => {
      const findings = [
        createFinding({
          location: { path: 'src/main.ts', startLine: 123 },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('src/main.ts:123')).toBeInTheDocument()
    })

    it('should handle missing line number gracefully', () => {
      const findings = [
        createFinding({
          location: { path: 'src/file.ts', startLine: undefined },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('src/file.ts:?')).toBeInTheDocument()
    })
  })

  describe('Sorting', () => {
    const unsortedFindings = [
      createFinding({
        id: 'f1',
        ruleId: 'RULE-C',
        severity: 'LOW',
        location: { path: 'z.ts', startLine: 1 },
        priority: { priority: 30, is_kev: false, epss_score: 0.3 },
      }),
      createFinding({
        id: 'f2',
        ruleId: 'RULE-A',
        severity: 'CRITICAL',
        location: { path: 'a.ts', startLine: 1 },
        priority: { priority: 90, is_kev: false, epss_score: 0.9 },
      }),
      createFinding({
        id: 'f3',
        ruleId: 'RULE-B',
        severity: 'MEDIUM',
        location: { path: 'm.ts', startLine: 1 },
        priority: { priority: 50, is_kev: false, epss_score: 0.5 },
      }),
    ]

    it('should sort by severity by default (ascending)', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const rows = screen.getAllByRole('row')
      // Severity order: CRITICAL (index 0) < HIGH < MEDIUM < LOW < INFO
      // Skip header row (index 0), only data rows
      const firstDataRow = rows[1]
      const secondDataRow = rows[2]
      const thirdDataRow = rows[3]

      // Ascending order: CRITICAL first, then MEDIUM, then LOW
      expect(within(firstDataRow).getByText('CRITICAL')).toBeInTheDocument()
      expect(within(secondDataRow).getByText('MEDIUM')).toBeInTheDocument()
      expect(within(thirdDataRow).getByText('LOW')).toBeInTheDocument()
    })

    it('should toggle sort direction when clicking same column', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const severityHeader = screen.getByText(/Severity/)
      fireEvent.click(severityHeader) // Toggle to desc

      const rows = screen.getAllByRole('row')
      const firstDataRow = rows[1]

      // After toggle, should be descending (LOW first)
      expect(within(firstDataRow).getByText('LOW')).toBeInTheDocument()
    })

    it('should sort by priority when priority column clicked', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const priorityHeader = screen.getByText(/Priority/)
      fireEvent.click(priorityHeader)

      const rows = screen.getAllByRole('row')
      const firstDataRow = rows[1]

      // Priority 30 should be first (ascending)
      expect(within(firstDataRow).getByText('30')).toBeInTheDocument()
    })

    it('should sort by ruleId when rule column clicked', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const ruleHeader = screen.getByText(/Rule/)
      fireEvent.click(ruleHeader)

      const rows = screen.getAllByRole('row')
      const firstDataRow = rows[1]

      // RULE-A should be first (ascending alphabetical)
      expect(within(firstDataRow).getByText('RULE-A')).toBeInTheDocument()
    })

    it('should sort by path when path column clicked', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const pathHeader = screen.getByText(/Path/)
      fireEvent.click(pathHeader)

      const rows = screen.getAllByRole('row')
      const firstDataRow = rows[1]

      // a.ts should be first (ascending alphabetical)
      expect(within(firstDataRow).getByText('a.ts:1')).toBeInTheDocument()
    })

    it('should show sort indicator (▲) when ascending', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      // Default sort is severity ascending
      expect(screen.getByText(/Severity ▲/)).toBeInTheDocument()
    })

    it('should show sort indicator (▼) when descending', () => {
      render(<FindingsTable findings={unsortedFindings} />)

      const severityHeader = screen.getByText(/Severity/)
      fireEvent.click(severityHeader) // Toggle to desc

      expect(screen.getByText(/Severity ▼/)).toBeInTheDocument()
    })
  })

  describe('Row Expansion', () => {
    it('should expand row when clicked', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          description: 'Detailed description of the finding',
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      const dataRow = rows[1] // First data row
      fireEvent.click(dataRow)

      expect(screen.getByText('Detailed description of the finding')).toBeInTheDocument()
    })

    it('should collapse expanded row when clicked again', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          description: 'Detailed description',
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      const dataRow = rows[1]

      // Expand
      fireEvent.click(dataRow)
      expect(screen.getByText('Detailed description')).toBeInTheDocument()

      // Collapse
      fireEvent.click(dataRow)
      expect(screen.queryByText('Detailed description')).not.toBeInTheDocument()
    })

    it('should show code snippet when available', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          context: { snippet: 'const password = "hardcoded123"' },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      expect(screen.getByText('const password = "hardcoded123"')).toBeInTheDocument()
    })

    it('should show remediation when available (string format)', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          remediation: 'Use environment variables instead of hardcoded secrets',
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      expect(screen.getByText('Remediation:')).toBeInTheDocument()
      expect(
        screen.getByText('Use environment variables instead of hardcoded secrets')
      ).toBeInTheDocument()
    })

    it('should show remediation when available (object format)', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          remediation: {
            summary: 'Use parameterized queries',
            steps: ['Step 1', 'Step 2'],
          },
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      expect(screen.getByText('Remediation:')).toBeInTheDocument()
      expect(screen.getByText('Use parameterized queries')).toBeInTheDocument()
    })

    it('should show references when available', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          references: ['https://cwe.mitre.org/data/definitions/79.html', 'https://owasp.org/...'],
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      expect(screen.getByText('References:')).toBeInTheDocument()
      expect(screen.getByText('https://cwe.mitre.org/data/definitions/79.html')).toBeInTheDocument()
    })

    it('should limit references to 3 items', () => {
      const findings = [
        createFinding({
          id: 'test-finding-1',
          references: ['ref1', 'ref2', 'ref3', 'ref4', 'ref5'],
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      expect(screen.getByText('ref1')).toBeInTheDocument()
      expect(screen.getByText('ref2')).toBeInTheDocument()
      expect(screen.getByText('ref3')).toBeInTheDocument()
      expect(screen.queryByText('ref4')).not.toBeInTheDocument()
    })

    it('should allow multiple rows to be expanded simultaneously', () => {
      const findings = [
        createFinding({ id: 'f1', description: 'Description 1' }),
        createFinding({ id: 'f2', description: 'Description 2' }),
      ]
      render(<FindingsTable findings={findings} />)

      let rows = screen.getAllByRole('row')
      fireEvent.click(rows[1]) // Expand first

      // Re-query rows after expansion
      rows = screen.getAllByRole('row')
      // After expanding first row: header(0), row1(1), expanded1(2), row2(3)
      fireEvent.click(rows[3]) // Expand second

      expect(screen.getByText('Description 1')).toBeInTheDocument()
      expect(screen.getByText('Description 2')).toBeInTheDocument()
    })
  })

  describe('Severity Colors', () => {
    it('should apply critical color class', () => {
      const findings = [createFinding({ severity: 'CRITICAL' })]
      render(<FindingsTable findings={findings} />)

      const criticalText = screen.getByText('CRITICAL')
      expect(criticalText.className).toContain('text-critical')
      expect(criticalText.className).toContain('font-bold')
    })

    it('should apply high color class', () => {
      const findings = [createFinding({ severity: 'HIGH' })]
      render(<FindingsTable findings={findings} />)

      const highText = screen.getByText('HIGH')
      expect(highText.className).toContain('text-high')
      expect(highText.className).toContain('font-bold')
    })

    it('should apply medium color class', () => {
      const findings = [createFinding({ severity: 'MEDIUM' })]
      render(<FindingsTable findings={findings} />)

      const mediumText = screen.getByText('MEDIUM')
      expect(mediumText.className).toContain('text-medium')
    })

    it('should apply low color class', () => {
      const findings = [createFinding({ severity: 'LOW' })]
      render(<FindingsTable findings={findings} />)

      const lowText = screen.getByText('LOW')
      expect(lowText.className).toContain('text-low')
    })

    it('should apply info color class', () => {
      const findings = [createFinding({ severity: 'INFO' })]
      render(<FindingsTable findings={findings} />)

      const infoText = screen.getByText('INFO')
      expect(infoText.className).toContain('text-info')
    })
  })

  describe('Edge Cases', () => {
    it('should handle finding without priority', () => {
      const findings = [createFinding({ priority: undefined })]
      render(<FindingsTable findings={findings} />)

      expect(screen.getByText('0')).toBeInTheDocument()
    })

    it('should handle finding without description (falls back to message)', () => {
      const findings = [
        createFinding({
          id: 'f1',
          message: 'Fallback message',
          description: undefined,
        }),
      ]
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      fireEvent.click(rows[1])

      // Message appears twice: in table and in expanded view
      const fallbackMessages = screen.getAllByText('Fallback message')
      expect(fallbackMessages).toHaveLength(2)
    })

    it('should handle large number of findings', () => {
      const findings = Array.from({ length: 100 }, (_, i) =>
        createFinding({ id: `f${i}`, ruleId: `RULE-${i}` })
      )
      render(<FindingsTable findings={findings} />)

      const rows = screen.getAllByRole('row')
      // 100 findings × 1 row each + 1 header row = 101 rows (when not expanded)
      expect(rows.length).toBe(101)
    })
  })
})
