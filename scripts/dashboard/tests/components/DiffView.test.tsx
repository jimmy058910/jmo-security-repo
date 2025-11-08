import { render, screen, fireEvent, within } from '@testing-library/react'
import DiffView from '../../src/components/DiffView'
import { DiffResult, CommonFinding } from '../../src/types/findings'

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

// Helper to create test diff result
const createDiffResult = (overrides: Partial<DiffResult>): DiffResult => ({
  baseline_count: 0,
  current_count: 0,
  new_findings: [],
  fixed_findings: [],
  modified_findings: [],
  unchanged_findings: [],
  ...overrides,
})

describe('DiffView', () => {
  describe('Summary Header', () => {
    it('should render summary statistics', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 12,
        new_findings: [createFinding({ id: 'f1' }), createFinding({ id: 'f2' })],
        fixed_findings: [],
        modified_findings: [],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Baseline')).toBeInTheDocument()
      expect(screen.getByText('10')).toBeInTheDocument()
      expect(screen.getByText('Current')).toBeInTheDocument()
      expect(screen.getByText('12')).toBeInTheDocument()
      expect(screen.getByText('Net Change')).toBeInTheDocument()
      expect(screen.getByText('+2')).toBeInTheDocument()
    })

    it('should show negative net change in green', () => {
      const diff = createDiffResult({
        baseline_count: 15,
        current_count: 10,
        fixed_findings: Array.from({ length: 5 }, (_, i) => createFinding({ id: `f${i}` })),
      })
      render(<DiffView diff={diff} />)

      const netChange = screen.getByText('-5')
      expect(netChange.className).toContain('text-green-600')
    })

    it('should show positive net change in red', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 15,
        new_findings: Array.from({ length: 5 }, (_, i) => createFinding({ id: `f${i}` })),
      })
      render(<DiffView diff={diff} />)

      const netChange = screen.getByText('+5')
      expect(netChange.className).toContain('text-red-600')
    })

    it('should show zero net change in gray', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 10,
      })
      render(<DiffView diff={diff} />)

      // Find the Net Change label, then get the value from the next sibling
      const netChangeLabel = screen.getByText('Net Change')
      const netChangeValue = netChangeLabel.nextElementSibling
      expect(netChangeValue?.textContent).toBe('0')
      expect(netChangeValue?.className).toContain('text-gray-600')
    })

    it('should display modified count', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 10,
        modified_findings: [
          {
            finding: createFinding({ id: 'f1' }),
            changes: { severity: { old: 'LOW', new: 'HIGH' } },
          },
          {
            finding: createFinding({ id: 'f2' }),
            changes: { message: { old: 'Old msg', new: 'New msg' } },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Modified')).toBeInTheDocument()
      expect(screen.getByText('2')).toBeInTheDocument()
    })
  })

  describe('Category Filter Buttons', () => {
    const diff = createDiffResult({
      baseline_count: 10,
      current_count: 12,
      new_findings: [createFinding({ id: 'new1', message: 'New finding' })],
      fixed_findings: [createFinding({ id: 'fixed1', message: 'Fixed finding' })],
      modified_findings: [
        {
          finding: createFinding({ id: 'mod1', message: 'Modified finding' }),
          changes: { severity: { old: 'LOW', new: 'HIGH' } },
        },
      ],
    })

    it('should render all filter buttons', () => {
      render(<DiffView diff={diff} />)

      expect(screen.getByText('All')).toBeInTheDocument()
      expect(screen.getByText(/New \(1\)/)).toBeInTheDocument()
      expect(screen.getByText(/Fixed \(1\)/)).toBeInTheDocument()
      expect(screen.getByText(/Modified \(1\)/)).toBeInTheDocument()
    })

    it('should default to All filter', () => {
      render(<DiffView diff={diff} />)

      const allButton = screen.getByText('All')
      expect(allButton.className).toContain('bg-primary')
    })

    it('should filter to New findings only', () => {
      render(<DiffView diff={diff} />)

      const newButton = screen.getByText(/New \(1\)/)
      fireEvent.click(newButton)

      expect(screen.getByText('New finding')).toBeInTheDocument()
      expect(screen.queryByText('Fixed finding')).not.toBeInTheDocument()
      expect(screen.queryByText('Modified finding')).not.toBeInTheDocument()
    })

    it('should filter to Fixed findings only', () => {
      render(<DiffView diff={diff} />)

      const fixedButton = screen.getByText(/Fixed \(1\)/)
      fireEvent.click(fixedButton)

      expect(screen.getByText('Fixed finding')).toBeInTheDocument()
      expect(screen.queryByText('New finding')).not.toBeInTheDocument()
      expect(screen.queryByText('Modified finding')).not.toBeInTheDocument()
    })

    it('should filter to Modified findings only', () => {
      render(<DiffView diff={diff} />)

      const modifiedButton = screen.getByText(/Modified \(1\)/)
      fireEvent.click(modifiedButton)

      expect(screen.getByText('Modified finding')).toBeInTheDocument()
      expect(screen.queryByText('New finding')).not.toBeInTheDocument()
      expect(screen.queryByText('Fixed finding')).not.toBeInTheDocument()
    })

    it('should toggle filter back to All', () => {
      render(<DiffView diff={diff} />)

      const newButton = screen.getByText(/New \(1\)/)
      fireEvent.click(newButton)

      const allButton = screen.getByText('All')
      fireEvent.click(allButton)

      expect(screen.getByText('New finding')).toBeInTheDocument()
      expect(screen.getByText('Fixed finding')).toBeInTheDocument()
      expect(screen.getByText('Modified finding')).toBeInTheDocument()
    })
  })

  describe('Section Expansion/Collapse', () => {
    const diff = createDiffResult({
      baseline_count: 5,
      current_count: 6,
      new_findings: [createFinding({ id: 'new1', message: 'New finding' })],
      fixed_findings: [createFinding({ id: 'fixed1', message: 'Fixed finding' })],
      modified_findings: [
        {
          finding: createFinding({ id: 'mod1', message: 'Modified finding' }),
          changes: { severity: { old: 'LOW', new: 'HIGH' } },
        },
      ],
    })

    it('should expand all sections by default', () => {
      render(<DiffView diff={diff} />)

      expect(screen.getByText('New finding')).toBeInTheDocument()
      expect(screen.getByText('Fixed finding')).toBeInTheDocument()
      expect(screen.getByText('Modified finding')).toBeInTheDocument()
    })

    it('should collapse section when clicked', () => {
      render(<DiffView diff={diff} />)

      const newSectionButton = screen.getByText(/New Findings \(Regressions\)/).closest('button')!
      fireEvent.click(newSectionButton)

      expect(screen.queryByText('New finding')).not.toBeInTheDocument()
    })

    it('should expand collapsed section when clicked again', () => {
      render(<DiffView diff={diff} />)

      const fixedSectionButton = screen.getByText(/Fixed Findings \(Improvements\)/).closest('button')!

      // Collapse
      fireEvent.click(fixedSectionButton)
      expect(screen.queryByText('Fixed finding')).not.toBeInTheDocument()

      // Expand
      fireEvent.click(fixedSectionButton)
      expect(screen.getByText('Fixed finding')).toBeInTheDocument()
    })

    it('should show chevron down for expanded sections', () => {
      render(<DiffView diff={diff} />)

      const newSectionButton = screen.getByText(/New Findings \(Regressions\)/).closest('button')!
      // Lucide icons are SVG elements, not img elements
      const chevronIcon = newSectionButton.querySelector('svg')
      expect(chevronIcon).toBeInTheDocument()
      expect(chevronIcon?.classList.contains('lucide-chevron-down')).toBe(true)
    })

    it('should toggle multiple sections independently', () => {
      render(<DiffView diff={diff} />)

      const newSectionButton = screen.getByText(/New Findings \(Regressions\)/).closest('button')!
      const fixedSectionButton = screen.getByText(/Fixed Findings \(Improvements\)/).closest('button')!

      // Collapse new section
      fireEvent.click(newSectionButton)
      expect(screen.queryByText('New finding')).not.toBeInTheDocument()
      expect(screen.getByText('Fixed finding')).toBeInTheDocument()

      // Collapse fixed section
      fireEvent.click(fixedSectionButton)
      expect(screen.queryByText('Fixed finding')).not.toBeInTheDocument()
    })
  })

  describe('Finding Rendering', () => {
    it('should render new findings with red styling', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [
          createFinding({
            id: 'f1',
            severity: 'CRITICAL',
            ruleId: 'RULE-001',
            message: 'Critical security issue',
            location: { path: 'src/app.ts', startLine: 42 },
            tool: { name: 'trivy', version: '1.0' },
          }),
        ],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      expect(screen.getByText('RULE-001')).toBeInTheDocument()
      expect(screen.getByText('Critical security issue')).toBeInTheDocument()
      expect(screen.getByText('src/app.ts:42')).toBeInTheDocument()
      expect(screen.getByText('trivy')).toBeInTheDocument()

      // Find the parent div that has the styling classes
      const findingRow = screen.getByText('Critical security issue').closest('div.p-4')!
      expect(findingRow.className).toContain('bg-red-50')
      expect(findingRow.className).toContain('border-red-500')
    })

    it('should render fixed findings with green styling', () => {
      const diff = createDiffResult({
        baseline_count: 1,
        current_count: 0,
        fixed_findings: [
          createFinding({
            id: 'f1',
            message: 'Fixed security issue',
          }),
        ],
      })
      render(<DiffView diff={diff} />)

      const findingRow = screen.getByText('Fixed security issue').closest('div.p-4')!
      expect(findingRow.className).toContain('bg-green-50')
      expect(findingRow.className).toContain('border-green-500')
    })

    it('should render modified findings with yellow styling', () => {
      const diff = createDiffResult({
        baseline_count: 1,
        current_count: 1,
        modified_findings: [
          {
            finding: createFinding({ id: 'f1', message: 'Modified issue' }),
            changes: { severity: { old: 'LOW', new: 'HIGH' } },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      const findingRow = screen.getByText('Modified issue').closest('div.p-4')!
      expect(findingRow.className).toContain('bg-yellow-50')
      expect(findingRow.className).toContain('border-yellow-500')
    })

    it('should show severity changes for modified findings', () => {
      const diff = createDiffResult({
        baseline_count: 1,
        current_count: 1,
        modified_findings: [
          {
            finding: createFinding({
              id: 'f1',
              severity: 'HIGH',
              message: 'Escalated issue',
            }),
            changes: {
              severity: { old: 'LOW', new: 'HIGH' },
            },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Severity:')).toBeInTheDocument()
      expect(screen.getByText('LOW')).toBeInTheDocument()
      expect(screen.getByText('→')).toBeInTheDocument()
      // HIGH appears twice: once in changes, once in current severity
      const highTexts = screen.getAllByText('HIGH')
      expect(highTexts.length).toBeGreaterThanOrEqual(1)
    })

    it('should show message change indicator', () => {
      const diff = createDiffResult({
        baseline_count: 1,
        current_count: 1,
        modified_findings: [
          {
            finding: createFinding({ id: 'f1', message: 'New message' }),
            changes: {
              message: { old: 'Old message', new: 'New message' },
            },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Message changed')).toBeInTheDocument()
    })

    it('should show both severity and message changes', () => {
      const diff = createDiffResult({
        baseline_count: 1,
        current_count: 1,
        modified_findings: [
          {
            finding: createFinding({ id: 'f1', severity: 'CRITICAL', message: 'New message' }),
            changes: {
              severity: { old: 'MEDIUM', new: 'CRITICAL' },
              message: { old: 'Old message', new: 'New message' },
            },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Severity:')).toBeInTheDocument()
      expect(screen.getByText('MEDIUM')).toBeInTheDocument()
      expect(screen.getByText('Message changed')).toBeInTheDocument()
    })
  })

  describe('Severity Colors', () => {
    it('should apply CRITICAL severity color', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [createFinding({ id: 'f1', severity: 'CRITICAL' })],
      })
      render(<DiffView diff={diff} />)

      const criticalText = screen.getByText('CRITICAL')
      expect(criticalText.className).toContain('text-red-700')
      expect(criticalText.className).toContain('font-bold')
    })

    it('should apply HIGH severity color', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [createFinding({ id: 'f1', severity: 'HIGH' })],
      })
      render(<DiffView diff={diff} />)

      const highText = screen.getByText('HIGH')
      expect(highText.className).toContain('text-orange-600')
      expect(highText.className).toContain('font-semibold')
    })

    it('should apply MEDIUM severity color', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [createFinding({ id: 'f1', severity: 'MEDIUM' })],
      })
      render(<DiffView diff={diff} />)

      const mediumText = screen.getByText('MEDIUM')
      expect(mediumText.className).toContain('text-yellow-600')
    })

    it('should apply LOW severity color', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [createFinding({ id: 'f1', severity: 'LOW' })],
      })
      render(<DiffView diff={diff} />)

      const lowText = screen.getByText('LOW')
      expect(lowText.className).toContain('text-blue-600')
    })

    it('should apply INFO severity color', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [createFinding({ id: 'f1', severity: 'INFO' })],
      })
      render(<DiffView diff={diff} />)

      const infoText = screen.getByText('INFO')
      expect(infoText.className).toContain('text-gray-600')
    })
  })

  describe('Empty States', () => {
    it('should show empty state for sections with no findings', () => {
      const diff = createDiffResult({
        baseline_count: 5,
        current_count: 5,
        new_findings: [],
        fixed_findings: [],
        modified_findings: [],
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('No new findings')).toBeInTheDocument()
      expect(screen.getByText('No fixed findings')).toBeInTheDocument()
      expect(screen.getByText('No modified findings')).toBeInTheDocument()
    })

    it('should show unchanged count message when filtering to All', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 10,
        unchanged_findings: Array.from({ length: 10 }, (_, i) => createFinding({ id: `f${i}` })),
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText(/10 unchanged findings \(hidden by default\)/)).toBeInTheDocument()
    })

    it('should not show unchanged message when filtered', () => {
      const diff = createDiffResult({
        baseline_count: 10,
        current_count: 11,
        new_findings: [createFinding({ id: 'f1' })],
        unchanged_findings: Array.from({ length: 10 }, (_, i) => createFinding({ id: `f${i}` })),
      })
      render(<DiffView diff={diff} />)

      const newButton = screen.getByText(/New \(1\)/)
      fireEvent.click(newButton)

      expect(screen.queryByText(/unchanged findings/)).not.toBeInTheDocument()
    })
  })

  describe('Edge Cases', () => {
    it('should handle large number of findings', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 100,
        new_findings: Array.from({ length: 100 }, (_, i) =>
          createFinding({ id: `f${i}`, message: `Finding ${i}` })
        ),
      })
      render(<DiffView diff={diff} />)

      expect(screen.getByText('Finding 0')).toBeInTheDocument()
      expect(screen.getByText('Finding 99')).toBeInTheDocument()
    })

    it('should handle finding without line number', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 1,
        new_findings: [
          createFinding({
            id: 'f1',
            location: { path: 'src/test.ts', startLine: undefined },
          }),
        ],
      })
      render(<DiffView diff={diff} />)

      // Should show path without line number
      expect(screen.getByText('src/test.ts')).toBeInTheDocument()
    })

    it('should handle zero findings in all categories', () => {
      const diff = createDiffResult({
        baseline_count: 0,
        current_count: 0,
        new_findings: [],
        fixed_findings: [],
        modified_findings: [],
        unchanged_findings: [],
      })
      render(<DiffView diff={diff} />)

      // Check net change specifically under "Net Change" label
      const netChangeLabel = screen.getByText('Net Change')
      const netChangeValue = netChangeLabel.nextElementSibling
      expect(netChangeValue?.textContent).toBe('0')

      expect(screen.getByText('No new findings')).toBeInTheDocument()
      expect(screen.getByText('No fixed findings')).toBeInTheDocument()
      expect(screen.getByText('No modified findings')).toBeInTheDocument()
    })

    it('should compute summary statistics correctly', () => {
      const diff = createDiffResult({
        baseline_count: 50,
        current_count: 45,
        new_findings: [createFinding({ id: 'f1' }), createFinding({ id: 'f2' })],
        fixed_findings: Array.from({ length: 7 }, (_, i) => createFinding({ id: `fixed${i}` })),
        modified_findings: [
          {
            finding: createFinding({ id: 'mod1' }),
            changes: { severity: { old: 'LOW', new: 'HIGH' } },
          },
        ],
      })
      render(<DiffView diff={diff} />)

      // Baseline: 50, Current: 45, Net: -5
      expect(screen.getByText('50')).toBeInTheDocument()
      expect(screen.getByText('45')).toBeInTheDocument()
      expect(screen.getByText('-5')).toBeInTheDocument()

      // New: 2, Fixed: 7, Modified: 1
      expect(screen.getByText(/New \(2\)/)).toBeInTheDocument()
      expect(screen.getByText(/Fixed \(7\)/)).toBeInTheDocument()
      expect(screen.getByText(/Modified \(1\)/)).toBeInTheDocument()
    })
  })
})
