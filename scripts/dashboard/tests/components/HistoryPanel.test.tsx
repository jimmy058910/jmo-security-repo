import { render, screen, fireEvent } from '@testing-library/react'
import HistoryPanel from '../../src/components/HistoryPanel'
import { ScanMetadata } from '../../src/types/findings'

// Helper to create test scan metadata
const createScanMetadata = (overrides: Partial<ScanMetadata>): ScanMetadata => ({
  scan_id: `scan-${Math.random()}`,
  timestamp: '2025-11-06T12:00:00Z',
  profile: 'balanced',
  tools: ['trivy', 'semgrep'],
  target_count: 5,
  summary: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  },
  ...overrides,
})

describe('HistoryPanel', () => {
  const mockOnScanSelect = jest.fn()
  const mockOnBaselineScanSelect = jest.fn()

  const defaultProps = {
    scans: [],
    selectedScanId: null,
    onScanSelect: mockOnScanSelect,
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Rendering', () => {
    it('should render header', () => {
      render(<HistoryPanel {...defaultProps} />)

      expect(screen.getByText('Scan History')).toBeInTheDocument()
    })

    it('should render scan selector dropdown', () => {
      render(<HistoryPanel {...defaultProps} />)

      expect(screen.getByRole('combobox')).toBeInTheDocument()
      expect(screen.getByText('Current Scan')).toBeInTheDocument() // Default option
    })

    it('should render empty state when no scans', () => {
      render(<HistoryPanel {...defaultProps} />)

      expect(screen.getByText('No scan history available')).toBeInTheDocument()
    })

    it('should render scan options', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
          profile: 'fast',
        }),
        createScanMetadata({
          scan_id: 'scan2',
          timestamp: '2025-11-06T14:00:00Z',
          profile: 'balanced',
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      // Options are in the select element
      const select = screen.getByRole('combobox')
      expect(select).toBeInTheDocument()
      expect((select as HTMLSelectElement).options).toHaveLength(3) // Current Scan + 2 scans
    })

    it('should format scan option with timestamp and profile', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
          profile: 'fast',
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      // The formatted text appears in the option
      expect(screen.getByText(/fast/)).toBeInTheDocument()
    })

    it('should include branch name in scan option when available', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
          profile: 'fast',
          git_context: { branch: 'main', commit: 'abc123' },
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      expect(screen.getByText(/main/)).toBeInTheDocument()
    })
  })

  describe('Scan Selection', () => {
    it('should call onScanSelect when scan selected', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      const select = screen.getByRole('combobox')
      fireEvent.change(select, { target: { value: 'scan1' } })

      expect(mockOnScanSelect).toHaveBeenCalledWith('scan1')
    })

    it('should call onScanSelect with null when current scan selected', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      const select = screen.getByRole('combobox')
      fireEvent.change(select, { target: { value: '' } })

      expect(mockOnScanSelect).toHaveBeenCalledWith(null)
    })

    it('should show selected scan in dropdown', () => {
      const scans = [
        createScanMetadata({
          scan_id: 'scan1',
          timestamp: '2025-11-06T12:00:00Z',
        }),
      ]
      render(<HistoryPanel {...defaultProps} scans={scans} selectedScanId="scan1" />)

      const select = screen.getByRole('combobox') as HTMLSelectElement
      expect(select.value).toBe('scan1')
    })
  })

  describe('Diff Mode', () => {
    it('should show baseline selector in diff mode', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(
        <HistoryPanel
          {...defaultProps}
          scans={scans}
          isDiffMode={true}
          onBaselineScanSelect={mockOnBaselineScanSelect}
        />
      )

      // In diff mode, "Current Scan" appears as a label (not just an option)
      const labels = screen.getAllByText('Current Scan')
      expect(labels.length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('Baseline Scan')).toBeInTheDocument()
    })

    it('should not show baseline selector when not in diff mode', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(<HistoryPanel {...defaultProps} scans={scans} isDiffMode={false} />)

      expect(screen.queryByText('Baseline Scan')).not.toBeInTheDocument()
    })

    it('should call onBaselineScanSelect when baseline selected', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(
        <HistoryPanel
          {...defaultProps}
          scans={scans}
          isDiffMode={true}
          baselineScanId={null}
          onBaselineScanSelect={mockOnBaselineScanSelect}
        />
      )

      const selects = screen.getAllByRole('combobox')
      const baselineSelect = selects[1] // Second dropdown
      fireEvent.change(baselineSelect, { target: { value: 'scan1' } })

      expect(mockOnBaselineScanSelect).toHaveBeenCalledWith('scan1')
    })

    it('should show baseline scan value in dropdown', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(
        <HistoryPanel
          {...defaultProps}
          scans={scans}
          isDiffMode={true}
          baselineScanId="scan1"
          onBaselineScanSelect={mockOnBaselineScanSelect}
        />
      )

      const selects = screen.getAllByRole('combobox')
      const baselineSelect = selects[1] as HTMLSelectElement
      expect(baselineSelect.value).toBe('scan1')
    })
  })

  describe('Scan Metadata Display', () => {
    const scanWithMetadata = createScanMetadata({
      scan_id: 'scan1',
      profile: 'balanced',
      tools: ['trivy', 'semgrep', 'checkov'],
      target_count: 10,
      summary: {
        critical: 2,
        high: 5,
        medium: 10,
        low: 15,
        info: 3,
        total: 35,
      },
      git_context: {
        branch: 'main',
        commit: 'abc123456789',
        tag: 'v1.0.0',
      },
    })

    it('should show scan metadata when scan selected', () => {
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanWithMetadata]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Profile:')).toBeInTheDocument()
      expect(screen.getByText('balanced')).toBeInTheDocument()
      expect(screen.getByText('Tools:')).toBeInTheDocument()
      // Find "3" by looking for the Tools label's sibling
      const toolsLabel = screen.getByText('Tools:')
      const toolsValue = toolsLabel.nextElementSibling
      expect(toolsValue?.textContent).toBe('3')
      expect(screen.getByText('Targets:')).toBeInTheDocument()
      // Find "10" by looking for Targets label's sibling (since "10" also appears in summary as Medium count)
      const targetsLabel = screen.getByText('Targets:')
      const targetsValue = targetsLabel.nextElementSibling
      expect(targetsValue?.textContent).toBe('10')
    })

    it('should show git context when available', () => {
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanWithMetadata]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Git Context')).toBeInTheDocument()
      expect(screen.getByText(/Branch: main/)).toBeInTheDocument()
      expect(screen.getByText(/Commit: abc1234/)).toBeInTheDocument() // Shortened to 7 chars
      expect(screen.getByText(/Tag: v1.0.0/)).toBeInTheDocument()
    })

    it('should show severity summary', () => {
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanWithMetadata]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Summary')).toBeInTheDocument()
      expect(screen.getByText('Critical:')).toBeInTheDocument()
      expect(screen.getByText('2')).toBeInTheDocument()
      expect(screen.getByText('High:')).toBeInTheDocument()
      expect(screen.getByText('5')).toBeInTheDocument()
      expect(screen.getByText('Medium:')).toBeInTheDocument()
      expect(screen.getByText('Low:')).toBeInTheDocument()
      expect(screen.getByText('Info:')).toBeInTheDocument()
    })

    it('should not show metadata when current scan selected', () => {
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanWithMetadata]}
          selectedScanId={null}
        />
      )

      expect(screen.getByText('Viewing current scan (not saved to history)')).toBeInTheDocument()
      expect(screen.queryByText('Profile:')).not.toBeInTheDocument()
    })

    it('should handle scan without git context', () => {
      const scanNoGit = createScanMetadata({
        scan_id: 'scan1',
        profile: 'fast',
        git_context: undefined,
      })
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanNoGit]}
          selectedScanId="scan1"
        />
      )

      expect(screen.queryByText('Git Context')).not.toBeInTheDocument()
      expect(screen.getByText('Profile:')).toBeInTheDocument() // Other metadata still shown
    })

    it('should handle partial git context', () => {
      const scanPartialGit = createScanMetadata({
        scan_id: 'scan1',
        git_context: {
          branch: 'dev',
          commit: undefined,
          tag: undefined,
        },
      })
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanPartialGit]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Git Context')).toBeInTheDocument()
      expect(screen.getByText(/Branch: dev/)).toBeInTheDocument()
      expect(screen.queryByText(/Commit:/)).not.toBeInTheDocument()
      expect(screen.queryByText(/Tag:/)).not.toBeInTheDocument()
    })
  })

  describe('Timestamp Formatting', () => {
    it('should format ISO timestamp to readable format', () => {
      const scan = createScanMetadata({
        scan_id: 'scan1',
        timestamp: '2025-11-06T14:30:00Z',
        profile: 'fast',
      })
      render(<HistoryPanel {...defaultProps} scans={[scan]} />)

      // Format depends on locale, but should contain "Nov 6" and time
      expect(screen.getByText(/Nov 6/)).toBeInTheDocument()
    })

    it('should handle invalid timestamp gracefully', () => {
      const scan = createScanMetadata({
        scan_id: 'scan1',
        timestamp: 'invalid-timestamp',
        profile: 'fast',
      })
      render(<HistoryPanel {...defaultProps} scans={[scan]} />)

      // Should still render the option (timestamp formatting catches error and returns raw string)
      // The formatTimestamp function returns the raw string on error
      const select = screen.getByRole('combobox') as HTMLSelectElement
      // Option will be "invalid-timestamp - fast"
      const options = Array.from(select.options)
      expect(options.length).toBe(2) // "Current Scan" + 1 scan
      expect(options[1].text).toContain('fast')
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty scan list', () => {
      render(<HistoryPanel {...defaultProps} scans={[]} />)

      expect(screen.getByText('No scan history available')).toBeInTheDocument()
      const select = screen.getByRole('combobox')
      expect((select as HTMLSelectElement).options).toHaveLength(1) // Only "Current Scan"
    })

    it('should handle large number of scans', () => {
      const scans = Array.from({ length: 50 }, (_, i) =>
        createScanMetadata({
          scan_id: `scan${i}`,
          timestamp: `2025-11-06T${i % 24}:00:00Z`,
        })
      )
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      const select = screen.getByRole('combobox')
      expect((select as HTMLSelectElement).options).toHaveLength(51) // 50 scans + "Current Scan"
    })

    it('should handle scan with zero findings', () => {
      const scanEmpty = createScanMetadata({
        scan_id: 'scan1',
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          total: 0,
        },
      })
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanEmpty]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Summary')).toBeInTheDocument()
      // Should show zeros for all severities
      const allZeros = screen.getAllByText('0')
      expect(allZeros.length).toBeGreaterThanOrEqual(5) // At least 5 severity levels
    })

    it('should handle scan with no tools', () => {
      const scanNoTools = createScanMetadata({
        scan_id: 'scan1',
        tools: [],
      })
      render(
        <HistoryPanel
          {...defaultProps}
          scans={[scanNoTools]}
          selectedScanId="scan1"
        />
      )

      expect(screen.getByText('Tools:')).toBeInTheDocument()
      // Find "0" by looking for Tools label's sibling
      const toolsLabel = screen.getByText('Tools:')
      const toolsValue = toolsLabel.nextElementSibling
      expect(toolsValue?.textContent).toBe('0')
    })

    it('should update when selectedScanId changes', () => {
      const scans = [
        createScanMetadata({ scan_id: 'scan1', profile: 'fast' }),
        createScanMetadata({ scan_id: 'scan2', profile: 'balanced' }),
      ]
      const { rerender } = render(
        <HistoryPanel {...defaultProps} scans={scans} selectedScanId="scan1" />
      )

      expect(screen.getByText('fast')).toBeInTheDocument()

      // Change selection
      rerender(
        <HistoryPanel {...defaultProps} scans={scans} selectedScanId="scan2" />
      )

      expect(screen.getByText('balanced')).toBeInTheDocument()
    })
  })

  describe('Accessibility', () => {
    it('should have proper labels for dropdowns', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(
        <HistoryPanel
          {...defaultProps}
          scans={scans}
          isDiffMode={true}
          onBaselineScanSelect={mockOnBaselineScanSelect}
        />
      )

      // Both labels exist (Current Scan appears multiple times - as label and option)
      const currentScanLabels = screen.getAllByText('Current Scan')
      expect(currentScanLabels.length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('Baseline Scan')).toBeInTheDocument()
    })

    it('should support keyboard navigation', () => {
      const scans = [createScanMetadata({ scan_id: 'scan1' })]
      render(<HistoryPanel {...defaultProps} scans={scans} />)

      const select = screen.getByRole('combobox')
      select.focus()
      expect(select).toHaveFocus()
    })
  })
})
