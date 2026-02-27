import { render, screen, fireEvent } from '@testing-library/react'
import FilterPanel from '../../src/components/FilterPanel'

describe('FilterPanel', () => {
  const mockOnSeverityChange = jest.fn()
  const mockOnToolChange = jest.fn()
  const mockOnSearchChange = jest.fn()

  const defaultProps = {
    severities: new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    onSeverityChange: mockOnSeverityChange,
    tools: ['trivy', 'semgrep', 'trufflehog'],
    selectedTool: '',
    onToolChange: mockOnToolChange,
    searchQuery: '',
    onSearchChange: mockOnSearchChange,
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Rendering', () => {
    it('should render severity filters', () => {
      render(<FilterPanel {...defaultProps} />)

      expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      expect(screen.getByText('HIGH')).toBeInTheDocument()
      expect(screen.getByText('MEDIUM')).toBeInTheDocument()
      expect(screen.getByText('LOW')).toBeInTheDocument()
      expect(screen.getByText('INFO')).toBeInTheDocument()
    })

    it('should render tool selector', () => {
      render(<FilterPanel {...defaultProps} />)

      expect(screen.getByText('Tool')).toBeInTheDocument()
      expect(screen.getByRole('combobox')).toBeInTheDocument()
    })

    it('should render search input', () => {
      render(<FilterPanel {...defaultProps} />)

      expect(screen.getByPlaceholderText('Search rule, message, or path...')).toBeInTheDocument()
    })

    it('should render all tools in dropdown', () => {
      render(<FilterPanel {...defaultProps} />)

      const select = screen.getByRole('combobox')
      expect(select).toBeInTheDocument()

      // Check options via select's options
      const options = (select as HTMLSelectElement).options
      expect(options).toHaveLength(4) // "All Tools" + 3 tools
      expect(options[0].value).toBe('')
      expect(options[0].text).toBe('All Tools')
      expect(options[1].value).toBe('trivy')
      expect(options[2].value).toBe('semgrep')
      expect(options[3].value).toBe('trufflehog')
    })
  })

  describe('Severity Filtering', () => {
    it('should call onSeverityChange when severity checkbox clicked', () => {
      render(<FilterPanel {...defaultProps} />)

      // Find checkbox by getting all checkboxes and matching by label
      const checkboxes = screen.getAllByRole('checkbox')
      const criticalCheckbox = checkboxes[0] // First one is CRITICAL
      fireEvent.click(criticalCheckbox)

      expect(mockOnSeverityChange).toHaveBeenCalledWith('CRITICAL')
    })

    it('should show checked state for selected severities', () => {
      render(<FilterPanel {...defaultProps} />)

      const checkboxes = screen.getAllByRole('checkbox')
      // All severities selected in defaultProps
      checkboxes.forEach((checkbox) => {
        expect(checkbox).toBeChecked()
      })
    })

    it('should show unchecked state for unselected severities', () => {
      const props = {
        ...defaultProps,
        severities: new Set(['HIGH']), // Only HIGH selected
      }
      render(<FilterPanel {...props} />)

      const checkboxes = screen.getAllByRole('checkbox')
      expect(checkboxes[0]).not.toBeChecked() // CRITICAL
      expect(checkboxes[1]).toBeChecked() // HIGH
      expect(checkboxes[2]).not.toBeChecked() // MEDIUM
      expect(checkboxes[3]).not.toBeChecked() // LOW
      expect(checkboxes[4]).not.toBeChecked() // INFO
    })
  })

  describe('Tool Filtering', () => {
    it('should call onToolChange when tool selected', () => {
      render(<FilterPanel {...defaultProps} />)

      const select = screen.getByRole('combobox')
      fireEvent.change(select, { target: { value: 'trivy' } })

      expect(mockOnToolChange).toHaveBeenCalledWith('trivy')
    })

    it('should show selected tool in dropdown', () => {
      const props = {
        ...defaultProps,
        selectedTool: 'semgrep',
      }
      render(<FilterPanel {...props} />)

      const select = screen.getByRole('combobox') as HTMLSelectElement
      expect(select.value).toBe('semgrep')
    })
  })

  describe('Search Functionality', () => {
    it('should call onSearchChange when search input changes', () => {
      render(<FilterPanel {...defaultProps} />)

      const searchInput = screen.getByPlaceholderText('Search rule, message, or path...')
      fireEvent.change(searchInput, { target: { value: 'SQL injection' } })

      expect(mockOnSearchChange).toHaveBeenCalledWith('SQL injection')
    })

    it('should display current search query', () => {
      const props = {
        ...defaultProps,
        searchQuery: 'XSS',
      }
      render(<FilterPanel {...props} />)

      const searchInput = screen.getByPlaceholderText(
        'Search rule, message, or path...'
      ) as HTMLInputElement
      expect(searchInput.value).toBe('XSS')
    })
  })

  describe('Accessibility', () => {
    it('should have proper labels', () => {
      render(<FilterPanel {...defaultProps} />)

      expect(screen.getByText('Severity')).toBeInTheDocument()
      expect(screen.getByText('Tool')).toBeInTheDocument()
      expect(screen.getByText('Search')).toBeInTheDocument()
    })

    it('should support keyboard navigation for checkboxes', () => {
      render(<FilterPanel {...defaultProps} />)

      const checkboxes = screen.getAllByRole('checkbox')
      const criticalCheckbox = checkboxes[0]
      criticalCheckbox.focus()
      expect(criticalCheckbox).toHaveFocus()
    })
  })
})
