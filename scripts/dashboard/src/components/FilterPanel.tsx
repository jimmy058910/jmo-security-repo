import { forwardRef } from 'react'

interface FilterPanelProps {
  severities: Set<string>
  onSeverityChange: (severity: string) => void
  selectedTool: string
  onToolChange: (tool: string) => void
  tools: string[]
  searchQuery: string
  onSearchChange: (query: string) => void
}

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const FilterPanel = forwardRef<HTMLInputElement, FilterPanelProps>(
  function FilterPanel(
    {
      severities,
      onSeverityChange,
      selectedTool,
      onToolChange,
      tools,
      searchQuery,
      onSearchChange
    },
    ref
  ) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-4 space-y-4 transition-colors">
      {/* Severity checkboxes */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Severity
        </label>
        <div className="flex flex-wrap gap-2">
          {SEVERITIES.map((sev) => (
            <label key={sev} className="inline-flex items-center">
              <input
                type="checkbox"
                checked={severities.has(sev)}
                onChange={() => onSeverityChange(sev)}
                className="rounded border-gray-300 dark:border-gray-600 text-primary focus:ring-primary dark:bg-gray-700"
              />
              <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">{sev}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Tool dropdown */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Tool
        </label>
        <select
          value={selectedTool}
          onChange={(e) => onToolChange(e.target.value)}
          className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary focus:ring-primary sm:text-sm dark:bg-gray-700 dark:text-white"
        >
          <option value="">All Tools</option>
          {tools.map((tool) => (
            <option key={tool} value={tool}>
              {tool}
            </option>
          ))}
        </select>
      </div>

      {/* Search */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Search
        </label>
        <input
          ref={ref}
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search rule, message, or path..."
          className="block w-full rounded-md border-gray-300 dark:border-gray-600 shadow-sm focus:border-primary focus:ring-primary sm:text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
        />
      </div>
    </div>
  )
})

export default FilterPanel
