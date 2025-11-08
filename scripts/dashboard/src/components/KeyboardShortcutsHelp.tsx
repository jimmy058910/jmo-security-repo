import { useState } from 'react'
import { Keyboard } from 'lucide-react'

/**
 * Keyboard shortcuts help modal
 *
 * Displays a floating help button that opens a modal showing all keyboard shortcuts
 */

const SHORTCUTS = [
  { keys: ['Ctrl', 'K'], description: 'Focus search input' },
  { keys: ['Esc'], description: 'Clear all filters and search' },
  { keys: ['↑', '↓'], description: 'Navigate table rows (future)' },
]

export default function KeyboardShortcutsHelp() {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <>
      {/* Help button */}
      <button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 p-3 bg-primary text-white rounded-full shadow-lg hover:bg-blue-700 transition-colors z-50"
        aria-label="Show keyboard shortcuts"
        title="Keyboard shortcuts (? key)"
      >
        <Keyboard className="w-6 h-6" />
      </button>

      {/* Modal overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          onClick={() => setIsOpen(false)}
        >
          <div
            className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 max-w-md w-full mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                Keyboard Shortcuts
              </h2>
              <button
                onClick={() => setIsOpen(false)}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              {SHORTCUTS.map((shortcut, idx) => (
                <div
                  key={idx}
                  className="flex justify-between items-center border-b border-gray-200 dark:border-gray-700 pb-3"
                >
                  <span className="text-gray-700 dark:text-gray-300">
                    {shortcut.description}
                  </span>
                  <div className="flex gap-1">
                    {shortcut.keys.map((key, kidx) => (
                      <kbd
                        key={kidx}
                        className="px-2 py-1 text-sm font-semibold text-gray-800 bg-gray-100 border border-gray-300 rounded dark:bg-gray-700 dark:text-gray-200 dark:border-gray-600"
                      >
                        {key}
                      </kbd>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
              Press <kbd className="px-1 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 rounded">Esc</kbd> to close
            </p>
          </div>
        </div>
      )}
    </>
  )
}
