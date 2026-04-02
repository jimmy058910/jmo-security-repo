import { Moon, Sun } from 'lucide-react'

interface DarkModeToggleProps {
  isDark: boolean
  onToggle: () => void
}

/**
 * Dark mode toggle button
 *
 * Displays a sun icon in dark mode, moon icon in light mode
 * Includes ARIA labels for accessibility
 */
export default function DarkModeToggle({ isDark, onToggle }: DarkModeToggleProps) {
  return (
    <button
      onClick={onToggle}
      className="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {isDark ? (
        <Sun className="w-5 h-5 text-yellow-500" />
      ) : (
        <Moon className="w-5 h-5 text-gray-700" />
      )}
    </button>
  )
}
