import { useState, useEffect } from 'react'

/**
 * Custom hook for dark mode state management with localStorage persistence
 *
 * Behavior:
 * 1. Reads initial state from localStorage ('theme' key)
 * 2. Defaults to dark mode if no saved preference
 * 3. Applies 'dark' class to document.documentElement
 * 4. Persists changes to localStorage
 *
 * @returns {[boolean, () => void]} [isDark, toggleDark]
 */
export function useDarkMode(): [boolean, () => void] {
  // Initialize state from localStorage or default to dark
  const [isDark, setIsDark] = useState<boolean>(() => {
    // Check localStorage first
    const saved = localStorage.getItem('theme')
    if (saved !== null) {
      return saved === 'dark'
    }

    // Default to dark mode
    return true
  })

  // Apply dark class to document.documentElement
  useEffect(() => {
    if (isDark) {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [isDark])

  // Toggle function with localStorage persistence
  const toggleDark = () => {
    setIsDark(prev => {
      const newValue = !prev
      localStorage.setItem('theme', newValue ? 'dark' : 'light')
      return newValue
    })
  }

  return [isDark, toggleDark]
}
