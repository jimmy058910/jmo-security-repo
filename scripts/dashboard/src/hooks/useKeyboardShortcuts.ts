import { useEffect, useRef } from 'react'

/**
 * Keyboard shortcut definitions and handler
 *
 * Supported shortcuts:
 * - Ctrl+K / Cmd+K: Focus search input
 * - Escape: Clear all filters and search
 * - Arrow Down/Up: Navigate table rows (future: when table row focus implemented)
 *
 * @param callbacks Object with shortcut handler functions
 */

interface KeyboardShortcutCallbacks {
  onSearchFocus?: () => void
  onClearFilters?: () => void
  onNavigateDown?: () => void
  onNavigateUp?: () => void
}

export function useKeyboardShortcuts(callbacks: KeyboardShortcutCallbacks) {
  const callbacksRef = useRef(callbacks)

  // Update callbacks ref when they change (avoid stale closures)
  useEffect(() => {
    callbacksRef.current = callbacks
  }, [callbacks])

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      const { key, ctrlKey, metaKey, target } = event

      // Don't intercept if user is typing in an input/textarea
      const isTyping = (target as HTMLElement)?.tagName === 'INPUT' ||
                      (target as HTMLElement)?.tagName === 'TEXTAREA'

      // Ctrl+K / Cmd+K: Focus search (works everywhere)
      if ((ctrlKey || metaKey) && key === 'k') {
        event.preventDefault()
        callbacksRef.current.onSearchFocus?.()
        return
      }

      // Escape: Clear filters (only when not typing)
      if (key === 'Escape' && !isTyping) {
        event.preventDefault()
        callbacksRef.current.onClearFilters?.()
        return
      }

      // Arrow navigation (only when not typing)
      if (!isTyping) {
        if (key === 'ArrowDown') {
          event.preventDefault()
          callbacksRef.current.onNavigateDown?.()
          return
        }

        if (key === 'ArrowUp') {
          event.preventDefault()
          callbacksRef.current.onNavigateUp?.()
          return
        }
      }
    }

    // Attach listener
    window.addEventListener('keydown', handleKeyDown)

    // Cleanup
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [])
}
