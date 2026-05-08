/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // Use class-based dark mode
  theme: {
    extend: {
      colors: {
        // Sourced from docs/brand/tokens.css — do not hardcode hex here
        critical: 'var(--jmo-severity-critical)',
        high: 'var(--jmo-severity-high)',
        medium: 'var(--jmo-severity-medium)',
        low: 'var(--jmo-severity-low)',
        info: 'var(--jmo-severity-info)',
        primary: 'var(--jmo-brand-primary)',
      },
    },
  },
  plugins: [],
}
