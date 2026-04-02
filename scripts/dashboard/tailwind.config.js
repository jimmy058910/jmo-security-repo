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
        // JMo Security brand colors (severity-based)
        critical: '#d32f2f',
        high: '#f57c00',
        medium: '#fbc02d',
        low: '#7cb342',
        info: '#757575',
        primary: '#1976d2',
      },
    },
  },
  plugins: [],
}
