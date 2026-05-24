/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./app/**/*.{js,ts,jsx,tsx,mdx}', './components/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          blue: '#2563eb',
          green: '#10b981',
          red: '#ef4444',
          purple: '#8b5cf6',
          yellow: '#f59e0b',
        },
        dark: { bg: '#0f172a', surface: '#1e293b', text: '#f1f5f9' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
};
