/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,ts}'],
  theme: {
    extend: {
      colors: {
        ink: '#0f172a',
        bg: '#f5f8fc',
        card: '#ffffff',
        line: '#e6ebf2',
        muted: '#64748b',
        primary: '#2563eb',
        teal: '#10b981',
        accent: '#10b981',
        ok: '#15803d',
        warn: '#b45309',
        crit: '#b91c1c',
        info: '#1d4ed8',
        identify: '#16a34a',
        track: '#2563eb',
        contain: '#7c3aed',
        decide: '#dc2626',
      },
      fontFamily: {
        display: ['Schibsted Grotesk', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
