/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:        '#07101a',
        surface:     '#0c1828',
        raised:      '#102236',
        overlay:     '#152a42',
        accent:      '#2563eb',
        'accent-hi': '#3b82f6',
        crit:        '#ef4444',
        hi:          '#f97316',
        med:         '#f59e0b',
        lo:          '#22d3ee',
        ok:          '#22c55e',
        dim:         '#4a6278',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
