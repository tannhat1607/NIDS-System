/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#090d16',
          panel: '#111827',
          border: '#1f2937',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          attack: '#ef4444',
          anomaly: '#f59e0b',
          benign: '#10b981',
        },
      },
    },
  },
  plugins: [],
};
