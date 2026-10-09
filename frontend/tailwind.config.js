/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          dark: '#0B0F17',
          card: '#131B2A',
          border: '#1E293B',
          accent: '#0EA5E9',
          muted: '#64748B',
          text: '#F8FAFC'
        }
      }
    },
  },
  plugins: [],
}
