module.exports = {
  darkMode: 'class',
  content: ['./index.html'],
  theme: {
    extend: {
      colors: {
        brand: { 500: '#10b981', 600: '#059669' },
        dark:  { 900: '#0f172a', 800: '#1e293b', 700: '#334155' }
      },
      fontFamily: {
        mono: ['ui-monospace','SFMono-Regular','Menlo','Monaco','Consolas','Liberation Mono','Courier New','monospace']
      }
    }
  },
  plugins: []
}
