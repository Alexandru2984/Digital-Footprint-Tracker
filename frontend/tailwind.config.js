module.exports = {
  darkMode: 'class',
  content: ['./*.html'],
  theme: {
    extend: {
      colors: {
        brand: { 300: '#6ee7b7', 400: '#34d399', 500: '#10b981', 600: '#059669', 700: '#047857', 900: '#064e3b' },
        dark:  { 900: '#0f172a', 800: '#1e293b', 700: '#334155', 600: '#475569' }
      },
      fontFamily: {
        mono: ['ui-monospace','SFMono-Regular','Menlo','Monaco','Consolas','Liberation Mono','Courier New','monospace']
      }
    }
  },
  plugins: []
}
