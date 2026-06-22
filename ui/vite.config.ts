import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

// The canonical graph style/mapping spec is the single source of truth shared
// with the Python HTML report (ziran/interfaces/graph_style/graph_style.json).
const graphStyle = fileURLToPath(
  new URL('../ziran/interfaces/graph_style/graph_style.json', import.meta.url),
)

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@graphstyle': graphStyle,
    },
  },
  build: {
    outDir: '../ziran/interfaces/web/static',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8484',
      '/ws': {
        target: 'ws://localhost:8484',
        ws: true,
      },
    },
  },
})
