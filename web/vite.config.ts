import path from 'node:path'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    // Tailnet/funnel hostname — without this vite rejects the Host header.
    allowedHosts: ['.tailf655a6.ts.net'],
    proxy: {
      // Dev: the client uses a same-origin /ws URL unless VITE_WROOMD_URL is
      // set (see src/lib/config.ts); proxy it to wroomd's default bind.
      '/ws': {
        target: 'http://localhost:8080',
        ws: true,
      },
    },
  },
})
