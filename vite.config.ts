import { defineConfig } from 'vite'
import pages from '@hono/vite-cloudflare-pages'
import devServer from '@hono/vite-dev-server'

export default defineConfig({
  plugins: [
    devServer({
      entry: 'src/index.tsx'
    }),
    pages({
      entry: 'src/index.tsx'
    })
  ],
  build: {
    outDir: 'dist'
  },
  server: {
    host: '0.0.0.0',
    port: 5000,
    allowedHosts: true
  }
})
