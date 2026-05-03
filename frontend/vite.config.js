import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/scan_pdf':         'http://localhost:8000',
      '/scan_pdf_async':   'http://localhost:8000',
      '/scan':             'http://localhost:8000',
      '/generate_attacks': 'http://localhost:8000',
      '/run_benchmark':    'http://localhost:8000',
      '/benchmark':        'http://localhost:8000',
      '/metrics':          'http://localhost:8000',
    }
  }
})
