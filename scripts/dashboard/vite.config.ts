import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { viteSingleFile } from 'vite-plugin-singlefile'
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig({
  plugins: [
    react(),
    viteSingleFile({
      // Inline all CSS/JS/fonts
      removeViteModuleLoader: true
    }),
    // Bundle analyzer (Phase 5.4)
    visualizer({
      filename: 'dist/stats.html',
      open: false,
      gzipSize: true,
      brotliSize: true,
    })
  ],
  build: {
    target: 'esnext',
    assetsInlineLimit: 100000000, // Inline everything (100MB limit)
    chunkSizeWarningLimit: 100000000,
    cssCodeSplit: false,
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
        manualChunks: undefined // Disable code splitting for single file
      }
    }
  },
  resolve: {
    alias: {
      '@': '/src'
    }
  }
})
