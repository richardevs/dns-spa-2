import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  base: '/', // Change this to your GitHub repository name
  build: {
    outDir: 'dist'
  }
})
