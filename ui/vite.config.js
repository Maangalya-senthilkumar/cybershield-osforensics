import { defineConfig } from 'vite';

export default defineConfig({
  // './' makes all asset paths relative, which is required when the built
  // index.html is loaded via file:// inside Electron's production build.
  base: './',

  server: {
    port: 5173,
    strictPort: true,
  },

  build: {
    // Put the output in the standard dist/ directory that electron/main.js
    // and electron-builder both expect.
    outDir: 'dist',
    emptyOutDir: true,
  },
});
