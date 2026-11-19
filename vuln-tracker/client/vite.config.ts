import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backendTarget = 'http://localhost:5248';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/auth': { target: backendTarget, changeOrigin: false },
      '/signin-oidc': { target: backendTarget, changeOrigin: false },
      '/signout-callback-oidc': { target: backendTarget, changeOrigin: false },
      '/api': { target: backendTarget, changeOrigin: false },
    },
  },
});