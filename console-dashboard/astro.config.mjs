import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

// Builds a static dashboard into ../secureagentnet/cloud/dashboard, which the
// cloud backend serves same-origin in production.
export default defineConfig({
  outDir: '../secureagentnet/cloud/dashboard',
  build: { format: 'file' },
  integrations: [tailwind()],
});
