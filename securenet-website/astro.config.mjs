import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  outDir: '../website',
  build: {
    format: 'directory',
  },
  integrations: [
    // applyBaseStyles:false — we import our own global.css (with @tailwind
    // directives) from the shared Layout, so pages not yet migrated off the
    // legacy CDN setup stay untouched.
    tailwind({ applyBaseStyles: false }),
  ],
});