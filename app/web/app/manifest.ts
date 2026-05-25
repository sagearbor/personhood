import type { MetadataRoute } from 'next';

/**
 * Web app manifest. Served at /manifest.webmanifest. Next 14 builds the JSON
 * automatically; consumers reference it via <link rel="manifest"> in the
 * root layout.
 *
 * Icons are produced by app/icon.tsx + app/apple-icon.tsx (both use
 * next/og.ImageResponse to render PNGs at build time, so we never commit
 * binary assets to git).
 */
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Personhood',
    short_name: 'Personhood',
    description:
      'Proof you are a person — without proving who you are. A pluggable proof-of-personhood credential.',
    start_url: '/',
    display: 'standalone',
    orientation: 'portrait',
    background_color: '#08090c',
    theme_color: '#08090c',
    categories: ['utilities', 'productivity', 'security'],
    icons: [
      {
        src: '/icon.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'any',
      },
      {
        src: '/icon.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'maskable',
      },
      {
        src: '/apple-icon.png',
        sizes: '180x180',
        type: 'image/png',
      },
    ],
  };
}
