/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Static export for Firebase Hosting (this app is no longer deployed to
  // Vercel — see README.md's "Deploy (Firebase Hosting)" section). `next
  // build` now writes a fully static site to `out/`. Next.js ignores
  // `headers()` under `output: 'export'` (there's no server to run them
  // against); the equivalent headers live in the repo-root firebase.json
  // instead, mirrored from what used to be here / in vercel.json.
  output: 'export',
};

export default nextConfig;
