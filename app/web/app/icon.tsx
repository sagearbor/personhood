import { ImageResponse } from 'next/og';

// Route segment config. (App Router auto-routes app/icon.tsx to /icon.png.)
//
// This used to declare `runtime = 'edge'` so next/og could render the PNG at
// the edge on Vercel. Under `output: 'export'` (static export for Firebase
// Hosting — see next.config.mjs) there is no edge runtime to render at:
// `runtime = 'edge'` actually disables static generation for this route
// entirely, so `next build` silently produced an `out/` with no icon.png.
// `dynamic = 'force-static'` makes explicit what output: 'export' already
// requires — render once at build time to a static file — and dropping
// `runtime` lets that build-time render use the default Node.js runtime.
export const dynamic = 'force-static';

export const size = { width: 512, height: 512 };
export const contentType = 'image/png';

/**
 * Personhood app icon — the brand mark.
 *
 * A single electric-lime monogram on near-black: stylized "P" rendered as
 * two concentric brackets and a vertical bar, suggesting both a person
 * (the bar) and a frame (the brackets — i.e. verification). Maskable-safe:
 * the mark sits inside the safe area circle (~40% of icon dimension).
 */
export default function Icon() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          background: '#08090c',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'monospace',
        }}
      >
        {/* outer bracket — left */}
        <div
          style={{
            position: 'absolute',
            left: 110,
            top: 110,
            width: 60,
            height: 292,
            borderLeft: '14px solid #cffd2c',
            borderTop: '14px solid #cffd2c',
            borderBottom: '14px solid #cffd2c',
            borderTopLeftRadius: 24,
            borderBottomLeftRadius: 24,
          }}
        />
        {/* outer bracket — right */}
        <div
          style={{
            position: 'absolute',
            right: 110,
            top: 110,
            width: 60,
            height: 292,
            borderRight: '14px solid #cffd2c',
            borderTop: '14px solid #cffd2c',
            borderBottom: '14px solid #cffd2c',
            borderTopRightRadius: 24,
            borderBottomRightRadius: 24,
          }}
        />
        {/* center bar = person */}
        <div
          style={{
            position: 'absolute',
            width: 36,
            height: 156,
            background: '#cffd2c',
            borderRadius: 18,
          }}
        />
        {/* tiny dot above center = "head" — gives the bar a person hint */}
        <div
          style={{
            position: 'absolute',
            top: 132,
            width: 56,
            height: 56,
            background: '#cffd2c',
            borderRadius: 999,
          }}
        />
      </div>
    ),
    { ...size },
  );
}
