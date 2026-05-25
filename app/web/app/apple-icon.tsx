import { ImageResponse } from 'next/og';

export const runtime = 'edge';
export const size = { width: 180, height: 180 };
export const contentType = 'image/png';

/**
 * iOS apple-touch-icon. Same mark as /icon.png but at 180x180 with iOS's
 * subtle rounded corner already accounted for (iOS clips it again at the OS
 * level, so we just deliver a square).
 */
export default function AppleIcon() {
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
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: 38,
            top: 38,
            width: 22,
            height: 104,
            borderLeft: '6px solid #cffd2c',
            borderTop: '6px solid #cffd2c',
            borderBottom: '6px solid #cffd2c',
            borderTopLeftRadius: 10,
            borderBottomLeftRadius: 10,
          }}
        />
        <div
          style={{
            position: 'absolute',
            right: 38,
            top: 38,
            width: 22,
            height: 104,
            borderRight: '6px solid #cffd2c',
            borderTop: '6px solid #cffd2c',
            borderBottom: '6px solid #cffd2c',
            borderTopRightRadius: 10,
            borderBottomRightRadius: 10,
          }}
        />
        <div
          style={{
            position: 'absolute',
            width: 14,
            height: 56,
            background: '#cffd2c',
            borderRadius: 8,
          }}
        />
        <div
          style={{
            position: 'absolute',
            top: 48,
            width: 20,
            height: 20,
            background: '#cffd2c',
            borderRadius: 999,
          }}
        />
      </div>
    ),
    { ...size },
  );
}
