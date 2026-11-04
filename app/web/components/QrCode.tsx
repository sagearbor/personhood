'use client';

import { useMemo } from 'react';
import qrcode from 'qrcode-generator';

/**
 * QrCode draws text as a QR code in an SVG (black on white, with the quiet
 * zone the spec needs, so it scans on a dark-themed page too). Error
 * correction M: the payloads here are ~15 characters, so the code stays a
 * small version-1/2 grid that a cheap phone camera reads from arm's length.
 */
export function QrCode({ text, size = 240, label }: { text: string; size?: number; label: string }) {
  const { n, path } = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const count = qr.getModuleCount();
    let d = '';
    for (let r = 0; r < count; r++) {
      for (let c = 0; c < count; c++) {
        if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
      }
    }
    return { n: count + 8, path: d };
  }, [text]);
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${n} ${n}`}
      shapeRendering="crispEdges"
      style={{ background: '#fff', borderRadius: 8, maxWidth: '100%', height: 'auto' }}
    >
      <path d={path} fill="#000" />
    </svg>
  );
}
