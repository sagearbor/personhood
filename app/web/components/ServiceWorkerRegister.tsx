'use client';

import { useEffect } from 'react';

/**
 * Registers /sw.js on the first mount. Splitting this out of the root
 * layout keeps the layout server-rendered.
 */
export function ServiceWorkerRegister() {
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (!('serviceWorker' in navigator)) return;
    const onLoad = () => {
      navigator.serviceWorker
        .register('/sw.js')
        .catch((err) => console.warn('Personhood SW registration failed:', err));
    };
    if (document.readyState === 'complete') {
      onLoad();
    } else {
      window.addEventListener('load', onLoad);
      return () => window.removeEventListener('load', onLoad);
    }
  }, []);
  return null;
}
