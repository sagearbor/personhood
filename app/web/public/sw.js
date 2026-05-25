// Personhood service worker.
//
// Two responsibilities:
//   1. Make the app installable as a PWA (the existence of a fetch handler is
//      enough for Chrome's installability heuristic).
//   2. Provide a tiny offline shell so Add-to-Home-Screen launches don't show
//      Chrome's "no internet" page when the network is briefly down.
//
// Strategy: network-first with a cached shell fallback for navigations.
// Everything else is network-only — we don't aggressively cache assets in
// v0.1 since Next.js handles its own immutable hashed bundles.

const CACHE_NAME = 'personhood-shell-v1';
const SHELL = ['/', '/offline'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL).catch(() => {}))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  // Only handle GET navigations.
  if (req.method !== 'GET') return;
  if (req.mode !== 'navigate') return;

  event.respondWith(
    (async () => {
      try {
        const res = await fetch(req);
        const cache = await caches.open(CACHE_NAME);
        cache.put('/', res.clone()).catch(() => {});
        return res;
      } catch (err) {
        const cache = await caches.open(CACHE_NAME);
        const cached = await cache.match('/');
        if (cached) return cached;
        return new Response(
          '<!doctype html><html><body style="background:#08090c;color:#ecf0fa;font:16px system-ui;padding:32px"><h1>Personhood</h1><p>Offline. Reconnect and reload.</p></body></html>',
          { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
        );
      }
    })()
  );
});
