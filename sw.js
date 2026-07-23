// Shift Rota service worker — makes the app installable and works offline for
// the app shell. Supabase / CDN requests are left to the network.
const CACHE = 'shift-rota-v4';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest?v=2',
  './icon-192.png?v=2',
  './icon-512.png?v=2',
  './apple-touch-icon.png?v=2'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Only handle our own files; Supabase and CDN calls go straight to the network.
  if (url.origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    // Network-first for the page so updates land immediately; fall back to cache offline.
    e.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  e.respondWith(caches.match(req).then((cached) => cached || fetch(req)));
});
