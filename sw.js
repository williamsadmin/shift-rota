// Shift Rota service worker — makes the app installable and works offline for
// the app shell. Supabase / CDN requests are left to the network.
const CACHE = 'shift-rota-v6';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest?v=3',
  './icon-192.png?v=3',
  './icon-512.png?v=3',
  './apple-touch-icon.png?v=3'
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
    // Only a genuinely successful response updates the offline fallback —
    // a path-based tracker share link (e.g. /theryantracker) that doesn't
    // match a real file resolves as an HTTP 404 (GitHub Pages serves 404.html
    // for it), which must never overwrite the cached real app shell.
    e.respondWith(
      fetch(req)
        .then((res) => {
          if(res.ok){
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put('./index.html', copy));
          }
          return res;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  e.respondWith(caches.match(req).then((cached) => cached || fetch(req)));
});
