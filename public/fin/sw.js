/* Finance module service worker.
   Cache-first for the third-party libraries (React, Babel, Chart.js, Vazirmatn)
   so the app opens with no network at all, network-first for our own HTML.
   API calls go to another origin and are never touched: only successful HTTP
   responses are cached here, so no account data is ever written to the cache. */
const CACHE = 'decor-fin-v4';

const SHELL = [
  './',
  './index.html',
  './sync.js',
  './manifest.webmanifest',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-192.png',
  './icon-maskable-512.png',
  './favicon-16.png',
  './favicon-32.png',
  './apple-touch-icon.png',
  './lock.js'
];

const LIBS = [
  'https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js',
  'https://cdn.jsdelivr.net/npm/react-dom@18/umd/react-dom.production.min.js',
  'https://cdn.jsdelivr.net/npm/@babel/standalone/babel.min.js',
  'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
  'https://cdn.jsdelivr.net/npm/vazirmatn@33.0.3/Vazirmatn-font-face.css'
];

function ownRequest(url) {
  if (url.origin !== self.location.origin) return false;
  return SHELL.some(entry => new URL(entry, self.location.href).pathname === url.pathname);
}

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c =>
      Promise.allSettled(SHELL.map(u => c.add(u)))
        .then(() => Promise.allSettled(LIBS.map(u =>
          fetch(u, { mode: 'cors' })
            .then(r => { if (r.ok) return c.put(u, r); })
            .catch(() => {})
        )))
    ).then(() => self.skipWaiting())
     .catch(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Our HTML always reflects the latest deployment.
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put('./index.html', copy));
          return res;
        })
        .catch(() => caches.match('./index.html').then(r => r || Response.error()))
    );
    return;
  }

  // Same-origin shell files and the CDN libraries: cache first.
  if (!ownRequest(url) && url.origin !== 'https://cdn.jsdelivr.net') return;

  e.respondWith(
    caches.match(req).then(hit => {
      const net = fetch(req).then(res => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy));
        }
        return res;
      }).catch(() => hit);
      return hit || net;
    })
  );
});
