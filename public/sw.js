/* Launcher service worker.
   Only the launcher's own files are cached. Anything belonging to a module
   (/anbar/..., /fin/...) is handed straight back to the browser so each module
   keeps its own service worker and its own cache. */
const CACHE = 'decor-launcher-v1';

const SHELL = [
  './',
  './index.html',
  './modules.json',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-192.png',
  './icons/icon-maskable-512.png',
  './icons/favicon-16.png',
  './icons/favicon-32.png',
  './icons/apple-touch-icon.png'
];

function isLauncherAsset(url) {
  if (url.origin !== self.location.origin) return false;
  const p = url.pathname;
  return SHELL.some(entry => {
    const target = new URL(entry, self.location.href);
    return target.pathname === p;
  });
}

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.allSettled(SHELL.map(u => c.add(u))))
      .then(() => self.skipWaiting())
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
  if (req.method !== 'GET') return;            // never touch API calls
  const url = new URL(req.url);

  // Modules own their own scope: bypass completely.
  if (!isLauncherAsset(url)) return;

  // Navigations to the launcher: network first, fall back to the cached shell.
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

  // Static assets: cache first, refresh in the background.
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
