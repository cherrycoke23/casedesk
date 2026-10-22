const CACHE = 'casedesk-v1';
const SHELL = ['./', 'app.dc.html', 'support.js', 'graph.js', 'auth.html', 'manifest.webmanifest', 'icon-180.png', 'icon-192.png', 'icon-512.png', 'ds/styles.css', 'ds/_ds_bundle.js'];
const SKIP = /(^|\.)(graph\.microsoft\.com|login\.microsoftonline\.com|login\.live\.com)$/;
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => Promise.all(SHELL.map((u) => c.add(u).catch(() => {})))));
  self.skipWaiting();
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
// Network first so updates arrive; fall back to the cached copy when offline.
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (!/^https?:$/.test(url.protocol) || SKIP.test(url.hostname)) return;
  e.respondWith(
    fetch(req).then((res) => {
      if (res && (res.ok || res.type === 'opaque')) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: url.origin === location.origin })
      .then((r) => r || (req.mode === 'navigate' ? caches.match('app.dc.html') : Response.error())))
  );
});