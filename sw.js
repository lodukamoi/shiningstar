// Shining Star service worker: makes the site installable, opens offline, and shows push notifications.
const CACHE = 'ss-v1', SHELL = ['/', '/manifest.json', '/icons/icon-192.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api') || u.pathname.startsWith('/socket.io')) return;
  e.respondWith(fetch(r).then(res => {
    if (res.ok && (r.mode === 'navigate' || u.pathname.startsWith('/icons'))) { const cp = res.clone(); caches.open(CACHE).then(c => c.put(r, cp)); }
    return res;
  }).catch(() => caches.match(r).then(m => m || caches.match('/'))));
});
self.addEventListener('push', e => {
  let d = {}; try { d = e.data.json(); } catch { d = { title: 'Shining Star', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const ring = d.kind === 'call' || d.kind === 'gcall';
    if (!ring && cs.some(c => c.visibilityState === 'visible')) return; // the open app shows its own alert
    return self.registration.showNotification(d.title || 'Shining Star', {
      body: d.body || '', icon: '/icons/icon-192.png', badge: '/icons/badge-96.png', tag: d.tag, renotify: !!d.tag,
      requireInteraction: !!d.requireInteraction, vibrate: ring ? [300, 150, 300, 150, 300] : [120], data: { url: d.url || '/' } });
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/', hash = url.includes('#') ? url.slice(url.indexOf('#')) : '';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    if (cs.length) { cs[0].postMessage({ open: hash }); return cs[0].focus(); }
    return self.clients.openWindow(url);
  }));
});
