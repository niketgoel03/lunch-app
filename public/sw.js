/* Service worker: handles web-push delivery and notification clicks. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; }
  catch { d = { title: 'Office Lunch', body: event.data ? event.data.text() : '' }; }
  const title = d.title || 'Office Lunch';
  const options = {
    body: d.body || '',
    icon: '/icon.svg',
    badge: '/icon.svg',
    tag: d.category || 'general',
    renotify: true,
    data: { url: d.url || '/' },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) { if ('focus' in c) { c.navigate(url); return c.focus(); } }
      return self.clients.openWindow(url);
    })
  );
});
