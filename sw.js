/* Guarda solo el código de la app, nunca datos de clientes: esos van cifrados en IndexedDB. */
const CACHE = 'oi-crm-v14';
const ARCHIVOS = ['./', 'index.html', 'app.js', 'config.js', 'estilos.css', 'manifest.webmanifest', 'icono-180.png', 'icono-192.png', 'icono-512.png'];
// 'reload' baja cada archivo del servidor y no de la copia del navegador, para no instalar una versión vieja.
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(ARCHIVOS.map(u => new Request(u, { cache: 'reload' })))).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(l => Promise.all(l.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== self.location.origin) return;
  const clave = e.request.mode === 'navigate' ? 'index.html' : e.request;
  e.respondWith(caches.open(CACHE).then(c => c.match(clave).then(enCache => {
    const red = fetch(e.request).then(r => { if (r && r.ok) c.put(clave, r.clone()); return r; });
    if (enCache) { red.catch(() => { }); return enCache; } // abre al instante y se actualiza para la próxima vez
    return red;
  })));
});
