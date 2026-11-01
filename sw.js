// Service worker - VNPT Kênh bán. Điều hướng: ưu tiên mạng, rớt mạng dùng bản cache.
// API (workers.dev) luôn đi mạng, không cache.
const CACHE = "vnpt-kenhban-v1";
const SHELL = ["/", "/index.html", "/manifest.webmanifest", "/icon.svg"];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.hostname.endsWith("workers.dev")) return; // API: không can thiệp
  if (e.request.mode === "navigate") {
    e.respondWith(
      fetch(e.request).then((r) => {
        const copy = r.clone();
        caches.open(CACHE).then((c) => c.put("/index.html", copy));
        return r;
      }).catch(() => caches.match("/index.html"))
    );
    return;
  }
  e.respondWith(
    caches.match(e.request).then((hit) => hit || fetch(e.request).then((r) => {
      const copy = r.clone();
      caches.open(CACHE).then((c) => c.put(e.request, copy));
      return r;
    }))
  );
});
