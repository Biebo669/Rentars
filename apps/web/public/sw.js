/**
 * Rentars Service Worker
 * 
 * Strategy:
 * - Static assets (JS, CSS, fonts, images): cache-first
 * - Navigation requests (HTML pages): network-first with offline fallback
 * - API calls: network-only (never serve stale data)
 */

// Version identifier. A build step may inject a concrete value by replacing the
// fallback below (e.g. `const CACHE_VERSION = 'v1.2.3';`). When no injection
// happens we fall back to a static version so the SW still works.
const CACHE_VERSION = 'v1';
const STATIC_CACHE = `rentars-static-${CACHE_VERSION}`;
const RUNTIME_CACHE = `rentars-runtime-${CACHE_VERSION}`;

// When set (e.g. injected by a build), tells the page that an immediate reload
// is required for compatibility with the backend. Empty string means no forced
// reload is needed.
const REQUIRED_MIN_VERSION = '';

const STATIC_ASSETS = [
  '/',
  '/offline.html',
  '/manifest.json',
];

// Install: pre-cache essential assets. We deliberately do NOT call
// skipWaiting() here — the page decides when it is safe to activate the new
// version (e.g. not in the middle of a booking) and sends SKIP_WAITING.
self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      try {
        const cache = await caches.open(STATIC_CACHE);
        await cache.addAll(STATIC_ASSETS);
      } catch (err) {
        // Precache failed (e.g. flaky network). Abort the install so the
        // previous working version and its caches are retained.
        throw err;
      }
    })()
  );
});

// Activate: clean up obsolete caches, then take control of clients.
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const cacheNames = await caches.keys();
      await Promise.all(
        cacheNames
          .filter((name) => name !== STATIC_CACHE && name !== RUNTIME_CACHE)
          .map((name) => caches.delete(name))
      );
      await self.clients.claim();
    })()
  );
});

// Message handler: lets the page request activation (SKIP_WAITING) and query
// the running version / compatibility requirements (GET_VERSION).
self.addEventListener('message', (event) => {
  const data = event.data || {};
  if (data.type === 'SKIP_WAITING') {
    self.skipWaiting();
    return;
  }
  if (data.type === 'GET_VERSION') {
    const reply = {
      type: 'VERSION',
      version: CACHE_VERSION,
      requiredMinVersion: REQUIRED_MIN_VERSION,
      forceReload: Boolean(REQUIRED_MIN_VERSION),
    };
    if (event.ports && event.ports[0]) {
      event.ports[0].postMessage(reply);
    } else if (event.source && event.source.postMessage) {
      event.source.postMessage(reply);
    }
  }
});

// Fetch strategy
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Never intercept API calls — always go to network
  if (url.pathname.startsWith('/api/') || url.origin !== self.location.origin) {
    return;
  }

  // Static asset cache-first (JS, CSS, fonts, images, icons)
  if (isStaticAsset(url.pathname)) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // Navigation requests: network-first with offline fallback
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstWithOfflineFallback(request));
    return;
  }
});

function isStaticAsset(pathname) {
  return (
    pathname.startsWith('/_next/static/') ||
    pathname.startsWith('/icons/') ||
    /\.(js|css|woff2?|ttf|otf|ico|png|jpg|jpeg|svg|webp|gif)$/.test(pathname)
  );
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Return nothing for failed static asset — browser handles gracefully
    return new Response('', { status: 408 });
  }
}

async function networkFirstWithOfflineFallback(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch {
    // Try the runtime cache
    const cached = await caches.match(request);
    if (cached) return cached;

    // Fall back to offline page
    const offline = await caches.match('/offline.html');
    return offline || new Response('Offline', { status: 503 });
  }
}
