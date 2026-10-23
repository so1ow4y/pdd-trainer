// Service worker хранилища: после входа отдаёт приложение по адресам ./app/… прямо из зашифрованного vault/,
// расшифровывая каждый файл в памяти (на диске в открытом виде ничего не появляется). Ключ — неэкспортируемый
// CryptoKey из IndexedDB, его кладёт туда страница входа (index.html) и стирает выход из приложения.
// Без ключа ./app/… не отдаётся: навигация уводит на страницу входа, остальное — 403.
// На localhost без ключа запросы идут в сеть как есть — так работает разработка с открытой папкой app/.

importScripts('vault-crypto.js');

const V = self.PddVault;
const BASE = new URL('./', self.registration.scope).href;
const APP = new URL('app/', BASE);
const DEV = ['localhost', '127.0.0.1', '[::1]'].includes(self.location.hostname);

let key = null; // CryptoKey AES-GCM
let state = null; // { header, manifest }

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

async function unlock(refresh = false) {
  if (!key) {
    const s = await V.loadSession();
    key = s && s.enc ? s.enc : null;
  }
  if (!key) {
    state = null;
    return null;
  }
  if (!state || refresh) {
    try {
      state = await V.readManifest(BASE, key);
    } catch (e) {
      // Новое хранилище с другим паролем (сменили пароль) — сессия больше не подходит.
      if (e.code === 'bad-key') {
        key = null;
        await V.clearSession();
      }
      if (!state || e.code === 'bad-key') state = null;
    }
  }
  return state;
}

self.addEventListener('message', (e) => {
  const reply = (data) => e.ports[0] && e.ports[0].postMessage(data);
  const t = e.data && e.data.type;
  if (t === 'lock') {
    key = null;
    state = null;
    reply({ ok: true });
  } else if (t === 'unlock' || t === 'status') {
    if (t === 'unlock') {
      key = null;
      state = null;
    }
    unlock(true).then((s) => reply({ unlocked: !!s, files: s ? Object.keys(s.manifest.files).length : 0 }), () => reply({ unlocked: false }));
  }
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== APP.origin || !url.pathname.startsWith(APP.pathname)) return;
  e.respondWith(serve(e.request, url));
});

const loginUrl = () => new URL('./', BASE).href;

async function serve(req, url) {
  const nav = req.mode === 'navigate';
  let rel = decodeURIComponent(url.pathname.slice(APP.pathname.length));
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  const st = await unlock(nav); // на каждой навигации — свежее оглавление (вдруг опубликовали новую версию)
  if (!st) {
    if (DEV) return fetch(req);
    return nav ? Response.redirect(loginUrl(), 302) : new Response('Требуется вход', { status: 403 });
  }
  if (rel === '__vault__') {
    const files = st.manifest.files;
    const info = {
      mode: 'vault', created: st.manifest.created, files: Object.keys(files).length,
      size: Object.values(files).reduce((s, f) => s + f.size, 0), iterations: st.header.kdf.iterations,
    };
    return new Response(JSON.stringify(info), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  }
  const entry = st.manifest.files[rel];
  if (!entry) return new Response('Не найдено: ' + rel, { status: 404 });
  try {
    const bytes = await V.readFile(BASE, key, rel, entry);
    return new Response(bytes, { headers: { 'Content-Type': entry.type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
  } catch (err) {
    return new Response('Не удалось расшифровать ' + rel + ': ' + err.message, { status: 500 });
  }
}
