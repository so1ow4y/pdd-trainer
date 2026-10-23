// Хранилище ПДД-тренажёра: шифрование приложения для публикации на GitHub Pages (общий код загрузчика index.html,
// service worker sw.js и веб-панели vault.html; та же схема — в tools/vault.py).
//
// Схема (версия 1):
//   ключи   — PBKDF2-HMAC-SHA256(пароль, соль 16 байт, 600 000 итераций) → 64 байта:
//             первые 32 — ключ AES-256-GCM, вторые 32 — ключ HMAC-SHA256 для имён файлов;
//   файлы   — каждый файл app/ шифруется AES-256-GCM со своим случайным IV (12 байт); доп. данные (AAD) —
//             «pdd-vault/1/file/<путь>», поэтому зашифрованный файл нельзя подсунуть под другим именем;
//             имя блоба — первые 16 байт HMAC(ключ имён, путь) в hex: по имени не понять, что внутри;
//   оглавление — JSON { files: { путь: { id, iv, size, sha256, type } } }, зашифрованное тем же ключом
//             (AAD «pdd-vault/1/manifest») → vault/manifest.bin; открытый заголовок vault/vault.json —
//             только соль, число итераций и IV оглавления.
// Пароль и его хеш нигде не хранятся: проверка пароля — это сама расшифровка (GCM не отдаёт ни байта, если ключ
// не тот или данные подменены). Подменить ключ в коде бесполезно: данные зашифрованы настоящим ключом.
//
// Классический скрипт (не модуль), потому что его подключает service worker через importScripts: всё — в self.PddVault.

(function (root) {
  'use strict';

  const FORMAT = 'pdd-vault';
  const VERSION = 1;
  const ITERATIONS = 600000;
  const AAD_FILE = 'pdd-vault/1/file/';
  const AAD_MANIFEST = 'pdd-vault/1/manifest';
  const DB = 'pdd-vault';
  const STORE = 'keys';

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = (root.crypto && root.crypto.subtle) || null;

  // ---------- base64url, hex ----------

  function toB64(bytes) {
    let s = '';
    const b = new Uint8Array(bytes);
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64(s) {
    const t = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  const toHex = (bytes) => Array.from(new Uint8Array(bytes), (x) => x.toString(16).padStart(2, '0')).join('');

  function randomBytes(n) {
    const b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }

  // ---------- ключи ----------

  /** Ключи из пароля: { enc — AES-GCM, names — HMAC }. Оба неэкспортируемые: сырые байты ключа никуда не уходят. */
  async function deriveKeys(password, salt, iterations = ITERATIONS) {
    if (!subtle) throw new Error('Шифрование недоступно: откройте страницу по https (или на localhost).');
    const base = await subtle.importKey('raw', enc.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, base, 512));
    const encKey = await subtle.importKey('raw', bits.slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const names = await subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    bits.fill(0);
    return { enc: encKey, names };
  }

  async function fileId(namesKey, path) {
    return toHex(new Uint8Array(await subtle.sign('HMAC', namesKey, enc.encode(path))).slice(0, 16));
  }

  async function encryptBytes(key, bytes, aad, iv = randomBytes(12)) {
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes);
    return { iv, ct: new Uint8Array(ct) };
  }

  /** Расшифровать; неверный ключ или подменённые данные — исключение «bad-key». */
  async function decryptBytes(key, iv, ct, aad) {
    try {
      return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, ct));
    } catch {
      const e = new Error('Неверный пароль или повреждённые данные');
      e.code = 'bad-key';
      throw e;
    }
  }

  async function sha256Hex(bytes) {
    return toHex(await subtle.digest('SHA-256', bytes));
  }

  // ---------- хранилище ----------

  const vaultUrl = (base, name) => new URL('vault/' + name, base).href;

  async function fetchHeader(base, opts = {}) {
    const res = await fetch(vaultUrl(base, 'vault.json'), { cache: 'no-cache', ...opts });
    if (!res.ok) throw new Error('Нет хранилища vault/vault.json (' + res.status + ')');
    const h = await res.json();
    if (h.format !== FORMAT || h.version !== VERSION) throw new Error('Неизвестный формат хранилища');
    return h;
  }

  async function readManifest(base, encKey, header) {
    const h = header || await fetchHeader(base);
    const res = await fetch(vaultUrl(base, h.manifest.file) + '?v=' + h.manifest.iv, { cache: 'no-cache' });
    if (!res.ok) throw new Error('Нет оглавления хранилища (' + res.status + ')');
    const pt = await decryptBytes(encKey, fromB64(h.manifest.iv), new Uint8Array(await res.arrayBuffer()), AAD_MANIFEST);
    return { header: h, manifest: JSON.parse(dec.decode(pt)) };
  }

  /** Открыть опубликованное хранилище паролем: ключи, заголовок и оглавление. Неверный пароль — исключение bad-key. */
  async function open(base, password) {
    const header = await fetchHeader(base);
    const keys = await deriveKeys(password, fromB64(header.kdf.salt), header.kdf.iterations);
    const { manifest } = await readManifest(base, keys.enc, header);
    return { keys, header, manifest };
  }

  const blobUrl = (base, entry) => vaultUrl(base, 'x/' + entry.id + '.bin') + '?v=' + entry.iv;

  async function readFile(base, encKey, path, entry) {
    const res = await fetch(blobUrl(base, entry));
    if (!res.ok) throw new Error('Нет файла хранилища для ' + path);
    return decryptBytes(encKey, fromB64(entry.iv), new Uint8Array(await res.arrayBuffer()), AAD_FILE + path);
  }

  /**
   * Зашифровать набор файлов. files: [{ path, bytes }]. prev — прошлое хранилище { header, manifest } тем же паролем:
   * неизменившиеся файлы (тот же sha256) сохраняют IV и блоб — повторная публикация меняет только новое.
   * Возвращает { header, manifestBin, blobs: [{ name, bytes }], manifest } — что записать в vault/.
   */
  async function seal(files, password, { prev = null, keys = null, salt = null, iterations = ITERATIONS, onProgress = null } = {}) {
    const useSalt = salt || (prev ? fromB64(prev.header.kdf.salt) : randomBytes(16));
    const useIter = prev && !salt ? prev.header.kdf.iterations : iterations;
    const k = keys || await deriveKeys(password, useSalt, useIter);
    const out = { files: {} };
    const blobs = [];
    let i = 0;
    for (const f of files) {
      const sha = await sha256Hex(f.bytes);
      const old = prev && prev.manifest.files[f.path];
      const id = await fileId(k.names, f.path);
      const entry = { id, size: f.bytes.length, sha256: sha, type: mimeOf(f.path) };
      if (old && old.sha256 === sha && old.id === id) {
        entry.iv = old.iv;
        entry.reused = true;
      } else {
        const { iv, ct } = await encryptBytes(k.enc, f.bytes, AAD_FILE + f.path);
        entry.iv = toB64(iv);
        blobs.push({ name: id + '.bin', bytes: ct });
      }
      out.files[f.path] = entry;
      if (onProgress) onProgress(++i, files.length, f.path);
    }
    const reused = Object.values(out.files).filter((e) => e.reused).length;
    for (const e of Object.values(out.files)) delete e.reused;
    out.created = new Date().toISOString();
    const { iv, ct } = await encryptBytes(k.enc, enc.encode(JSON.stringify(out)), AAD_MANIFEST);
    const header = {
      format: FORMAT, version: VERSION, cipher: 'AES-256-GCM',
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: useIter, salt: toB64(useSalt) },
      manifest: { file: 'manifest.bin', iv: toB64(iv) },
    };
    return { header, manifestBin: ct, blobs, manifest: out, reused };
  }

  // ---------- типы файлов ----------

  const MIME = {
    html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8',
    css: 'text/css; charset=utf-8', json: 'application/json; charset=utf-8', svg: 'image/svg+xml', png: 'image/png',
    jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', ico: 'image/x-icon', md: 'text/markdown; charset=utf-8',
    txt: 'text/plain; charset=utf-8', py: 'text/plain; charset=utf-8', ps1: 'text/plain; charset=utf-8', webmanifest: 'application/manifest+json',
    woff2: 'font/woff2', mp4: 'video/mp4', pdf: 'application/pdf',
  };
  function mimeOf(path) {
    const ext = (path.split('.').pop() || '').toLowerCase();
    return MIME[ext] || 'application/octet-stream';
  }

  /** Что не шифруем и не публикуем (мусор систем и редакторов). */
  const skipPath = (p) => /(^|\/)(__pycache__|\.DS_Store|Thumbs\.db|desktop\.ini|\.git)(\/|$)/i.test(p) || /\.pyc$/i.test(p);

  // ---------- ключ сессии в IndexedDB (неэкспортируемый CryptoKey) ----------

  function idb() {
    return new Promise((resolve, reject) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  async function idbDo(mode, fn) {
    const db = await idb();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => resolve(req && req.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  const saveSession = (keys, meta) => idbDo('readwrite', (s) => s.put({ enc: keys.enc, names: keys.names, ...meta, at: Date.now() }, 'session'));
  const loadSession = () => idbDo('readonly', (s) => s.get('session')).catch(() => null);
  const clearSession = () => idbDo('readwrite', (s) => s.delete('session')).catch(() => null);

  function deleteDb(name) {
    return new Promise((resolve) => {
      let done = false;
      const fin = () => { if (!done) { done = true; resolve(); } };
      try {
        const r = indexedDB.deleteDatabase(name);
        r.onsuccess = fin;
        r.onerror = fin;
        r.onblocked = () => setTimeout(fin, 800);
      } catch {
        fin();
      }
      setTimeout(fin, 3000);
    });
  }

  /**
   * Стереть приложение с устройства: ключ сессии, все базы IndexedDB, localStorage и sessionStorage этого сайта,
   * Cache Storage и service worker. Зашифрованные файлы в обычном кеше браузера остаются — без пароля они бесполезны.
   */
  async function wipeDevice() {
    try { navigator.serviceWorker && navigator.serviceWorker.controller && navigator.serviceWorker.controller.postMessage({ type: 'lock' }); } catch { /* нет worker'а */ }
    try { localStorage.clear(); } catch { /* недоступно */ }
    try { sessionStorage.clear(); } catch { /* недоступно */ }
    try {
      const names = new Set([DB]);
      if (indexedDB.databases) for (const d of await indexedDB.databases()) if (d.name) names.add(d.name);
      await Promise.all([...names].map(deleteDb));
    } catch { /* ничего */ }
    try { if (root.caches) for (const k of await caches.keys()) await caches.delete(k); } catch { /* ничего */ }
    try { if (navigator.serviceWorker) for (const r of await navigator.serviceWorker.getRegistrations()) await r.unregister(); } catch { /* ничего */ }
  }

  // ---------- ZIP (без сжатия) — для браузеров без доступа к папкам ----------

  const CRC = (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(b) {
    let c = 0xffffffff;
    for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  /** entries: [{ name, bytes }] → Blob .zip (STORE, имена UTF-8). */
  function makeZip(entries) {
    const parts = [];
    const central = [];
    let offset = 0;
    for (const e of entries) {
      const name = enc.encode(e.name);
      const crc = crc32(e.bytes);
      const lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
      lh.setUint32(14, crc, true); lh.setUint32(18, e.bytes.length, true); lh.setUint32(22, e.bytes.length, true);
      lh.setUint16(26, name.length, true);
      parts.push(lh.buffer, name, e.bytes);
      const cd = new DataView(new ArrayBuffer(46));
      cd.setUint32(0, 0x02014b50, true); cd.setUint16(4, 20, true); cd.setUint16(6, 20, true); cd.setUint16(8, 0x0800, true);
      cd.setUint32(16, crc, true); cd.setUint32(20, e.bytes.length, true); cd.setUint32(24, e.bytes.length, true);
      cd.setUint16(28, name.length, true); cd.setUint32(42, offset, true);
      central.push(cd.buffer, name);
      offset += 30 + name.length + e.bytes.length;
    }
    const size = central.reduce((s, p) => s + (p.byteLength || p.length), 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true); end.setUint16(8, entries.length, true); end.setUint16(10, entries.length, true);
    end.setUint32(12, size, true); end.setUint32(16, offset, true);
    return new Blob([...parts, ...central, end.buffer], { type: 'application/zip' });
  }

  root.PddVault = {
    FORMAT, VERSION, ITERATIONS, AAD_FILE, AAD_MANIFEST,
    toB64, fromB64, toHex, randomBytes, deriveKeys, fileId, encryptBytes, decryptBytes, sha256Hex,
    fetchHeader, readManifest, open, readFile, blobUrl, seal, mimeOf, skipPath,
    saveSession, loadSession, clearSession, wipeDevice, makeZip,
  };
})(typeof self !== 'undefined' ? self : globalThis);
