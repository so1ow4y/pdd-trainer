// Панель хранилища (vault.html): шифрование app/ → vault/, расшифровка vault/ → app/, смена пароля — в выбранной
// папке проекта через File System Access API; без него — расшифровка опубликованного хранилища в ZIP и шифрование
// выбранной папки в ZIP. Формат тот же, что у tools/vault.py (см. vault-crypto.js), файлы взаимозаменяемы.

(function () {
  'use strict';
  const V = window.PddVault;
  const $ = (id) => document.getElementById(id);
  const BASE = new URL('./', location.href).href;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  let root = null; // FileSystemDirectoryHandle папки проекта
  let busy = false;

  const log = (el, text, tone = '') => {
    const line = document.createElement('div');
    if (tone) line.className = tone;
    line.textContent = text;
    el.append(line);
    el.scrollTop = el.scrollHeight;
  };
  const L = (t, tone) => log($('log'), t, tone);
  const L2 = (t, tone) => log($('log2'), t, tone);
  const bar = (i, n) => { $('bar').style.width = n ? `${Math.round((i / n) * 100)}%` : '0'; };
  const password = () => $('pw').value;

  async function run(fn, out = L) {
    if (busy) return;
    busy = true;
    document.querySelectorAll('button').forEach((b) => { b.dataset.was = b.disabled; b.disabled = true; });
    const t0 = performance.now();
    try {
      await fn();
      out(`Готово за ${((performance.now() - t0) / 1000).toFixed(1)} с.`, 'ok');
    } catch (e) {
      out(e.code === 'bad-key' ? 'Неверный пароль (или хранилище повреждено).' : 'Ошибка: ' + (e.message || e), 'bad');
    } finally {
      document.querySelectorAll('button').forEach((b) => { b.disabled = b.dataset.was === 'true'; });
      busy = false;
      bar(0, 0);
    }
  }

  function needPassword() {
    if (!password()) throw new Error('введите пароль в пункте 1');
    return password();
  }

  // ---------- 1. Пароль ----------

  $('check').onclick = () => run(async () => {
    const st = $('pw-status');
    st.className = 'muted';
    st.textContent = 'Проверяю (600 000 итераций PBKDF2 — пара секунд)…';
    try {
      const { manifest } = await V.open(BASE, needPassword());
      const files = Object.values(manifest.files);
      st.className = 'ok';
      st.textContent = `Пароль подходит к хранилищу сайта: ${files.length} файлов, ${(files.reduce((s, f) => s + f.size, 0) / 1048576).toFixed(1)} МБ, собрано ${new Date(manifest.created).toLocaleString('ru-RU')}.`;
    } catch (e) {
      st.className = 'bad';
      st.textContent = e.code === 'bad-key' ? 'Неверный пароль.' : e.message;
      throw e;
    }
  }, () => {});

  // ---------- папка проекта (File System Access API) ----------

  if (!window.showDirectoryPicker) {
    $('fs').querySelector('p').insertAdjacentHTML('afterend', '<p class="warn">Этот браузер не умеет работать с папками — используйте пункт 3 или Chrome/Edge на компьютере.</p>');
    $('pick').disabled = true;
    $('gen').disabled = true;
  }

  async function sub(dir, name, create = false) {
    try {
      return await dir.getDirectoryHandle(name, { create });
    } catch {
      return null;
    }
  }
  async function readFile(dir, name) {
    try {
      return new Uint8Array(await (await (await dir.getFileHandle(name)).getFile()).arrayBuffer());
    } catch {
      return null;
    }
  }
  async function writeFile(dir, name, bytes) {
    const w = await (await dir.getFileHandle(name, { create: true })).createWritable();
    await w.write(bytes);
    await w.close();
  }
  async function dirAt(base, path, create) {
    let d = base;
    for (const part of path.split('/').slice(0, -1)) {
      d = await (create ? d.getDirectoryHandle(part, { create: true }) : d.getDirectoryHandle(part));
    }
    return d;
  }

  /** Все файлы папки: [{ path, handle }], без .git, __pycache__ и системного мусора. */
  async function walk(dir, prefix = '') {
    const out = [];
    for await (const [name, h] of dir.entries()) {
      const path = prefix + name;
      if (V.skipPath(path)) continue;
      if (h.kind === 'directory') out.push(...await walk(h, path + '/'));
      else out.push({ path, handle: h });
    }
    return out.sort((a, b) => (a.path < b.path ? -1 : 1));
  }

  $('pick').onclick = async () => {
    try {
      const d = await window.showDirectoryPicker({ id: 'pdd-trainer', mode: 'readwrite' });
      const app = await sub(d, 'app');
      const vault = await sub(d, 'vault');
      if (!app && !vault) {
        L(`В «${d.name}» нет ни app/, ни vault/ — выберите папку pdd-trainer.`, 'bad');
        return;
      }
      root = d;
      $('folder').textContent = `${d.name}: app/ ${app ? 'есть' : 'нет'}, vault/ ${vault ? 'есть' : 'нет'}`;
      ['status', 'encrypt', 'decrypt', 'passwd'].forEach((id) => { $(id).disabled = false; });
    } catch (e) {
      if (e.name !== 'AbortError') L('Ошибка: ' + e.message, 'bad');
    }
  };

  /** Локальное хранилище папки: { header, manifest, keys } или null, если его нет. */
  async function openLocal(pw) {
    const vault = await sub(root, 'vault');
    const raw = vault && await readFile(vault, 'vault.json');
    if (!raw) return null;
    const header = JSON.parse(dec.decode(raw));
    if (header.format !== V.FORMAT || header.version !== V.VERSION) throw new Error('vault/vault.json: неизвестный формат');
    const keys = await V.deriveKeys(pw, V.fromB64(header.kdf.salt), header.kdf.iterations);
    const mbin = await readFile(vault, header.manifest.file);
    if (!mbin) throw new Error('нет vault/' + header.manifest.file);
    const manifest = JSON.parse(dec.decode(await V.decryptBytes(keys.enc, V.fromB64(header.manifest.iv), mbin, V.AAD_MANIFEST)));
    return { header, manifest, keys, vault };
  }

  async function appFiles() {
    const app = await sub(root, 'app');
    if (!app) throw new Error('нет папки app/ — сначала расшифруйте');
    const list = await walk(app);
    const files = [];
    for (const f of list) files.push({ path: f.path, bytes: new Uint8Array(await (await f.handle.getFile()).arrayBuffer()) });
    return files;
  }

  /** Записать результат seal() в vault/ и удалить блобы, которых больше нет в оглавлении. */
  async function writeVault(sealed) {
    const vault = await sub(root, 'vault', true);
    const x = await vault.getDirectoryHandle('x', { create: true });
    let i = 0;
    for (const b of sealed.blobs) {
      await writeFile(x, b.name, b.bytes);
      bar(++i, sealed.blobs.length);
    }
    await writeFile(vault, 'manifest.bin', sealed.manifestBin);
    await writeFile(vault, 'vault.json', enc.encode(JSON.stringify(sealed.header, null, 1) + '\n'));
    const keep = new Set(Object.values(sealed.manifest.files).map((e) => e.id + '.bin'));
    let removed = 0;
    for await (const [name] of x.entries()) {
      if (name.endsWith('.bin') && !keep.has(name)) {
        await x.removeEntry(name);
        removed++;
      }
    }
    return removed;
  }

  $('status').onclick = () => run(async () => {
    const local = await openLocal(needPassword());
    const files = await appFiles();
    if (!local) {
      L(`Хранилища ещё нет. В app/ файлов: ${files.length} — нажмите «Зашифровать».`);
      return;
    }
    const old = local.manifest.files;
    const now = new Set(files.map((f) => f.path));
    let n = 0;
    for (const f of files) {
      if (!old[f.path]) { L('  новый: ' + f.path); n++; } else if (await V.sha256Hex(f.bytes) !== old[f.path].sha256) { L('  изменён: ' + f.path); n++; }
    }
    for (const p of Object.keys(old)) if (!now.has(p)) { L('  удалён: ' + p); n++; }
    L(n ? `Изменений: ${n} — нажмите «Зашифровать».` : 'Хранилище совпадает с app/.');
  });

  $('encrypt').onclick = () => run(async () => {
    const pw = needPassword();
    const files = await appFiles();
    const local = $('rekey').checked ? null : await openLocal(pw);
    let prev = null;
    if (local) {
      // переиспользуем только те файлы, чьи блобы действительно лежат в vault/x/
      const x = await sub(local.vault, 'x');
      const have = new Set();
      if (x) for await (const [name] of x.entries()) have.add(name);
      const kept = {};
      for (const [p, e] of Object.entries(local.manifest.files)) if (have.has(e.id + '.bin')) kept[p] = e;
      prev = { header: local.header, manifest: { files: kept } };
    }
    L(local ? `Шифрую ${files.length} файлов (тем же ключом, неизменившиеся пропускаются)…` : `Шифрую ${files.length} файлов новым ключом…`);
    const sealed = await V.seal(files, pw, { prev, keys: local ? local.keys : null, onProgress: (i, n) => bar(i, n) });
    const removed = await writeVault(sealed);
    L(`Файлов ${files.length}: зашифровано заново ${sealed.blobs.length}, без изменений ${sealed.reused}, удалено старых блобов ${removed}.`, 'ok');
    L('Дальше — git add vault и коммит (в публичную репу).');
  });

  $('decrypt').onclick = () => run(async () => {
    const local = await openLocal(needPassword());
    if (!local) throw new Error('нет vault/vault.json');
    const app = await sub(root, 'app', true);
    const x = await sub(local.vault, 'x');
    const entries = Object.entries(local.manifest.files);
    let written = 0, same = 0, skipped = 0, i = 0;
    for (const [path, e] of entries) {
      const ct = x && await readFile(x, e.id + '.bin');
      if (!ct) throw new Error('нет блоба для ' + path);
      const data = await V.decryptBytes(local.keys.enc, V.fromB64(e.iv), ct, V.AAD_FILE + path);
      if (await V.sha256Hex(data) !== e.sha256) throw new Error(path + ': контрольная сумма не совпала');
      const d = await dirAt(app, path, true);
      const name = path.split('/').pop();
      const cur = await readFile(d, name);
      if (cur && cur.length === data.length && cur.every((b, k) => b === data[k])) same++;
      else if (cur && !$('force').checked) { L('  пропущен (в app/ другая версия): ' + path, 'warn'); skipped++; }
      else { await writeFile(d, name, data); written++; }
      bar(++i, entries.length);
    }
    L(`Записано ${written}, уже совпадали ${same}, пропущено ${skipped}.`, 'ok');
    if (skipped) L('Чтобы перезаписать пропущенные — отметьте «перезаписывать» и запустите ещё раз.', 'warn');
  });

  const ALPHABET = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  $('gen').onclick = () => {
    const pick = () => {
      const b = new Uint8Array(1);
      do crypto.getRandomValues(b); while (b[0] >= 256 - (256 % ALPHABET.length));
      return ALPHABET[b[0] % ALPHABET.length];
    };
    const pw = Array.from({ length: 4 }, () => Array.from({ length: 5 }, pick).join('')).join('-');
    $('pw-new').value = $('pw-new2').value = pw;
    $('pw-new').type = 'text';
    L('Придуман пароль (запишите его!): ' + pw);
  };

  $('passwd').onclick = () => run(async () => {
    const oldPw = needPassword();
    const pw = $('pw-new').value;
    if (pw.length < 12) throw new Error('новый пароль короче 12 символов');
    if (pw !== $('pw-new2').value) throw new Error('новые пароли не совпадают');
    const local = await openLocal(oldPw);
    if (!local) throw new Error('нет vault/vault.json');
    const x = await sub(local.vault, 'x');
    const files = [];
    let i = 0;
    const entries = Object.entries(local.manifest.files);
    L(`Расшифровываю ${entries.length} файлов старым ключом…`);
    for (const [path, e] of entries) {
      const ct = await readFile(x, e.id + '.bin');
      if (!ct) throw new Error('нет блоба для ' + path);
      files.push({ path, bytes: await V.decryptBytes(local.keys.enc, V.fromB64(e.iv), ct, V.AAD_FILE + path) });
      bar(++i, entries.length);
    }
    L('Шифрую новым ключом…');
    const sealed = await V.seal(files, pw, { onProgress: (k, n) => bar(k, n) });
    await writeVault(sealed);
    const secrets = await sub(root, 'secrets');
    if (secrets && await readFile(secrets, 'vault-password.txt')) {
      await writeFile(secrets, 'vault-password.txt', enc.encode(pw + '\n'));
      L('secrets/vault-password.txt обновлён.');
    }
    $('pw').value = pw;
    L('Пароль сменён. Опубликуйте vault/ — после этого старый пароль не подойдёт.', 'ok');
  });

  // ---------- 3. ZIP ----------

  const download = (blob, name) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  };
  const stamp = () => new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');

  $('zip-src').onclick = () => run(async () => {
    const { keys, manifest } = await V.open(BASE, needPassword());
    const entries = Object.entries(manifest.files);
    const out = [];
    for (const [path, e] of entries) {
      const data = await V.readFile(BASE, keys.enc, path, e);
      out.push({ name: 'app/' + path, bytes: data });
      if (out.length % 10 === 0) L2(`  ${out.length}/${entries.length}`);
    }
    download(V.makeZip(out), `pdd-trainer-app-${stamp()}.zip`);
    L2(`Архив: ${out.length} файлов — распакуйте в папку проекта.`, 'ok');
  }, L2);

  $('zip-enc-btn').onclick = () => $('zip-enc').click();
  $('zip-enc').onchange = (ev) => run(async () => {
    const pw = needPassword();
    const picked = [...ev.target.files];
    ev.target.value = '';
    if (!picked.length) return;
    // webkitRelativePath = «app/src/…»: первая часть — имя выбранной папки
    const files = [];
    for (const f of picked) {
      const path = f.webkitRelativePath.split('/').slice(1).join('/');
      if (!path || V.skipPath(path)) continue;
      files.push({ path, bytes: new Uint8Array(await f.arrayBuffer()) });
    }
    let prev = null;
    let keys = null;
    try {
      const site = await V.open(BASE, pw);
      prev = { header: site.header, manifest: site.manifest };
      keys = site.keys;
      L2('Пароль подходит к хранилищу сайта — ключ тот же, неизменившиеся файлы сохранят свои блобы.');
    } catch (e) {
      if (e.code === 'bad-key') L2('К хранилищу сайта пароль не подходит — шифрую новым ключом (это смена пароля).', 'warn');
    }
    const sealed = await V.seal(files, pw, { prev, keys });
    const out = [
      { name: 'vault/vault.json', bytes: enc.encode(JSON.stringify(sealed.header, null, 1) + '\n') },
      { name: 'vault/manifest.bin', bytes: sealed.manifestBin },
      ...sealed.blobs.map((b) => ({ name: 'vault/x/' + b.name, bytes: b.bytes })),
    ];
    const fresh = new Set(sealed.blobs.map((b) => b.name));
    for (const e of Object.values(sealed.manifest.files)) {
      if (fresh.has(e.id + '.bin')) continue;
      const res = await fetch(V.blobUrl(BASE, e));
      out.push({ name: 'vault/x/' + e.id + '.bin', bytes: new Uint8Array(await res.arrayBuffer()) });
    }
    download(V.makeZip(out), `pdd-trainer-vault-${stamp()}.zip`);
    L2(`Архив vault/: ${files.length} файлов. Удалите старую папку vault/ в проекте и распакуйте этот архив на её место.`, 'ok');
  }, L2);

  // ---------- 4. Выход ----------

  $('wipe').onclick = async () => {
    if (!confirm('Стереть с этого устройства всё, что оставило приложение (вход, прогресс, настройки)?')) return;
    await V.wipeDevice();
    $('pw').value = '';
    $('wipe-status').className = 'ok';
    $('wipe-status').textContent = 'Стёрто. Для входа снова понадобится пароль.';
  };
})();
