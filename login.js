// Страница входа: регистрирует service worker (sw.js), проверяет, открыт ли уже вход на этом устройстве,
// иначе спрашивает пароль, выводит из него ключ (PBKDF2, 600 000 итераций), проверяет его расшифровкой оглавления
// хранилища и кладёт неэкспортируемый ключ в IndexedDB — дальше приложение по адресу ./app/ отдаёт service worker.
// После входа — переход в приложение с тем же #адресом (или на ?next=…, если пришли по ссылке внутрь приложения).

(function () {
  'use strict';
  const V = window.PddVault;
  const $ = (id) => document.getElementById(id);
  const form = $('login');
  const status = $('status');
  const BASE = new URL('./', location.href).href;
  const params = new URLSearchParams(location.search);

  const say = (text, tone = '') => {
    status.textContent = text;
    status.className = 'gate-status' + (tone ? ' ' + tone : '');
  };

  function target() {
    const next = params.get('next');
    const safe = next && /^app\/[\w\-./]*$/.test(next) ? next : 'app/';
    return new URL(safe, BASE).href + location.hash;
  }

  function ask(worker, type) {
    return new Promise((resolve) => {
      const ch = new MessageChannel();
      const timer = setTimeout(() => resolve({ unlocked: false, timeout: true }), 8000);
      ch.port1.onmessage = (e) => {
        clearTimeout(timer);
        resolve(e.data);
      };
      worker.postMessage({ type }, [ch.port2]);
    });
  }

  async function start() {
    if (!window.isSecureContext || !crypto.subtle) return say('Откройте страницу по https — без этого браузер не даёт шифрование.', 'bad');
    if (!('serviceWorker' in navigator)) return say('Этот браузер (или приватный режим) не поддерживает service worker — приложение не сможет расшифроваться.', 'bad');
    if (params.has('bye')) say('Вы вышли: ключ, прогресс и настройки стёрты с этого устройства.', 'ok');
    let reg;
    try {
      reg = await navigator.serviceWorker.register('sw.js', { scope: './' });
      await navigator.serviceWorker.ready;
    } catch (e) {
      return say('Не удалось запустить service worker: ' + e.message, 'bad');
    }
    const worker = reg.active || navigator.serviceWorker.controller;
    if (!params.has('bye')) {
      const st = await ask(worker, 'status');
      if (st.unlocked) {
        say('Вход уже выполнен — открываю…');
        location.replace(target());
        return;
      }
      say('');
    }
    form.hidden = false;
    $('password').focus();

    $('show').onclick = () => {
      const p = $('password');
      const on = p.type === 'password';
      p.type = on ? 'text' : 'password';
      $('show').setAttribute('aria-pressed', String(on));
    };

    form.onsubmit = async (e) => {
      e.preventDefault();
      const pw = $('password').value;
      if (!pw) return;
      $('enter').disabled = true;
      say('Проверяю пароль…');
      try {
        const { keys, manifest } = await V.open(BASE, pw);
        await V.saveSession(keys, { created: manifest.created });
        const st = await ask(reg.active || navigator.serviceWorker.controller, 'unlock');
        if (!st.unlocked) throw new Error('service worker не принял ключ');
        say('Пароль верный — открываю приложение…', 'ok');
        location.replace(target());
      } catch (err) {
        $('enter').disabled = false;
        $('password').select();
        say(err.code === 'bad-key' ? 'Неверный пароль.' : 'Ошибка: ' + err.message, 'bad');
      }
    };
  }

  start();
})();
