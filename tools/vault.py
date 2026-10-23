"""Хранилище ПДД-тренажёра: шифрование папки app/ в vault/ (то, что публикуется на GitHub) и обратно.

    python tools/vault.py status            что изменилось в app/ по сравнению с vault/
    python tools/vault.py encrypt           зашифровать app/ → vault/ (неизменившиеся файлы не перешифровываются)
    python tools/vault.py decrypt           расшифровать vault/ → app/ (после git clone на новом компьютере)
    python tools/vault.py verify [--deep]   проверить пароль (--deep — расшифровать и сверить все файлы)
    python tools/vault.py passwd            сменить пароль: всё перешифровать новым ключом с новой солью
    python tools/vault.py genpass           придумать надёжный пароль и сохранить в secrets/vault-password.txt

Пароль берётся из переменной окружения PDD_VAULT_PASSWORD, из файла --password-file (по умолчанию
secrets/vault-password.txt, папка в .gitignore) или спрашивается с клавиатуры.

Схема — та же, что в vault-crypto.js (браузер): PBKDF2-HMAC-SHA256 (600 000 итераций, соль 16 байт) → 64 байта:
ключ AES-256-GCM и ключ HMAC-SHA256 для имён файлов. Каждый файл — AES-256-GCM со своим IV и путём в AAD;
оглавление (пути, размеры, sha256) тоже зашифровано. Пароль и его хеш нигде не хранятся.

Работает на стандартной библиотеке Python (AES-GCM реализован ниже); если установлен пакет cryptography —
использует его (быстрее). Без него полное шифрование всех картинок занимает десятки секунд.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / 'app'
VAULT = ROOT / 'vault'
BLOBS = VAULT / 'x'
PASSWORD_FILE = ROOT / 'secrets' / 'vault-password.txt'

FORMAT = 'pdd-vault'
VERSION = 1
ITERATIONS = 600_000
AAD_FILE = 'pdd-vault/1/file/'
AAD_MANIFEST = 'pdd-vault/1/manifest'

MIME = {
    'html': 'text/html; charset=utf-8', 'js': 'text/javascript; charset=utf-8', 'mjs': 'text/javascript; charset=utf-8',
    'css': 'text/css; charset=utf-8', 'json': 'application/json; charset=utf-8', 'svg': 'image/svg+xml', 'png': 'image/png',
    'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'webp': 'image/webp', 'gif': 'image/gif', 'ico': 'image/x-icon',
    'md': 'text/markdown; charset=utf-8', 'txt': 'text/plain; charset=utf-8', 'py': 'text/plain; charset=utf-8',
    'ps1': 'text/plain; charset=utf-8', 'webmanifest': 'application/manifest+json', 'woff2': 'font/woff2',
    'mp4': 'video/mp4', 'pdf': 'application/pdf',
}
SKIP_DIRS = {'__pycache__', '.git'}
SKIP_FILES = {'.DS_Store', 'Thumbs.db', 'desktop.ini'}


def mime_of(path):
    return MIME.get(path.rsplit('.', 1)[-1].lower(), 'application/octet-stream')


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


# ---------------------------------------------------------------- AES-256-GCM на чистом Python (NIST SP 800-38D)

def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        rot = lambda v, s: ((v << s) | (v >> (8 - s))) & 0xFF  # noqa: E731
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _make_sbox()
TE0 = [(_xtime(s) << 24) | (s << 16) | (s << 8) | (_xtime(s) ^ s) for s in SBOX]
TE1 = [((t >> 8) | (t << 24)) & 0xFFFFFFFF for t in TE0]
TE2 = [((t >> 16) | (t << 16)) & 0xFFFFFFFF for t in TE0]
TE3 = [((t >> 24) | (t << 8)) & 0xFFFFFFFF for t in TE0]


class _AES256:
    def __init__(self, key):
        assert len(key) == 32
        w = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(8)]
        rcon = 1
        sub = lambda t: (SBOX[t >> 24] << 24) | (SBOX[(t >> 16) & 255] << 16) | (SBOX[(t >> 8) & 255] << 8) | SBOX[t & 255]  # noqa: E731
        for i in range(8, 60):
            t = w[i - 1]
            if i % 8 == 0:
                t = sub(((t << 8) & 0xFFFFFFFF) | (t >> 24)) ^ (rcon << 24)
                rcon = _xtime(rcon)
            elif i % 8 == 4:
                t = sub(t)
            w.append(w[i - 8] ^ t)
        self.w = w

    def block(self, b):
        """Зашифровать один 128-битный блок (как целое число)."""
        w = self.w
        t0_, t1_, t2_, t3_ = TE0, TE1, TE2, TE3
        s0 = (b >> 96) ^ w[0]
        s1 = ((b >> 64) & 0xFFFFFFFF) ^ w[1]
        s2 = ((b >> 32) & 0xFFFFFFFF) ^ w[2]
        s3 = (b & 0xFFFFFFFF) ^ w[3]
        for k in range(4, 56, 4):
            s0, s1, s2, s3 = (
                t0_[s0 >> 24] ^ t1_[(s1 >> 16) & 255] ^ t2_[(s2 >> 8) & 255] ^ t3_[s3 & 255] ^ w[k],
                t0_[s1 >> 24] ^ t1_[(s2 >> 16) & 255] ^ t2_[(s3 >> 8) & 255] ^ t3_[s0 & 255] ^ w[k + 1],
                t0_[s2 >> 24] ^ t1_[(s3 >> 16) & 255] ^ t2_[(s0 >> 8) & 255] ^ t3_[s1 & 255] ^ w[k + 2],
                t0_[s3 >> 24] ^ t1_[(s0 >> 16) & 255] ^ t2_[(s1 >> 8) & 255] ^ t3_[s2 & 255] ^ w[k + 3],
            )
        S = SBOX
        o0 = ((S[s0 >> 24] << 24) | (S[(s1 >> 16) & 255] << 16) | (S[(s2 >> 8) & 255] << 8) | S[s3 & 255]) ^ w[56]
        o1 = ((S[s1 >> 24] << 24) | (S[(s2 >> 16) & 255] << 16) | (S[(s3 >> 8) & 255] << 8) | S[s0 & 255]) ^ w[57]
        o2 = ((S[s2 >> 24] << 24) | (S[(s3 >> 16) & 255] << 16) | (S[(s0 >> 8) & 255] << 8) | S[s1 & 255]) ^ w[58]
        o3 = ((S[s3 >> 24] << 24) | (S[(s0 >> 16) & 255] << 16) | (S[(s1 >> 8) & 255] << 8) | S[s2 & 255]) ^ w[59]
        return (o0 << 96) | (o1 << 64) | (o2 << 32) | o3


class _PureGCM:
    """AES-256-GCM с 96-битным IV и 128-битным тегом — совместим с WebCrypto."""

    R = 0xE1 << 120

    def __init__(self, key):
        self.aes = _AES256(key)
        h = self.aes.block(0)
        v = [h]
        for _ in range(127):
            x = v[-1]
            v.append((x >> 1) ^ self.R if x & 1 else x >> 1)
        tables = []
        for i in range(16):
            t = [0] * 256
            for b in range(1, 256):
                low = b & -b
                t[b] = t[b ^ low] ^ v[8 * i + 7 - (low.bit_length() - 1)]
            tables.append(t)
        self.tables = tables

    def _ghash(self, aad, ct):
        T = self.tables
        T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15 = T
        y = 0

        def absorb(data, y):
            n = len(data)
            if n % 16:
                data = data + bytes(16 - n % 16)
            fb = int.from_bytes
            for i in range(0, len(data), 16):
                x = y ^ fb(data[i:i + 16], 'big')
                y = (T0[x >> 120] ^ T1[(x >> 112) & 255] ^ T2[(x >> 104) & 255] ^ T3[(x >> 96) & 255]
                     ^ T4[(x >> 88) & 255] ^ T5[(x >> 80) & 255] ^ T6[(x >> 72) & 255] ^ T7[(x >> 64) & 255]
                     ^ T8[(x >> 56) & 255] ^ T9[(x >> 48) & 255] ^ T10[(x >> 40) & 255] ^ T11[(x >> 32) & 255]
                     ^ T12[(x >> 24) & 255] ^ T13[(x >> 16) & 255] ^ T14[(x >> 8) & 255] ^ T15[x & 255])
            return y

        y = absorb(aad, y)
        y = absorb(ct, y)
        y = absorb(((len(aad) * 8) << 64 | (len(ct) * 8)).to_bytes(16, 'big'), y)
        return y

    def _ctr(self, iv, data):
        if not data:
            return b''
        base = int.from_bytes(iv, 'big') << 32
        enc = self.aes.block
        n = (len(data) + 15) // 16
        ks = b''.join(enc(base | ((c + 2) & 0xFFFFFFFF)).to_bytes(16, 'big') for c in range(n))[:len(data)]
        return (int.from_bytes(data, 'big') ^ int.from_bytes(ks, 'big')).to_bytes(len(data), 'big')

    def _tag(self, iv, aad, ct):
        j0 = (int.from_bytes(iv, 'big') << 32) | 1
        return (self.aes.block(j0) ^ self._ghash(aad, ct)).to_bytes(16, 'big')

    def encrypt(self, iv, data, aad):
        ct = self._ctr(iv, data)
        return ct + self._tag(iv, aad, ct)

    def decrypt(self, iv, data, aad):
        ct, tag = data[:-16], data[-16:]
        if len(data) < 16 or not hmac.compare_digest(tag, self._tag(iv, aad, ct)):
            raise BadKey()
        return self._ctr(iv, ct)


class BadKey(Exception):
    pass


def gcm(key):
    """AES-GCM: пакет cryptography, если есть, иначе реализация выше."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        from cryptography.exceptions import InvalidTag  # type: ignore

        class _Fast:
            def __init__(self, k):
                self.a = AESGCM(k)

            def encrypt(self, iv, data, aad):
                return self.a.encrypt(iv, data, aad)

            def decrypt(self, iv, data, aad):
                try:
                    return self.a.decrypt(iv, data, aad)
                except InvalidTag as e:
                    raise BadKey() from e

        return _Fast(key)
    except ImportError:
        return _PureGCM(key)


def self_test():
    """Контрольные векторы: AES-256 (FIPS-197, C.3) и GCM (тест 16 из спецификации GCM)."""
    aes = _AES256(bytes(range(32)))
    assert aes.block(0x00112233445566778899AABBCCDDEEFF).to_bytes(16, 'big').hex() == '8ea2b7ca516745bfeafc49904b496089', 'AES-256'
    k = bytes.fromhex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308')
    iv = bytes.fromhex('cafebabefacedbaddecaf888')
    p = bytes.fromhex('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39')
    a = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
    out = _PureGCM(k).encrypt(iv, p, a)
    assert out[:-16].hex() == '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662', 'GCM шифртекст'
    assert out[-16:].hex() == '76fc6ece0f4e1768cddf8853bb2d551b', 'GCM тег'
    assert _PureGCM(k).decrypt(iv, out, a) == p


# ---------------------------------------------------------------- ключи и хранилище

class Keys:
    def __init__(self, password, salt, iterations):
        raw = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=64)
        self.cipher = gcm(raw[:32])
        self.names = raw[32:]

    def file_id(self, path):
        return hmac.new(self.names, path.encode('utf-8'), 'sha256').digest()[:16].hex()


def read_header():
    p = VAULT / 'vault.json'
    if not p.exists():
        return None
    h = json.loads(p.read_text(encoding='utf-8'))
    if h.get('format') != FORMAT or h.get('version') != VERSION:
        sys.exit('vault/vault.json: неизвестный формат хранилища')
    return h


def open_vault(password, header):
    keys = Keys(password, unb64(header['kdf']['salt']), header['kdf']['iterations'])
    data = (VAULT / header['manifest']['file']).read_bytes()
    try:
        manifest = json.loads(keys.cipher.decrypt(unb64(header['manifest']['iv']), data, AAD_MANIFEST.encode()))
    except BadKey:
        sys.exit('Неверный пароль (или хранилище повреждено).')
    return keys, manifest


def list_app():
    if not APP.is_dir():
        sys.exit('Нет папки app/ — сначала расшифруйте: python tools/vault.py decrypt')
    out = []
    for dirpath, dirnames, filenames in os.walk(APP):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            if f in SKIP_FILES or f.endswith('.pyc'):
                continue
            full = Path(dirpath) / f
            out.append(full.relative_to(APP).as_posix())
    return out


def get_password(args, confirm=False, prompt='Пароль хранилища: '):
    if os.environ.get('PDD_VAULT_PASSWORD'):
        return os.environ['PDD_VAULT_PASSWORD']
    pf = Path(args.password_file) if args.password_file else PASSWORD_FILE
    if pf.exists() and not getattr(args, 'ask', False):
        pw = pf.read_text(encoding='utf-8').strip()
        if pw:
            print(f'Пароль — из {pf.relative_to(ROOT) if pf.is_relative_to(ROOT) else pf}')
            return pw
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass('Ещё раз: ') != pw:
        sys.exit('Пароли не совпадают.')
    if len(pw) < 12:
        print('Внимание: пароль короче 12 символов — перебором его подобрать проще.')
    return pw


def write_vault(keys, header_kdf, manifest_files, new_blobs):
    BLOBS.mkdir(parents=True, exist_ok=True)
    for name, data in new_blobs:
        (BLOBS / name).write_bytes(data)
    manifest = {'files': manifest_files, 'created': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    iv = secrets.token_bytes(12)
    mbin = keys.cipher.encrypt(iv, json.dumps(manifest, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), AAD_MANIFEST.encode())
    (VAULT / 'manifest.bin').write_bytes(mbin)
    header = {
        'format': FORMAT, 'version': VERSION, 'cipher': 'AES-256-GCM',
        'kdf': header_kdf,
        'manifest': {'file': 'manifest.bin', 'iv': b64(iv)},
    }
    (VAULT / 'vault.json').write_text(json.dumps(header, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    keep = {e['id'] + '.bin' for e in manifest_files.values()}
    removed = 0
    for p in BLOBS.glob('*.bin'):
        if p.name not in keep:
            p.unlink()
            removed += 1
    return removed


def encrypt_files(keys, kdf, files, prev_files):
    out = {}
    new_blobs = []
    t0 = time.time()
    for i, path in enumerate(files, 1):
        data = (APP / path).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        fid = keys.file_id(path)
        old = prev_files.get(path)
        entry = {'id': fid, 'size': len(data), 'sha256': sha, 'type': mime_of(path)}
        if old and old.get('sha256') == sha and old.get('id') == fid and (BLOBS / (fid + '.bin')).exists():
            entry['iv'] = old['iv']
        else:
            iv = secrets.token_bytes(12)
            new_blobs.append((fid + '.bin', keys.cipher.encrypt(iv, data, (AAD_FILE + path).encode('utf-8'))))
            entry['iv'] = b64(iv)
            print(f'  [{i}/{len(files)}] {path}')
        out[path] = entry
    removed = write_vault(keys, kdf, out, new_blobs)
    print(f'Готово за {time.time() - t0:.1f} с: файлов {len(files)}, зашифровано заново {len(new_blobs)}, удалено старых блобов {removed}.')


def cmd_encrypt(args):
    header = read_header()
    files = list_app()
    if header and not args.rekey:
        pw = get_password(args)
        keys, manifest = open_vault(pw, header)
        kdf = header['kdf']
        prev = manifest['files']
    else:
        pw = get_password(args, confirm=True, prompt='Новый пароль хранилища: ')
        salt = secrets.token_bytes(16)
        kdf = {'name': 'PBKDF2', 'hash': 'SHA-256', 'iterations': args.iterations, 'salt': b64(salt)}
        keys = Keys(pw, salt, args.iterations)
        prev = {}
    encrypt_files(keys, kdf, files, prev)


def cmd_decrypt(args):
    header = read_header()
    if not header:
        sys.exit('Нет vault/vault.json — нечего расшифровывать.')
    pw = get_password(args)
    keys, manifest = open_vault(pw, header)
    files = manifest['files']
    written = skipped = 0
    t0 = time.time()
    for path, e in files.items():
        data = keys.cipher.decrypt(unb64(e['iv']), (BLOBS / (e['id'] + '.bin')).read_bytes(), (AAD_FILE + path).encode('utf-8'))
        if hashlib.sha256(data).hexdigest() != e['sha256']:
            sys.exit(f'{path}: контрольная сумма не совпала')
        dest = APP / path
        if dest.exists():
            cur = dest.read_bytes()
            if cur == data:
                continue
            if not args.force:
                print(f'  пропущен (в app/ другая версия, --force — перезаписать): {path}')
                skipped += 1
                continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        written += 1
    extra = [p for p in (list_app() if APP.is_dir() else []) if p not in files]
    if extra and args.clean:
        for p in extra:
            (APP / p).unlink()
        print(f'Удалено файлов, которых нет в хранилище: {len(extra)}')
    elif extra:
        print(f'В app/ есть файлы, которых нет в хранилище ({len(extra)}), — оставлены; --clean удалит их.')
    print(f'Готово за {time.time() - t0:.1f} с: записано {written}, пропущено {skipped}, всего в хранилище {len(files)}.')


def cmd_verify(args):
    header = read_header()
    if not header:
        sys.exit('Нет vault/vault.json.')
    pw = get_password(args)
    keys, manifest = open_vault(pw, header)
    files = manifest['files']
    missing = [p for p, e in files.items() if not (BLOBS / (e['id'] + '.bin')).exists()]
    print(f'Пароль верный. Файлов: {len(files)}, размер: {sum(e["size"] for e in files.values()) / 1e6:.1f} МБ, создано: {manifest.get("created")}.')
    if missing:
        sys.exit(f'Не хватает блобов: {len(missing)} (например, {missing[0]})')
    if args.deep:
        for path, e in files.items():
            data = keys.cipher.decrypt(unb64(e['iv']), (BLOBS / (e['id'] + '.bin')).read_bytes(), (AAD_FILE + path).encode('utf-8'))
            if hashlib.sha256(data).hexdigest() != e['sha256']:
                sys.exit(f'{path}: контрольная сумма не совпала')
        print('Все файлы расшифровываются и совпадают по sha256.')


def cmd_status(args):
    header = read_header()
    files = list_app()
    if not header:
        print(f'Хранилища ещё нет. В app/ файлов: {len(files)} — python tools/vault.py encrypt')
        return
    pw = get_password(args)
    _, manifest = open_vault(pw, header)
    old = manifest['files']
    changed = [p for p in files if p in old and hashlib.sha256((APP / p).read_bytes()).hexdigest() != old[p]['sha256']]
    added = [p for p in files if p not in old]
    gone = [p for p in old if p not in set(files)]
    for title, lst in (('изменены', changed), ('новые', added), ('удалены', gone)):
        for p in lst:
            print(f'  {title}: {p}')
    print('Без изменений.' if not (changed or added or gone) else f'Изменено {len(changed)}, новых {len(added)}, удалено {len(gone)} — python tools/vault.py encrypt')


def cmd_passwd(args):
    header = read_header()
    if not header:
        sys.exit('Нет хранилища.')
    old_pw = get_password(args, prompt='Текущий пароль: ')
    keys, manifest = open_vault(old_pw, header)
    plain = {}
    for path, e in manifest['files'].items():
        plain[path] = keys.cipher.decrypt(unb64(e['iv']), (BLOBS / (e['id'] + '.bin')).read_bytes(), (AAD_FILE + path).encode('utf-8'))
    args.ask = True
    new_pw = get_password(args, confirm=True, prompt='Новый пароль: ')
    salt = secrets.token_bytes(16)
    kdf = {'name': 'PBKDF2', 'hash': 'SHA-256', 'iterations': args.iterations, 'salt': b64(salt)}
    new_keys = Keys(new_pw, salt, args.iterations)
    out = {}
    blobs = []
    for path, data in plain.items():
        iv = secrets.token_bytes(12)
        fid = new_keys.file_id(path)
        blobs.append((fid + '.bin', new_keys.cipher.encrypt(iv, data, (AAD_FILE + path).encode('utf-8'))))
        out[path] = {'id': fid, 'iv': b64(iv), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'type': mime_of(path)}
    write_vault(new_keys, kdf, out, blobs)
    if PASSWORD_FILE.exists():
        PASSWORD_FILE.write_text(new_pw + '\n', encoding='utf-8')
        print(f'Новый пароль записан в {PASSWORD_FILE.relative_to(ROOT)}.')
    print('Пароль сменён: всё перешифровано новым ключом. Старый пароль к новому хранилищу не подходит.')


def cmd_genpass(args):
    alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    pw = '-'.join(''.join(secrets.choice(alphabet) for _ in range(5)) for _ in range(4))
    if PASSWORD_FILE.exists() and not args.force:
        sys.exit(f'{PASSWORD_FILE.relative_to(ROOT)} уже есть (--force — перезаписать).')
    PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
    PASSWORD_FILE.write_text(pw + '\n', encoding='utf-8')
    print(f'Пароль сохранён в {PASSWORD_FILE.relative_to(ROOT)} (папка secrets/ в .gitignore): {pw}')


def main():
    ap = argparse.ArgumentParser(description='Шифрование app/ ↔ vault/ для публикации ПДД-тренажёра.')
    ap.add_argument('--password-file', help='файл с паролем (по умолчанию secrets/vault-password.txt)')
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('encrypt', help='app/ → vault/')
    e.add_argument('--rekey', action='store_true', help='новая соль и новый пароль: всё перешифровать')
    e.add_argument('--iterations', type=int, default=ITERATIONS)
    d = sub.add_parser('decrypt', help='vault/ → app/')
    d.add_argument('--force', action='store_true', help='перезаписывать файлы app/, которые отличаются')
    d.add_argument('--clean', action='store_true', help='удалить из app/ файлы, которых нет в хранилище')
    v = sub.add_parser('verify', help='проверить пароль и хранилище')
    v.add_argument('--deep', action='store_true')
    sub.add_parser('status', help='что изменилось в app/')
    p = sub.add_parser('passwd', help='сменить пароль')
    p.add_argument('--iterations', type=int, default=ITERATIONS)
    g = sub.add_parser('genpass', help='придумать пароль')
    g.add_argument('--force', action='store_true')
    sub.add_parser('selftest', help='проверить реализацию AES-GCM на контрольных векторах')
    args = ap.parse_args()
    if args.cmd != 'selftest':
        self_test()
    {'encrypt': cmd_encrypt, 'decrypt': cmd_decrypt, 'verify': cmd_verify, 'status': cmd_status, 'passwd': cmd_passwd,
     'genpass': cmd_genpass, 'selftest': lambda a: (self_test(), print('AES-256 и AES-256-GCM: контрольные векторы сошлись.'))}[args.cmd](args)


if __name__ == '__main__':
    main()
