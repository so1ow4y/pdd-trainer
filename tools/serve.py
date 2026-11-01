"""Локальный сервер для разработки: python tools/serve.py [порт] [адрес] → http://localhost:8080

Адрес по умолчанию — localhost. Чтобы открыть приложение с телефона в той же сети: python tools/serve.py 8080 0.0.0.0
(вход по паролю работает только на localhost или по HTTPS: на http://<ip> браузер не запускает service worker).
"""

import functools
import http.server
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
HOST = sys.argv[2] if len(sys.argv) > 2 else 'localhost'


class Handler(http.server.SimpleHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'  # соединение живёт дольше одного файла: сотни картинок грузятся заметно быстрее
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, '.js': 'text/javascript', '.mjs': 'text/javascript',
                      '.webmanifest': 'application/manifest+json', '.webp': 'image/webp'}

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()


class DualStackServer(http.server.ThreadingHTTPServer):
    """IPv4 и IPv6 сразу: на Windows localhost сначала пробует ::1 и без этого теряет по 300 мс на каждый файл."""

    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def lan_addresses():
    """IPv4-адреса этого компьютера в локальной сети (без 127.x)."""
    found = set()
    try:
        found.update(a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('10.255.255.255', 1))  # пакет не отправляется — так ОС выбирает адрес основного интерфейса
            found.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in found if not a.startswith('127.'))


if __name__ == '__main__':
    handler = functools.partial(Handler, directory=str(ROOT))
    server = DualStackServer if HOST in ('0.0.0.0', '') else http.server.ThreadingHTTPServer
    with server(('::' if server is DualStackServer else HOST, PORT), handler) as httpd:
        print(f'http://localhost:{PORT}', flush=True)
        if HOST in ('0.0.0.0', ''):
            for ip in lan_addresses():
                print(f'http://{ip}:{PORT}', flush=True)
        httpd.serve_forever()
