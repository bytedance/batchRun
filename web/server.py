import os
import sys
import html
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import partial


def _safe_join(base_dir, rel_path):
    """
    Join base_dir + rel_path and guarantee the resolved real path stays inside
    base_dir. Returns None on any escape attempt (path traversal).
    """
    if not base_dir:
        return None

    rel_path = rel_path.split('?', 1)[0].split('#', 1)[0]
    rel_path = rel_path.lstrip('/')
    candidate = os.path.normpath(os.path.join(base_dir, rel_path))
    base_real = os.path.realpath(base_dir)
    candidate_real = os.path.realpath(candidate)

    if candidate_real != base_real and not candidate_real.startswith(base_real + os.sep):
        return None

    if not os.path.exists(candidate_real):
        return None

    return candidate_real


class DualPathHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, web_dir='', data_dir='', auth_token='', **kwargs):
        self.web_dir = os.path.realpath(web_dir) if web_dir else ''
        self.data_dir = os.path.realpath(data_dir) if data_dir else ''
        self.auth_token = auth_token
        super().__init__(*args, **kwargs)

    def _check_auth(self):
        if not self.auth_token:
            return True

        token = ''
        cookie = self.headers.get('Cookie', '')

        for item in cookie.split(';'):
            if item.strip().startswith('token='):
                token = item.strip().split('=', 1)[1]
                break

        if not token:
            auth = self.headers.get('Authorization', '')

            if auth.startswith('Bearer '):
                token = auth[len('Bearer '):]

        if not token and '?' in self.path:
            qs = self.path.split('?', 1)[1]

            for pair in qs.split('&'):
                if pair.startswith('token='):
                    token = pair[len('token='):]
                    break

        return hmac.compare_digest(token, self.auth_token)

    def translate_path(self, path):
        path = path.split('?', 1)[0].split('#', 1)[0]

        if path.startswith('/host_stat'):
            rel_path = path[len('/host_stat'):]
            return _safe_join(self.data_dir, rel_path)
        else:
            rel_path = path
            return _safe_join(self.web_dir, rel_path)

    def do_GET(self):
        if not self._check_auth():
            self.send_response(401)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Unauthorized')
            return

        path = self.translate_path(self.path)

        if path is None:
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')
            return

        if os.path.isdir(path):
            return self._list_dir(path)

        return self._serve_file(path)

    def _serve_file(self, path):
        try:
            with open(path, 'rb') as FH:
                content = FH.read()

            self.send_response(200)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except PermissionError:
            self.send_response(403)
            self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()

    def _list_dir(self, path):
        try:
            entries = sorted(os.listdir(path))
            lines = ['<html><head><meta charset="utf-8"><title>Index</title></head><body><h1>Index</h1><ul>']

            for entry in entries:
                full = os.path.join(path, entry)
                name = entry + '/' if os.path.isdir(full) else entry
                safe = html.escape(name, quote=True)
                lines.append('<li><a href="{0}">{1}</a></li>'.format(safe, safe))

            lines.append('</ul></body></html>')
            content = '\n'.join(lines).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except PermissionError:
            self.send_response(403)
            self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def main():
    if len(sys.argv) < 4:
        sys.stderr.write('Usage: server.py <port> <web_dir> <data_dir> [bind_host] [auth_token]\n')
        sys.exit(1)

    port = int(sys.argv[1])
    web_dir = sys.argv[2]
    data_dir = sys.argv[3]
    bind_host = sys.argv[4] if len(sys.argv) > 4 else '127.0.0.1'
    auth_token = sys.argv[5] if len(sys.argv) > 5 else ''

    handler = partial(DualPathHandler, web_dir=web_dir, data_dir=data_dir, auth_token=auth_token)
    server = HTTPServer((bind_host, port), handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
