import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
from functools import partial


class DualPathHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, web_dir='', data_dir='', **kwargs):
        self.web_dir = web_dir
        self.data_dir = data_dir
        super().__init__(*args, **kwargs)

    def translate_path(self, path):
        path = path.split('?', 1)[0].split('#', 1)[0]

        if path.startswith('/host_stat'):
            rel_path = path[len('/host_stat'):]
            return os.path.join(self.data_dir, rel_path.lstrip('/'))
        else:
            rel_path = path.lstrip('/')
            return os.path.join(self.web_dir, rel_path)

    def log_message(self, format, *args):
        pass


def main():
    port = int(sys.argv[1])
    web_dir = sys.argv[2]
    data_dir = sys.argv[3]

    handler = partial(DualPathHandler, web_dir=web_dir, data_dir=data_dir)
    server = HTTPServer(('0.0.0.0', port), handler)
    server.serve_forever()


if __name__ == '__main__':
    main()
