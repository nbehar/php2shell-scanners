#!/usr/bin/env python3
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROUTES = {
    "/vulnerable": [("X-Powered-By", "PHP/8.4.26")],
    "/fixed": [("X-Powered-By", "PHP/8.4.27")],
    "/vendor": [("X-Powered-By", "PHP/8.5.11-1+deb12u1")],
    "/eol": [("X-Powered-By", "PHP/7.4.33")],
    "/old-unassessed": [("X-Powered-By", "PHP/7.3.33")],
    "/duplicate": [
        ("X-Powered-By", "PHP/8.4.27"),
        ("X-Powered-By", "PHP/8.3.35"),
    ],
    "/none": [],
}


class Handler(BaseHTTPRequestHandler):
    server_version = "php2shell-test"
    sys_version = ""

    def do_GET(self):
        headers = ROUTES.get(self.path)
        if headers is None:
            self.send_error(404)
            return

        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        pass


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, _request, _client_address):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    QuietThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
