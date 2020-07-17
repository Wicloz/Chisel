#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import cloudscraper
import validators

requests = cloudscraper.create_scraper()


class Chisel(BaseHTTPRequestHandler):
    def do_GET(self):
        self.path = self.path[1:]
        if not validators.url(self.path):
            self.send_error(400)
            return
        resp = requests.get(self.path)

        self.send_response(resp.status_code)
        if 'content-type' in resp.headers:
            self.send_header('content-type', resp.headers['content-type'])
        self.end_headers()

        self.wfile.write(resp.content)


if __name__ == '__main__':
    HTTPServer(('', 1234), Chisel).serve_forever()
